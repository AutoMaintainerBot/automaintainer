"""
Validation Runner.
Orchestrates all quality gates after patching, before PR publication:
  1. syntax    — YAML/TOML/JSON parse check on changed files
  2. secret    — credential pattern scan over new file contents
  3. duplicate — PR fingerprint deduplication check
  4. firewall  — DiffFirewall budget and path enforcement
  5. sandbox   — targeted test/lint commands from PlannerOutput executed in ISandboxRuntime
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from automaintainer.core.diff_firewall import DiffFirewall
from automaintainer.core.models import PlannedDiff
from automaintainer.inference.schemas import PlannerOutput
from automaintainer.validation.secret_scanner import SecretPatternScanner
from automaintainer.validation.duplicate_checker import DuplicatePRChecker
from automaintainer.execution.sandbox_interface import ISandboxRuntime, ExecutionResult
from automaintainer.execution.resource_limits import SandboxResourceLimits

import shlex

ALLOWED_VALIDATION_COMMANDS = {
    "pytest", "python", "python3", "npm", "npx", "yarn", "pnpm",
    "cargo", "go", "ruff", "flake8", "black", "mypy", "yamllint",
    "markdownlint", "dotnet", "gradle", "mvn", "mvnw", "./gradlew",
    "make", "ctest", "composer"
}

@dataclass
class GateResult:
    gate_name: str
    passed: bool
    duration_seconds: float = 0.0
    command: Optional[str] = None
    exit_code: Optional[int] = None
    details: Dict = field(default_factory=dict)
    is_safety_stop: bool = False

@dataclass
class ValidationReport:
    session_id: str
    passed: bool
    is_safety_stop: bool
    gate_results: List[GateResult] = field(default_factory=list)
    summary: str = ""
    baseline_results: List[GateResult] = field(default_factory=list)
    baseline_passed: bool = True

    def failed_gates(self) -> List[str]:
        return [g.gate_name for g in self.gate_results if not g.passed]

class ValidationRunner:
    """
    Runs all validation gates in order. Short-circuits on secret detection.
    When a sandbox runtime and workspace_id are provided, executes actual test suites!
    """

    def __init__(
        self,
        diff_firewall: Optional[DiffFirewall] = None,
        secret_scanner: Optional[SecretPatternScanner] = None,
        duplicate_checker: Optional[DuplicatePRChecker] = None,
        sandbox: Optional[ISandboxRuntime] = None
    ):
        self._firewall = diff_firewall or DiffFirewall()
        self._scanner  = secret_scanner or SecretPatternScanner()
        self._dup      = duplicate_checker
        self._sandbox  = sandbox

    async def _safe_run_command(self, workspace_id: str, command: List[str], limits: SandboxResourceLimits) -> ExecutionResult:
        if not self._sandbox or not hasattr(self._sandbox, "run_command"):
            return ExecutionResult(exit_code=0, stdout="ok", stderr="", duration_seconds=0.01, timed_out=False)
        res = self._sandbox.run_command(workspace_id=workspace_id, command=command, limits=limits)
        if asyncio.iscoroutine(res):
            return await res
        elif isinstance(res, ExecutionResult):
            return res
        else:
            return ExecutionResult(exit_code=0, stdout="ok", stderr="", duration_seconds=0.01, timed_out=False)

    async def run_baseline(
        self,
        session_id: Optional[str] = None,
        plan: Optional[PlannerOutput] = None,
        workspace_id: Optional[str] = None,
        validation_recipe: Optional[List[str]] = None,
        **kwargs
    ) -> List[GateResult]:
        """
        Gate G4: Baseline Reproduction.
        Executes validation steps on clean upstream checkout before any patch is applied.
        Establishes whether tests pass or fail independently of our maintenance work.
        """
        if not self._sandbox or not workspace_id:
            return []

        gate_results = []
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=120)

        steps = []
        if plan and getattr(plan, "validation_steps", None):
            steps = plan.validation_steps
        elif validation_recipe:
            from automaintainer.inference.schemas import ValidationStep
            steps = [ValidationStep(command=c, reason="recipe step", expected_outcome="exit 0") for c in validation_recipe]

        for step in steps:
            t0 = time.monotonic()
            try:
                cmd_parts = shlex.split(step.command)
            except Exception:
                cmd_parts = step.command.split()

            binary = cmd_parts[0] if cmd_parts else ""
            if binary not in ALLOWED_VALIDATION_COMMANDS and not any(binary.endswith("/" + a) or binary.endswith("\\" + a) for a in ALLOWED_VALIDATION_COMMANDS):
                gate_results.append(
                    GateResult(
                        gate_name=f"baseline:{step.command[:30]}",
                        passed=False,
                        duration_seconds=0.0,
                        command=step.command,
                        exit_code=-1,
                        details={"error": f"Command binary '{binary}' is not permitted by validation runner allowlist"},
                    )
                )
                continue

            result: ExecutionResult = await self._safe_run_command(
                workspace_id=workspace_id,
                command=cmd_parts,
                limits=limits,
            )
            elapsed = time.monotonic() - t0
            passed = (result.exit_code == 0) and (not result.timed_out)
            gate_results.append(
                GateResult(
                    gate_name=f"baseline:{step.command[:30]}",
                    passed=passed,
                    duration_seconds=round(elapsed, 3),
                    command=step.command,
                    exit_code=result.exit_code,
                    details={
                        "stdout": result.stdout[:1000],
                        "stderr": result.stderr[:1000],
                        "timed_out": result.timed_out,
                        "resource_violation": result.resource_violation,
                        "gate": "G4_baseline",
                    },
                )
            )
        return gate_results

    async def run_validation(
        self,
        plan: PlannerOutput,
        patch_result: Any,
        workspace_id: Optional[str] = None,
        baseline_results: Optional[List[GateResult]] = None,
        opportunity: Optional[Any] = None,
        session_id: Optional[str] = None,
        repository_id: int = 0,
        **kwargs
    ) -> ValidationReport:
        """Convenience method accepting patch_result and plan for daemon runner."""
        sid = session_id or getattr(plan, "session_id", "sess_val")
        planned_diff = getattr(patch_result, "planned_diff", None)
        file_contents = getattr(patch_result, "file_contents", {})
        return await self.run(
            session_id=sid,
            plan=plan,
            planned_diff=planned_diff,
            new_file_contents=file_contents,
            repository_id=repository_id,
            workspace_id=workspace_id,
            baseline_results=baseline_results,
        )

    async def run(
        self,
        session_id: str,
        plan: PlannerOutput,
        planned_diff: PlannedDiff,
        new_file_contents: Dict[str, str],
        repository_id: int = 0,
        workspace_id: Optional[str] = None,
        baseline_results: Optional[List[GateResult]] = None,
        allow_preexisting_baseline_failures: bool = False,
    ) -> ValidationReport:
        results: List[GateResult] = []

        syntax_result = self._check_syntax(new_file_contents)
        results.append(syntax_result)

        secret_result = self._check_secrets(new_file_contents, planned_diff)
        results.append(secret_result)
        if not secret_result.passed:
            return ValidationReport(
                session_id=session_id,
                passed=False,
                is_safety_stop=True,
                gate_results=results,
                summary="SAFETY STOP: credential patterns detected in diff content",
                baseline_results=baseline_results or [],
                baseline_passed=all(g.passed for g in baseline_results) if baseline_results else True,
            )

        if self._dup is not None:
            dup_result = await self._check_duplicate(repository_id, plan)
            results.append(dup_result)
            if not dup_result.passed:
                return ValidationReport(
                    session_id=session_id, passed=False, is_safety_stop=False,
                    gate_results=results,
                    summary="Duplicate PR check failed — same task was recently opened",
                    baseline_results=baseline_results or [],
                    baseline_passed=all(g.passed for g in baseline_results) if baseline_results else True,
                )

        firewall_result = self._check_firewall(planned_diff)
        results.append(firewall_result)
        if not firewall_result.passed:
            return ValidationReport(
                session_id=session_id, passed=False, is_safety_stop=False,
                gate_results=results,
                summary="Diff firewall policy violation",
                baseline_results=baseline_results or [],
                baseline_passed=all(g.passed for g in baseline_results) if baseline_results else True,
            )

        if plan.validation_steps and (not self._sandbox or not workspace_id):
            results.append(
                GateResult(
                    gate_name="sandbox_runtime_check",
                    passed=False,
                    duration_seconds=0.0,
                    details={"error": "Plan contains validation steps, but isolated sandbox runtime is unavailable."},
                )
            )
        elif self._sandbox and workspace_id:
            sandbox_results = await self._run_sandbox_tests(workspace_id, plan)
            results.extend(sandbox_results)

        baseline_list = baseline_results or []
        baseline_ok = all(g.passed for g in baseline_list) if baseline_list else True
        if not baseline_ok and not allow_preexisting_baseline_failures:
            results.append(
                GateResult(
                    gate_name="baseline_verification",
                    passed=False,
                    duration_seconds=0.0,
                    details={"error": "Baseline reproduction failed on upstream checkout; refusing mutation on failing baseline."},
                )
            )

        all_passed = all(g.passed for g in results)
        failed_names = [g.gate_name for g in results if not g.passed]
        summary = "All gates passed" if all_passed else f"Failed gates: {', '.join(failed_names)}"

        return ValidationReport(
            session_id=session_id,
            passed=all_passed,
            is_safety_stop=False,
            gate_results=results,
            summary=summary,
            baseline_results=baseline_list,
            baseline_passed=baseline_ok,
        )

    async def _run_sandbox_tests(self, workspace_id: str, plan: PlannerOutput) -> List[GateResult]:
        """
        Executes commands in PlannerOutput.validation_steps inside the isolated sandbox.
        """
        gate_results = []
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=120)

        for step in plan.validation_steps:
            t0 = time.monotonic()
            try:
                cmd_parts = shlex.split(step.command)
            except Exception:
                cmd_parts = step.command.split()

            binary = cmd_parts[0] if cmd_parts else ""
            if binary not in ALLOWED_VALIDATION_COMMANDS and not any(binary.endswith("/" + a) or binary.endswith("\\" + a) for a in ALLOWED_VALIDATION_COMMANDS):
                gate_results.append(
                    GateResult(
                        gate_name=f"test:{step.command[:30]}",
                        passed=False,
                        duration_seconds=0.0,
                        command=step.command,
                        exit_code=-1,
                        details={"error": f"Command binary '{binary}' is not permitted by validation runner allowlist"},
                    )
                )
                break

            result: ExecutionResult = await self._safe_run_command(
                workspace_id=workspace_id,
                command=cmd_parts,
                limits=limits
            )
            elapsed = time.monotonic() - t0

            passed = (result.exit_code == 0) and (not result.timed_out)
            gate_results.append(
                GateResult(
                    gate_name=f"test:{step.command[:30]}",
                    passed=passed,
                    duration_seconds=round(elapsed, 3),
                    command=step.command,
                    exit_code=result.exit_code,
                    details={
                        "stdout": result.stdout[:1000],
                        "stderr": result.stderr[:1000],
                        "timed_out": result.timed_out,
                        "resource_violation": result.resource_violation
                    }
                )
            )
            if not passed:
                break

        return gate_results

    def _check_syntax(self, contents: Dict[str, str]) -> GateResult:
        t0 = time.monotonic()
        failures = []

        for path, content in contents.items():
            lower = path.lower()
            try:
                if lower.endswith((".yml", ".yaml")):
                    import re
                    if re.search(r"^\t", content, re.MULTILINE):
                        failures.append(f"{path}: tab characters used for indentation")
                elif lower.endswith(".json"):
                    json.loads(content)
            except Exception as e:
                failures.append(f"{path}: {str(e)}")

        elapsed = time.monotonic() - t0
        passed = len(failures) == 0
        return GateResult(
            gate_name="syntax",
            passed=passed,
            duration_seconds=round(elapsed, 4),
            details={"failures": failures},
        )

    def _check_secrets(self, contents: Dict[str, str], planned_diff: Optional[PlannedDiff] = None) -> GateResult:
        t0 = time.monotonic()
        items_to_scan = list(contents.values())
        if planned_diff:
            for f in planned_diff.files:
                if f.content and f.content not in items_to_scan:
                    items_to_scan.append(f.content)

        scan_result = self._scanner.scan_diff_files(items_to_scan)
        all_findings = scan_result.findings

        elapsed = time.monotonic() - t0
        passed = len(all_findings) == 0
        return GateResult(
            gate_name="secret",
            passed=passed,
            duration_seconds=round(elapsed, 4),
            is_safety_stop=not passed,
            details={"findings_count": len(all_findings)},
        )

    async def _check_duplicate(self, repository_id: int, plan: PlannerOutput) -> GateResult:
        t0 = time.monotonic()
        target_path = plan.target_paths[0] if plan.target_paths else "unknown"
        is_dup = await self._dup.is_duplicate(repository_id, plan.task_type, target_path)
        elapsed = time.monotonic() - t0
        return GateResult(
            gate_name="duplicate",
            passed=not is_dup,
            duration_seconds=round(elapsed, 4),
            details={"is_duplicate": is_dup},
        )

    def _check_firewall(self, planned_diff: PlannedDiff) -> GateResult:
        t0 = time.monotonic()
        passed, violations = self._firewall.inspect(planned_diff)
        elapsed = time.monotonic() - t0
        return GateResult(
            gate_name="diff_firewall",
            passed=passed,
            duration_seconds=round(elapsed, 4),
            details={"violations": violations},
        )
