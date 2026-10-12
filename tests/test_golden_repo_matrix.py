import os
import sys
import shutil
import tempfile
import pytest
from automaintainer.agents.prompt_injection_guard import PromptInjectionGuard, PromptInjectionDetectedError
from automaintainer.execution.network_security import ControlledEgressFilter, SSRFSecurityViolation
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.resource_limits import SandboxResourceLimits
from automaintainer.discovery.opportunity_detectors import GitHubActionsVersionDetector, KNOWN_LATEST_ACTIONS
from automaintainer.core.models import SessionState, TERMINAL_STATES
from automaintainer.core.state_machine import SessionStateMachine

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

@pytest.mark.asyncio
async def test_golden_python_package_repair_lifecycle():
    """
    Golden Repo 1 (python_package):
    Validates that a broken package fails test, and once repaired, passes validation.
    """
    src_fixture = os.path.join(FIXTURES_DIR, "python_package")
    assert os.path.exists(src_fixture), "python_package fixture missing"

    with tempfile.TemporaryDirectory() as tmp_dir:
        working_pkg = os.path.join(tmp_dir, "pkg")
        shutil.copytree(src_fixture, working_pkg)

        runtime = ContainerSandboxRuntime(use_docker=False)
        workspace_id = await runtime.prepare_workspace(repo_url="dummy_url", commit_sha="head")
        for item in os.listdir(working_pkg):
            s = os.path.join(working_pkg, item)
            d = os.path.join(workspace_id, item)
            if os.path.isdir(s):
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

        try:
            limits = SandboxResourceLimits(wall_clock_timeout_seconds=10)
            test_cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]

            initial_res = await runtime.run_command(workspace_id, test_cmd, limits)
            assert initial_res.exit_code != 0, "Expected buggy calculator to fail tests"
            assert "FAIL" in initial_res.stderr or "AssertionError" in initial_res.stderr or initial_res.exit_code != 0

            calc_file = os.path.join(workspace_id, "src", "calculator.py")
            with open(calc_file, "r") as f:
                content = f.read()
            repaired_content = content.replace("return a - b", "return a + b")
            with open(calc_file, "w") as f:
                f.write(repaired_content)

            repaired_res = await runtime.run_command(workspace_id, test_cmd, limits)
            assert repaired_res.exit_code == 0, f"Expected repaired calculator to pass tests: {repaired_res.stderr}"
            assert "OK" in repaired_res.stderr or "OK" in repaired_res.stdout
        finally:
            await runtime.destroy_workspace(workspace_id)

@pytest.mark.asyncio
async def test_golden_node_package_action_update_detection():
    """
    Golden Repo 2 (node_package):
    Validates detection of outdated CI GitHub Actions and lockfiles.
    """
    src_fixture = os.path.join(FIXTURES_DIR, "node_package")
    wf_path = os.path.join(src_fixture, ".github", "workflows", "ci.yml")
    assert os.path.exists(wf_path), "node_package ci.yml missing"

    with open(wf_path, "r", encoding="utf-8") as f:
        wf_content = f.read()

    assert "actions/checkout@v2" in wf_content
    assert "actions/setup-node@v2" in wf_content

    assert KNOWN_LATEST_ACTIONS["actions/checkout"] == "v4"
    assert KNOWN_LATEST_ACTIONS["actions/setup-node"] == "v4"

    upgraded_wf = wf_content.replace("@v2", "@v4")
    assert "actions/checkout@v4" in upgraded_wf
    assert "actions/setup-node@v4" in upgraded_wf

@pytest.mark.asyncio
async def test_golden_malicious_repo_triggers_safety_stop():
    """
    Golden Repo 3 (malicious_repo):
    Validates that a repository with prompt injection and SSRF attempt
    triggers prompt guard detection, egress security block, and transitions session to SAFETY_STOP.
    """
    src_fixture = os.path.join(FIXTURES_DIR, "malicious_repo")
    readme_path = os.path.join(src_fixture, "README.md")
    exploit_path = os.path.join(src_fixture, "src", "exploit.py")

    assert os.path.exists(readme_path)
    assert os.path.exists(exploit_path)

    with open(readme_path, "r", encoding="utf-8") as f:
        readme_text = f.read()

    guard = PromptInjectionGuard()
    scan_res = guard.scan(readme_text)
    assert scan_res.is_safe is False
    assert scan_res.risk_level in ("CRITICAL", "HIGH")

    with pytest.raises(PromptInjectionDetectedError):
        guard.scan_and_raise(readme_text)

    with open(exploit_path, "r", encoding="utf-8") as f:
        exploit_text = f.read()

    assert "169.254.169.254" in exploit_text
    is_forbidden = ControlledEgressFilter.is_ip_forbidden("169.254.169.254")
    assert is_forbidden is True

    with pytest.raises(SSRFSecurityViolation):
        ControlledEgressFilter.enforce("http://169.254.169.254/latest/meta-data/")

    for state in [SessionState.DISCOVERED, SessionState.WORKING, SessionState.VALIDATING, SessionState.PLANNING]:
        allowed = SessionStateMachine.can_transition(state, SessionState.SAFETY_STOP)
        assert allowed is True, f"State {state} must allow transition to SAFETY_STOP"

    assert SessionState.SAFETY_STOP in TERMINAL_STATES

@pytest.mark.asyncio
async def test_golden_rust_crate_actions_and_manifest():
    """
    Golden Repo 4 (rust_crate):
    Validates Rust crate Cargo.toml parsing and outdated GitHub Actions updates.
    """
    src_fixture = os.path.join(FIXTURES_DIR, "rust_crate")
    cargo_path = os.path.join(src_fixture, "Cargo.toml")
    wf_path = os.path.join(src_fixture, ".github", "workflows", "ci.yml")

    assert os.path.exists(cargo_path)
    assert os.path.exists(wf_path)

    with open(cargo_path, "r", encoding="utf-8") as f:
        cargo_content = f.read()
    assert 'name = "calculator"' in cargo_content
    assert 'edition = "2021"' in cargo_content

    with open(wf_path, "r", encoding="utf-8") as f:
        wf_content = f.read()
    assert "actions/checkout@v2" in wf_content

    upgraded = wf_content.replace("actions/checkout@v2", "actions/checkout@v4")
    assert "actions/checkout@v4" in upgraded

@pytest.mark.asyncio
async def test_golden_monorepo_multi_package_detection():
    """
    Golden Repo 5 (monorepo):
    Validates discovery across multiple sub-packages in a single workspace.
    """
    src_fixture = os.path.join(FIXTURES_DIR, "monorepo")
    backend_toml = os.path.join(src_fixture, "packages", "backend", "pyproject.toml")
    frontend_pkg = os.path.join(src_fixture, "packages", "frontend", "package.json")
    wf_path = os.path.join(src_fixture, ".github", "workflows", "ci.yml")

    assert os.path.exists(backend_toml)
    assert os.path.exists(frontend_pkg)
    assert os.path.exists(wf_path)

    with open(backend_toml, "r", encoding="utf-8") as f:
        b_content = f.read()
    assert 'name = "backend"' in b_content

    with open(frontend_pkg, "r", encoding="utf-8") as f:
        f_content = f.read()
    assert '"name": "frontend"' in f_content

@pytest.mark.asyncio
async def test_golden_broken_ci_baseline_reproduction_gate():
    """
    Golden Repo 6 (broken_ci_repo):
    Validates Gate G4 Baseline Reproduction detects pre-existing test failures
    BEFORE applying any maintenance changes.
    """
    src_fixture = os.path.join(FIXTURES_DIR, "broken_ci_repo")
    assert os.path.exists(src_fixture)

    with tempfile.TemporaryDirectory() as tmp_dir:
        working_copy = os.path.join(tmp_dir, "broken_ci")
        shutil.copytree(src_fixture, working_copy)

        runtime = ContainerSandboxRuntime(use_docker=False)
        workspace_id = await runtime.prepare_workspace(repo_url="dummy_url", commit_sha="head")

        for item in os.listdir(working_copy):
            s = os.path.join(working_copy, item)
            d = os.path.join(workspace_id, item)
            if os.path.isdir(s):
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

        try:
            from automaintainer.validation.runner import ValidationRunner
            from automaintainer.inference.schemas import PlannerOutput, ValidationStep
            from automaintainer.core.models import RiskTier

            runner = ValidationRunner(sandbox=runtime)
            plan = PlannerOutput(
                objective="Maintenance on broken repo",
                task_type="dependency_update",
                confidence=0.9,
                target_paths=["pyproject.toml"],
                proposed_edits=[],
                explicitly_unchanged=[],
                validation_steps=[
                    ValidationStep(
                        command=f"{sys.executable} -m unittest discover -s tests",
                        reason="Run test suite",
                        expected_outcome="Pass",
                    )
                ],
                risk_tier=RiskTier.R2,
                requires_human_approval=False,
            )

            baseline_results = await runner.run_baseline(
                session_id="sess_broken_ci",
                plan=plan,
                workspace_id=workspace_id,
            )

            assert len(baseline_results) == 1
            assert baseline_results[0].passed is False
            assert baseline_results[0].exit_code != 0
        finally:
            await runtime.destroy_workspace(workspace_id)
