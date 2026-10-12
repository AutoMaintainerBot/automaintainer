"""Tests for ValidationRunner — all 4 deterministic gates."""
import pytest

from automaintainer.core.models import FileDiff, PlannedDiff
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.validation.runner import ValidationRunner
from automaintainer.core.models import RiskTier


def _make_plan(task_type: str = "github_action_update", paths=None, validation_steps=None) -> PlannerOutput:
    if validation_steps is None:
        validation_steps = [
            ValidationStep(command="yamllint .", reason="lint", expected_outcome="ok")
        ]
    return PlannerOutput(
        objective="Test plan",
        task_type=task_type,
        confidence=0.95,
        target_paths=paths or [".github/workflows/ci.yml"],
        proposed_edits=[],
        explicitly_unchanged=[],
        validation_steps=validation_steps,
        risk_tier=RiskTier.R1,
        requires_human_approval=False,
    )


def _make_diff(files=None) -> PlannedDiff:
    return PlannedDiff(
        files=files or [FileDiff(path=".github/workflows/ci.yml", lines_added=2, lines_deleted=2)],
        total_lines_added=2,
        total_lines_deleted=2,
        total_files=1,
    )


@pytest.mark.asyncio
async def test_all_gates_pass_on_clean_diff():
    runner = ValidationRunner()
    plan = _make_plan("package_metadata", paths=["pyproject.toml"], validation_steps=[])
    files = [FileDiff(path="pyproject.toml", lines_added=2, lines_deleted=0)]
    diff = PlannedDiff(files=files, total_lines_added=2, total_lines_deleted=0, total_files=1)
    contents = {"pyproject.toml": '[project]\nname = "mypkg"\nversion = "1.0.0"\n'}

    report = await runner.run(
        session_id="sess_test",
        plan=plan,
        planned_diff=diff,
        new_file_contents=contents,
    )

    assert report.passed
    assert not report.is_safety_stop
    assert report.summary == "All gates passed"


@pytest.mark.asyncio
async def test_all_gates_pass_with_mock_sandbox():
    from unittest.mock import AsyncMock
    from automaintainer.execution.sandbox_interface import ExecutionResult
    mock_sandbox = AsyncMock()
    mock_sandbox.run_command.return_value = ExecutionResult(exit_code=0, stdout="All tests passed", stderr="", duration_seconds=0.1)

    runner = ValidationRunner(sandbox=mock_sandbox)
    plan = _make_plan("package_metadata", paths=["pyproject.toml"], validation_steps=[
        ValidationStep(command="python -m pytest", reason="test", expected_outcome="exit 0")
    ])
    files = [FileDiff(path="pyproject.toml", lines_added=2, lines_deleted=0)]
    diff = PlannedDiff(files=files, total_lines_added=2, total_lines_deleted=0, total_files=1)
    contents = {"pyproject.toml": '[project]\nname = "mypkg"\nversion = "1.0.0"\n'}

    report = await runner.run(
        session_id="sess_test",
        workspace_id="ws_mock_123",
        plan=plan,
        planned_diff=diff,
        new_file_contents=contents,
    )

    assert report.passed
    assert not report.is_safety_stop
    assert report.summary == "All gates passed"
    assert any(g.gate_name.startswith("test:") and g.passed for g in report.gate_results)


@pytest.mark.asyncio
async def test_secret_scan_triggers_safety_stop():
    runner = ValidationRunner()
    plan = _make_plan()
    diff = _make_diff()
    contents = {".github/workflows/ci.yml": "api_key = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}

    report = await runner.run(
        session_id="sess_test",
        plan=plan,
        planned_diff=diff,
        new_file_contents=contents,
    )

    assert not report.passed
    assert report.is_safety_stop
    assert "SAFETY STOP" in report.summary


@pytest.mark.asyncio
async def test_diff_firewall_rejects_oversized_diff():
    runner = ValidationRunner()
    plan = _make_plan()

    files = [FileDiff(path=f"file_{i}.py", lines_added=10, lines_deleted=5) for i in range(12)]
    big_diff = PlannedDiff(files=files, total_files=12, total_lines_added=120, total_lines_deleted=60)
    contents = {f"file_{i}.py": "# safe content\n" for i in range(12)}

    report = await runner.run(
        session_id="sess_test",
        plan=plan,
        planned_diff=big_diff,
        new_file_contents=contents,
    )

    assert not report.passed
    assert not report.is_safety_stop
    assert "diff_firewall" in report.failed_gates()


@pytest.mark.asyncio
async def test_secret_scan_short_circuits_before_firewall():
    """Secret detection must stop processing immediately — firewall is never reached."""
    runner = ValidationRunner()
    plan = _make_plan()
    files = [FileDiff(path=f"file_{i}.py", lines_added=10) for i in range(12)]
    big_diff = PlannedDiff(files=files, total_files=12, total_lines_added=120)
    contents = {"file_0.py": "API_KEY=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}

    report = await runner.run(
        session_id="sess_test",
        plan=plan,
        planned_diff=big_diff,
        new_file_contents=contents,
    )

    assert report.is_safety_stop
    gate_names = [g.gate_name for g in report.gate_results]
    assert "diff_firewall" not in gate_names


@pytest.mark.asyncio
async def test_invalid_yaml_fails_syntax_gate():
    runner = ValidationRunner()
    plan = _make_plan()
    diff = _make_diff()
    contents = {".github/workflows/ci.yml": "steps:\n\t- name: bad\n"}

    report = await runner.run(
        session_id="sess_test",
        plan=plan,
        planned_diff=diff,
        new_file_contents=contents,
    )

    assert not report.passed
    assert "syntax" in report.failed_gates()
