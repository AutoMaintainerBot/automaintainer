"""Tests for SessionOrchestrator — full lifecycle state transitions."""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from automaintainer.core.models import SessionState, RiskTier, TaskType
from automaintainer.core.session_orchestrator import SessionOrchestrator, SafetyStopError
from automaintainer.data.tables import SessionRecord
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.validation.runner import ValidationReport, GateResult


def _make_session(state: str, version: int = 1) -> SessionRecord:
    s = SessionRecord()
    s.id = f"sess_{uuid.uuid4().hex[:8]}"
    s.repository_id = 1
    s.state = state
    s.version = version
    s.mode = "installed"
    s.risk_tier = "R1"
    s.opportunity_score = 0.8
    s.pr_number = None
    s.workspace_id = None
    s.branch_name = None
    s.budget_json = {}
    return s


def _make_opportunity() -> DetectedOpportunity:
    return DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        evidence=["actions/checkout@v2 → v4"],
        target_paths=[".github/workflows/ci.yml"],
        risk_tier=RiskTier.R1,
        confidence=0.95,
        validation_recipe=["yamllint ."],
        summary="Outdated Actions",
        metadata={"outdated_actions": [{"action": "actions/checkout", "current": "v2", "latest": "v4"}]},
    )


def _make_plan() -> PlannerOutput:
    return PlannerOutput(
        objective="Update Actions",
        task_type="github_action_update",
        confidence=0.95,
        target_paths=[".github/workflows/ci.yml"],
        proposed_edits=[
            ProposedEdit(
                path=".github/workflows/ci.yml",
                operation="regex_replace",
                rationale="Bump checkout",
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[ValidationStep(command="yamllint .", reason="lint", expected_outcome="ok")],
        risk_tier=RiskTier.R1,
        requires_human_approval=False,
    )


def _make_db_session():
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.execute = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_discovered_transitions_to_eligible():
    db = _make_db_session()
    session_rec = _make_session("DISCOVERED")
    updated = _make_session("ELIGIBLE")

    repo = AsyncMock()
    repo.get_session = AsyncMock(return_value=session_rec)
    repo.transition_state_optimistic = AsyncMock(return_value=updated)

    orchestrator = SessionOrchestrator(db)
    orchestrator._repo = repo
    orchestrator._audit = AsyncMock()
    orchestrator._audit.record = AsyncMock()

    result = await orchestrator.advance(session_rec.id)
    assert result.state == "ELIGIBLE"


@pytest.mark.asyncio
async def test_terminal_session_returns_unchanged():
    db = _make_db_session()
    session_rec = _make_session("MERGED")

    repo = AsyncMock()
    repo.get_session = AsyncMock(return_value=session_rec)

    orchestrator = SessionOrchestrator(db)
    orchestrator._repo = repo

    result = await orchestrator.advance(session_rec.id)
    assert result.state == "MERGED"
    repo.transition_state_optimistic.assert_not_called()


@pytest.mark.asyncio
async def test_apply_validation_result_safety_stop():
    db = _make_db_session()
    session_rec = _make_session("VALIDATING")
    safety_stopped = _make_session("SAFETY_STOP")

    repo = AsyncMock()
    repo.get_session = AsyncMock(return_value=session_rec)
    repo.transition_state_optimistic = AsyncMock(return_value=safety_stopped)

    orchestrator = SessionOrchestrator(db)
    orchestrator._repo = repo
    orchestrator._audit = AsyncMock()
    orchestrator._audit.record = AsyncMock()

    report = ValidationReport(
        session_id=session_rec.id,
        passed=False,
        is_safety_stop=True,
        gate_results=[GateResult(gate_name="secret_scan", passed=False, is_safety_stop=True)],
        summary="SAFETY STOP: credentials found",
    )

    result = await orchestrator.apply_validation_result(session_rec, report)
    assert result.state == "SAFETY_STOP"


@pytest.mark.asyncio
async def test_apply_validation_result_pr_open_on_success():
    db = _make_db_session()
    session_rec = _make_session("VALIDATING")
    pr_open = _make_session("PR_OPEN")

    repo = AsyncMock()
    repo.transition_state_optimistic = AsyncMock(return_value=pr_open)

    orchestrator = SessionOrchestrator(db)
    orchestrator._repo = repo
    orchestrator._audit = AsyncMock()
    orchestrator._audit.record = AsyncMock()

    report = ValidationReport(
        session_id=session_rec.id,
        passed=True,
        is_safety_stop=False,
        gate_results=[
            GateResult(gate_name="syntax", passed=True),
            GateResult(gate_name="secret_scan", passed=True),
            GateResult(gate_name="diff_firewall", passed=True),
        ],
        summary="All gates passed",
    )

    result = await orchestrator.apply_validation_result(session_rec, report)
    assert result.state == "PR_OPEN"


@pytest.mark.asyncio
async def test_cancel_transitions_to_cancelled():
    db = _make_db_session()
    session_rec = _make_session("WORKING")
    cancelled = _make_session("CANCELLED")

    repo = AsyncMock()
    repo.transition_state_optimistic = AsyncMock(return_value=cancelled)

    orchestrator = SessionOrchestrator(db)
    orchestrator._repo = repo
    orchestrator._audit = AsyncMock()
    orchestrator._audit.record = AsyncMock()

    result = await orchestrator.cancel(session_rec)
    assert result.state == "CANCELLED"
