"""
Tests for Issue 1 & 2:
- Worker daemon handles DISCOVERED sessions without ignoring them.
- SessionOrchestrator coordinates DISCOVERED -> PLANNING -> WORKING.
"""
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from automaintainer.core.models import SessionState, RiskTier, TaskType
from automaintainer.core.session_orchestrator import SessionOrchestrator
from automaintainer.data.tables import SessionRecord, OpportunityRecord, PlanRecord
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.queue.lease import QueuedJob, JobStatus


def _make_opp() -> DetectedOpportunity:
    return DetectedOpportunity(
        task_type=TaskType.PACKAGE_METADATA,
        evidence=["Fix pyproject.toml author field"],
        target_paths=["pyproject.toml"],
        risk_tier=RiskTier.R1,
        confidence=0.95,
        validation_recipe=["echo ok"],
        summary="Metadata fix",
    )


def _make_plan(requires_human_approval: bool = False, risk_tier: RiskTier = RiskTier.R1) -> PlannerOutput:
    return PlannerOutput(
        objective="Fix pyproject.toml metadata",
        task_type="package_metadata",
        confidence=0.95,
        target_paths=["pyproject.toml"],
        proposed_edits=[
            ProposedEdit(
                path="pyproject.toml",
                operation="full_replace",
                rationale="Update metadata",
                new_content='[project]\nname = "test"\nversion = "1.0.0"\n',
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[ValidationStep(command="echo ok", reason="test", expected_outcome="ok")],
        risk_tier=risk_tier,
        requires_human_approval=requires_human_approval,
    )


@pytest.mark.asyncio
async def test_coordinate_discovery_to_working_autonomous():
    """Verify session is coordinated from DISCOVERED through PLANNING to WORKING when autonomous."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()

    sess = SessionRecord()
    sess.id = "sess_disc_1"
    sess.state = SessionState.DISCOVERED.value
    sess.repository_id = 100
    sess.version = 1
    sess.risk_tier = "R1"
    sess.mode = "public"

    states = [SessionState.DISCOVERED.value]

    async def fake_transition(session_id, expected_state, target_state, expected_version):
        sess.state = target_state.value
        sess.version += 1
        states.append(target_state.value)
        return sess

    repo = AsyncMock()
    repo.get_session = AsyncMock(return_value=sess)
    repo.transition_state_optimistic = AsyncMock(side_effect=fake_transition)

    planner = MagicMock()
    planner.plan = AsyncMock(return_value=_make_plan(requires_human_approval=False))

    orchestrator = SessionOrchestrator(db=db, planner=planner)
    orchestrator._repo = repo
    orchestrator._audit = AsyncMock()
    orchestrator._audit.record = AsyncMock()

    opp = _make_opp()
    final_sess = await orchestrator.coordinate_discovery_to_working("sess_disc_1", opportunity=opp)

    assert final_sess.state == SessionState.WORKING.value
    assert SessionState.ELIGIBLE.value in states
    assert SessionState.ANALYZING.value in states
    assert SessionState.PLANNING.value in states
    assert SessionState.AWAITING_POLICY.value in states
    assert states[-1] == SessionState.WORKING.value


@pytest.mark.asyncio
async def test_coordinate_discovery_stops_at_awaiting_policy_when_human_approval_required():
    """Verify session pauses in AWAITING_POLICY when plan requires human approval."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()

    sess = SessionRecord()
    sess.id = "sess_disc_2"
    sess.state = SessionState.DISCOVERED.value
    sess.repository_id = 100
    sess.version = 1
    sess.risk_tier = "R2"
    sess.mode = "public"

    async def fake_transition(session_id, expected_state, target_state, expected_version):
        sess.state = target_state.value
        sess.version += 1
        return sess

    repo = AsyncMock()
    repo.get_session = AsyncMock(return_value=sess)
    repo.transition_state_optimistic = AsyncMock(side_effect=fake_transition)

    planner = MagicMock()
    planner.plan = AsyncMock(return_value=_make_plan(requires_human_approval=True))

    orchestrator = SessionOrchestrator(db=db, planner=planner)
    orchestrator._repo = repo
    orchestrator._audit = AsyncMock()
    orchestrator._audit.record = AsyncMock()

    opp = _make_opp()
    final_sess = await orchestrator.coordinate_discovery_to_working("sess_disc_2", opportunity=opp)

    assert final_sess.state == SessionState.AWAITING_POLICY.value


@pytest.mark.asyncio
async def test_worker_daemon_processes_discovered_session():
    """Verify WorkerDaemon coordinates DISCOVERED session into WORKING and executes patch pipeline."""
    queue = MagicMock()
    queue.heartbeat = MagicMock()
    sandbox = MagicMock()
    sandbox.prepare_workspace = AsyncMock(return_value="fake_ws")
    sandbox.destroy_workspace = AsyncMock()

    daemon = WorkerDaemon(queue=queue, sandbox=sandbox)

    sess = SessionRecord()
    sess.id = "sess_disc_3"
    sess.state = SessionState.DISCOVERED.value
    sess.repository_id = 101
    sess.version = 1
    sess.risk_tier = "R1"
    sess.mode = "public"
    sess.pr_number = None

    job = QueuedJob(
        job_id="job_disc_1",
        session_id="sess_disc_3",
        task_type="public_discovery_analysis",
        payload={"repository": "test-owner/test-repo", "task_type": "package_metadata"},
        status=JobStatus.LEASED,
    )

    fake_db = AsyncMock()
    fake_db_mgr = MagicMock()
    fake_db_mgr.get_session.return_value.__aenter__.return_value = fake_db
    fake_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    with patch("automaintainer.apps.worker.daemon.get_db_manager", return_value=fake_db_mgr), \
         patch("automaintainer.apps.worker.daemon.SessionRepository") as mock_repo_cls, \
         patch("automaintainer.apps.worker.daemon.SessionOrchestrator") as mock_orch_cls, \
         patch.object(daemon, "_execute_patch_pipeline", new_callable=AsyncMock) as mock_patch_pipe:

        mock_repo = AsyncMock()
        mock_repo.get_session = AsyncMock(return_value=sess)
        mock_repo_cls.return_value = mock_repo

        coordinated_sess = SessionRecord()
        coordinated_sess.id = "sess_disc_3"
        coordinated_sess.state = SessionState.WORKING.value
        coordinated_sess.repository_id = 101

        mock_orch = AsyncMock()
        mock_orch.coordinate_discovery_to_working = AsyncMock(return_value=coordinated_sess)
        mock_orch_cls.return_value = mock_orch

        await daemon.execute_job("discovery", job)

        mock_orch.coordinate_discovery_to_working.assert_awaited_once()
        mock_patch_pipe.assert_awaited_once()
