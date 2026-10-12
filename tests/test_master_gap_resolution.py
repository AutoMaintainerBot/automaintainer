import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from automaintainer.app.main import app
from automaintainer.app.auth import create_test_token, UserRole, is_platform_admin, AuthUser
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import (
    SessionRecord, RepositoryRecord, InstallationRecord, WorkspaceRecord
)
from automaintainer.core.models import SessionState, TERMINAL_STATES
from automaintainer.core.state_machine import SessionStateMachine, InvalidStateTransitionError
from automaintainer.config import Settings


@pytest.mark.asyncio
async def test_tenant_isolation_in_list_and_create_sessions():
    """
    Verifies:
    1. SQL-level tenant isolation in list_sessions().
    2. Repository ownership check in create_session().
    3. Proper identity chain: User.account_id -> InstallationRecord.account_id -> InstallationRecord.id -> RepositoryRecord.installation_id.
    """
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        inst_100 = InstallationRecord(id=1001, github_installation_id=9001, account_id=100)
        repo_100 = RepositoryRecord(id=2001, github_repo_id=8001, installation_id=1001, owner="tenant100", name="repo1")
        sess_100 = SessionRecord(id="sess_t100_01", repository_id=2001, state="WORKING", version=1)

        inst_200 = InstallationRecord(id=1002, github_installation_id=9002, account_id=200)
        repo_200 = RepositoryRecord(id=2002, github_repo_id=8002, installation_id=1002, owner="tenant200", name="repo2")
        sess_200 = SessionRecord(id="sess_t200_01", repository_id=2002, state="WORKING", version=1)

        db.add_all([inst_100, repo_100, sess_100, inst_200, repo_200, sess_200])
        await db.commit()

    token_t100 = create_test_token(username="user100", roles=[UserRole.MAINTAINER], account_id=100)
    token_t200 = create_test_token(username="user200", roles=[UserRole.MAINTAINER], account_id=200)
    token_admin = create_test_token(username="platform_admin", roles=[UserRole.SECURITY_ADMIN], account_id=0)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res_100 = await client.get("/v1/sessions", headers={"Authorization": f"Bearer {token_t100}"})
        assert res_100.status_code == 200
        ids_100 = [s["id"] for s in res_100.json()]
        assert "sess_t100_01" in ids_100
        assert "sess_t200_01" not in ids_100

        res_200 = await client.get("/v1/sessions", headers={"Authorization": f"Bearer {token_t200}"})
        assert res_200.status_code == 200
        ids_200 = [s["id"] for s in res_200.json()]
        assert "sess_t200_01" in ids_200
        assert "sess_t100_01" not in ids_200

        res_admin = await client.get("/v1/sessions", headers={"Authorization": f"Bearer {token_admin}"})
        assert res_admin.status_code == 200
        admin_ids = [s["id"] for s in res_admin.json()]
        assert "sess_t100_01" in admin_ids
        assert "sess_t200_01" in admin_ids

        create_cross = await client.post(
            "/v1/sessions",
            json={"session_id": "sess_malicious_t100", "repository_id": 2002},
            headers={"Authorization": f"Bearer {token_t100}"}
        )
        assert create_cross.status_code == 403
        assert "Access denied" in create_cross.json()["detail"]

        create_ok = await client.post(
            "/v1/sessions",
            json={"session_id": "sess_valid_t100", "repository_id": 2001},
            headers={"Authorization": f"Bearer {token_t100}"}
        )
        assert create_ok.status_code == 201


@pytest.mark.asyncio
async def test_account_zero_bypass_mitigation():
    """Verify account_id=0 without administrative roles cannot bypass tenant isolation."""
    fake_system_user = AuthUser(
        user_id="fake_sys",
        username="imposter",
        roles=[UserRole.MAINTAINER],
        account_id=0
    )
    assert is_platform_admin(fake_system_user) is False

    real_admin = AuthUser(
        user_id="sec_admin",
        username="admin",
        roles=[UserRole.SECURITY_ADMIN],
        account_id=0
    )
    assert is_platform_admin(real_admin) is True


@pytest.mark.asyncio
async def test_resume_only_allowed_from_paused_state():
    """Verify resume() rejects any session that is not in PAUSED state."""
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    session_id = "sess_non_paused_test"
    async with db_mgr.get_session() as db:
        inst = InstallationRecord(id=1050, github_installation_id=9050, account_id=500)
        repo = RepositoryRecord(id=2050, github_repo_id=8050, installation_id=1050, owner="org", name="repo")
        s = SessionRecord(id=session_id, repository_id=2050, state="WORKING", version=1)
        db.add_all([inst, repo, s])
        await db.commit()

    token = create_test_token(roles=[UserRole.OPERATOR], account_id=500)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.post(f"/v1/sessions/{session_id}/resume", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 400
        assert "session must be in PAUSED state" in res.json()["detail"]


@pytest.mark.asyncio
async def test_atomic_pause_and_resume_flow():
    """Verify atomic state transition to PAUSED preserves previous state and transitions back."""
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    session_id = "sess_pause_resume_atomic"
    async with db_mgr.get_session() as db:
        inst = InstallationRecord(id=1060, github_installation_id=9060, account_id=600)
        repo = RepositoryRecord(id=2060, github_repo_id=8060, installation_id=1060, owner="org", name="repo")
        s = SessionRecord(id=session_id, repository_id=2060, state="PLANNING", version=1)
        db.add_all([inst, repo, s])
        await db.commit()

    token = create_test_token(roles=[UserRole.OPERATOR], account_id=600)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pause_res = await client.post(f"/v1/sessions/{session_id}/pause", headers={"Authorization": f"Bearer {token}"})
        assert pause_res.status_code == 200
        assert pause_res.json()["state"] == "PAUSED"

        resume_res = await client.post(f"/v1/sessions/{session_id}/resume", headers={"Authorization": f"Bearer {token}"})
        assert resume_res.status_code == 200
        assert resume_res.json()["state"] == "PLANNING"


@pytest.mark.asyncio
async def test_resume_queue_failure_rollback():
    """Verify that if queue enqueue fails during resume, the state rolls back to PAUSED."""
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    session_id = "sess_resume_queue_fail"
    async with db_mgr.get_session() as db:
        inst = InstallationRecord(id=1070, github_installation_id=9070, account_id=700)
        repo = RepositoryRecord(id=2070, github_repo_id=8070, installation_id=1070, owner="org", name="repo")
        s = SessionRecord(
            id=session_id,
            repository_id=2070,
            state="PAUSED",
            version=1,
            metadata_json={"paused_from_state": "WORKING"}
        )
        db.add_all([inst, repo, s])
        await db.commit()

    token = create_test_token(roles=[UserRole.OPERATOR], account_id=700)
    transport = ASGITransport(app=app)

    with patch("automaintainer.app.routes.sessions.get_partitioned_queue") as mock_q_getter:
        mock_q = mock_q_getter.return_value
        mock_q.enqueue.side_effect = ConnectionError("Redis cluster unreachable")

        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.post(f"/v1/sessions/{session_id}/resume", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 503
            assert "Queue dispatch failed" in res.json()["detail"]

    async with db_mgr.get_session() as db:
        from automaintainer.data.repositories import SessionRepository
        repo = SessionRepository(db)
        rec = await repo.get_session(session_id)
        assert rec.state == "PAUSED"


@pytest.mark.asyncio
async def test_terminate_records_destruction_failure():
    """Verify that if sandbox destruction fails, WorkspaceRecord is marked destroy_failed."""
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    session_id = "sess_term_fail_ws"
    async with db_mgr.get_session() as db:
        inst = InstallationRecord(id=1080, github_installation_id=9080, account_id=800)
        repo = RepositoryRecord(id=2080, github_repo_id=8080, installation_id=1080, owner="org", name="repo")
        s = SessionRecord(id=session_id, repository_id=2080, state="WORKING", workspace_id="ws_fail_1", version=1)
        w = WorkspaceRecord(id="ws_fail_1", session_id=session_id, runtime_id="rt_container_fail_1", status="active")
        db.add_all([inst, repo, s, w])
        await db.commit()

    token = create_test_token(roles=[UserRole.OPERATOR], account_id=800)
    transport = ASGITransport(app=app)

    with patch("automaintainer.app.routes.sessions.get_sandbox_runtime") as mock_sb_getter:
        mock_sb = mock_sb_getter.return_value
        mock_sb.destroy_workspace = AsyncMock(side_effect=RuntimeError("Docker daemon timeout"))

        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            res = await client.post(f"/v1/sessions/{session_id}/terminate", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200
            assert res.json()["workspace_status"] == "destroy_failed"
            assert "Docker daemon timeout" in res.json()["destruction_error"]

    async with db_mgr.get_session() as db:
        from sqlalchemy import select
        res = await db.execute(select(WorkspaceRecord).where(WorkspaceRecord.id == "ws_fail_1"))
        ws_rec = res.scalar_one()
        assert ws_rec.status == "destroy_failed"


def test_state_machine_immutable_terminal_enforcement():
    """Verify no transitions out of any terminal states are permitted."""
    for term_state in TERMINAL_STATES:
        assert SessionStateMachine.can_transition(term_state, SessionState.WORKING) is False
        assert SessionStateMachine.can_transition(term_state, SessionState.PAUSED) is False
        assert SessionStateMachine.can_transition(term_state, SessionState.CANCELLED) is False

        with pytest.raises(InvalidStateTransitionError):
            SessionStateMachine.validate_transition(term_state, SessionState.WORKING)


def test_production_config_rejects_insecure_sandbox_backend():
    """Verify production environment strictly forbids non-isolated sandbox backends."""
    with pytest.raises(ValueError) as excinfo:
        Settings(
            ENVIRONMENT="production",
            JWT_SECRET="prod_jwt_secret_99887766554433221100aa_bb_cc_dd",
            DATABASE_URL="postgresql+asyncpg://app_user:strong_password@db.prod.internal:5432/automaintainer",
            REDIS_URL="redis://redis.prod.internal:6379/0",
            GITHUB_WEBHOOK_SECRET="high_entropy_webhook_secret_32_bytes_long!",
            QUEUE_BACKEND="redis",
            ALLOW_IN_MEMORY_QUEUE=False,
            ALLOW_HOST_SUBPROCESS=False,
            SANDBOX_BACKEND="subprocess_jail"  # Insecure for production
        )
    assert "SANDBOX_BACKEND='subprocess_jail' is forbidden in production" in str(excinfo.value)


def test_redis_dead_letter_replay_and_attempt_sync():
    """Verify Redis dead letters can be queried, replayed into active queue, and synchronized."""
    from unittest.mock import MagicMock
    from automaintainer.queue.redis_queue import PartitionedLeasedQueue, RedisStreamLeasedQueue

    mock_redis = MagicMock()
    mock_redis.xrange.return_value = [
        (
            b"1700000000000-0",
            {
                b"job_id": b"job_dlq_test_1",
                b"queue_name": b"analysis",
                b"session_id": b"sess_dlq_1",
                b"task_type": b"analyze",
                b"payload": b'{"sample": "data"}',
                b"attempt": b"3",
                b"error": b"Transient inference timeout",
                b"dead_lettered_at": b"1700000000.0",
            }
        )
    ]
    mock_redis.xadd.return_value = "1700000001000-0"

    pq = PartitionedLeasedQueue(redis_client=mock_redis)

    dls = pq.get_dead_letters()
    assert len(dls) == 1
    assert dls[0]["job_id"] == "job_dlq_test_1"
    assert dls[0]["queue_name"] == "analysis"
    assert dls[0]["attempt"] == 3

    retried = pq.retry_dead_letters(job_id="job_dlq_test_1")
    assert retried == 1

    assert mock_redis.xadd.called
    mock_redis.xdel.assert_called_with("automaintainer:stream:dead_letters", b"1700000000000-0")
    mock_redis.delete.assert_called_with("automaintainer:job_meta:job_dlq_test_1")
