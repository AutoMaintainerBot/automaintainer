import pytest
from httpx import AsyncClient, ASGITransport
from automaintainer.app.main import app
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.queue.redis_queue import PartitionedLeasedQueue
from automaintainer.queue.lease import JobStatus
from automaintainer.observability.metrics_exporter import PrometheusMetricsExporter
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import OpportunityRecord, RepositoryRecord

@pytest.mark.asyncio
async def test_opportunities_router_is_mounted_and_accessible():
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        opp = OpportunityRecord(
            id="opp_test_123",
            repository_id=456,
            task_type="dependency_update",
            summary="Bump requests to 2.32",
            score=92.5,
            confidence=0.98,
            risk_tier="R2",
            status="detected"
        )
        db.add(opp)
        await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res_unauth = await client.get("/v1/opportunities")
        assert res_unauth.status_code == 401

        from automaintainer.app.auth import create_test_token, UserRole
        token = create_test_token(roles=[UserRole.PLATFORM_OPERATOR])
        headers = {"Authorization": f"Bearer {token}"}

        res = await client.get("/v1/opportunities", headers=headers)
        assert res.status_code == 200
        items = res.json()
        assert len(items) >= 1
        assert any(o["id"] == "opp_test_123" for o in items)

        single = await client.get("/v1/opportunities/opp_test_123", headers=headers)
        assert single.status_code == 200
        assert single.json()["score"] == 92.5

@pytest.mark.asyncio
async def test_worker_daemon_consumer_loop():
    db_mgr = get_db_manager()
    await db_mgr.init_models()
    from automaintainer.data.tables import SessionRecord
    from automaintainer.core.models import SessionState
    async with db_mgr.get_session() as db:
        repo = await db.get(RepositoryRecord, 888)
        if not repo:
            db.add(RepositoryRecord(id=888, github_repo_id=888, owner="octo", name="testrepo"))
        sess = await db.get(SessionRecord, "sess_w1")
        if not sess:
            db.add(SessionRecord(id="sess_w1", repository_id=888, state=SessionState.COMPLETED.value))
        await db.commit()

    queue = PartitionedLeasedQueue()
    queue.enqueue("patch", "sess_w1", "patch_task", {"file": "main.py"})

    daemon = WorkerDaemon(worker_id="test_worker_alpha", queue=queue)
    await daemon.start(poll_interval=0.01, max_iterations=1)

    job = queue.queues["patch"]._jobs[list(queue.queues["patch"]._jobs.keys())[0]]
    assert job.status == JobStatus.SUCCEEDED

@pytest.mark.asyncio
async def test_worker_daemon_fails_job_on_missing_session():
    queue = PartitionedLeasedQueue()
    queue.enqueue("patch", "sess_non_existent_999", "patch_task", {"file": "main.py"})

    daemon = WorkerDaemon(worker_id="test_worker_beta", queue=queue)
    await daemon.start(poll_interval=0.01, max_iterations=1)

    job = queue.queues["patch"]._jobs[list(queue.queues["patch"]._jobs.keys())[0]]
    assert job.status in (JobStatus.PENDING, JobStatus.DEAD_LETTER)
    assert job.lease_owner is None

@pytest.mark.asyncio
async def test_prometheus_metrics_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/metrics")
        assert res.status_code == 200
        assert "automaintainer_" in res.text

@pytest.mark.asyncio
async def test_pr_retry_endpoint():
    db_mgr = get_db_manager()
    await db_mgr.init_models()
    async with db_mgr.get_session() as db:
        existing_repo = await db.get(RepositoryRecord, 1)
        if not existing_repo:
            db.add(RepositoryRecord(id=1, github_repo_id=99001, owner="octo", name="demo"))
            await db.commit()

    from automaintainer.app.auth import create_test_token, UserRole
    auth_headers = {"Authorization": f"Bearer {create_test_token(roles=[UserRole.PLATFORM_OPERATOR])}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        seed_res = await client.post("/v1/sessions", json={"session_id": "sess_retry_pr", "repository_id": 1}, headers=auth_headers)
        assert seed_res.status_code == 201
        res = await client.post("/v1/sessions/sess_retry_pr/pr/retry", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["status"] == "retry_scheduled"
