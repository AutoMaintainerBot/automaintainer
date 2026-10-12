import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.data.tables import SessionRecord
from automaintainer.queue.lease import QueuedJob
from automaintainer.core.models import SessionState


@pytest.mark.asyncio
async def test_acquire_session_lock_prevents_concurrent_execution():
    """Verify two workers cannot acquire lock on the same session concurrently."""
    worker1 = WorkerDaemon(worker_id="worker_alpha")
    worker2 = WorkerDaemon(worker_id="worker_beta")

    session_id = "sess_concurrent_lock_1"

    acq1, epoch1 = await worker1.acquire_session_lock(session_id)
    assert acq1 is True
    assert len(epoch1) > 0

    acq2, epoch2 = await worker2.acquire_session_lock(session_id)
    assert acq2 is False
    assert epoch2 == ""

    rel1 = await worker1.release_session_lock(session_id, lease_epoch=epoch1)
    assert rel1 is True

    acq2_retry, epoch2_retry = await worker2.acquire_session_lock(session_id)
    assert acq2_retry is True
    assert len(epoch2_retry) > 0

    await worker2.release_session_lock(session_id, lease_epoch=epoch2_retry)


@pytest.mark.asyncio
async def test_daemon_defers_patch_pipeline_when_session_locked():
    """Verify daemon defers and re-enqueues job if session is locked by another worker."""
    daemon = WorkerDaemon(worker_id="worker_worker")
    mock_queue = MagicMock()
    mock_queue.redis_client = None
    mock_queue.redis_stream_driver = None
    daemon.queue = mock_queue

    session_rec = SessionRecord(
        id="sess_locked_defer",
        repository_id=555,
        state=SessionState.WORKING.value,
        mode="public",
        risk_tier="R1",
    )

    job = QueuedJob(
        job_id="job_locked_1",
        session_id="sess_locked_defer",
        task_type="patch",
        payload={"repo_url": "https://github.com/org/repo.git"}
    )

    await daemon.acquire_session_lock("sess_locked_defer")

    mock_sandbox = MagicMock()
    mock_sandbox.prepare_workspace = AsyncMock()
    daemon.sandbox = mock_sandbox

    mock_db = AsyncMock()
    mock_orchestrator = AsyncMock()

    await daemon._execute_patch_pipeline(
        queue_name="patch",
        job=job,
        session_rec=session_rec,
        db=mock_db,
        orchestrator=mock_orchestrator
    )

    assert not mock_sandbox.prepare_workspace.called

    assert mock_queue.enqueue.called
    re_enqueued_call = mock_queue.enqueue.call_args[1]
    assert re_enqueued_call["session_id"] == "sess_locked_defer"

    await daemon.release_session_lock("sess_locked_defer")
