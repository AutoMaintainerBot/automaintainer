import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from automaintainer.queue.lease import LeasedTaskQueue, JobStatus
from automaintainer.core.models import SessionState
from automaintainer.data.tables import EventRecord, SessionRecord
from automaintainer.app.routes.webhooks import handle_github_webhook
from sqlalchemy.exc import IntegrityError


def test_leased_task_queue_resets_dead_letter_on_re_enqueue():
    """Verify that a dead-lettered job is restored to PENDING when re-enqueued."""
    queue = LeasedTaskQueue()
    job = queue.enqueue(session_id="sess_1", task_type="analysis", payload={"repo": "a/b"}, dedupe_key="deliv_1")
    assert job.status == JobStatus.PENDING

    job.status = JobStatus.DEAD_LETTER
    job.attempt = 3
    job.error_message = "Crashed worker"

    re_job = queue.enqueue(session_id="sess_1", task_type="analysis", payload={"repo": "a/b"}, dedupe_key="deliv_1")
    assert re_job.job_id == job.job_id
    assert re_job.status == JobStatus.PENDING
    assert re_job.attempt == 0
    assert re_job.error_message is None
    assert re_job.lease_owner is None


@pytest.mark.asyncio
async def test_webhook_redelivery_re_enqueues_when_previous_job_incomplete():
    """Verify that a duplicate webhook delivery for an incomplete session is re-enqueued."""
    req = MagicMock()
    req.body = AsyncMock(return_value=b'{"repository": {"full_name": "owner/repo"}}')

    settings = MagicMock()
    settings.GITHUB_WEBHOOK_SECRET = "secret"

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock(side_effect=IntegrityError("duplicate", params=None, orig=None))
    mock_db.rollback = AsyncMock()

    existing_event = EventRecord(delivery_id="deliv_123", session_id="sess_crashed", event_type="github.push")
    existing_session = SessionRecord()
    existing_session.id = "sess_crashed"
    existing_session.state = SessionState.WORKING.value  # Worker crashed halfway, still WORKING

    event_exec = MagicMock()
    event_exec.scalar_one_or_none.return_value = existing_event

    sess_exec = MagicMock()
    sess_exec.scalar_one_or_none.return_value = existing_session

    mock_db.execute = AsyncMock(side_effect=[event_exec, sess_exec])

    mock_db_mgr = MagicMock()
    mock_db_mgr.get_session.return_value.__aenter__.return_value = mock_db
    mock_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    mock_queue = MagicMock()

    with patch("automaintainer.app.routes.webhooks.get_db_manager", return_value=mock_db_mgr), \
         patch("automaintainer.app.routes.webhooks.GitHubWebhookVerifier.verify", return_value=True), \
         patch("automaintainer.app.routes.webhooks.get_partitioned_queue", return_value=mock_queue):

        res = await handle_github_webhook(
            request=req,
            x_github_delivery="deliv_123",
            x_github_event="push",
            x_hub_signature_256="sha256=valid",
            settings=settings,
        )

        assert res["status"] == "re-enqueued"
        assert res["delivery_id"] == "deliv_123"
        assert res["session_id"] == "sess_crashed"
        assert "incomplete or crashed" in res["reason"]
        mock_queue.enqueue.assert_called_once()


@pytest.mark.asyncio
async def test_webhook_redelivery_skips_when_previous_job_completed():
    """Verify that duplicate webhook delivery is discarded if previous session completed (e.g. PR_OPEN)."""
    req = MagicMock()
    req.body = AsyncMock(return_value=b'{"repository": {"full_name": "owner/repo"}}')

    settings = MagicMock()
    settings.GITHUB_WEBHOOK_SECRET = "secret"

    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock(side_effect=IntegrityError("duplicate", params=None, orig=None))
    mock_db.rollback = AsyncMock()

    existing_event = EventRecord(delivery_id="deliv_123", session_id="sess_done", event_type="github.push")
    existing_session = SessionRecord()
    existing_session.id = "sess_done"
    existing_session.state = SessionState.PR_OPEN.value  # Completed!

    event_exec = MagicMock()
    event_exec.scalar_one_or_none.return_value = existing_event

    sess_exec = MagicMock()
    sess_exec.scalar_one_or_none.return_value = existing_session

    mock_db.execute = AsyncMock(side_effect=[event_exec, sess_exec])

    mock_db_mgr = MagicMock()
    mock_db_mgr.get_session.return_value.__aenter__.return_value = mock_db
    mock_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    mock_queue = MagicMock()

    with patch("automaintainer.app.routes.webhooks.get_db_manager", return_value=mock_db_mgr), \
         patch("automaintainer.app.routes.webhooks.GitHubWebhookVerifier.verify", return_value=True), \
         patch("automaintainer.app.routes.webhooks.get_partitioned_queue", return_value=mock_queue):

        res = await handle_github_webhook(
            request=req,
            x_github_delivery="deliv_123",
            x_github_event="push",
            x_hub_signature_256="sha256=valid",
            settings=settings,
        )

        assert res["status"] == "already_processed"
        assert res["delivery_id"] == "deliv_123"
        mock_queue.enqueue.assert_not_called()
