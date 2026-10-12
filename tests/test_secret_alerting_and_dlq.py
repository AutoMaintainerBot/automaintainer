import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock
from automaintainer.core.secrets_manager import (
    SecurityAlertDispatcher,
    SecretRotationManager,
    KmsRotationDriver,
)
from automaintainer.queue.lease import LeasedTaskQueue, JobStatus
from automaintainer.queue.redis_queue import PartitionedLeasedQueue


@pytest.mark.asyncio
async def test_security_alert_dispatcher_delivers_to_webhook_and_slack():
    """Verify SecurityAlertDispatcher posts alerts to generic webhook and Slack."""
    dispatcher = SecurityAlertDispatcher(
        webhook_url="https://mock.security/webhook",
        slack_webhook_url="https://mock.slack/hooks/xxx",
        pagerduty_routing_key="pd_routing_key_123"
    )

    posted_urls = []

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        posted_urls.append(url)
        if "events.pagerduty.com" in url:
            return httpx.Response(202, json={"status": "success"})
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        outcomes = await dispatcher.send_alert(
            event_type="secret_rotation_failed",
            details={"secret_name": "github_app_private_key", "error": "KMS decryption timeout"},
            severity="critical",
            client=mock_client
        )

    assert outcomes["webhook"] is True
    assert outcomes["slack"] is True
    assert outcomes["pagerduty"] is True
    assert len(posted_urls) == 3


def test_secret_rotation_manager_dispatches_alert_on_success_and_failure():
    """Verify SecretRotationManager triggers alert dispatcher on rotation outcomes."""
    mock_driver = MagicMock(spec=KmsRotationDriver)
    mock_driver.provider = "aws"
    mock_dispatcher = MagicMock(spec=SecurityAlertDispatcher)

    manager = SecretRotationManager(driver=mock_driver, alert_dispatcher=mock_dispatcher)

    mock_driver.rotate_secret.return_value = True
    ok = manager.rotate_secret("api_token_1", "new_secret_val")
    assert ok is True
    assert mock_dispatcher.send_alert_sync.called
    call_args = mock_dispatcher.send_alert_sync.call_args[1]
    assert call_args["event_type"] == "secret_rotated"
    assert call_args["severity"] == "info"

    mock_dispatcher.reset_mock()
    mock_driver.rotate_secret.return_value = False
    ok_fail = manager.rotate_secret("api_token_bad", "val")
    assert ok_fail is False
    assert mock_dispatcher.send_alert_sync.called
    fail_args = mock_dispatcher.send_alert_sync.call_args[1]
    assert fail_args["event_type"] == "secret_rotation_failed"
    assert fail_args["severity"] == "critical"


def test_dead_letter_queue_query_and_retry():
    """Verify PartitionedLeasedQueue tracks dead letters and retries them."""
    pq = PartitionedLeasedQueue()
    q = pq.queues["patch"]

    job = q.enqueue("sess_dlq_1", "patch_task", {"foo": "bar"})
    job.attempt = job.max_retries
    job.status = JobStatus.DEAD_LETTER

    dead_letters = pq.get_dead_letters()
    assert len(dead_letters) == 1
    assert dead_letters[0]["session_id"] == "sess_dlq_1"
    assert dead_letters[0]["status"] == "DEAD_LETTER"

    retried_count = pq.retry_dead_letters(job_id=job.job_id)
    assert retried_count == 1

    assert len(pq.get_dead_letters()) == 0
    assert job.status == JobStatus.PENDING
    assert job.attempt == 0
