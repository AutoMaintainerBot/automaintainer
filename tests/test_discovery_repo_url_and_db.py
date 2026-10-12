import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from automaintainer.discovery.candidate_crawler import CandidateCrawler
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.data.tables import SessionRecord, RepositoryRecord, OpportunityRecord
from automaintainer.queue.lease import QueuedJob
from automaintainer.core.models import SessionState


@pytest.mark.asyncio
async def test_candidate_crawler_enqueues_repo_url():
    """Verify CandidateCrawler includes repo_url in job payload."""
    crawler = CandidateCrawler(token="ghp_test")

    crawler.filter_candidate = MagicMock(return_value=(True, "eligible"))
    crawler.fingerprinter.build = AsyncMock(return_value=MagicMock())

    health_mock = MagicMock()
    health_mock.is_eligible = True
    health_mock.total = 90.0
    crawler.health_scorer.score = AsyncMock(return_value=health_mock)

    opp_mock = MagicMock()
    opp_mock.task_type.value = "lockfile_refresh"
    opp_mock.summary = "Refresh lockfile"
    opp_mock.evidence = ["missing lock"]
    opp_mock.target_paths = ["poetry.lock"]
    opp_mock.confidence = 0.95
    opp_mock.risk_tier.value = "R2"
    crawler.scanner.scan = AsyncMock(return_value=[opp_mock])

    scored_mock = MagicMock()
    scored_mock.opportunity_score = 0.95
    scored_mock.threshold_decision.value = "autonomous"
    crawler.scorer.score = MagicMock(return_value=scored_mock)

    mock_queue = MagicMock()
    enqueued_payloads = []

    def mock_enqueue(queue_name, session_id, task_type, payload):
        enqueued_payloads.append(payload)

    mock_queue.enqueue = mock_enqueue

    candidates = [
        {"id": 12345, "full_name": "acme/project", "stargazers_count": 100}
    ]

    admitted = await crawler.process_and_admit_candidates(candidates, queue=mock_queue)
    assert len(admitted) == 1
    assert len(enqueued_payloads) == 1
    payload = enqueued_payloads[0]
    assert payload["repository"] == "acme/project"
    assert payload["repo_url"] == "https://github.com/acme/project.git"


@pytest.mark.asyncio
async def test_worker_daemon_repo_url_fallback_from_db():
    """Verify WorkerDaemon falls back to RepositoryRecord when repo_url missing from payload."""
    mock_sandbox = MagicMock()
    prepared_urls = []

    async def mock_prepare(repo_url, commit_sha):
        prepared_urls.append(repo_url)
        return "/tmp/workspace_test"

    mock_sandbox.prepare_workspace = mock_prepare
    mock_sandbox.destroy_workspace = AsyncMock()

    daemon = WorkerDaemon(sandbox=mock_sandbox)
    daemon.queue = MagicMock()
    daemon.queue.heartbeat = MagicMock()

    session_rec = SessionRecord(
        id="sess_fallback_1",
        repository_id=999,
        state=SessionState.DISCOVERED.value,
        mode="public",
        risk_tier="R2",
    )

    job = QueuedJob(
        job_id="job_1",
        session_id="sess_fallback_1",
        task_type="public_discovery_analysis",
        payload={"repository": "owner/fallback_repo"}
    )

    mock_repo_rec = RepositoryRecord(
        id=999,
        github_repo_id=999,
        owner="owner",
        name="fallback_repo",
        visibility="public",
    )

    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = mock_repo_rec
    mock_db.execute.return_value = mock_result

    mock_orchestrator = AsyncMock()

    with patch.object(daemon, "acquire_session_lock", return_value=True), \
         patch.object(daemon, "release_session_lock", return_value=True):
        try:
            await daemon._execute_patch_pipeline(
                queue_name="discovery",
                job=job,
                session_rec=session_rec,
                db=mock_db,
                orchestrator=mock_orchestrator
            )
        except Exception:
            pass

    assert len(prepared_urls) >= 1
    assert prepared_urls[0] == "https://github.com/owner/fallback_repo.git"
