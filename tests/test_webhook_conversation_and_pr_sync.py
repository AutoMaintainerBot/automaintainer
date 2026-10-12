"""
Tests for Issues 4 & 6:
- Webhooks resolve session_id from PR issue comments.
- Worker daemon routes conversation jobs to MaintainerCommentAgent and triggers repair iteration.
- Worker daemon routes PR closed/merged webhooks to orchestrator state sync.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from automaintainer.core.models import SessionState
from automaintainer.data.tables import SessionRecord
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.queue.lease import QueuedJob, JobStatus
from automaintainer.agents.comment_agent import CommentIntent, CommentClassification


@pytest.mark.asyncio
async def test_worker_routes_conversation_safe_change_triggers_repair():
    """Verify issue_comment requesting safe change advances session to CHANGES_REQUESTED -> WORKING."""
    queue = MagicMock()
    queue.heartbeat = MagicMock()
    sandbox = MagicMock()

    daemon = WorkerDaemon(queue=queue, sandbox=sandbox)

    sess = SessionRecord()
    sess.id = "sess_review_1"
    sess.state = SessionState.PR_OPEN.value
    sess.repository_id = 201
    sess.pr_number = 12

    job = QueuedJob(
        job_id="job_conv_1",
        session_id="sess_review_1",
        task_type="github.issue_comment",
        payload={
            "action": "created",
            "issue": {"number": 12, "pull_request": {}},
            "comment": {
                "body": "Please revert this link change and update only the version",
                "user": {"login": "repo-owner"},
                "author_association": "OWNER",
            },
            "repository": {"full_name": "owner/repo"},
        },
        status=JobStatus.LEASED,
    )

    fake_db = AsyncMock()
    fake_db_mgr = MagicMock()
    fake_db_mgr.get_session.return_value.__aenter__.return_value = fake_db
    fake_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    transition_states = []

    async def fake_handle_changes_requested(record):
        record.state = SessionState.CHANGES_REQUESTED.value
        transition_states.append("CHANGES_REQUESTED")
        return record

    async def fake_transition(session_id, target_state, actor, reason):
        sess.state = target_state.value
        transition_states.append(target_state.value)
        return sess

    mock_orch = MagicMock()
    mock_orch.handle_changes_requested = AsyncMock(side_effect=fake_handle_changes_requested)
    mock_orch.transition = AsyncMock(side_effect=fake_transition)

    with patch("automaintainer.apps.worker.daemon.get_db_manager", return_value=fake_db_mgr), \
         patch("automaintainer.apps.worker.daemon.SessionRepository") as mock_repo_cls, \
         patch("automaintainer.apps.worker.daemon.SessionOrchestrator") as mock_orch_cls, \
         patch("automaintainer.apps.worker.daemon.MaintainerCommentAgent") as mock_agent_cls, \
         patch.object(daemon, "_execute_patch_pipeline", new_callable=AsyncMock) as mock_patch_pipe:

        mock_orch_cls.return_value = mock_orch
        mock_repo = AsyncMock()
        mock_repo.get_session = AsyncMock(return_value=sess)
        mock_repo_cls.return_value = mock_repo

        mock_agent = AsyncMock()
        mock_agent.classify = AsyncMock(return_value=CommentClassification(
            intent=CommentIntent.REQUEST_SAFE_CHANGE,
            confidence=0.98,
            summary="Maintainer requested reverting link change",
            is_actionable=True,
        ))
        mock_agent_cls.return_value = mock_agent

        await daemon.execute_job("conversation", job)

        assert "CHANGES_REQUESTED" in transition_states
        assert SessionState.WORKING.value in transition_states
        mock_patch_pipe.assert_awaited_once()
        _, kwargs = mock_patch_pipe.call_args
        assert kwargs.get("maintainer_feedback") == "Please revert this link change and update only the version"


@pytest.mark.asyncio
async def test_worker_routes_github_write_pr_merged_sync():
    """Verify pull_request event with action=closed and merged=true transitions session to MERGED."""
    queue = MagicMock()
    queue.heartbeat = MagicMock()
    sandbox = MagicMock()

    daemon = WorkerDaemon(queue=queue, sandbox=sandbox)

    sess = SessionRecord()
    sess.id = "sess_sync_merge"
    sess.state = SessionState.PR_OPEN.value
    sess.repository_id = 202
    sess.pr_number = 50

    job = QueuedJob(
        job_id="job_merge_1",
        session_id="sess_sync_merge",
        task_type="github.pull_request",
        payload={
            "action": "closed",
            "pull_request": {"number": 50, "merged": True},
            "repository": {"full_name": "owner/merged-repo"},
        },
        status=JobStatus.LEASED,
    )

    fake_db = AsyncMock()
    fake_db_mgr = MagicMock()
    fake_db_mgr.get_session.return_value.__aenter__.return_value = fake_db
    fake_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    mock_orch = AsyncMock()

    with patch("automaintainer.apps.worker.daemon.get_db_manager", return_value=fake_db_mgr), \
         patch("automaintainer.apps.worker.daemon.SessionRepository") as mock_repo_cls, \
         patch("automaintainer.apps.worker.daemon.SessionOrchestrator", return_value=mock_orch), \
         patch("automaintainer.apps.worker.daemon.get_anti_spam_manager") as mock_spam_fn:

        mock_spam = MagicMock()
        mock_spam_fn.return_value = mock_spam

        mock_repo = AsyncMock()
        mock_repo.get_session = AsyncMock(return_value=sess)
        mock_repo_cls.return_value = mock_repo

        await daemon.execute_job("github-write", job)

        mock_orch.handle_pr_merged.assert_awaited_once_with(sess)
        mock_spam.record_pr_merge.assert_called_once_with("owner/merged-repo")
        mock_spam.release_active_pr.assert_called_once_with("owner/merged-repo", 50)


@pytest.mark.asyncio
async def test_worker_routes_github_write_pr_closed_unmerged_sync():
    """Verify pull_request event with action=closed and merged=false transitions session to REJECTED."""
    queue = MagicMock()
    queue.heartbeat = MagicMock()
    sandbox = MagicMock()

    daemon = WorkerDaemon(queue=queue, sandbox=sandbox)

    sess = SessionRecord()
    sess.id = "sess_sync_closed"
    sess.state = SessionState.PR_OPEN.value
    sess.repository_id = 203
    sess.pr_number = 51

    job = QueuedJob(
        job_id="job_close_1",
        session_id="sess_sync_closed",
        task_type="github.pull_request",
        payload={
            "action": "closed",
            "pull_request": {"number": 51, "merged": False},
            "repository": {"full_name": "owner/closed-repo"},
        },
        status=JobStatus.LEASED,
    )

    fake_db = AsyncMock()
    fake_db_mgr = MagicMock()
    fake_db_mgr.get_session.return_value.__aenter__.return_value = fake_db
    fake_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    mock_orch = AsyncMock()

    with patch("automaintainer.apps.worker.daemon.get_db_manager", return_value=fake_db_mgr), \
         patch("automaintainer.apps.worker.daemon.SessionRepository") as mock_repo_cls, \
         patch("automaintainer.apps.worker.daemon.SessionOrchestrator", return_value=mock_orch), \
         patch("automaintainer.apps.worker.daemon.get_anti_spam_manager") as mock_spam_fn:

        mock_spam = MagicMock()
        mock_spam_fn.return_value = mock_spam

        mock_repo = AsyncMock()
        mock_repo.get_session = AsyncMock(return_value=sess)
        mock_repo_cls.return_value = mock_repo

        await daemon.execute_job("github-write", job)

        mock_orch.handle_pr_closed.assert_awaited_once_with(sess)
        mock_spam.record_pr_rejection.assert_called_once_with("owner/closed-repo")
        mock_spam.release_active_pr.assert_called_once_with("owner/closed-repo", 51)


@pytest.mark.asyncio
async def test_worker_handles_github_installation_created():
    """Verify github.installation created event binds repository to installation."""
    from automaintainer.data.tables import InstallationRecord, RepositoryRecord

    queue = MagicMock()
    queue.heartbeat = MagicMock()
    daemon = WorkerDaemon(queue=queue, sandbox=MagicMock())

    job = QueuedJob(
        job_id="job_inst_create",
        session_id="sess_inst_evt",
        task_type="github.installation",
        payload={
            "action": "created",
            "installation": {
                "id": 998877,
                "account": {"id": 1234, "type": "User", "login": "testowner"},
            },
            "repositories": [
                {"id": 556677, "full_name": "testowner/sandbox", "private": False}
            ]
        },
        status=JobStatus.LEASED,
    )

    fake_db = AsyncMock()
    fake_db.add = MagicMock()
    fake_db_mgr = MagicMock()
    fake_db_mgr.get_session.return_value.__aenter__.return_value = fake_db
    fake_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    # DB mocks: no existing installation, existing repo without installation
    existing_repo = RepositoryRecord(
        id=10,
        github_repo_id=556677,
        owner="testowner",
        name="sandbox",
        installation_id=None
    )

    mock_inst_res = MagicMock()
    mock_inst_res.scalars.return_value.first.return_value = None

    mock_repo_res = MagicMock()
    mock_repo_res.scalars.return_value.first.return_value = existing_repo

    fake_db.execute.side_effect = [mock_inst_res, mock_repo_res]

    with patch("automaintainer.apps.worker.daemon.get_db_manager", return_value=fake_db_mgr):
        await daemon.execute_job("analysis", job)

    assert fake_db.add.called
    added_inst = fake_db.add.call_args[0][0]
    assert isinstance(added_inst, InstallationRecord)
    assert added_inst.github_installation_id == 998877
    assert added_inst.status == "active"
    assert existing_repo.installation_id == added_inst.id
    fake_db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_worker_handles_github_installation_deleted():
    """Verify github.installation deleted event marks installation deleted and clears repository binding."""
    from automaintainer.data.tables import InstallationRecord

    queue = MagicMock()
    queue.heartbeat = MagicMock()
    daemon = WorkerDaemon(queue=queue, sandbox=MagicMock())

    job = QueuedJob(
        job_id="job_inst_del",
        session_id="sess_inst_evt",
        task_type="github.installation",
        payload={
            "action": "deleted",
            "installation": {
                "id": 998877,
                "account": {"id": 1234, "type": "User", "login": "testowner"},
            }
        },
        status=JobStatus.LEASED,
    )

    fake_db = AsyncMock()
    fake_db_mgr = MagicMock()
    fake_db_mgr.get_session.return_value.__aenter__.return_value = fake_db
    fake_db_mgr.get_session.return_value.__aexit__ = AsyncMock()

    existing_inst = InstallationRecord(
        id=5,
        github_installation_id=998877,
        status="active"
    )

    mock_inst_res = MagicMock()
    mock_inst_res.scalars.return_value.first.return_value = existing_inst
    fake_db.execute.return_value = mock_inst_res

    with patch("automaintainer.apps.worker.daemon.get_db_manager", return_value=fake_db_mgr):
        await daemon.execute_job("analysis", job)

    assert existing_inst.status == "deleted"
    fake_db.commit.assert_awaited_once()

