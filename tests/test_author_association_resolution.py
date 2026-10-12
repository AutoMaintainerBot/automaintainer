import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from automaintainer.github.collaborator_resolver import GitHubCollaboratorResolver
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.data.tables import SessionRecord
from automaintainer.queue.lease import QueuedJob
from automaintainer.core.models import SessionState
from automaintainer.agents.comment_agent import CommentIntent


@pytest.mark.asyncio
async def test_collaborator_resolver_respects_author_association_without_token():
    """Verify author_association grants maintainer authorization even without a GitHub token."""
    resolver = GitHubCollaboratorResolver(token="")

    assert await resolver.is_authorized_maintainer("public/repo", "alice", author_association="OWNER") is True
    assert await resolver.is_authorized_maintainer("public/repo", "bob", author_association="MEMBER") is True
    assert await resolver.is_authorized_maintainer("public/repo", "charlie", author_association="COLLABORATOR") is True

    assert await resolver.is_authorized_maintainer("public/repo", "dave", author_association="CONTRIBUTOR") is False
    assert await resolver.is_authorized_maintainer("public/repo", "eve", author_association="NONE") is False


@pytest.mark.asyncio
async def test_collaborator_resolver_falls_back_to_author_association_on_403():
    """Verify collaborator resolver falls back to author_association when GitHub API returns 403 Forbidden."""
    resolver = GitHubCollaboratorResolver(token="ghp_restricted_token")

    def mock_transport(request: httpx.Request):
        return httpx.Response(403, json={"message": "Must have admin rights to Repository"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        is_auth = await resolver.is_authorized_maintainer(
            "public/repo", "frank", author_association="COLLABORATOR", client=mock_client
        )
        assert is_auth is True

        is_unauth = await resolver.is_authorized_maintainer(
            "public/repo", "grace", author_association="CONTRIBUTOR", client=mock_client
        )
        assert is_unauth is False


@pytest.mark.asyncio
async def test_worker_daemon_authorizes_maintainer_comment_from_author_association():
    """Verify daemon _handle_conversation_job recognizes maintainer from webhook author_association."""
    daemon = WorkerDaemon()
    session_rec = SessionRecord(
        id="sess_comment_assoc",
        repository_id=101,
        state=SessionState.PR_OPEN.value,
        mode="public",
        risk_tier="R1",
    )

    job = QueuedJob(
        job_id="job_comment_1",
        session_id="sess_comment_assoc",
        task_type="conversation_review",
        payload={
            "repository": {"full_name": "public/library"},
            "comment": {
                "body": "Please bump this to 2.0 instead",
                "user": {"login": "maintainer_bob"},
                "author_association": "MEMBER",
            }
        }
    )

    mock_db = AsyncMock()
    mock_orchestrator = AsyncMock()
    mock_orchestrator.handle_changes_requested = AsyncMock(return_value=session_rec)
    mock_orchestrator.transition = AsyncMock(return_value=session_rec)

    classification_mock = MagicMock()
    classification_mock.intent = CommentIntent.REQUEST_SAFE_CHANGE
    classification_mock.is_actionable = True
    classification_mock.summary = "Bump to 2.0"

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "automaintainer.agents.comment_agent.MaintainerCommentAgent.classify",
            AsyncMock(return_value=classification_mock)
        )
        with patch.object(daemon, "_execute_patch_pipeline", new=AsyncMock()) as mock_patch_pipe:
            await daemon._handle_conversation_job(
                queue_name="conversation",
                job=job,
                session_rec=session_rec,
                db=mock_db,
                orchestrator=mock_orchestrator
            )
            assert mock_patch_pipe.called

    assert mock_orchestrator.handle_changes_requested.called or mock_orchestrator.transition.called
