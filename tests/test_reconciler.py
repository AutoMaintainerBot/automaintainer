import pytest
import pytest_asyncio
import httpx
from automaintainer.data.database import DatabaseManager
from automaintainer.data.repositories import SessionRepository
from automaintainer.core.reconciler import SessionReconciler
from automaintainer.core.models import SessionState

@pytest_asyncio.fixture
async def db_session():
    mgr = DatabaseManager("sqlite+aiosqlite:///:memory:")
    await mgr.init_models()
    async with mgr.session_factory() as session:
        yield session

@pytest.mark.asyncio
async def test_reconciler_updates_externally_merged_pr(db_session, monkeypatch):
    repo = SessionRepository(db_session)
    session = await repo.create_session("sess_rec_1", repository_id=99)
    session.pr_number = 42

    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.DISCOVERED,
        target_state=SessionState.ELIGIBLE,
        expected_version=1
    )
    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.ELIGIBLE,
        target_state=SessionState.ANALYZING,
        expected_version=2
    )
    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.ANALYZING,
        target_state=SessionState.PLANNING,
        expected_version=3
    )
    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.PLANNING,
        target_state=SessionState.AWAITING_POLICY,
        expected_version=4
    )
    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.AWAITING_POLICY,
        target_state=SessionState.WORKING,
        expected_version=5
    )
    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.WORKING,
        target_state=SessionState.VALIDATING,
        expected_version=6
    )
    session = await repo.transition_state_optimistic(
        session_id="sess_rec_1",
        expected_state=SessionState.VALIDATING,
        target_state=SessionState.PR_OPEN,
        expected_version=7
    )
    assert session.state == SessionState.PR_OPEN.value

    async def mock_get(*args, **kwargs):
        class MockResponse:
            status_code = 200
            def json(self):
                return {"state": "closed", "merged": True}
            def raise_for_status(self):
                pass
        return MockResponse()

    client = httpx.AsyncClient()
    monkeypatch.setattr(client, "get", mock_get)

    reconciler = SessionReconciler(db_session)
    updated = await reconciler.reconcile_session(
        session=session,
        repo_owner_name="test_org/test_repo",
        github_token="fake_token",
        client=client
    )

    assert updated.state == SessionState.MERGED.value
