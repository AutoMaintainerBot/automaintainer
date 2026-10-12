import pytest
import pytest_asyncio
from automaintainer.data.database import DatabaseManager
from automaintainer.data.repositories import SessionRepository
from automaintainer.core.models import SessionState
from automaintainer.core.state_machine import StaleSessionVersionError

@pytest_asyncio.fixture
async def db_session():
    mgr = DatabaseManager("sqlite+aiosqlite:///:memory:")
    await mgr.init_models()
    async with mgr.session_factory() as session:
        yield session

@pytest.mark.asyncio
async def test_optimistic_concurrency_advances_version(db_session):
    repo = SessionRepository(db_session)
    session = await repo.create_session("sess_100", repository_id=42)
    assert session.version == 1
    assert session.state == SessionState.DISCOVERED.value

    updated = await repo.transition_state_optimistic(
        session_id="sess_100",
        expected_state=SessionState.DISCOVERED,
        target_state=SessionState.ELIGIBLE,
        expected_version=1
    )
    assert updated.version == 2
    assert updated.state == SessionState.ELIGIBLE.value

@pytest.mark.asyncio
async def test_optimistic_concurrency_aborts_stale_worker(db_session):
    repo = SessionRepository(db_session)
    session = await repo.create_session("sess_101", repository_id=42)

    await repo.transition_state_optimistic(
        session_id="sess_101",
        expected_state=SessionState.DISCOVERED,
        target_state=SessionState.ELIGIBLE,
        expected_version=1
    )

    with pytest.raises(StaleSessionVersionError):
        await repo.transition_state_optimistic(
            session_id="sess_101",
            expected_state=SessionState.DISCOVERED,
            target_state=SessionState.ELIGIBLE,
            expected_version=1
        )
