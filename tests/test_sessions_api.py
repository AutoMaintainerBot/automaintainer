import pytest
from httpx import AsyncClient, ASGITransport
from automaintainer.app.main import app
from automaintainer.app.auth import create_test_token, UserRole
from automaintainer.data.database import get_db_manager
from automaintainer.data.repositories import SessionRepository
from automaintainer.core.models import SessionState

@pytest.mark.asyncio
async def test_sessions_api_endpoints():
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        s = await repo.create_session("sess_api_test", repository_id=123)

    token = create_test_token(roles=[UserRole.OPERATOR, UserRole.SECURITY_ADMIN])
    headers = {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/v1/sessions/sess_api_test", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "sess_api_test"
        assert data["state"] == "DISCOVERED"
        assert data["version"] == 1
        assert data["is_terminal"] is False

        unauth_resp = await client.post("/v1/sessions/sess_api_test/pause")
        assert unauth_resp.status_code == 401

        pause_resp = await client.post("/v1/sessions/sess_api_test/pause", headers=headers)
        assert pause_resp.status_code == 200
        assert pause_resp.json()["status"] == "paused"
        assert pause_resp.json()["state"] == "PAUSED"

        resume_resp = await client.post("/v1/sessions/sess_api_test/resume", headers=headers)
        assert resume_resp.status_code == 200
        assert resume_resp.json()["status"] == "resumed"

        assert (await client.get("/metrics-summary")).status_code == 401

        metrics_resp = await client.get("/metrics-summary", headers=headers)
        assert metrics_resp.status_code == 200
        metrics_data = metrics_resp.json()
        assert "candidates_scanned" in metrics_data
        assert "active_sessions" in metrics_data
        assert metrics_data["active_sessions"] >= 1

        unauth_cancel = await client.post("/v1/sessions/sess_api_test/cancel")
        assert unauth_cancel.status_code == 401

        cancel_resp = await client.post("/v1/sessions/sess_api_test/cancel", headers=headers)
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["state"] == "CANCELLED"

        verify_resp = await client.get("/v1/sessions/sess_api_test", headers=headers)
        assert verify_resp.json()["is_terminal"] is True

