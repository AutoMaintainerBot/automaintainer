import pytest
import pytest_asyncio
import httpx
import json
import time
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from automaintainer.data.tables import Base, RepositoryRecord, SessionRecord, ArtifactRecord, WorkspaceRecord
from automaintainer.core.models import SessionState
from automaintainer.config import Settings
from automaintainer.github.auth import InstallationTokenBroker, InstallationTokenRecord
from automaintainer.github.collaborator_resolver import GitHubCollaboratorResolver
from automaintainer.discovery.opportunity_detectors import LockfileOpportunityDetector
from automaintainer.discovery.candidate_crawler import OpportunityScanner


@pytest.fixture(scope="session")
def test_rsa_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    return pem


@pytest_asyncio.fixture
async def test_db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session
    await engine.dispose()



@pytest.mark.asyncio
async def test_installation_token_broker_with_settings(test_rsa_key):
    settings = Settings(
        GITHUB_APP_ID="12345",
        GITHUB_APP_PRIVATE_KEY=test_rsa_key,
        GITHUB_WEBHOOK_SECRET="super-secret-production-webhook-key-16chars",
        GITHUB_API_BASE_URL="https://mock-github.internal",
    )
    broker = InstallationTokenBroker(settings)

    jwt_token = broker.generate_app_jwt()
    assert isinstance(jwt_token, str)
    assert len(jwt_token) > 20

    def mock_transport(request: httpx.Request):
        assert "access_tokens" in str(request.url)
        return httpx.Response(201, json={"token": "ghs_mock_installation_token_abc123"})

    with patch_broker_client(broker, mock_transport):
        token_rec = await broker.get_token(installation_id=98765)
        assert isinstance(token_rec, InstallationTokenRecord)
        assert token_rec.token == "ghs_mock_installation_token_abc123"
        assert str(token_rec) == "ghs_mock_installation_token_abc123"

        token_str = await broker.get_installation_token(installation_id=98765)
        assert token_str == "ghs_mock_installation_token_abc123"


def patch_broker_client(broker, transport_fn):
    """Context manager or patch for base broker's httpx client."""
    from unittest.mock import patch
    original_client = httpx.AsyncClient

    class CustomAsyncClient(original_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(transport_fn)
            super().__init__(*args, **kwargs)

    return patch("httpx.AsyncClient", CustomAsyncClient)



@pytest.mark.asyncio
async def test_collaborator_resolver_unified():
    resolver = GitHubCollaboratorResolver(api_base_url="https://api.mock.github")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        if "maintainer_user" in url:
            return httpx.Response(200, json={"permission": "maintain"})
        elif "writer_user" in url:
            return httpx.Response(200, json={"permission": "write"})
        elif "viewer_user" in url:
            return httpx.Response(200, json={"permission": "read"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as client:
        assert await resolver.is_authorized_maintainer(
            "org/repo", "maintainer_user", token="ghs_tok", client=client
        ) is True
        assert await resolver.is_authorized_maintainer(
            "org/repo", "writer_user", token="ghs_tok", client=client
        ) is True
        assert await resolver.is_authorized_maintainer(
            "org/repo", "viewer_user", token="ghs_tok", client=client
        ) is False
        assert await resolver.is_authorized_maintainer(
            "org/repo", "unknown_user", token="ghs_tok", client=client
        ) is False



@pytest.mark.asyncio
async def test_list_repositories_route():
    from automaintainer.app.main import app
    from automaintainer.data.database import get_db_manager
    from httpx import ASGITransport, AsyncClient

    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        r1 = RepositoryRecord(
            github_repo_id=101,
            installation_id=1,
            owner="octocat",
            name="hello-world",
            visibility="public",
            default_branch="main",
            archived=False,
            health_score=85.0
        )
        r2 = RepositoryRecord(
            github_repo_id=102,
            installation_id=2,
            owner="testorg",
            name="backend-app",
            visibility="private",
            default_branch="master",
            archived=False,
            health_score=92.0
        )
        db.add_all([r1, r2])
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res_unauth = await client.get("/v1/repositories")
        assert res_unauth.status_code == 401

        from automaintainer.app.auth import create_test_token, UserRole
        token = create_test_token(roles=[UserRole.PLATFORM_OPERATOR])
        headers = {"Authorization": f"Bearer {token}"}

        resp = await client.get("/v1/repositories", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 2

        resp_filtered = await client.get("/v1/repositories?installation_id=1", headers=headers)
        assert resp_filtered.status_code == 200
        filtered_data = resp_filtered.json()
        assert len(filtered_data) == 1
        assert filtered_data[0]["name"] == "hello-world"

        resp_owner = await client.get("/v1/repositories?owner=testorg", headers=headers)
        assert resp_owner.status_code == 200
        owner_data = resp_owner.json()
        assert len(owner_data) == 1
        assert owner_data[0]["name"] == "backend-app"



@pytest.mark.asyncio
async def test_session_artifacts_route():
    from automaintainer.app.main import app
    from automaintainer.data.database import get_db_manager
    from httpx import ASGITransport, AsyncClient

    session_id = "sess_art_test_01"
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        s = SessionRecord(
            id=session_id,
            repository_id=1,
            mode="installed",
            state="WORKING",
            version=1
        )
        a1 = ArtifactRecord(
            id="art_01",
            session_id=session_id,
            artifact_type="diff",
            object_key="diffs/patch.diff",
            sha256="abc123sha",
            retention_until=datetime.now(timezone.utc) + timedelta(days=7)
        )
        a2 = ArtifactRecord(
            id="art_02",
            session_id=session_id,
            artifact_type="test_log",
            object_key="logs/pytest.log",
            sha256="def456sha",
            retention_until=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add_all([s, a1, a2])
        await db.commit()

    from automaintainer.app.auth import create_test_token, UserRole
    token = create_test_token(roles=[UserRole.PLATFORM_OPERATOR])
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(f"/v1/sessions/{session_id}/artifacts", headers=headers)
        assert resp.status_code == 200
        artifacts = resp.json()
        assert len(artifacts) == 2
        types = {a["artifact_type"] for a in artifacts}
        assert "diff" in types
        assert "test_log" in types


@pytest.mark.asyncio
async def test_session_resume_and_terminate_routes():
    from automaintainer.app.main import app
    from automaintainer.data.database import get_db_manager
    from automaintainer.app.auth import create_test_token, UserRole
    from httpx import ASGITransport, AsyncClient

    session_id = "sess_resume_term_01"
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        s = SessionRecord(
            id=session_id,
            repository_id=1,
            mode="installed",
            state="WORKING",
            version=1
        )
        w = WorkspaceRecord(
            id="ws_01",
            session_id=session_id,
            runtime_id="rt_container_123",
            status="active"
        )
        db.add_all([s, w])
        await db.commit()

    token = create_test_token(roles=[UserRole.OPERATOR, UserRole.SECURITY_ADMIN])
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        pause_resp = await client.post(f"/v1/sessions/{session_id}/pause", headers=headers)
        assert pause_resp.status_code == 200
        assert pause_resp.json()["status"] == "paused"

        resume_resp = await client.post(f"/v1/sessions/{session_id}/resume", headers=headers)
        assert resume_resp.status_code == 200
        assert resume_resp.json()["status"] == "resumed"

        term_resp = await client.post(f"/v1/sessions/{session_id}/terminate", headers=headers)
        assert term_resp.status_code == 200
        assert term_resp.json()["status"] == "terminated"
        assert term_resp.json()["state"] == "CANCELLED"

        async with db_mgr.get_session() as db:
            from sqlalchemy import select
            res = await db.execute(select(WorkspaceRecord).where(WorkspaceRecord.session_id == session_id))
            ws = res.scalar_one()
            assert ws.status == "destroyed"

        res_fail = await client.post(f"/v1/sessions/{session_id}/resume", headers=headers)
        assert res_fail.status_code == 400



@pytest.mark.asyncio
async def test_lockfile_detector_and_scanner():
    detector = LockfileOpportunityDetector(api_base_url="https://api.mock.github")

    def mock_transport(request: httpx.Request):
        if "/contents" in str(request.url):
            items = [
                {"name": "pyproject.toml", "type": "file"},
                {"name": "package.json", "type": "file"},
                {"name": "README.md", "type": "file"}
            ]
            return httpx.Response(200, json=items)
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as client:
        opps = await detector.detect(owner="octo", repo="test", token="ghs_tok", client=client)
        assert len(opps) == 2
        targets = {o.target_paths[0] for o in opps}
        assert "poetry.lock" in targets
        assert "package-lock.json" in targets

    scanner = OpportunityScanner()
    detector_types = [type(d).__name__ for d in scanner.detectors]
    assert "LockfileOpportunityDetector" in detector_types
    assert len(scanner.detectors) == 5
