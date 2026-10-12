import pytest
from httpx import ASGITransport, AsyncClient
from automaintainer.app.main import app
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import (
    InstallationRecord, RepositoryRecord, SessionRecord, RepoPolicyRecord,
    OpportunityRecord, TaskRecord, WorkspaceRecord, ArtifactRecord
)
from automaintainer.app.auth import create_test_token, UserRole, is_platform_admin, AuthUser
from automaintainer.core.models import MutationOp, RiskTier, SessionState

@pytest.mark.asyncio
async def test_database_foreign_key_metadata():
    """Verify that ORM models have explicit ForeignKey constraints defined."""
    assert RepositoryRecord.__table__.c.installation_id.foreign_keys
    assert SessionRecord.__table__.c.repository_id.foreign_keys
    assert RepoPolicyRecord.__table__.c.repo_id.foreign_keys
    assert OpportunityRecord.__table__.c.repository_id.foreign_keys
    assert WorkspaceRecord.__table__.c.session_id.foreign_keys
    assert TaskRecord.__table__.c.session_id.foreign_keys
    assert ArtifactRecord.__table__.c.session_id.foreign_keys

@pytest.mark.asyncio
async def test_repository_api_authentication_and_tenant_isolation():
    """Verify /v1/repositories requires auth, scopes list to tenant, prevents enumeration, and enqueues scan."""
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        inst_100 = InstallationRecord(id=11001, github_installation_id=91001, account_id=100)
        repo_100 = RepositoryRecord(id=21001, github_repo_id=82001, installation_id=11001, owner="tenant100", name="repo-a")
        inst_200 = InstallationRecord(id=11002, github_installation_id=91002, account_id=200)
        repo_200 = RepositoryRecord(id=21002, github_repo_id=82002, installation_id=11002, owner="tenant200", name="repo-b")
        db.add_all([inst_100, repo_100, inst_200, repo_200])
        await db.commit()

    token_100 = create_test_token(username="user100", roles=[UserRole.OPERATOR], account_id=100)
    token_200 = create_test_token(username="user200", roles=[UserRole.OPERATOR], account_id=200)
    token_admin = create_test_token(username="plat_admin", roles=[UserRole.PLATFORM_OPERATOR], account_id=999)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/v1/repositories")).status_code == 401
        assert (await client.get("/v1/repositories/21001")).status_code == 401
        assert (await client.post("/v1/repositories/21001/scan")).status_code == 401

        res_list = await client.get("/v1/repositories", headers={"Authorization": f"Bearer {token_100}"})
        assert res_list.status_code == 200
        ids = [r["id"] for r in res_list.json()]
        assert 21001 in ids
        assert 21002 not in ids

        res_enum = await client.get("/v1/repositories/21002", headers={"Authorization": f"Bearer {token_100}"})
        assert res_enum.status_code == 404

        res_cross_scan = await client.post("/v1/repositories/21002/scan", headers={"Authorization": f"Bearer {token_100}"})
        assert res_cross_scan.status_code == 403

        res_scan = await client.post("/v1/repositories/21001/scan", headers={"Authorization": f"Bearer {token_100}"})
        assert res_scan.status_code == 200
        data = res_scan.json()
        assert data["status"] == "scan_scheduled"
        assert data["repository_id"] == 21001
        assert "job_id" in data

        res_admin = await client.get("/v1/repositories", headers={"Authorization": f"Bearer {token_admin}"})
        assert res_admin.status_code == 200
        admin_ids = [r["id"] for r in res_admin.json()]
        assert 21001 in admin_ids
        assert 21002 in admin_ids

@pytest.mark.asyncio
async def test_installation_api_auth_and_reconciliation():
    """Verify /v1/installations requires auth, scopes listing, and durably enqueues reconciliation."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        inst_1 = InstallationRecord(id=33001, github_installation_id=73301, account_id=300)
        inst_2 = InstallationRecord(id=33002, github_installation_id=73302, account_id=400)
        db.add_all([inst_1, inst_2])
        await db.commit()

    token_300 = create_test_token(username="user300", roles=[UserRole.OPERATOR], account_id=300)
    token_400 = create_test_token(username="user400", roles=[UserRole.OPERATOR], account_id=400)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/v1/installations")).status_code == 401
        assert (await client.post("/v1/installations/73301/reconcile")).status_code == 401

        res = await client.get("/v1/installations", headers={"Authorization": f"Bearer {token_300}"})
        assert res.status_code == 200
        inst_ids = [i["github_installation_id"] for i in res.json()]
        assert 73301 in inst_ids
        assert 73302 not in inst_ids

        res_cross = await client.post("/v1/installations/73302/reconcile", headers={"Authorization": f"Bearer {token_300}"})
        assert res_cross.status_code == 403

        res_rec = await client.post("/v1/installations/73301/reconcile", headers={"Authorization": f"Bearer {token_300}"})
        assert res_rec.status_code == 200
        rec_data = res_rec.json()
        assert rec_data["status"] == "reconciliation_queued"
        assert rec_data["installation_id"] == 73301
        assert "job_id" in rec_data

@pytest.mark.asyncio
async def test_policy_api_auth_simulation_and_effective_policy():
    """Verify /v1/policies requires auth, separates simulation from effective policy, and enforces tenant check."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        inst = InstallationRecord(id=55001, github_installation_id=65501, account_id=500)
        repo = RepositoryRecord(id=55002, github_repo_id=65502, installation_id=55001, owner="tenant500", name="repo-policy")
        pol = RepoPolicyRecord(
            id="pol_55002",
            repo_id=55002,
            autonomy="autonomous",
            allowed_classes_json=["dependency_update"],
            excluded_paths_json=["internal/*"]
        )
        db.add_all([inst, repo, pol])
        await db.commit()

    token_500 = create_test_token(roles=[UserRole.OPERATOR], account_id=500)
    token_foreign = create_test_token(roles=[UserRole.OPERATOR], account_id=600)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/v1/policies")).status_code == 401
        assert (await client.get("/v1/policies/effective/55002")).status_code == 401
        assert (await client.post("/v1/policies/simulate", json={"repository": "test", "operation": "create_commit", "target_paths": []})).status_code == 401

        assert (await client.get("/v1/policies/effective/55002", headers={"Authorization": f"Bearer {token_foreign}"})).status_code == 404

        res_eff = await client.get("/v1/policies/effective/55002", headers={"Authorization": f"Bearer {token_500}"})
        assert res_eff.status_code == 200
        data = res_eff.json()
        assert data["repository_id"] == 55002
        assert data["autonomy"] == "autonomous"
        assert "dependency_update" in data["allowed_classes"]
        assert "effective_limits" in data

        sim_res = await client.post(
            "/v1/policies/simulate",
            json={
                "repository": "test",
                "operation": "create_commit",
                "target_paths": ["main.py"],
                "risk_tier": "R1"
            },
            headers={"Authorization": f"Bearer {token_500}"}
        )
        assert sim_res.status_code == 200
        assert sim_res.json()["simulation"] is True

@pytest.mark.asyncio
async def test_inference_endpoints_auth_and_no_leak():
    """Verify /v1/inference endpoints are authenticated and health does not leak secrets."""
    token = create_test_token(roles=[UserRole.OPERATOR], account_id=700)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        assert (await client.get("/v1/inference/health")).status_code == 401
        assert (await client.get("/v1/inference/models")).status_code == 401

        res = await client.get("/v1/inference/health", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        health_data = res.json()
        assert "provider" in health_data
        assert "status" in health_data
        assert "provider_available" in health_data
        assert "organization_id" not in health_data
        assert "primary_key_configured" not in health_data

@pytest.mark.asyncio
async def test_session_creation_repo_validation():
    """Verify POST /v1/sessions rejects non-existent repo (404) and foreign repo (403)."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        inst_a = InstallationRecord(id=77001, github_installation_id=87701, account_id=700)
        repo_a = RepositoryRecord(id=88001, github_repo_id=98801, installation_id=77001, owner="tenant700", name="repo-700")
        inst_b = InstallationRecord(id=77002, github_installation_id=87702, account_id=800)
        repo_b = RepositoryRecord(id=88002, github_repo_id=98802, installation_id=77002, owner="tenant800", name="repo-800")
        db.add_all([inst_a, repo_a, inst_b, repo_b])
        await db.commit()

    token_700 = create_test_token(roles=[UserRole.OPERATOR], account_id=700)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res_404 = await client.post(
            "/v1/sessions",
            json={"session_id": "sess_non_exist", "repository_id": 999999},
            headers={"Authorization": f"Bearer {token_700}"}
        )
        assert res_404.status_code == 404

        res_403 = await client.post(
            "/v1/sessions",
            json={"session_id": "sess_foreign", "repository_id": 88002},
            headers={"Authorization": f"Bearer {token_700}"}
        )
        assert res_403.status_code == 403

        res_201 = await client.post(
            "/v1/sessions",
            json={"session_id": "sess_owned_ok", "repository_id": 88001},
            headers={"Authorization": f"Bearer {token_700}"}
        )
        assert res_201.status_code == 201
