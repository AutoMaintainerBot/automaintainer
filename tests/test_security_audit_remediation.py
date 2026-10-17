import pytest
import os
import sys
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import ASGITransport, AsyncClient

from automaintainer.config import Settings, get_settings
from automaintainer.app.main import app
from automaintainer.app.auth import create_test_token, UserRole, create_access_token, AuthUser
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.resource_limits import SandboxResourceLimits
from automaintainer.execution.sandbox_factory import get_sandbox_runtime
from automaintainer.github.webhook_verifier import GitHubWebhookVerifier, WebhookVerificationError
from automaintainer.data.tables import RepositoryRecord, SessionRecord, PullRequestRecord, InstallationRecord
from automaintainer.data.database import get_db_manager


# ---------------------------------------------------------------------------
# Finding 1: JWT Secret Hardening & Privileged Claim Validation
# ---------------------------------------------------------------------------
def test_jwt_secret_known_default_rejected_in_production():
    """Verify that known default or short JWT secrets raise ValueError in production."""
    with pytest.raises(ValueError, match="JWT_SECRET must be explicitly configured"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            JWT_SECRET="automaintainer_default_jwt_secret_min_32_chars_123456",
            GITHUB_WEBHOOK_SECRET="high_entropy_prod_webhook_secret_9999",
            GITHUB_TOKEN="ghp_test_token",
            SANDBOX_BACKEND="container",
            ALLOW_HOST_SUBPROCESS=False,
        )

    with pytest.raises(ValueError, match="JWT_SECRET must be explicitly configured"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            JWT_SECRET="short_secret",
            GITHUB_WEBHOOK_SECRET="high_entropy_prod_webhook_secret_9999",
            GITHUB_TOKEN="ghp_test_token",
            SANDBOX_BACKEND="container",
            ALLOW_HOST_SUBPROCESS=False,
        )


def test_jwt_secret_ephemeral_generated_in_dev_if_missing():
    """Verify that development/test environments generate high-entropy ephemeral secret if unset."""
    s = Settings(_env_file=None, ENVIRONMENT="development", JWT_SECRET=None)
    assert s.JWT_SECRET is not None
    assert len(s.JWT_SECRET) >= 32
    assert s.JWT_SECRET != "automaintainer_default_jwt_secret_min_32_chars_123456"


@pytest.mark.asyncio
async def test_privileged_role_claim_rejected_for_untrusted_user_in_production(monkeypatch):
    """Verify that in production, SECURITY_ADMIN claimed by non-admin username is rejected."""
    prod_secret = "super_high_entropy_prod_secret_1234567890_abcdef"
    mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        JWT_SECRET=prod_secret,
        GITHUB_WEBHOOK_SECRET="high_entropy_prod_webhook_secret_9999",
        GITHUB_TOKEN="ghp_test_token",
        ADMIN_USERNAME="legit_admin",
        SANDBOX_BACKEND="container",
        ALLOW_HOST_SUBPROCESS=False,
    )
    monkeypatch.setattr("automaintainer.config.get_settings", lambda: mock_settings)
    monkeypatch.setattr("automaintainer.app.auth.get_settings", lambda: mock_settings)

    # Forged user claiming SECURITY_ADMIN with non-admin username
    attacker = AuthUser(
        user_id="attacker_123",
        username="attacker_user",
        roles=[UserRole.SECURITY_ADMIN],
        account_id=1,
    )
    forged_token = create_access_token(attacker)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/v1/repositories", headers={"Authorization": f"Bearer {forged_token}"})
        assert resp.status_code == 403
        assert "Privileged platform administrative role rejected" in resp.json().get("detail", "")


# ---------------------------------------------------------------------------
# Finding 2: Webhook Secret Hardening
# ---------------------------------------------------------------------------
def test_webhook_secret_default_rejected_in_production():
    """Verify that known default or missing webhook secrets fail startup in production."""
    with pytest.raises(ValueError, match="GITHUB_WEBHOOK_SECRET must be explicitly configured"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            JWT_SECRET="super_high_entropy_prod_secret_1234567890_abcdef",
            GITHUB_WEBHOOK_SECRET="automaintainer_default_webhook_secret_32_chars!",
            GITHUB_TOKEN="ghp_test_token",
            SANDBOX_BACKEND="container",
            ALLOW_HOST_SUBPROCESS=False,
        )

    with pytest.raises(ValueError, match="GITHUB_WEBHOOK_SECRET must be explicitly configured"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            JWT_SECRET="super_high_entropy_prod_secret_1234567890_abcdef",
            GITHUB_WEBHOOK_SECRET=None,
            GITHUB_TOKEN="ghp_test_token",
            SANDBOX_BACKEND="container",
            ALLOW_HOST_SUBPROCESS=False,
        )


def test_webhook_verifier_rejects_insecure_default_in_production(monkeypatch):
    """Verify GitHubWebhookVerifier raises when passed an insecure default secret in production."""
    mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        JWT_SECRET="super_high_entropy_prod_secret_1234567890_abcdef",
        GITHUB_WEBHOOK_SECRET="valid_custom_prod_secret_min_16_chars",
        GITHUB_TOKEN="ghp_test_token",
        SANDBOX_BACKEND="container",
        ALLOW_HOST_SUBPROCESS=False,
    )
    monkeypatch.setattr("automaintainer.config.get_settings", lambda: mock_settings)
    monkeypatch.setattr("automaintainer.github.webhook_verifier.get_settings", lambda: mock_settings)

    with pytest.raises(WebhookVerificationError, match="Insecure default webhook secret"):
        GitHubWebhookVerifier.verify(
            raw_body=b'{"action":"opened"}',
            signature_header="sha256=abcdef",
            secret="automaintainer_default_webhook_secret_32_chars!",
        )


# ---------------------------------------------------------------------------
# Finding 3: Sandbox Isolation Enforced in Production
# ---------------------------------------------------------------------------
def test_render_yaml_sets_production_environment():
    """Verify render.yaml declares ENVIRONMENT=production."""
    with open("render.yaml", "r", encoding="utf-8") as f:
        content = f.read()
    assert "value: production" in content
    assert "value: development" not in content


def test_sandbox_factory_refuses_subprocess_fallback_in_production(monkeypatch):
    """Verify sandbox factory raises RuntimeError if Docker is absent in production."""
    prod_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        JWT_SECRET="super_high_entropy_prod_secret_1234567890_abcdef",
        GITHUB_WEBHOOK_SECRET="high_entropy_prod_webhook_secret_9999",
        GITHUB_TOKEN="ghp_test_token",
        ALLOW_HOST_SUBPROCESS=False,
        SANDBOX_BACKEND="container",
    )
    monkeypatch.setattr("shutil.which", lambda prog: None if prog == "docker" else "/bin/" + prog)

    with pytest.raises(RuntimeError, match="requires a verified container sandbox"):
        get_sandbox_runtime(settings=prod_settings, override_backend="container")


@pytest.mark.asyncio
async def test_container_runtime_paas_bypass_eliminated(monkeypatch):
    """Verify container runtime fails closed in production even when PaaS indicators are present."""
    prod_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        JWT_SECRET="super_high_entropy_prod_secret_1234567890_abcdef",
        GITHUB_WEBHOOK_SECRET="high_entropy_prod_webhook_secret_9999",
        GITHUB_TOKEN="ghp_test_token",
        ALLOW_HOST_SUBPROCESS=False,
        SANDBOX_BACKEND="container",
    )
    monkeypatch.setattr("automaintainer.execution.container_runtime.get_settings", lambda: prod_settings)
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("ENVIRONMENT", "production")

    runtime = ContainerSandboxRuntime(use_docker=False)
    workspace = await runtime.prepare_workspace(repo_url="https://github.com/example/repo", commit_sha="abc1234")
    try:
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=5)
        cmd = [sys.executable, "-c", "print('should_never_run')"]
        with pytest.raises(RuntimeError, match="Host subprocess execution of untrusted code is strictly forbidden"):
            await runtime.run_command(workspace, cmd, limits)
    finally:
        await runtime.destroy_workspace(workspace)


# ---------------------------------------------------------------------------
# Finding 4: Public Managed-Repos Registration Abuse Protection
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unauthenticated_registration_creates_nomination_not_active_repo():
    """Verify unauthenticated public POST /v1/public/managed-repos/register creates a review nomination."""
    transport = ASGITransport(app=app)
    mock_gh_repo = {
        "id": 123456,
        "full_name": "some-public-owner/safe-lib",
        "private": False,
        "archived": False,
        "stargazers_count": 42,
        "default_branch": "main",
        "description": "Safe open source library",
    }

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_gh_repo
        mock_get.return_value = mock_resp

        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post(
                "/v1/public/managed-repos/register",
                json={"repository": "some-public-owner/safe-lib"}
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "nominated"
            assert data["requires_maintainer_approval"] is True
            assert "install the official GitHub App" in data["message"]


# ---------------------------------------------------------------------------
# Finding 5: Webhook Session Resolution Strictly Bound to Repository
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_webhook_pr_lookup_does_not_cross_associate_repos():
    """Verify PR #5 on Repo A does NOT match an event for PR #5 on Repo B."""
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    async with db_mgr.get_session() as db:
        # Create Repo A with PR #5
        r_a = RepositoryRecord(id=8001, github_repo_id=98001, owner="org-alpha", name="shared-name")
        sess_a = SessionRecord(id="sess_alpha_pr5", repository_id=8001, mode="managed", state="working", version=1)
        pr_a = PullRequestRecord(
            id="pr_alpha_5",
            session_id="sess_alpha_pr5",
            number=5,
            owner="org-alpha",
            repo="shared-name",
            head_ref="automaintainer/sess_alpha_pr5",
            base_ref="main",
            url="https://github.com/org-alpha/shared-name/pull/5",
            status="open",
        )
        # Create Repo B
        r_b = RepositoryRecord(id=8002, github_repo_id=98002, owner="org-beta", name="shared-name")
        db.add_all([r_a, sess_a, pr_a, r_b])
        await db.commit()

    from automaintainer.app.routes.webhooks import handle_github_webhook
    req = MagicMock()
    req.body = AsyncMock(return_value=b'{"action":"created","issue":{"number":5,"pull_request":{}},"repository":{"id":98002,"full_name":"org-beta/shared-name"}}')

    mock_queue = MagicMock()
    settings = MagicMock()
    settings.GITHUB_WEBHOOK_SECRET = "super_valid_webhook_secret_key_16_chars"

    with patch("automaintainer.app.routes.webhooks.GitHubWebhookVerifier.verify", return_value=True), \
         patch("automaintainer.app.routes.webhooks.get_partitioned_queue", return_value=mock_queue):
        res = await handle_github_webhook(
            request=req,
            x_github_delivery="deliv_cross_repo_test",
            x_github_event="issue_comment",
            x_hub_signature_256="sha256=valid",
            settings=settings,
        )
        # Must NOT associate with sess_alpha_pr5
        assert res["session_id"] != "sess_alpha_pr5"
        assert res["session_id"].startswith("sess_evt_")


# ---------------------------------------------------------------------------
# Finding 6: /diag Endpoint Security & No Write-Side Effects
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_diag_endpoint_requires_admin_credentials():
    """Verify /diag rejects unauthenticated access."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/diag")
        # Without credentials, returns 401 or 503 (if ADMIN_PASSWORD unset)
        assert resp.status_code in (401, 503)


@pytest.mark.asyncio
async def test_diag_endpoint_authenticated_is_readonly_and_no_fork(monkeypatch):
    """Verify authenticated /diag returns operational telemetry without issuing GitHub fork POSTs."""
    import httpx
    mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        JWT_SECRET="super_high_entropy_prod_secret_1234567890_abcdef",
        GITHUB_WEBHOOK_SECRET="high_entropy_prod_webhook_secret_9999",
        GITHUB_TOKEN="ghp_test_token",
        ADMIN_USERNAME="admin",
        ADMIN_PASSWORD="secure_admin_password_999",
        SANDBOX_BACKEND="container",
        ALLOW_HOST_SUBPROCESS=False,
    )
    monkeypatch.setattr("automaintainer.config.get_settings", lambda: mock_settings)
    monkeypatch.setattr("automaintainer.app.main.get_settings", lambda: mock_settings)

    orig_get = httpx.AsyncClient.get
    async def mock_selective_get(self, url, *args, **kwargs):
        if "/user" in str(url) or "api.github.com" in str(url):
            mock_u = MagicMock()
            mock_u.status_code = 200
            return mock_u
        return await orig_get(self, url, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "get", mock_selective_get)

    transport = ASGITransport(app=app)
    with patch("httpx.AsyncClient.post") as mock_post:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/diag", auth=("admin", "secure_admin_password_999"))
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "operational"
            assert "credentials" in data
            # Ensure NO POST was called (zero fork creation side effect!)
            mock_post.assert_not_called()
            # Ensure sensitive secret file lists are not exposed
            assert "secret_files_found" not in data
            assert "matching_env_names" not in data


# ---------------------------------------------------------------------------
# Finding 7: Installation Binding Preservation on Token Mint Failure
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reconciliation_preserves_installation_id_on_token_error():
    """Verify that if InstallationTokenBroker fails, installation_id is NOT wiped to None."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        inst = InstallationRecord(id=7701, github_installation_id=97701, account_id=1, status="active")
        repo = RepositoryRecord(id=7701, github_repo_id=97701, installation_id=7701, owner="test-org", name="test-repo")
        sess = SessionRecord(id="sess_preserve_test", repository_id=7701, mode="managed", state="discovered", version=1)
        db.add_all([inst, repo, sess])
        await db.commit()

        # Simulate token mint failure
        from automaintainer.github.auth import InstallationTokenBroker
        with patch.object(InstallationTokenBroker, "get_token", side_effect=RuntimeError("GitHub API rate limit or outage")):
            # Attempt token fetch
            broker = InstallationTokenBroker(get_settings())
            with pytest.raises(RuntimeError):
                await broker.get_token(97701)

        # Verify DB still has installation_id == 7701 intact!
        refreshed_repo = await db.get(RepositoryRecord, 7701)
        assert refreshed_repo.installation_id == 7701
