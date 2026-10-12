import pytest
from httpx import AsyncClient, ASGITransport
from automaintainer.app.main import app
from automaintainer.core.repo_config import RepoConfigEngine, RepoConfig
from automaintainer.discovery.anti_spam import AntiSpamManager
from automaintainer.inference.model_registry import ModelRegistry, ModelLifecycleState
from automaintainer.queue.redis_queue import PartitionedLeasedQueue

def test_repo_config_precedence_and_platform_ceilings():
    user_yaml = """
    automaintainer:
      autonomy: autonomous
      limits:
        max_files: 100
        max_changed_lines: 5000
    """
    config = RepoConfigEngine.parse_yaml(user_yaml)
    effective = RepoConfigEngine.merge_with_platform_ceilings(config)

    assert effective["max_files"] == RepoConfigEngine.PLATFORM_CEILING_MAX_FILES  # 25
    assert effective["max_changed_lines"] == RepoConfigEngine.PLATFORM_CEILING_MAX_LINES  # 1500
    assert any(".github/workflows" in p for p in effective["denied_paths"])

def test_anti_spam_cooldown_and_opt_out():
    mgr = AntiSpamManager(cooldown_days=7)
    mgr.register_opt_out("blocked-org")

    allowed, reason = mgr.can_open_pr("blocked-org/repo-a")
    assert allowed is False
    assert "opt-out" in reason

    mgr.record_pr_rejection("normal-user/repo-b")
    allowed, reason = mgr.can_open_pr("normal-user/repo-b")
    assert allowed is False
    assert "cooling-off" in reason

def test_model_registry_deprecation_fallback():
    reg = ModelRegistry()
    resolved = reg.resolve_active_model("mixtral-8x7b-32768")
    assert resolved == "llama-3.3-70b-versatile"

def test_partitioned_leased_queue_prioritization():
    pq = PartitionedLeasedQueue()
    pq.enqueue("discovery", "sess_disc", "discovery", {"q": "python"})
    pq.enqueue("patch", "sess_patch", "patch", {"repo": "test"})

    queue_name, job = pq.acquire_next_job("worker_1")
    assert queue_name == "patch"
    assert job.session_id == "sess_patch"

@pytest.mark.asyncio
async def test_rest_api_surface():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/v1/health")
        assert res.status_code == 200

        res_unauth = await client.get("/v1/policies")
        assert res_unauth.status_code == 401

        from automaintainer.app.auth import create_test_token, UserRole
        token = create_test_token(roles=[UserRole.OPERATOR])
        headers = {"Authorization": f"Bearer {token}"}
        res = await client.get("/v1/policies", headers=headers)
        assert res.status_code == 200
        assert "platform_limits" in res.json()

        res_inf_unauth = await client.get("/v1/inference/models")
        assert res_inf_unauth.status_code == 401

        res = await client.get("/v1/inference/models", headers=headers)
        assert res.status_code == 200
        assert len(res.json()["models"]) >= 3

        res = await client.get("/")
        assert res.status_code == 200
        assert "AutoMaintainer" in res.text
