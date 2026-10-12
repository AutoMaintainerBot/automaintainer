import pytest
import sys
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.resource_limits import SandboxResourceLimits

@pytest.mark.asyncio
async def test_sandbox_workspace_lifecycle_and_command_execution():
    runtime = ContainerSandboxRuntime(use_docker=False)
    workspace = await runtime.prepare_workspace(repo_url="https://github.com/example/repo", commit_sha="abc1234")

    try:
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=5)
        cmd = [sys.executable, "-c", "print('hello_sandbox')"]
        result = await runtime.run_command(workspace, cmd, limits)

        assert result.exit_code == 0
        assert "hello_sandbox" in result.stdout
        assert not result.timed_out
    finally:
        await runtime.destroy_workspace(workspace)

@pytest.mark.asyncio
async def test_sandbox_enforces_execution_timeout():
    runtime = ContainerSandboxRuntime(use_docker=False)
    workspace = await runtime.prepare_workspace(repo_url="https://github.com/example/repo", commit_sha="abc1234")

    try:
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=1)
        cmd = [sys.executable, "-c", "import time; time.sleep(3)"]
        result = await runtime.run_command(workspace, cmd, limits)

        assert result.timed_out is True
        assert result.resource_violation == "WALL_CLOCK_TIMEOUT"
    finally:
        await runtime.destroy_workspace(workspace)


@pytest.mark.asyncio
async def test_sandbox_paas_container_allowed_in_production(monkeypatch):
    """Verifies that PaaS cloud containers (Render, K8s) allow sanitized host execution in production."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("RENDER", "true")

    runtime = ContainerSandboxRuntime(use_docker=False)
    workspace = await runtime.prepare_workspace(repo_url="https://github.com/example/repo", commit_sha="abc1234")
    try:
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=5)
        cmd = [sys.executable, "-c", "print('paas_render_success')"]
        result = await runtime.run_command(workspace, cmd, limits)
        assert result.exit_code == 0
        assert "paas_render_success" in result.stdout
    finally:
        await runtime.destroy_workspace(workspace)


@pytest.mark.asyncio
async def test_sandbox_bare_metal_production_fails_closed(monkeypatch):
    """Verifies that bare-metal production without PaaS/Docker raises RuntimeError."""
    from automaintainer.config import Settings
    mock_settings = Settings(
        ENVIRONMENT="production",
        SANDBOX_BACKEND="container",
        ALLOW_HOST_SUBPROCESS=False,
        GITHUB_TOKEN="ghp_test123",
        JWT_SECRET="automaintainer_default_jwt_secret_min_32_chars_123456",
        GITHUB_WEBHOOK_SECRET="test_webhook_secret_min_16_chars_valid",
    )
    monkeypatch.setattr("automaintainer.execution.container_runtime.get_settings", lambda: mock_settings)
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("FLY_APP_NAME", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("CONTAINER_ISOLATED", raising=False)

    runtime = ContainerSandboxRuntime(use_docker=False)
    workspace = await runtime.prepare_workspace(repo_url="https://github.com/example/repo", commit_sha="abc1234")
    try:
        limits = SandboxResourceLimits(wall_clock_timeout_seconds=5)
        cmd = [sys.executable, "-c", "print('should_fail')"]
        with pytest.raises(RuntimeError, match="Host subprocess execution is strictly forbidden"):
            await runtime.run_command(workspace, cmd, limits)
    finally:
        await runtime.destroy_workspace(workspace)

