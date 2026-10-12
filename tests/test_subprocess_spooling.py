import pytest
import sys
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.resource_limits import SandboxResourceLimits


@pytest.mark.asyncio
async def test_subprocess_spooling_handles_massive_output():
    """
    Verify that generating > 256KB of output does not deadlock or hang
    on Windows due to 64KB OS pipe buffers.
    """
    runtime = ContainerSandboxRuntime(use_docker=False)
    ws = await runtime.prepare_workspace(repo_url="", commit_sha="")
    limits = SandboxResourceLimits(wall_clock_timeout_seconds=15)

    cmd = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('A' * 300000); sys.stderr.write('B' * 10000)"
    ]

    try:
        res = await runtime.run_command(ws, cmd, limits)
        assert res.exit_code == 0
        assert res.timed_out is False
        assert len(res.stdout) == 300000
        assert len(res.stderr) == 10000
    finally:
        await runtime.destroy_workspace(ws)
