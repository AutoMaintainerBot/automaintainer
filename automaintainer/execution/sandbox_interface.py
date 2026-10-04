from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from automaintainer.execution.resource_limits import SandboxResourceLimits

class ExecutionResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    timed_out: bool = False
    resource_violation: Optional[str] = None

class ISandboxRuntime(ABC):
    """
    Abstract interface for Hostile Repository Execution Sandboxes.
    Implementations: ContainerRuntime (Docker/Rootless), MicroVMRuntime (Firecracker/gVisor).
    Must strictly prevent host escapes, secret exfiltration and unchecked network access.
    """

    @abstractmethod
    async def prepare_workspace(self, repo_url: str, commit_sha: str) -> str:
        """Clones repo into ephemeral workspace at immutable SHA."""
        pass

    @abstractmethod
    async def run_command(
        self,
        workspace_id: str,
        command: List[str],
        limits: SandboxResourceLimits
    ) -> ExecutionResult:
        """Executes a command inside the bounded, isolated sandbox."""
        pass

    @abstractmethod
    async def destroy_workspace(self, workspace_id: str) -> None:
        """Ephemeral destruction of workspace, disk, and runtime resources."""
        pass


def safe_workspace_path(workspace_dir: str, rel_path: str) -> str:
    """
    Canonicalizes path and enforces that target stays strictly within the workspace directory root.
    Raises ValueError on directory traversal attempts.
    """
    import os
    root = os.path.realpath(os.path.abspath(workspace_dir))
    target = os.path.realpath(os.path.abspath(os.path.join(root, rel_path)))
    if target != root and not target.startswith(root + os.sep):
        raise ValueError(f"Path traversal detected: '{rel_path}' escapes workspace '{workspace_dir}'")
    return target

    async def cleanup_stale_workspaces(self, max_age_seconds: float = 3600.0) -> int:
        """Sweeps orphaned ephemeral workspaces left behind by dead processes."""
        return 0
