"""
Sandbox Runtime Factory.
Instantiates the appropriate kernel-isolated or container runtime based on system configuration:
  - 'gvisor': MicroVMSandboxRuntime with runsc isolation and seccomp syscall filtering.
  - 'container': Rootless Docker with read-only rootfs and dropped capabilities.
  - 'subprocess_jail': Ephemeral directory jail with environment stripping.
"""
from typing import Optional
import subprocess
import json
import shutil
import logging
from automaintainer.execution.sandbox_interface import ISandboxRuntime
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.gvisor_runtime import MicroVMSandboxRuntime
from automaintainer.config import Settings, get_settings

logger = logging.getLogger("automaintainer.sandbox")

def is_gvisor_supported() -> bool:
    """
    Auto-detects whether gVisor (runsc) is installed and registered in Docker runtimes:
    Queries `docker info --format '{{json .Runtimes}}'`
    """
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{json .Runtimes}}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            runtimes = json.loads(proc.stdout)
            if isinstance(runtimes, dict):
                return "runsc" in runtimes
    except Exception as e:
        logger.debug(f"Docker runtime capability detection failed: {e}")
    return False

def get_sandbox_runtime(
    settings: Optional[Settings] = None,
    override_backend: Optional[str] = None
) -> ISandboxRuntime:
    """
    Selects and instantiates the configured sandbox execution backend.
    Enforces gVisor capability auto-detection with fallback negotiation.
    """
    effective_settings = settings or get_settings()
    backend = (override_backend or effective_settings.SANDBOX_BACKEND).lower().strip()
    base_image = effective_settings.DOCKER_BASE_IMAGE or "python:3.12-slim"

    has_docker = shutil.which("docker") is not None

    if backend == "gvisor":
        if has_docker and is_gvisor_supported():
            return MicroVMSandboxRuntime(use_gvisor=True, base_image=base_image)
        elif has_docker:
            logger.warning("gVisor (runsc) runtime is not registered in Docker. Falling back to hardened container runtime.")
            return ContainerSandboxRuntime(use_docker=True, base_image=base_image)
        else:
            logger.warning("gVisor backend requested but Docker CLI is not on PATH. Falling back to Subprocess Jail.")
            return ContainerSandboxRuntime(use_docker=False)

    elif backend == "container":
        if has_docker:
            return ContainerSandboxRuntime(use_docker=True, base_image=base_image)
        else:
            logger.warning("Container backend requested but Docker CLI is not on PATH. Falling back to Subprocess Jail.")
            return ContainerSandboxRuntime(use_docker=False)

    else:
        # Default / Subprocess Jail
        return ContainerSandboxRuntime(use_docker=False)
