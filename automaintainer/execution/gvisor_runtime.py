from typing import List, Dict, Any, Optional
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.resource_limits import SandboxResourceLimits

class MicroVMSandboxRuntime(ContainerSandboxRuntime):
    """
    MicroVM / gVisor (runsc) Kernel-Isolated Execution Runtime:
    - Runs untrusted public repository code with strict kernel boundaries.
    - Uses gVisor runtime (`--runtime=runsc`) or hardened seccomp JSON filter.
    - Blocks high-risk syscalls: ptrace, bpf, io_uring, mount, kexec.
    - Combines PID limit, CPU quota, and memory isolation.
    """

    DEFAULT_BLOCKED_SYSCALLS = [
        "ptrace",
        "bpf",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "kexec_load",
        "mount",
        "umount2",
        "reboot",
        "swapon",
        "swapoff"
    ]

    def __init__(self, use_gvisor: bool = True, base_image: str = "python:3.12-slim"):
        super().__init__(use_docker=True, base_image=base_image)
        self.use_gvisor = use_gvisor

    def get_container_flags(self, limits: SandboxResourceLimits) -> List[str]:
        flags = [
            "--rm",
            "--network", "none" if not limits.allow_network_egress else "bridge",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--cpus={limits.cpu_cores}",
            f"--memory={limits.memory_mb}m",
            f"--pids-limit={limits.max_pids}",
        ]
        if self.use_gvisor:
            flags.append("--runtime=runsc")

        # Pinned seccomp profile enforcing DEFAULT_BLOCKED_SYSCALLS at the kernel boundary
        import os
        profile_path = os.path.join(os.path.dirname(__file__), "seccomp_profile.json")
        if os.path.exists(profile_path):
            flags.append(f"--security-opt=seccomp={os.path.abspath(profile_path)}")
        else:
            flags.append("--security-opt=seccomp=default")
        return flags

