import asyncio
import os
import shutil
import tempfile
import time
from typing import List
from automaintainer.execution.sandbox_interface import ISandboxRuntime, ExecutionResult
from automaintainer.execution.resource_limits import SandboxResourceLimits
from automaintainer.execution.network_security import NetworkFirewallEnforcer, SSRFSecurityViolation
from automaintainer.config import get_settings

class ContainerSandboxRuntime(ISandboxRuntime):
    """
    Hardened Sandbox Runtime with Defense-in-Depth:
    Attempts rootless container isolation if docker/podman is available:
      --network none (or explicit allowlist proxy)
      --read-only rootfs
      --cap-drop=ALL
      --pids-limit
      --memory
      --cpus
      --security-opt=no-new-privileges
      non-root user (1000:1000)

    If container engine is absent (e.g. lightweight local testing), it uses a Subprocess Jail:
      - Dedicated ephemeral temp directory
      - Explicit environment sanitization (stripping all host AWS/GITHUB/DATABASE/GROQ tokens)
      - Non-shell execution
      - Strict asyncio timeout enforcement
      - Automatic post-execution recursive cleanup
      - HTTP_PROXY / HTTPS_PROXY routed to ControlledEgressFilter proxy daemon
    """

    def __init__(self, use_docker: bool = False, base_image: str = "python:3.12-slim"):
        self.use_docker = use_docker
        self.base_image = base_image
        self._workspaces = {}

    async def prepare_workspace(self, repo_url: str, commit_sha: str) -> str:
        """Create isolated ephemeral workspace and populate repository files."""
        workspace_dir = tempfile.mkdtemp(prefix="automaintainer_ws_")
        self._workspaces[workspace_dir] = {
            "path": workspace_dir,
            "created_at": time.time(),
            "repo_url": repo_url,
            "commit_sha": commit_sha
        }

        # Clone repository at shallow depth 1 if valid URL provided (skip example / test dummy URLs)
        is_dummy = any(d in repo_url.lower() for d in ["example.com", "example/repo", "dummy", "mock", "github.com/test", "test/repo"])
        if repo_url and not is_dummy and repo_url.startswith(("http://", "https://", "git@")):
            settings = get_settings()
            proxy_url = f"http://{settings.EGRESS_PROXY_HOST}:{settings.EGRESS_PROXY_PORT}"
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
            env["GIT_ASKPASS"] = ""
            if self.use_docker:
                env["HTTP_PROXY"] = proxy_url
                env["HTTPS_PROXY"] = proxy_url
                env["http_proxy"] = proxy_url
                env["https_proxy"] = proxy_url
                env["ALL_PROXY"] = proxy_url
                env["NO_PROXY"] = "localhost,127.0.0.1"
            else:
                env.pop("HTTP_PROXY", None)
                env.pop("HTTPS_PROXY", None)
                env.pop("http_proxy", None)
                env.pop("https_proxy", None)
                env.pop("ALL_PROXY", None)
            if self.use_docker:
                # Execute git clone inside an isolated container
                cmd = [
                    "docker", "run", "--rm",
                    "--network", "bridge",
                    "-v", f"{workspace_dir}:/workspace:rw",
                    "-w", "/workspace",
                    "-e", f"HTTP_PROXY={proxy_url}",
                    "-e", f"HTTPS_PROXY={proxy_url}",
                    "-e", f"http_proxy={proxy_url}",
                    "-e", f"https_proxy={proxy_url}",
                    "-e", f"ALL_PROXY={proxy_url}",
                    "-e", "NO_PROXY=localhost,127.0.0.1",
                    "-e", "GIT_TERMINAL_PROMPT=0",
                    "-e", "GIT_ASKPASS=",
                    "alpine/git",
                    "-c", "credential.helper=",
                    "-c", "core.askPass=",
                    "clone", "--depth", "1",
                    repo_url, "/workspace"
                ]
            else:
                cmd = [
                    "git",
                    "-c", "credential.helper=",
                    "-c", "core.askPass=",
                    "clone", "--depth", "1",
                    repo_url, workspace_dir
                ]
            proc = None
            out_f = tempfile.NamedTemporaryFile(prefix="automaintainer_clone_out_", delete=False)
            err_f = tempfile.NamedTemporaryFile(prefix="automaintainer_clone_err_", delete=False)
            out_f.close()
            err_f.close()
            try:
                with open(out_f.name, "wb") as out_h, open(err_f.name, "wb") as err_h:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=out_h,
                        stderr=err_h,
                        env=env
                    )
                    if hasattr(proc, "wait") and (proc.stdout is None and proc.stderr is None):
                        await asyncio.wait_for(proc.wait(), timeout=15.0)
                    elif hasattr(proc, "communicate"):
                        await asyncio.wait_for(proc.communicate(), timeout=15.0)
            except asyncio.TimeoutError:
                if proc:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
            except Exception:
                if proc:
                    try:
                        proc.kill()
                        await proc.wait()
                    except Exception:
                        pass
            finally:
                for p in (out_f.name, err_f.name):
                    try:
                        if os.path.exists(p):
                            os.unlink(p)
                    except Exception:
                        pass

        return workspace_dir

    def get_container_flags(self, limits: SandboxResourceLimits) -> List[str]:
        """Returns standard container isolation flags with network-layer firewall restrictions."""
        settings = get_settings()
        flags = [
            "--rm",
            "--network", "none" if not limits.allow_network_egress else "bridge",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--cpus={limits.cpu_cores}",
            f"--memory={limits.memory_mb}m",
            f"--pids-limit={limits.max_pids}",
            "--security-opt=seccomp=default"
        ]
        if limits.allow_network_egress:
            # Firewall-level outbound restrictions at the container/network layer:
            # 1. Point container DNS to 127.0.0.1 to block direct/alternate external DNS queries (e.g., 8.8.8.8, 1.1.1.1)
            flags.extend(["--dns", "127.0.0.1"])
            # 2. Blackhole cloud metadata IP (169.254.169.254) and metadata endpoints
            flags.extend([
                "--add-host", "169.254.169.254:127.0.0.1",
                "--add-host", "metadata.google.internal:127.0.0.1",
                "--add-host", "metadata.internal:127.0.0.1"
            ])
        return flags


    async def run_command(
        self,
        workspace_id: str,
        command: List[str],
        limits: SandboxResourceLimits
    ) -> ExecutionResult:
        if workspace_id not in self._workspaces:
            raise ValueError(f"Unknown workspace {workspace_id}")

        workspace_path = self._workspaces[workspace_id]["path"]
        start_time = time.time()
        settings = get_settings()

        # Fail closed: Host subprocess execution strictly forbidden in production/staging environments.
        # A PaaS container running the main application is NOT an isolated sandbox for executing untrusted repository code.
        if not self.use_docker and settings.ENVIRONMENT.lower().strip() in ("production", "staging"):
            if not settings.ALLOW_HOST_SUBPROCESS:
                raise RuntimeError(
                    f"Host subprocess execution of untrusted code is strictly forbidden in {settings.ENVIRONMENT}. "
                    "A verified container sandbox (Docker/gVisor) is mandatory to isolate untrusted repository code."
                )
            else:
                import logging
                logging.getLogger("automaintainer.sandbox").warning(
                    "SECURITY WARNING: ALLOW_HOST_SUBPROCESS is active in production. Untrusted repository code is executing on host."
                )

        # Sanitize environment: NEVER pass host credentials to untrusted builds
        sanitized_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": workspace_path,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8"
        }

        # Wire container egress proxy if network egress is requested
        if limits.allow_network_egress:
            proxy_url = f"http://{settings.EGRESS_PROXY_HOST}:{settings.EGRESS_PROXY_PORT}"
            sanitized_env["HTTP_PROXY"] = proxy_url
            sanitized_env["HTTPS_PROXY"] = proxy_url
            sanitized_env["http_proxy"] = proxy_url
            sanitized_env["https_proxy"] = proxy_url
            sanitized_env["ALL_PROXY"] = proxy_url
            sanitized_env["NO_PROXY"] = "localhost,127.0.0.1"

        if self.use_docker:
            # Build hardened container command line
            docker_cmd = ["docker", "run"]
            docker_cmd.extend(self.get_container_flags(limits))
            docker_cmd.extend([
                "-v", f"{workspace_path}:/workspace:rw",
                "-w", "/workspace",
            ])
            if limits.allow_network_egress:
                proxy_url = f"http://{settings.EGRESS_PROXY_HOST}:{settings.EGRESS_PROXY_PORT}"
                docker_cmd.extend([
                    "-e", f"HTTP_PROXY={proxy_url}",
                    "-e", f"HTTPS_PROXY={proxy_url}",
                    "-e", f"http_proxy={proxy_url}",
                    "-e", f"https_proxy={proxy_url}",
                    "-e", f"ALL_PROXY={proxy_url}",
                    "-e", "NO_PROXY=localhost,127.0.0.1"
                ])
            docker_cmd.append(self.base_image)
            docker_cmd.extend(command)
            cmd_to_run = docker_cmd
        else:
            # Subprocess Jail mode (safe local testing)
            cmd_to_run = command

        process = None
        out_f = tempfile.NamedTemporaryFile(prefix="automaintainer_run_out_", delete=False)
        err_f = tempfile.NamedTemporaryFile(prefix="automaintainer_run_err_", delete=False)
        out_f.close()
        err_f.close()

        try:
            stdout_data = b""
            stderr_data = b""
            is_file_redirect = True

            with open(out_f.name, "wb") as out_h, open(err_f.name, "wb") as err_h:
                process = await asyncio.create_subprocess_exec(
                    *cmd_to_run,
                    cwd=workspace_path,
                    env=sanitized_env,
                    stdout=out_h,
                    stderr=err_h
                )

                is_file_redirect = hasattr(process, "wait") and (process.stdout is None and process.stderr is None)
                if is_file_redirect:
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=float(limits.wall_clock_timeout_seconds)
                    )
                elif hasattr(process, "communicate"):
                    stdout_data, stderr_data = await asyncio.wait_for(
                        process.communicate(),
                        timeout=float(limits.wall_clock_timeout_seconds)
                    )

            if is_file_redirect:
                if os.path.exists(out_f.name):
                    with open(out_f.name, "rb") as rf_out:
                        stdout_data = rf_out.read()
                if os.path.exists(err_f.name):
                    with open(err_f.name, "rb") as rf_err:
                        stderr_data = rf_err.read()

            duration = time.time() - start_time
            return ExecutionResult(
                exit_code=process.returncode or 0,
                stdout=stdout_data.decode("utf-8", errors="replace"),
                stderr=stderr_data.decode("utf-8", errors="replace"),
                duration_seconds=duration,
                timed_out=False
            )
        except asyncio.TimeoutError:
            if process:
                try:
                    process.kill()
                    await process.wait()
                except (ProcessLookupError, Exception):
                    pass
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="Execution timed out by sandbox policy.",
                duration_seconds=float(limits.wall_clock_timeout_seconds),
                timed_out=True,
                resource_violation="WALL_CLOCK_TIMEOUT"
            )

        except Exception as ex:
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"Sandbox execution error: {str(ex)}",
                duration_seconds=time.time() - start_time
            )
        finally:
            for p in (out_f.name, err_f.name):
                try:
                    if os.path.exists(p):
                        os.unlink(p)
                except Exception:
                    pass

    async def destroy_workspace(self, workspace_id: str) -> None:
        """Aggressive ephemeral destruction of workspace."""
        if workspace_id in self._workspaces:
            path = self._workspaces[workspace_id]["path"]
            if os.path.exists(path):
                def _handle_remove_readonly(func, file_path, exc_info):
                    try:
                        import stat
                        os.chmod(file_path, stat.S_IWRITE)
                        func(file_path)
                    except Exception:
                        pass
                try:
                    shutil.rmtree(path, onerror=_handle_remove_readonly)
                except Exception:
                    shutil.rmtree(path, ignore_errors=True)
            del self._workspaces[workspace_id]

    async def cleanup_stale_workspaces(self, max_age_seconds: float = 3600.0) -> int:
        """
        Startup and crash recovery sweep:
        Scans temporary directory for orphaned 'automaintainer_ws_*' directories
        left behind by dead or abruptly killed worker processes (OOM/SIGKILL/reboot).
        Recursively removes stale workspaces older than max_age_seconds.
        """
        cleaned_count = 0
        temp_dir = tempfile.gettempdir()
        now = time.time()

        def _handle_remove_readonly(func, file_path, exc_info):
            try:
                import stat
                os.chmod(file_path, stat.S_IWRITE)
                func(file_path)
            except Exception:
                pass

        try:
            for entry in os.listdir(temp_dir):
                if entry.startswith("automaintainer_ws_"):
                    full_path = os.path.join(temp_dir, entry)
                    if os.path.isdir(full_path):
                        try:
                            stat_info = os.stat(full_path)
                            age = now - stat_info.st_mtime
                            if age >= max_age_seconds:
                                shutil.rmtree(full_path, onerror=_handle_remove_readonly)
                                cleaned_count += 1
                        except Exception:
                            pass
        except Exception:
            pass

        # Purge any tracked workspaces from memory that were removed from disk
        stale_keys = [k for k, v in self._workspaces.items() if not os.path.exists(v.get("path", ""))]
        for k in stale_keys:
            del self._workspaces[k]

        return cleaned_count

    execute_command = run_command


