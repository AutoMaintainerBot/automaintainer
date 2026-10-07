from typing import List, Dict, Any, Optional
from automaintainer.core.models import RiskTier

class LockfileOpportunity:
    def __init__(self, task_type: str, lockfile_path: str, manifest_path: str, regenerate_cmd: str, summary: str):
        self.task_type = task_type
        self.lockfile_path = lockfile_path
        self.manifest_path = manifest_path
        self.regenerate_cmd = regenerate_cmd
        self.summary = summary
        self.risk_tier = RiskTier.R2
        self.confidence = 0.95

class LockfileRefreshDetector:
    """
    Generated File / Lockfile Refresh Detector:
    Detects out-of-sync or missing lockfiles (poetry.lock, package-lock.json, Cargo.lock)
    and prepares safe regeneration using deterministic package manager commands.
    """

    SUPPORTED_ECOSYSTEMS = [
        {
            "manifest": "pyproject.toml",
            "lockfile": "poetry.lock",
            "cmd": "poetry lock --no-update",
            "summary": "Refresh poetry.lock to synchronize with pyproject.toml"
        },
        {
            "manifest": "package.json",
            "lockfile": "package-lock.json",
            "cmd": "npm install --package-lock-only",
            "summary": "Refresh package-lock.json to synchronize with package.json"
        },
        {
            "manifest": "Cargo.toml",
            "lockfile": "Cargo.lock",
            "cmd": "cargo generate-lockfile",
            "summary": "Refresh Cargo.lock to synchronize with Cargo.toml"
        }
    ]

    IGNORED_DIRS = {
        "node_modules", ".git", "venv", ".venv", "env",
        "target", "dist", "build", ".tox", ".pytest_cache", "__pycache__"
    }

    @classmethod
    def detect_lockfile_opportunities(cls, repo_files: List[str]) -> List[LockfileOpportunity]:
        """
        Detects missing or stale lockfiles across root projects and nested monorepo packages.
        Supports:
        - Root files (e.g. pyproject.toml -> poetry.lock)
        - Monorepo subdirectories (e.g. packages/frontend/package.json -> packages/frontend/package-lock.json)
        """
        opportunities = []
        normalized_files = set()
        for f in repo_files:
            norm = f.replace("\\", "/").lstrip("/")
            normalized_files.add(norm)

        for file_path in sorted(list(normalized_files)):
            parts = file_path.split("/")
            # Skip ignored directories
            if any(p in cls.IGNORED_DIRS for p in parts[:-1]):
                continue

            basename = parts[-1]
            dir_prefix = "/".join(parts[:-1]) if len(parts) > 1 else ""

            for eco in cls.SUPPORTED_ECOSYSTEMS:
                if basename == eco["manifest"]:
                    lock_name = eco["lockfile"]
                    lock_path = f"{dir_prefix}/{lock_name}" if dir_prefix else lock_name

                    if dir_prefix:
                        if "npm" in eco["cmd"]:
                            cmd = f"npm --prefix {dir_prefix} install --package-lock-only"
                        elif "poetry" in eco["cmd"]:
                            cmd = f"cd {dir_prefix} && poetry lock --no-update"
                        elif "cargo" in eco["cmd"]:
                            cmd = f"cargo generate-lockfile --manifest-path {file_path}"
                        else:
                            cmd = f"cd {dir_prefix} && {eco['cmd']}"
                        summary = f"Refresh {lock_path} to synchronize with {file_path}"
                    else:
                        cmd = eco["cmd"]
                        summary = eco["summary"]

                    opportunities.append(
                        LockfileOpportunity(
                            task_type="lockfile_refresh",
                            lockfile_path=lock_path,
                            manifest_path=file_path,
                            regenerate_cmd=cmd,
                            summary=summary,
                        )
                    )

        return opportunities

