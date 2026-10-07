"""
Repository Fingerprinter.
Reads GitHub API tree metadata, manifests, and CI config to build a compact RepoFingerprint
WITHOUT cloning or executing any repository code.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import httpx


@dataclass
class RepoFingerprint:
    commit_sha: str = ""
    default_branch: str = "main"
    language_stack: List[str] = field(default_factory=list)
    package_managers: List[str] = field(default_factory=list)
    build_systems: List[str] = field(default_factory=list)
    test_commands: List[str] = field(default_factory=list)
    lint_commands: List[str] = field(default_factory=list)
    ci_workflows: List[str] = field(default_factory=list)
    has_makefile: bool = False
    risk_flags: List[str] = field(default_factory=list)   # auth | crypto | deploy | secrets

    def to_dict(self) -> Dict:
        return {
            "commit_sha": self.commit_sha,
            "default_branch": self.default_branch,
            "language_stack": self.language_stack,
            "package_managers": self.package_managers,
            "build_systems": self.build_systems,
            "test_commands": self.test_commands,
            "lint_commands": self.lint_commands,
            "ci_workflows": self.ci_workflows,
            "has_makefile": self.has_makefile,
            "risk_flags": self.risk_flags,
        }


# filename → language / package_manager signals
_MANIFEST_SIGNALS: Dict[str, Dict[str, str]] = {
    "pyproject.toml":     {"lang": "python",     "pm": "pip/uv/poetry"},
    "setup.py":           {"lang": "python",     "pm": "pip"},
    "setup.cfg":          {"lang": "python",     "pm": "pip"},
    "requirements.txt":   {"lang": "python",     "pm": "pip"},
    "package.json":       {"lang": "javascript", "pm": "npm"},
    "pnpm-lock.yaml":     {"lang": "javascript", "pm": "pnpm"},
    "yarn.lock":          {"lang": "javascript", "pm": "yarn"},
    "Cargo.toml":         {"lang": "rust",       "pm": "cargo"},
    "go.mod":             {"lang": "go",         "pm": "go modules"},
    "pom.xml":            {"lang": "java",       "pm": "maven"},
    "build.gradle":       {"lang": "java",       "pm": "gradle"},
    "build.gradle.kts":   {"lang": "kotlin",     "pm": "gradle"},
    "CMakeLists.txt":     {"lang": "c/c++",      "pm": "cmake"},
    "Makefile":           {"lang": "make",       "pm": "make"},
    "composer.json":      {"lang": "php",        "pm": "composer"},
    "Gemfile":            {"lang": "ruby",       "pm": "bundler"},
    "mix.exs":            {"lang": "elixir",     "pm": "mix"},
}

_RISK_PATH_PATTERNS = [
    (re.compile(r"auth", re.IGNORECASE),                                   "auth"),
    (re.compile(r"crypto|cipher|encrypt|decrypt|hmac|jwt", re.IGNORECASE), "crypto"),
    (re.compile(r"deploy|infra|terraform|pulumi|k8s|kubernetes", re.IGNORECASE), "deploy"),
    (re.compile(r"secret|credential|password|token", re.IGNORECASE),       "secrets"),
]


class RepositoryFingerprinter:
    """
    Builds a compact `RepoFingerprint` from GitHub API metadata only.
    No clone, no code execution. Stores result in `RepositoryRecord.fingerprint_json`.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: str) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def _read_file_content(
        self,
        c: httpx.AsyncClient,
        owner: str,
        repo: str,
        token: str,
        path: str,
    ) -> Optional[str]:
        resp = await c.get(
            f"{self.api_base_url}/repos/{owner}/{repo}/contents/{path}",
            headers=self._headers(token), timeout=10.0,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        raw = data.get("content", "")
        encoding = data.get("encoding", "base64")
        if encoding == "base64":
            return base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="replace")
        return raw

    async def build(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> RepoFingerprint:
        fp = RepoFingerprint()

        async def _build(c: httpx.AsyncClient) -> RepoFingerprint:
            headers = self._headers(token)

            repo_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}",
                headers=headers, timeout=10.0,
            )
            if repo_resp.status_code != 200:
                return fp
            repo_data = repo_resp.json()
            fp.default_branch = repo_data.get("default_branch", "main")

            ref_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/git/ref/heads/{fp.default_branch}",
                headers=headers, timeout=10.0,
            )
            if ref_resp.status_code == 200:
                fp.commit_sha = ref_resp.json().get("object", {}).get("sha", "")

            tree_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/{fp.default_branch}",
                headers=headers, timeout=10.0,
            )
            if tree_resp.status_code != 200:
                return fp

            root_items = tree_resp.json().get("tree", [])
            root_file_names = {item["path"] for item in root_items if item.get("type") == "blob"}

            langs_seen: set = set()
            pms_seen: set = set()
            for filename, signals in _MANIFEST_SIGNALS.items():
                if filename in root_file_names:
                    lang = signals["lang"]
                    pm = signals["pm"]
                    if lang not in langs_seen:
                        fp.language_stack.append(lang)
                        langs_seen.add(lang)
                    if pm not in pms_seen:
                        fp.package_managers.append(pm)
                        pms_seen.add(pm)
                    if filename == "Makefile":
                        fp.has_makefile = True
                        fp.build_systems.append("make")

            if any(item["path"] == ".github" for item in root_items):
                wf_resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/contents/.github/workflows",
                    headers=headers, timeout=10.0,
                )
                if wf_resp.status_code == 200:
                    fp.ci_workflows = [
                        f["name"] for f in wf_resp.json()
                        if isinstance(f, dict) and f.get("type") == "file"
                    ]

            if "pyproject.toml" in root_file_names:
                content = await self._read_file_content(c, owner, repo, token, "pyproject.toml")
                if content:
                    if "[tool.pytest" in content:
                        fp.test_commands.append("pytest")
                    if "unittest" in content:
                        fp.test_commands.append("python -m unittest")
                    if "ruff" in content:
                        fp.lint_commands.append("ruff check .")
                    if "black" in content:
                        fp.lint_commands.append("black --check .")
                    if "mypy" in content:
                        fp.lint_commands.append("mypy .")
                    if "flake8" in content:
                        fp.lint_commands.append("flake8 .")

            if "package.json" in root_file_names:
                content = await self._read_file_content(c, owner, repo, token, "package.json")
                if content and '"test"' in content:
                    fp.test_commands.append("npm test")
                if content and '"lint"' in content:
                    fp.lint_commands.append("npm run lint")

            all_names = " ".join(root_file_names).lower()
            flags_seen: set = set()
            for pattern, flag in _RISK_PATH_PATTERNS:
                if pattern.search(all_names) and flag not in flags_seen:
                    fp.risk_flags.append(flag)
                    flags_seen.add(flag)

            return fp

        if client:
            return await _build(client)
        async with httpx.AsyncClient() as c:
            return await _build(c)
