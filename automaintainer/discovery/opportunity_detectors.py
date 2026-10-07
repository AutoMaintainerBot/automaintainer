"""
Maintenance opportunity detectors.
All detectors are PURELY STATIC: no code execution, only GitHub API reads.
Simple / deterministic tasks NEVER call Groq — only the planner escalates complex ones.
"""
from __future__ import annotations

import base64
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import httpx

from automaintainer.core.models import TaskType, RiskTier


@dataclass
class DetectedOpportunity:
    task_type: TaskType
    evidence: List[str]                       # Human-readable evidence list
    target_paths: List[str]                   # Files that will change
    risk_tier: RiskTier
    confidence: float                         # 0.0 – 1.0
    validation_recipe: List[str]              # Commands to run after fix
    summary: str                              # One-line human description
    metadata: Dict = field(default_factory=dict)   # Detector-specific payload


def make_github_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token and str(token).strip():
        headers["Authorization"] = f"Bearer {str(token).strip()}"
    return headers


class BaseDetector(ABC):
    """Stateless, idempotent detector contract."""

    @abstractmethod
    async def detect(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[DetectedOpportunity]:
        ...


# Detector 1: Outdated GitHub Actions references

# Latest stable MAJOR versions for the most commonly used public actions
KNOWN_LATEST_ACTIONS: Dict[str, str] = {
    "actions/checkout":               "v4",
    "actions/setup-python":           "v5",
    "actions/setup-node":             "v4",
    "actions/setup-java":             "v4",
    "actions/setup-go":               "v5",
    "actions/setup-dotnet":           "v4",
    "actions/upload-artifact":        "v4",
    "actions/download-artifact":      "v4",
    "actions/cache":                  "v4",
    "actions/github-script":          "v7",
    "actions/labeler":                "v5",
    "actions/stale":                  "v9",
    "actions/dependency-review-action": "v4",
    "codecov/codecov-action":         "v4",
    "docker/build-push-action":       "v6",
    "docker/login-action":            "v3",
    "docker/setup-buildx-action":     "v3",
    "docker/metadata-action":         "v5",
    "softprops/action-gh-release":    "v2",
    "peter-evans/create-pull-request":"v7",
    "EndBug/add-and-commit":          "v9",
    "crazy-max/ghaction-docker-meta": "v5",
}

_USES_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)@(v[\d]+(?:[.\-][\d]+)*|[a-f0-9]{40}|\w+)",
    re.MULTILINE,
)


def _major(version_str: str) -> Optional[int]:
    m = re.match(r"v(\d+)", version_str)
    return int(m.group(1)) if m else None


class GitHubActionsVersionDetector(BaseDetector):
    """
    Deterministic: version comparison is purely mechanical — no Groq call needed.
    Scans .github/workflows/*.yml for outdated `uses:` action references.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: str) -> Dict[str, str]:
        return make_github_headers(token)

    async def detect(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[DetectedOpportunity]:
        opportunities: List[DetectedOpportunity] = []

        async def _check(c: httpx.AsyncClient) -> None:
            wf_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/contents/.github/workflows",
                headers=self._headers(token), timeout=10.0,
            )
            if wf_resp.status_code != 200:
                return

            wf_files = [
                f for f in wf_resp.json()
                if isinstance(f, dict) and f.get("type") == "file"
                and f["name"].endswith((".yml", ".yaml"))
            ]

            for wf_file in wf_files:
                file_path = wf_file["path"]
                dl_resp = await c.get(wf_file["download_url"], timeout=10.0)
                if dl_resp.status_code != 200:
                    continue
                content = dl_resp.text

                outdated = []
                for match in _USES_RE.finditer(content):
                    action_name = match.group(1)
                    current_ver = match.group(2)
                    latest = KNOWN_LATEST_ACTIONS.get(action_name)
                    if not latest:
                        continue
                    cur_major = _major(current_ver)
                    lat_major = _major(latest)
                    if cur_major is not None and lat_major is not None and cur_major < lat_major:
                        outdated.append({
                            "action": action_name,
                            "current": current_ver,
                            "latest": latest,
                        })

                if outdated:
                    evidence = [f"{o['action']}@{o['current']} → {o['latest']}" for o in outdated]
                    opportunities.append(DetectedOpportunity(
                        task_type=TaskType.GITHUB_ACTION_UPDATE,
                        evidence=evidence,
                        target_paths=[file_path],
                        risk_tier=RiskTier.R1,
                        confidence=0.95,
                        validation_recipe=["yamllint .github/workflows/"],
                        summary=f"{len(outdated)} outdated GitHub Action(s) in {wf_file['name']}",
                        metadata={"workflow_file": file_path, "outdated_actions": outdated},
                    ))

        if client:
            await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                await _check(c)
        return opportunities


# Detector 2: Broken internal documentation links

_MD_LINK_RE  = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_ANCHOR_RE   = re.compile(r"^#")
_HTTP_RE     = re.compile(r"^https?://")
_MAILTO_RE   = re.compile(r"^mailto:")


class BrokenDocLinkDetector(BaseDetector):
    """
    Deterministic: checks relative path resolution against the repo tree.
    Only internal (relative) links — no external HTTP calls.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: str) -> Dict[str, str]:
        return make_github_headers(token)

    async def detect(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[DetectedOpportunity]:
        opportunities: List[DetectedOpportunity] = []

        async def _check(c: httpx.AsyncClient) -> None:
            # Get full recursive tree (capped by GitHub at 100k nodes, truncated flag if larger)
            tree_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
                headers=self._headers(token), timeout=15.0,
            )
            if tree_resp.status_code != 200:
                return
            all_paths = {
                item["path"]
                for item in tree_resp.json().get("tree", [])
                if item.get("type") == "blob"
            }
            md_files = [p for p in all_paths if p.lower().endswith((".md", ".mdx", ".rst"))]

            for md_path in md_files[:25]:  # cap to 25 docs files per scan
                cr = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/contents/{md_path}",
                    headers=self._headers(token), timeout=10.0,
                )
                if cr.status_code != 200:
                    continue
                raw = cr.json().get("content", "")
                text = base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="replace")

                broken = []
                md_dir = "/".join(md_path.split("/")[:-1])

                for link_text, link_url in _MD_LINK_RE.findall(text):
                    if _ANCHOR_RE.match(link_url) or _HTTP_RE.match(link_url) or _MAILTO_RE.match(link_url):
                        continue
                    url_path = link_url.split("#")[0].strip()
                    if not url_path:
                        continue
                    resolved = f"{md_dir}/{url_path}".lstrip("/") if md_dir else url_path.lstrip("/")
                    resolved = re.sub(r"^\./", "", resolved)
                    if resolved not in all_paths:
                        broken.append({"text": link_text, "url": link_url, "resolved": resolved})

                if broken:
                    evidence = [
                        f"[{b['text']}]({b['url']}) → '{b['resolved']}' not found"
                        for b in broken
                    ]
                    resolved_paths = [b["resolved"] for b in broken if b.get("resolved")]
                    opportunities.append(DetectedOpportunity(
                        task_type=TaskType.DOCS_LINK_FIX,
                        evidence=evidence,
                        target_paths=resolved_paths if resolved_paths else [md_path],
                        risk_tier=RiskTier.R1,
                        confidence=0.88,
                        validation_recipe=["Verify target paths exist after fix"],
                        summary=f"{len(broken)} broken internal link(s) in {md_path}",
                        metadata={"markdown_file": md_path, "broken_links": broken},
                    ))

        if client:
            await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                await _check(c)
        return opportunities


# Detector 3: Python package metadata issues

class PackageMetadataDetector(BaseDetector):
    """
    Deterministic: parses pyproject.toml text for missing/malformed fields.
    No Groq call needed.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: str) -> Dict[str, str]:
        return make_github_headers(token)

    async def detect(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[DetectedOpportunity]:
        opportunities: List[DetectedOpportunity] = []

        async def _check(c: httpx.AsyncClient) -> None:
            manifest_paths = ["pyproject.toml"]
            try:
                tree_resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
                    headers=self._headers(token),
                    timeout=10.0,
                )
                if tree_resp.status_code == 200 and "tree" in tree_resp.json():
                    discovered = [
                        item.get("path", "")
                        for item in tree_resp.json().get("tree", [])
                        if item.get("type") == "blob"
                        and item.get("path", "").endswith("pyproject.toml")
                        and not any(ig in item.get("path", "") for ig in ("venv", ".git", "node_modules", ".tox", "dist", "build"))
                    ]
                    if discovered:
                        manifest_paths = discovered
            except Exception:
                pass

            for manifest_path in manifest_paths:
                resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/contents/{manifest_path}",
                    headers=self._headers(token), timeout=10.0,
                )
                if resp.status_code != 200:
                    continue
                raw = resp.json().get("content", "")
                content = base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="replace")

                issues = []
                if "[project]" in content:
                    if "license" not in content.lower():
                        issues.append("Missing license field in [project] section")
                    if "description" not in content:
                        issues.append("Missing description field in [project] section")
                    if "requires-python" not in content:
                        issues.append("Missing requires-python constraint")
                    if re.search(r'version\s*=\s*"0\.0\.0"', content):
                        issues.append("Version is placeholder '0.0.0'")
                    if "readme" not in content.lower():
                        issues.append("Missing readme field in [project] section")

                if issues:
                    dir_prefix = "/".join(manifest_path.split("/")[:-1])
                    val_recipe = [f"cd {dir_prefix} && python -m build --no-isolation --sdist 2>&1 | head -20"] if dir_prefix else ["python -m build --no-isolation --sdist 2>&1 | head -20"]
                    opportunities.append(DetectedOpportunity(
                        task_type=TaskType.PACKAGE_METADATA,
                        evidence=issues,
                        target_paths=[manifest_path],
                        risk_tier=RiskTier.R1,
                        confidence=0.85,
                        validation_recipe=val_recipe,
                        summary=f"{len(issues)} package metadata issue(s) in {manifest_path}",
                        metadata={"issues": issues, "manifest_path": manifest_path},
                    ))

        if client:
            await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                await _check(c)
        return opportunities


# Detector 4: Dependency manifest issues

_REQ_LINE_RE = re.compile(r"^([a-zA-Z0-9_\-]+)\s*(?:[><=!~].*)?\s*$")


class DependencyMetadataDetector(BaseDetector):
    """
    Deterministic: detects duplicate entries in requirements.txt.
    For complex version-range analysis, escalation to Groq is handled by the Planner.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: str) -> Dict[str, str]:
        return make_github_headers(token)

    async def detect(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[DetectedOpportunity]:
        opportunities: List[DetectedOpportunity] = []

        async def _check(c: httpx.AsyncClient) -> None:
            req_paths = ["requirements.txt"]
            try:
                tree_resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
                    headers=self._headers(token),
                    timeout=10.0,
                )
                if tree_resp.status_code == 200 and "tree" in tree_resp.json():
                    discovered = [
                        item.get("path", "")
                        for item in tree_resp.json().get("tree", [])
                        if item.get("type") == "blob"
                        and item.get("path", "").endswith("requirements.txt")
                        and not any(ig in item.get("path", "") for ig in ("venv", ".git", "node_modules", ".tox"))
                    ]
                    if discovered:
                        req_paths = discovered
            except Exception:
                pass

            for req_path in req_paths:
                resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/contents/{req_path}",
                    headers=self._headers(token), timeout=10.0,
                )
                if resp.status_code != 200:
                    continue
                raw = resp.json().get("content", "")
                content = base64.b64decode(raw.replace("\n", "")).decode("utf-8", errors="replace")

                seen: Dict[str, int] = {}
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith(("#", "-r ", "-c ")):
                        continue
                    m = _REQ_LINE_RE.match(line)
                    if m:
                        pkg = m.group(1).lower().replace("-", "_")
                        seen[pkg] = seen.get(pkg, 0) + 1

                duplicates = [pkg for pkg, count in seen.items() if count > 1]
                if duplicates:
                    opportunities.append(DetectedOpportunity(
                        task_type=TaskType.DEPENDENCY_UPDATE,
                        evidence=[f"Duplicate entry: '{p}'" for p in duplicates],
                        target_paths=[req_path],
                        risk_tier=RiskTier.R2,
                        confidence=0.88,
                        validation_recipe=[f"pip install -r {req_path} --dry-run"],
                        summary=f"Duplicate dependencies in {req_path}: {', '.join(duplicates)}",
                        metadata={"duplicates": duplicates, "path": req_path},
                    ))

        if client:
            await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                await _check(c)
        return opportunities


# Lockfile Refresh Detector

from automaintainer.discovery.lockfile_detector import LockfileRefreshDetector


class LockfileOpportunityDetector(BaseDetector):
    """
    Generated File / Lockfile Refresh Detector:
    Detects out-of-sync or missing lockfiles (poetry.lock, package-lock.json, Cargo.lock)
    across root and nested monorepo packages.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: str) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def detect(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[DetectedOpportunity]:
        opportunities: List[DetectedOpportunity] = []

        async def _check(c: httpx.AsyncClient) -> None:
            repo_files = []
            try:
                tree_resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/git/trees/HEAD?recursive=1",
                    headers=self._headers(token),
                    timeout=10.0,
                )
                if tree_resp.status_code == 200 and "tree" in tree_resp.json():
                    repo_files = [
                        item.get("path", "")
                        for item in tree_resp.json().get("tree", [])
                        if item.get("type") == "blob"
                    ]
            except Exception:
                pass

            if not repo_files:
                resp = await c.get(
                    f"{self.api_base_url}/repos/{owner}/{repo}/contents",
                    headers=self._headers(token),
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    items = resp.json()
                    if isinstance(items, list):
                        repo_files = [item.get("name", "") for item in items if isinstance(item, dict)]

            if not repo_files:
                return

            lockfile_opps = LockfileRefreshDetector.detect_lockfile_opportunities(repo_files)

            for opp in lockfile_opps:
                opportunities.append(
                    DetectedOpportunity(
                        task_type=TaskType.DEPENDENCY_UPDATE,
                        evidence=[f"Manifest '{opp.manifest_path}' detected without fresh lockfile '{opp.lockfile_path}'"],
                        target_paths=[opp.lockfile_path],
                        risk_tier=opp.risk_tier,
                        confidence=opp.confidence,
                        validation_recipe=[opp.regenerate_cmd],
                        summary=opp.summary,
                        metadata={
                            "manifest": opp.manifest_path,
                            "lockfile": opp.lockfile_path,
                            "regenerate_cmd": opp.regenerate_cmd,
                        },
                    )
                )

        if client:
            await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                await _check(c)
        return opportunities

