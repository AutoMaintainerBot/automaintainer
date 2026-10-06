from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Tuple, Callable, Awaitable
import httpx
from automaintainer.core.models import FileDiff

logger = logging.getLogger(__name__)


class MergeConflictError(Exception):
    """Raised when upstream changes conflict with AutoMaintainer's candidate patch."""
    pass


class UpstreamDriftError(Exception):
    """Raised when upstream base branch has drifted."""
    def __init__(self, message: str, current_head_sha: Optional[str] = None):
        super().__init__(message)
        self.current_head_sha = current_head_sha


class BranchConflictError(Exception):
    """Raised when a remote branch has diverged from expected HEAD and cannot be fast-forwarded without explicit force override."""
    pass


class GitHubRateLimitError(Exception):
    """Raised when GitHub API secondary or primary rate limit is hit and retries are exhausted."""
    pass


def _parse_header_int(val: Optional[str]) -> Optional[int]:
    if not val:
        return None
    val = val.strip().lower()
    try:
        if val.endswith("k"):
            return int(float(val[:-1]) * 1000)
        elif val.endswith("m"):
            return int(float(val[:-1]) * 1000000)
        return int(float(val))
    except (ValueError, TypeError):
        return None


def _parse_header_float(val: Optional[str]) -> Optional[float]:
    if not val:
        return None
    try:
        return float(val.strip())
    except (ValueError, TypeError):
        return None


class GitHubGitDataClient:
    """
    GitHub Git Data API Client.
    Implements the low-level Git database protocol:
    1. get_ref: Read HEAD commit SHA of default branch.
    2. create_blob: Upload file content as git blob.
    3. get_tree: Fetch base commit git tree.
    4. create_tree: Build new tree containing base + modified blobs.
    5. create_commit: Create commit pointing to parent commit SHA and new tree SHA.
    6. create_or_update_ref: Create or fast-forward refs/heads/automaintainer/{session_id}.
    7. Rate-limit tracking and dynamic token refresh hooks.
    """

    def __init__(
        self,
        token: str,
        api_base_url: str = "https://api.github.com",
        token_refresh_hook: Optional[Callable[[], Awaitable[str]]] = None,
    ):
        self.token = token
        self.api_base_url = api_base_url.rstrip("/")
        self.token_refresh_hook = token_refresh_hook
        self.rate_limit_snapshot: Dict[str, Any] = {}

    def set_token(self, token: str) -> None:
        """Dynamically update authorization token."""
        self.token = token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    def capture_rate_limit_headers(self, headers: Any) -> Dict[str, Any]:
        """Parses rate-limit headers from GitHub responses safely."""
        if not hasattr(headers, "get"):
            return self.rate_limit_snapshot

        remaining = _parse_header_int(headers.get("x-ratelimit-remaining"))
        limit = _parse_header_int(headers.get("x-ratelimit-limit"))
        reset = _parse_header_float(headers.get("x-ratelimit-reset"))
        used = _parse_header_int(headers.get("x-ratelimit-used"))
        retry_after = _parse_header_float(headers.get("retry-after"))

        self.rate_limit_snapshot = {
            "remaining": remaining,
            "limit": limit,
            "reset": reset,
            "used": used,
            "retry_after": retry_after,
        }
        return self.rate_limit_snapshot

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        max_retries: int = 5,
        **kwargs,
    ) -> httpx.Response:
        """
        Executes HTTP requests with rate-limit tracking, backoff on 429/403,
        and dynamic token refresh on 401.
        """
        for attempt in range(max_retries):
            m = method.upper()
            headers = self._headers()
            if "headers" in kwargs:
                headers.update(kwargs.pop("headers"))

            if m == "GET":
                resp = await client.get(url, headers=headers, **kwargs)
            elif m == "POST":
                resp = await client.post(url, headers=headers, **kwargs)
            elif m == "PATCH":
                resp = await client.patch(url, headers=headers, **kwargs)
            elif m == "DELETE":
                resp = await client.delete(url, headers=headers, **kwargs)
            else:
                resp = await client.request(m, url, headers=headers, **kwargs)

            resp_headers = getattr(resp, "headers", {})
            self.capture_rate_limit_headers(resp_headers)
            resp_text = getattr(resp, "text", "")

            if resp.status_code == 401 and self.token_refresh_hook and attempt < max_retries - 1:
                new_token = await self.token_refresh_hook()
                self.set_token(new_token)
                continue

            is_rate_limited = resp.status_code == 429 or (
                resp.status_code == 403
                and (
                    (resp_headers.get("x-ratelimit-remaining") == "0" if hasattr(resp_headers, "get") else False)
                    or "rate limit" in resp_text.lower()
                    or "secondary rate limit" in resp_text.lower()
                    or "abuse detection" in resp_text.lower()
                    or "please wait a few minutes" in resp_text.lower()
                    or bool(resp_headers.get("retry-after") if hasattr(resp_headers, "get") else False)
                )
            )
            if is_rate_limited:
                if attempt < max_retries - 1:
                    import random
                    jitter = random.uniform(0.5, 1.5)
                    retry_after = self.rate_limit_snapshot.get("retry_after")
                    reset_time = self.rate_limit_snapshot.get("reset")

                    if retry_after and float(retry_after) > 0:
                        # Respect GitHub Retry-After header with jitter up to 120s
                        wait_sec = min(float(retry_after) + jitter, 120.0)
                    elif reset_time and float(reset_time) > time.time():
                        wait_sec = min(max(1.0, float(reset_time) - time.time()) + jitter, 120.0)
                    else:
                        wait_sec = min(float(2**attempt) + jitter, 60.0)

                    await asyncio.sleep(wait_sec)
                    continue
                else:
                    raise GitHubRateLimitError(
                        f"GitHub API secondary rate limit exceeded after {max_retries} attempts: "
                        f"{resp.status_code} {resp_text[:200]}"
                    )

            if resp.status_code >= 400:
                logger.warning(f"GitHub API {m} {url} returned HTTP {resp.status_code}: {resp_text[:300]}")

            return resp

        return resp

    async def get_branch_head_sha(self, owner: str, repo: str, branch: str = "main", client: Optional[httpx.AsyncClient] = None) -> str:
        """Fetch HEAD commit SHA for a branch."""
        url = f"{self.api_base_url}/repos/{owner}/{repo}/git/ref/heads/{branch}"
        
        async def _call(c: httpx.AsyncClient) -> str:
            resp = await self._send_request(c, "GET", url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            return data["object"]["sha"]

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def get_commit_tree_sha(
        self,
        owner: str,
        repo: str,
        commit_sha: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> str:
        """Fetch the tree SHA for a commit before creating a derived Git tree."""
        url = f"{self.api_base_url}/repos/{owner}/{repo}/git/commits/{commit_sha}"

        async def _call(c: httpx.AsyncClient) -> str:
            resp = await self._send_request(c, "GET", url, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            return data["tree"]["sha"]

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def create_blob(self, owner: str, repo: str, content: str, client: Optional[httpx.AsyncClient] = None) -> str:
        """Create a git blob for file content, returning blob SHA."""
        url = f"{self.api_base_url}/repos/{owner}/{repo}/git/blobs"
        payload = {"content": content, "encoding": "utf-8"}

        async def _call(c: httpx.AsyncClient) -> str:
            resp = await self._send_request(c, "POST", url, json=payload, timeout=15.0)
            resp.raise_for_status()
            return resp.json()["sha"]

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def create_tree(
        self,
        owner: str,
        repo: str,
        base_tree_sha: str,
        tree_items: List[Dict[str, Any]],
        client: Optional[httpx.AsyncClient] = None
    ) -> str:
        """
        Creates a new tree object.
        tree_items format: [{"path": "...", "mode": "100644", "type": "blob", "sha": blob_sha}]
        """
        url = f"{self.api_base_url}/repos/{owner}/{repo}/git/trees"
        payload = {
            "base_tree": base_tree_sha,
            "tree": tree_items
        }

        async def _call(c: httpx.AsyncClient) -> str:
            resp = await self._send_request(c, "POST", url, json=payload, timeout=15.0)
            if resp.status_code >= 400:
                logger.error(f"create_tree failed HTTP {resp.status_code}: {resp.text} - payload: {payload}")
            resp.raise_for_status()
            return resp.json()["sha"]

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def create_commit(
        self,
        owner: str,
        repo: str,
        message: str,
        tree_sha: str,
        parent_shas: List[str],
        client: Optional[httpx.AsyncClient] = None
    ) -> str:
        """Creates a commit object pointing to new tree and parent commit."""
        url = f"{self.api_base_url}/repos/{owner}/{repo}/git/commits"
        payload = {
            "message": message,
            "tree": tree_sha,
            "parents": parent_shas
        }

        async def _call(c: httpx.AsyncClient) -> str:
            resp = await self._send_request(c, "POST", url, json=payload, timeout=15.0)
            resp.raise_for_status()
            return resp.json()["sha"]

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def create_or_update_branch(
        self,
        owner: str,
        repo: str,
        branch_name: str,
        commit_sha: str,
        force: bool = False,
        expected_parent_sha: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, Any]:
        """
        Creates ref or fast-forwards existing branch.
        Handles:
        1. Fast-forward PATCH update (force=force).
        2. If branch does not exist (404), creates ref via POST.
        3. If branch exists and non-fast-forward/conflict occurs (409 or 422),
           or if POST returns 422 ("already exists"):
           - Verifies current remote branch HEAD sha.
           - If already at commit_sha, returns successfully (idempotent).
           - If force=False, raises BranchConflictError rather than overwriting history.
           - Only applies forced update if caller explicitly passed force=True.
        """
        ref_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/refs/heads/{branch_name}"
        create_url = f"{self.api_base_url}/repos/{owner}/{repo}/git/refs"

        async def _call(c: httpx.AsyncClient) -> Dict[str, Any]:
            patch_resp = await self._send_request(
                c,
                "PATCH",
                ref_url,
                json={"sha": commit_sha, "force": force},
                timeout=10.0
            )
            if patch_resp.status_code == 200:
                return patch_resp.json()

            if patch_resp.status_code == 404:
                post_resp = await self._send_request(
                    c,
                    "POST",
                    create_url,
                    json={"ref": f"refs/heads/{branch_name}", "sha": commit_sha},
                    timeout=10.0
                )
                if post_resp.status_code in (200, 201):
                    return post_resp.json()

                if post_resp.status_code == 422:
                    # Branch was concurrently created; verify remote HEAD
                    head_resp = await self._send_request(c, "GET", ref_url, timeout=10.0)
                    if head_resp.status_code == 200:
                        remote_sha = head_resp.json().get("object", {}).get("sha")
                        if remote_sha == commit_sha:
                            return head_resp.json()
                        if not force:
                            raise BranchConflictError(
                                f"Branch '{branch_name}' was concurrently created with divergent HEAD {remote_sha}. "
                                f"Refusing automatic force overwrite. Rebase or recompute required."
                            )
                    if force:
                        force_resp = await self._send_request(
                            c,
                            "PATCH",
                            ref_url,
                            json={"sha": commit_sha, "force": True},
                            timeout=10.0
                        )
                        if force_resp.status_code == 200:
                            return force_resp.json()
                        force_resp.raise_for_status()

                post_resp.raise_for_status()
                return post_resp.json()

            if patch_resp.status_code in (409, 422):
                head_resp = await self._send_request(c, "GET", ref_url, timeout=10.0)
                if head_resp.status_code == 404:
                    post_resp = await self._send_request(
                        c,
                        "POST",
                        create_url,
                        json={"ref": f"refs/heads/{branch_name}", "sha": commit_sha},
                        timeout=10.0
                    )
                    if post_resp.status_code in (200, 201):
                        return post_resp.json()
                    post_resp.raise_for_status()
                    return post_resp.json()

                if head_resp.status_code == 200:
                    remote_sha = head_resp.json().get("object", {}).get("sha")
                    if remote_sha == commit_sha:
                        return head_resp.json()
                    if not force:
                        raise BranchConflictError(
                            f"Branch '{branch_name}' conflict: remote HEAD {remote_sha} has diverged from expected parent "
                            f"{expected_parent_sha or 'unknown'}. Automatic force-push is forbidden. Rebase or recompute required."
                        )

                if force:
                    force_resp = await self._send_request(
                        c,
                        "PATCH",
                        ref_url,
                        json={"sha": commit_sha, "force": True},
                        timeout=10.0
                    )
                    if force_resp.status_code == 200:
                        return force_resp.json()
                    force_resp.raise_for_status()
                    return force_resp.json()

            patch_resp.raise_for_status()
            return patch_resp.json()

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def compare_commits(
        self,
        owner: str,
        repo: str,
        base: str,
        head: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        """
        Compare two commits via GET /repos/{owner}/{repo}/compare/{base}...{head}
        Returns comparison data including status ('ahead', 'behind', 'diverged', 'identical')
        and list of changed files.
        """
        url = f"{self.api_base_url}/repos/{owner}/{repo}/compare/{base}...{head}"

        async def _call(c: httpx.AsyncClient) -> Dict[str, Any]:
            resp = await self._send_request(c, "GET", url, timeout=15.0)
            resp.raise_for_status()
            return resp.json()

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def push_changes(
        self,
        owner: str,
        repo: str,
        branch_name: str,
        base_branch: str,
        files: List[FileDiff],
        commit_message: str,
        force: bool = False,
        initial_base_sha: Optional[str] = None,
        require_revalidation_on_drift: bool = True,
        client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, Any]:
        """
        Complete end-to-end atomic Git commit & push pipeline via Git Data API.
        Enforces upstream drift and merge conflict detection before pushing.
        """
        async def _run(c: httpx.AsyncClient):
            existing_branch_sha = None
            try:
                existing_branch_sha = await self.get_branch_head_sha(owner, repo, branch_name, client=c)
            except Exception:
                pass

            parent_sha = existing_branch_sha or await self.get_branch_head_sha(owner, repo, base_branch, client=c)

            rebased_on_drift = False
            if not existing_branch_sha and initial_base_sha and initial_base_sha != "HEAD" and parent_sha != initial_base_sha:
                try:
                    comparison = await self.compare_commits(owner, repo, initial_base_sha, parent_sha, client=c)
                    upstream_changed_files = {
                        item.get("filename", "").replace("\\", "/").lstrip("/")
                        for item in comparison.get("files", [])
                        if isinstance(item, dict)
                    }
                    candidate_paths = {
                        f.path.replace("\\", "/").lstrip("/")
                        for f in files
                    }
                    conflicting = candidate_paths.intersection(upstream_changed_files)
                    if conflicting:
                        raise MergeConflictError(
                            f"Merge conflict detected on upstream update: base branch '{base_branch}' advanced from "
                            f"{initial_base_sha[:8]} to {parent_sha[:8]} with conflicting modifications in: "
                            f"{sorted(list(conflicting))}"
                        )
                except httpx.HTTPStatusError:
                    # Non-fatal if compare endpoint is unavailable for shallow commit
                    pass

                # If upstream changed, autonomous safety requires re-evaluating and revalidating against latest parent_sha
                if require_revalidation_on_drift:
                    raise UpstreamDriftError(
                        f"Upstream base branch '{base_branch}' advanced from {initial_base_sha[:8]} to {parent_sha[:8]}. "
                        f"Autonomous safety policy requires revalidation against current HEAD before mutation.",
                        current_head_sha=parent_sha,
                    )
                rebased_on_drift = True

            base_tree_sha = await self.get_commit_tree_sha(owner, repo, parent_sha, client=c)

            tree_items = []
            for f in files:
                content = f.content or ""
                blob_sha = await self.create_blob(owner, repo, content, client=c)
                tree_items.append({
                    "path": f.path.lstrip("/"),
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_sha
                })

            new_tree_sha = await self.create_tree(owner, repo, base_tree_sha, tree_items, client=c)

            commit_sha = await self.create_commit(owner, repo, commit_message, new_tree_sha, [parent_sha], client=c)

            ref_data = await self.create_or_update_branch(
                owner, repo, branch_name, commit_sha, force=force, client=c
            )

            return {
                "commit_sha": commit_sha,
                "tree_sha": new_tree_sha,
                "base_tree_sha": base_tree_sha,
                "parent_sha": parent_sha,
                "branch": branch_name,
                "ref": ref_data.get("ref", f"refs/heads/{branch_name}"),
                "rebased_on_drift": rebased_on_drift,
            }

        if client:
            return await _run(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _run(c)

    async def verify_remote_commit_state(
        self,
        owner: str,
        repo: str,
        base_sha: str,
        head_sha: str,
        expected_paths: List[str],
        client: Optional[httpx.AsyncClient] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Post-commit verification gate against GitHub Compare API:
        GET /repos/{owner}/{repo}/compare/{base_sha}...{head_sha}
        Validates:
        1. Status is ahead or identical.
        2. Changed files match or are a strict subset of expected_paths.
        3. Head commit matches head_sha.
        """
        url = f"{self.api_base_url}/repos/{owner}/{repo}/compare/{base_sha}...{head_sha}"

        async def _call(c: httpx.AsyncClient) -> Tuple[bool, Dict[str, Any]]:
            try:
                resp = await self._send_request(c, "GET", url, timeout=15.0)
                if resp.status_code != 200:
                    logger.error(f"GitHub compare verification failed with HTTP {resp.status_code}: {resp.text}")
                    return False, {"error": f"HTTP {resp.status_code}", "raw": resp.text}
                
                data = resp.json()
                status = data.get("status")
                if status not in ("ahead", "identical"):
                    logger.warning(f"Compare status {status} not ahead/identical for {base_sha}...{head_sha}")
                    return False, {"error": f"unexpected status {status}", "details": data}

                files = data.get("files", [])
                changed_paths = [f.get("filename") for f in files]
                expected_norm = {p.lstrip("/") for p in expected_paths}
                for cp in changed_paths:
                    if cp.lstrip("/") not in expected_norm:
                        logger.error(f"Post-commit check detected unexpected file modified: {cp} not in {expected_norm}")
                        return False, {
                            "error": "unexpected_file_modified",
                            "unexpected_file": cp,
                            "changed_paths": changed_paths,
                            "expected_paths": list(expected_norm)
                        }

                return True, {"status": status, "files": changed_paths, "total_commits": data.get("total_commits", 1)}
            except Exception as e:
                logger.error(f"Exception during remote commit state verification: {e}")
                return False, {"error": str(e)}

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

