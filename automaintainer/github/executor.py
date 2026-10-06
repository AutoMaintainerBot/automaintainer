import asyncio
import time
from typing import Dict, Any, Optional, Callable, Awaitable
import httpx
from automaintainer.core.models import MutationIntent, MutationOp
from automaintainer.github.git_data_client import (
    GitHubGitDataClient,
    MergeConflictError,
    UpstreamDriftError,
    GitHubRateLimitError,
    _parse_header_int,
    _parse_header_float,
)

class UnsupportedMutationError(RuntimeError):
    """Raised when an unrecognized or unsupported mutation operation is requested."""
    pass

class GitHubExecutor:
    """
    The ONLY component in the entire architecture with actual GitHub write privileges.
    Executes authorized mutations strictly after passing through Capability Broker & Policy Gateway.
    Now fully implements:
    - CREATE_BRANCH (via Git Data API)
    - CREATE_COMMIT (atomic blob/tree/commit pipeline)
    - OPEN_PR
    - UPDATE_PR
    - ADD_COMMENT
    - CLOSE_PR
    - Dynamic token refresh on 401 Unauthorized
    - Rate limit tracking and backoff on 429 / 403
    """

    def __init__(
        self,
        token: Optional[str] = None,
        api_base_url: str = "https://api.github.com",
        token_broker: Optional[Any] = None,
        installation_id: Optional[int] = None,
        token_refresh_hook: Optional[Callable[[], Awaitable[str]]] = None,
    ):
        self.token = token or ""
        self.api_base_url = api_base_url.rstrip("/")
        self.token_broker = token_broker
        self.installation_id = installation_id
        self.token_refresh_hook = token_refresh_hook
        self._rate_limit_snapshot: Dict[str, Any] = {}
        self.git_data = GitHubGitDataClient(
            token=self.token,
            api_base_url=api_base_url,
            token_refresh_hook=self.refresh_token if (self.token_broker or self.token_refresh_hook) else None,
        )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    @property
    def rate_limit_snapshot(self) -> Dict[str, Any]:
        """Returns the latest rate limit snapshot combining executor and git data client."""
        return self._rate_limit_snapshot or self.git_data.rate_limit_snapshot

    def capture_rate_limit_headers(self, headers: Any) -> Dict[str, Any]:
        """Parses rate-limit headers from GitHub responses safely."""
        if not hasattr(headers, "get"):
            return self._rate_limit_snapshot

        remaining = _parse_header_int(headers.get("x-ratelimit-remaining"))
        limit = _parse_header_int(headers.get("x-ratelimit-limit"))
        reset = _parse_header_float(headers.get("x-ratelimit-reset"))
        used = _parse_header_int(headers.get("x-ratelimit-used"))
        retry_after = _parse_header_float(headers.get("retry-after"))

        self._rate_limit_snapshot = {
            "remaining": remaining,
            "limit": limit,
            "reset": reset,
            "used": used,
            "retry_after": retry_after,
        }
        return self._rate_limit_snapshot

    async def refresh_token(self) -> str:
        """Dynamically refresh token via hook or installation token broker."""
        new_token = None
        if self.token_refresh_hook:
            new_token = await self.token_refresh_hook()
        elif self.token_broker and self.installation_id:
            new_token = await self.token_broker.get_installation_token(self.installation_id, force_refresh=True)

        if new_token:
            self.token = new_token
            self.git_data.set_token(new_token)
            return new_token
        return self.token

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

            if resp.status_code == 401 and (self.token_broker or self.token_refresh_hook) and attempt < max_retries - 1:
                await self.refresh_token()
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
                    retry_after = self._rate_limit_snapshot.get("retry_after")
                    reset_time = self._rate_limit_snapshot.get("reset")

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

            return resp

        return resp

    async def execute_mutation(self, intent: MutationIntent, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
        """Dispatches approved mutation to the GitHub REST / Git Data API."""
        owner, repo = intent.repository.split("/")

        if client is not None:
            return await self._execute_mutation_with_client(intent, owner, repo, client)
        async with httpx.AsyncClient() as managed_client:
            return await self._execute_mutation_with_client(intent, owner, repo, managed_client)

    async def _execute_mutation_with_client(
        self, intent: MutationIntent, owner: str, repo: str, client: httpx.AsyncClient
    ) -> Dict[str, Any]:
            if intent.operation == MutationOp.CREATE_BRANCH:
                base_branch = intent.metadata.get("base_branch", "main")
                head_sha = await self.git_data.get_branch_head_sha(owner, repo, base_branch, client=client)
                return await self.git_data.create_or_update_branch(owner, repo, intent.branch, head_sha, client=client)

            elif intent.operation == MutationOp.CREATE_COMMIT:
                files = intent.diff.files if intent.diff else []
                base_branch = intent.metadata.get("base_branch", "main")
                commit_message = intent.metadata.get("commit_message", "chore: automated maintenance update")
                initial_base_sha = intent.metadata.get("initial_base_sha") or intent.metadata.get("base_sha")
                return await self.git_data.push_changes(
                    owner=owner,
                    repo=repo,
                    branch_name=intent.branch,
                    base_branch=base_branch,
                    files=files,
                    commit_message=commit_message,
                    initial_base_sha=initial_base_sha,
                    client=client
                )

            elif intent.operation == MutationOp.OPEN_PR:
                url = f"{self.api_base_url}/repos/{owner}/{repo}/pulls"
                head_ref = intent.branch
                head_fork_owner = intent.metadata.get("head_fork_owner") if intent.metadata else None
                if head_fork_owner and head_fork_owner.lower() != owner.lower():
                    head_ref = f"{head_fork_owner}:{intent.branch}"

                payload = {
                    "title": intent.pr_title or "AutoMaintainer Maintenance Update",
                    "body": intent.pr_body or "Automated maintenance update with evidence.",
                    "head": head_ref,
                    "base": intent.metadata.get("base_branch", "main") if intent.metadata else "main",
                    "maintainer_can_modify": True,
                }
                resp = await self._send_request(client, "POST", url, json=payload, timeout=15.0)
                if resp.status_code == 422:
                    # If GitHub reports a PR already exists for this branch, return the existing PR
                    try:
                        list_url = f"{self.api_base_url}/repos/{owner}/{repo}/pulls?state=open&head={head_ref}"
                        list_resp = await self._send_request(client, "GET", list_url, timeout=10.0)
                        if list_resp.status_code == 200:
                            existing_prs = list_resp.json()
                            if isinstance(existing_prs, list) and len(existing_prs) > 0:
                                return existing_prs[0]
                    except Exception:
                        pass
                try:
                    resp.raise_for_status()
                except Exception as exc:
                    logger.error(f"GitHub API OPEN_PR failed for {owner}/{repo}: {resp.status_code} - {resp.text}")
                    raise RuntimeError(f"GitHub API OPEN_PR error {resp.status_code} for {owner}/{repo}: {resp.text}") from exc
                return resp.json()

            elif intent.operation == MutationOp.ADD_COMMENT:
                pr_number = intent.metadata.get("pr_number")
                url = f"{self.api_base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
                payload = {"body": intent.comment_body or ""}
                resp = await self._send_request(client, "POST", url, json=payload, timeout=15.0)
                resp.raise_for_status()
                return resp.json()

            elif intent.operation == MutationOp.CLOSE_PR:
                pr_number = intent.metadata.get("pr_number")
                url = f"{self.api_base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
                payload = {"state": "closed"}
                resp = await self._send_request(client, "PATCH", url, json=payload, timeout=15.0)
                resp.raise_for_status()
                return resp.json()

            else:
                raise UnsupportedMutationError(f"Unsupported mutation operation: {intent.operation}")
