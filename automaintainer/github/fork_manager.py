import time
from typing import Dict, Any, Optional
import httpx

class PublicForkManager:
    """
    Public Repository Fork & Working Copy Lifecycle:
    Public Mode operates strictly via temporary, disposable bot-owned forks:
    1. Check upstream repository eligibility.
    2. Fork upstream repo to bot-controlled org/account.
    3. Create isolated session branch from pinned upstream SHA.
    4. Provide branch reference for validation and PR opening.
    5. Cleanup/delete session branch or archive fork on session completion.
    """

    def __init__(self, token: str, bot_org: Optional[str] = None, api_base_url: str = "https://api.github.com"):
        self.token = token
        self.bot_org = bot_org
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    async def create_or_get_fork(
        self,
        upstream_owner: str,
        upstream_repo: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, Any]:
        """
        Creates a fork in the bot org/account if not already present.
        If the authenticated user owns the upstream repo directly, returns the upstream repo without forking.
        """
        url = f"{self.api_base_url}/repos/{upstream_owner}/{upstream_repo}/forks"
        payload = {}
        if self.bot_org:
            payload["organization"] = self.bot_org

        async def _call(c: httpx.AsyncClient):
            # 1. If bot_org is specified, check if upstream is already in bot_org or if fork exists in bot_org
            if self.bot_org:
                if self.bot_org.lower() == upstream_owner.lower():
                    repo_resp = await c.get(f"{self.api_base_url}/repos/{upstream_owner}/{upstream_repo}", headers=self._headers(), timeout=10.0)
                    if repo_resp.status_code == 200:
                        return repo_resp.json()
                else:
                    # Check if the fork already exists under bot_org
                    fork_check = await c.get(f"{self.api_base_url}/repos/{self.bot_org}/{upstream_repo}", headers=self._headers(), timeout=10.0)
                    if fork_check.status_code == 200:
                        fork_data = fork_check.json()
                        # Sync default branch with upstream
                        try:
                            default_branch = fork_data.get("default_branch", "main")
                            sync_url = f"{self.api_base_url}/repos/{self.bot_org}/{upstream_repo}/merge-upstream"
                            await c.post(sync_url, headers=self._headers(), json={"branch": default_branch}, timeout=10.0)
                        except Exception:
                            pass
                        return fork_data
            else:
                # No bot_org: Check if token owner is the upstream owner (no fork needed)
                try:
                    user_resp = await c.get(f"{self.api_base_url}/user", headers=self._headers(), timeout=10.0)
                    if user_resp.status_code == 200:
                        current_user = user_resp.json().get("login", "")
                        if current_user.lower() == upstream_owner.lower():
                            repo_resp = await c.get(f"{self.api_base_url}/repos/{upstream_owner}/{upstream_repo}", headers=self._headers(), timeout=10.0)
                            if repo_resp.status_code == 200:
                                return repo_resp.json()
                except Exception:
                    pass

            # 2. Request fork from GitHub
            resp = await c.post(url, headers=self._headers(), json=payload, timeout=15.0)
            if resp.status_code in (200, 202):
                data = resp.json()
                if resp.status_code == 202:
                    import asyncio
                    await asyncio.sleep(2.0)

                # Attempt to sync default branch with upstream if fork already existed
                try:
                    fork_owner = data.get("owner", {}).get("login")
                    fork_name = data.get("name", upstream_repo)
                    default_branch = data.get("default_branch", "main")
                    if fork_owner and fork_owner.lower() != upstream_owner.lower():
                        sync_url = f"{self.api_base_url}/repos/{fork_owner}/{fork_name}/merge-upstream"
                        await c.post(sync_url, headers=self._headers(), json={"branch": default_branch}, timeout=10.0)
                except Exception:
                    pass

                return data

            if resp.status_code >= 400:
                import logging
                logging.getLogger("automaintainer.fork").error(
                    f"GitHub fork creation failed HTTP {resp.status_code}: {resp.text} (url: {url}, payload: {payload})"
                )
            resp.raise_for_status()

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def create_session_branch(
        self,
        fork_owner: str,
        fork_repo: str,
        session_id: str,
        base_sha: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> str:
        """Creates an ephemeral session branch in the fork."""
        branch_name = f"automaintainer/{session_id}"
        url = f"{self.api_base_url}/repos/{fork_owner}/{fork_repo}/git/refs"
        payload = {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha
        }

        async def _call(c: httpx.AsyncClient):
            resp = await c.post(url, headers=self._headers(), json=payload, timeout=15.0)
            resp.raise_for_status()
            return branch_name

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)

    async def cleanup_session_branch(
        self,
        fork_owner: str,
        fork_repo: str,
        session_id: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> bool:
        """Deletes ephemeral branch upon session completion."""
        branch_name = f"automaintainer/{session_id}"
        url = f"{self.api_base_url}/repos/{fork_owner}/{fork_repo}/git/refs/heads/{branch_name}"

        async def _call(c: httpx.AsyncClient):
            resp = await c.delete(url, headers=self._headers(), timeout=10.0)
            return resp.status_code in (204, 404)

        if client:
            return await _call(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _call(c)
