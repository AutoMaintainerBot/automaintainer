from typing import Optional, Dict
import httpx

class GitHubCollaboratorResolver:
    """
    Maintainer Comment Authorization & Verification:
    Resolves commenter authority against GitHub API:
      GET /repos/{owner}/{repo}/collaborators/{username}/permission
    Ensures only users with write/admin/maintain permission can direct maintenance sessions.
    External or non-collaborator comments are treated as untrusted data, never instructions.
    """

    ALLOWED_PERMISSIONS = {"admin", "write", "maintain"}

    def __init__(self, token: Optional[str] = None, api_base_url: str = "https://api.github.com"):
        self.token = token
        self.api_base_url = api_base_url.rstrip("/")
        # In-memory short cache: "owner/repo:username" -> is_authorized (bool)
        self._permission_cache: Dict[str, bool] = {}

    async def is_authorized_maintainer(
        self,
        repository: str,
        username: str,
        token: Optional[str] = None,
        author_association: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None
    ) -> bool:
        if not repository or not username:
            return False

        if author_association:
            norm_assoc = str(author_association).strip().upper()
            if norm_assoc in ("OWNER", "MEMBER", "COLLABORATOR"):
                return True
            if norm_assoc in ("CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "NONE"):
                if not (token or self.token):
                    return False

        effective_token = token or self.token
        if not effective_token:
            return False

        owner_repo = repository.strip().strip("/")
        if "/" not in owner_repo:
            return False
        owner, repo = owner_repo.split("/", 1)

        cache_key = f"{owner.lower()}/{repo.lower()}:{username.lower()}"
        if cache_key in self._permission_cache:
            return self._permission_cache[cache_key]

        url = f"{self.api_base_url}/repos/{owner}/{repo}/collaborators/{username}/permission"
        headers = {
            "Authorization": f"Bearer {effective_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        async def _check(c: httpx.AsyncClient) -> bool:
            try:
                resp = await c.get(url, headers=headers, timeout=10.0)
                if resp.status_code in (403, 404):
                    # Public repo or missing collaborator read permissions:
                    # Fall back to author_association if provided
                    if author_association:
                        norm = str(author_association).strip().upper()
                        return norm in ("OWNER", "MEMBER", "COLLABORATOR")
                    self._permission_cache[cache_key] = False
                    return False
                if resp.status_code != 200:
                    if author_association:
                        return str(author_association).strip().upper() in ("OWNER", "MEMBER", "COLLABORATOR")
                    return False

                data = resp.json()
                permission = data.get("permission", "").lower()
                is_authorized = permission in self.ALLOWED_PERMISSIONS
                self._permission_cache[cache_key] = is_authorized
                return is_authorized
            except Exception:
                if author_association:
                    return str(author_association).strip().upper() in ("OWNER", "MEMBER", "COLLABORATOR")
                return False

        if client:
            return await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _check(c)
