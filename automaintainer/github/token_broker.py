import time
from typing import Dict, Optional, Any
import jwt
import httpx

class InstallationTokenBroker:
    """
    Stateless-aware GitHub App Installation Token Broker.
    - Mints App JWT using RSA Private Key.
    - Obtains short-lived installation access tokens from GitHub API.
    - Caches valid tokens close to expiry (tokens expire in 1 hour; cache for 50 mins).
    - Treats token strings as opaque blobs (making NO assumptions on length or format,
      accommodating GitHub 2026 stateless tokens).
    """

    def __init__(self, app_id: str, private_key_pem: str, api_base_url: str = "https://api.github.com"):
        self.app_id = app_id
        self.private_key_pem = private_key_pem
        self.api_base_url = api_base_url.rstrip("/")
        # Cache: installation_id -> { "token": str, "expires_at": float }
        self._token_cache: Dict[int, Dict[str, Any]] = {}

    def generate_app_jwt(self) -> str:
        """Generate RS256 JWT valid for 10 minutes for App authentication."""
        now = int(time.time())
        payload = {
            "iat": now - 60,  # 1 min in the past to prevent clock drift issues
            "exp": now + (10 * 60),
            "iss": str(self.app_id)
        }
        return jwt.encode(payload, self.private_key_pem, algorithm="RS256")

    def invalidate_token(self, installation_id: int) -> None:
        """Explicitly invalidate cached installation token."""
        self._token_cache.pop(installation_id, None)

    async def get_installation_token(
        self,
        installation_id: int,
        repositories: Optional[list] = None,
        permissions: Optional[dict] = None,
        force_refresh: bool = False,
    ) -> str:
        """
        Returns a valid installation token, using cache when available unless force_refresh is True.
        """
        now = time.time()
        if not force_refresh:
            cached = self._token_cache.get(installation_id)
            if cached and cached["expires_at"] > now + 300:  # At least 5 mins buffer
                return cached["token"]

        jwt_token = self.generate_app_jwt()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        body: Dict[str, Any] = {}
        if repositories:
            body["repositories"] = repositories
        if permissions:
            body["permissions"] = permissions

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.api_base_url}/app/installations/{installation_id}/access_tokens",
                headers=headers,
                json=body,
                timeout=10.0
            )
            resp.raise_for_status()
            data = resp.json()

            token = data["token"]
            # Typically valid 1 hour; cache for 50 minutes
            self._token_cache[installation_id] = {
                "token": token,
                "expires_at": now + 3000
            }
            return token

    async def get_token_record(
        self,
        installation_id: int,
        repositories: Optional[list] = None,
        permissions: Optional[dict] = None,
        force_refresh: bool = False,
    ) -> "TokenRecord":
        token_str = await self.get_installation_token(
            installation_id=installation_id,
            repositories=repositories,
            permissions=permissions,
            force_refresh=force_refresh,
        )
        cached = self._token_cache.get(installation_id, {})
        return TokenRecord(token=token_str, expires_at=cached.get("expires_at"))


class TokenRecord:
    """Public token model representing an active installation access token."""

    def __init__(self, token: str, expires_at: Optional[float] = None):
        self.token = token
        self.expires_at = expires_at

    def __str__(self) -> str:
        return self.token

    def __repr__(self) -> str:
        return f"TokenRecord(token='***', expires_at={self.expires_at})"
