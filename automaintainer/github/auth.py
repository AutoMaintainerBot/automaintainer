from typing import Optional, Dict, Any, Union
import time
import httpx
from automaintainer.config import Settings
from automaintainer.github.token_broker import InstallationTokenBroker as BaseInstallationTokenBroker


class InstallationTokenRecord:
    """Represents a minted GitHub App installation access token."""

    def __init__(self, token: str, expires_at: Optional[float] = None):
        self.token = token
        self.expires_at = expires_at

    def __str__(self) -> str:
        return self.token

    def __repr__(self) -> str:
        return f"InstallationTokenRecord(token='***', expires_at={self.expires_at})"


class InstallationTokenBroker:
    """
    Unified GitHub App Token Broker.
    Accepts either a `Settings` instance or direct credentials (app_id, private_key_pem).
    Provides both `get_token` (returning InstallationTokenRecord) and `get_installation_token` (returning str).
    """

    def __init__(
        self,
        settings_or_app_id: Optional[Union[Settings, str, int]] = None,
        private_key_pem: Optional[str] = None,
        api_base_url: Optional[str] = None,
        app_id: Optional[Union[str, int]] = None,
    ):
        resolved_id = app_id if app_id is not None else settings_or_app_id
        if isinstance(resolved_id, Settings):
            self.app_id = str(resolved_id.GITHUB_APP_ID or "")
            self.private_key_pem = resolved_id.GITHUB_APP_PRIVATE_KEY or ""
            base_url = api_base_url or resolved_id.GITHUB_API_BASE_URL or "https://api.github.com"
            self.api_base_url = base_url.rstrip("/")
        else:
            self.app_id = str(resolved_id or "")
            self.private_key_pem = private_key_pem or ""
            self.api_base_url = (api_base_url or "https://api.github.com").rstrip("/")

        self._base_broker = BaseInstallationTokenBroker(
            app_id=self.app_id,
            private_key_pem=self.private_key_pem,
            api_base_url=self.api_base_url,
        )

    def generate_app_jwt(self) -> str:
        return self._base_broker.generate_app_jwt()

    def invalidate_token(self, installation_id: int) -> None:
        self._base_broker.invalidate_token(installation_id)

    async def get_installation_token(
        self,
        installation_id: int,
        repositories: Optional[list] = None,
        permissions: Optional[dict] = None,
        force_refresh: bool = False,
    ) -> str:
        return await self._base_broker.get_installation_token(
            installation_id=installation_id,
            repositories=repositories,
            permissions=permissions,
            force_refresh=force_refresh,
        )

    async def get_token(
        self,
        installation_id: int,
        repositories: Optional[list] = None,
        permissions: Optional[dict] = None,
        force_refresh: bool = False,
    ) -> InstallationTokenRecord:
        rec = await self._base_broker.get_token_record(
            installation_id=installation_id,
            repositories=repositories,
            permissions=permissions,
            force_refresh=force_refresh,
        )
        return InstallationTokenRecord(token=rec.token, expires_at=rec.expires_at)
