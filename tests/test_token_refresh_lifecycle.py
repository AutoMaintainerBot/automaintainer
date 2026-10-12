import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from automaintainer.github.token_broker import InstallationTokenBroker
from automaintainer.github.auth import InstallationTokenBroker as UnifiedTokenBroker
from automaintainer.github.executor import GitHubExecutor
from automaintainer.core.models import MutationIntent, MutationOp


@pytest.mark.asyncio
async def test_token_broker_force_refresh_bypasses_cache():
    """Verify force_refresh=True gets a new token even when cache is valid."""
    broker = InstallationTokenBroker(app_id="123", private_key_pem="dummy_pem")
    broker._token_cache[999] = {
        "token": "cached_old_token",
        "expires_at": time.time() + 3000,
    }

    with patch.object(broker, "generate_app_jwt", return_value="jwt_fake"), \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"token": "freshly_minted_token"}
        mock_post.return_value = mock_resp

        token1 = await broker.get_installation_token(999, force_refresh=False)
        assert token1 == "cached_old_token"
        assert mock_post.call_count == 0

        token2 = await broker.get_installation_token(999, force_refresh=True)
        assert token2 == "freshly_minted_token"
        assert mock_post.call_count == 1
        assert broker._token_cache[999]["token"] == "freshly_minted_token"


@pytest.mark.asyncio
async def test_token_broker_invalidate_token():
    broker = InstallationTokenBroker(app_id="123", private_key_pem="dummy_pem")
    broker._token_cache[999] = {"token": "cached_token", "expires_at": time.time() + 3000}

    broker.invalidate_token(999)
    assert 999 not in broker._token_cache


@pytest.mark.asyncio
async def test_executor_retries_mutation_on_401_with_refreshed_token():
    """Verify 401 Unauthorized dynamically calls refresh_token and retries mutation."""
    token_broker = MagicMock()
    token_broker.get_installation_token = AsyncMock(return_value="refreshed_new_token")

    executor = GitHubExecutor(
        token="expired_token",
        token_broker=token_broker,
        installation_id=456,
    )

    request_tokens_used = []

    async def mock_post(url, headers=None, json=None, timeout=None):
        token_used = (headers or {}).get("Authorization", "").replace("Bearer ", "")
        request_tokens_used.append(token_used)

        resp = MagicMock()
        if len(request_tokens_used) == 1:
            resp.status_code = 401
            resp.text = "Bad credentials / token expired"
            resp.headers = {}
            return resp

        resp.status_code = 200
        resp.headers = {}
        resp.json.return_value = {"id": 101, "number": 12, "body": "Fixed"}
        return resp

    with patch("httpx.AsyncClient.post", side_effect=mock_post):
        intent = MutationIntent(
            session_id="sess_token_refresh",
            actor="test",
            operation=MutationOp.ADD_COMMENT,
            repository="owner/repo",
            branch="main",
            comment_body="Test comment",
            metadata={"pr_number": 12},
        )

        res = await executor.execute_mutation(intent)

        assert res["number"] == 12
        assert len(request_tokens_used) == 2
        assert request_tokens_used[0] == "expired_token"
        assert request_tokens_used[1] == "refreshed_new_token"
        assert executor.token == "refreshed_new_token"
        assert executor.git_data.token == "refreshed_new_token"
        token_broker.get_installation_token.assert_awaited_once_with(456, force_refresh=True)
