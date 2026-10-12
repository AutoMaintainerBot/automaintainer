import pytest
import httpx
from automaintainer.github.collaborator_resolver import GitHubCollaboratorResolver

@pytest.mark.asyncio
async def test_collaborator_resolver_approves_admin_write(monkeypatch):
    resolver = GitHubCollaboratorResolver(token="ghp_fake_token")

    async def mock_get(url, *args, **kwargs):
        class MockResponse:
            status_code = 200
            def json(self):
                return {"permission": "write", "user": {"login": "maintainer_dan"}}
        return MockResponse()

    client = httpx.AsyncClient()
    monkeypatch.setattr(client, "get", mock_get)

    is_auth = await resolver.is_authorized_maintainer(
        repository="owner/repo",
        username="maintainer_dan",
        client=client
    )
    assert is_auth is True

@pytest.mark.asyncio
async def test_collaborator_resolver_rejects_unauthorized_user(monkeypatch):
    resolver = GitHubCollaboratorResolver(token="ghp_fake_token")

    async def mock_get(url, *args, **kwargs):
        class MockResponse:
            status_code = 404
            def json(self):
                return {"message": "Not Found"}
        return MockResponse()

    client = httpx.AsyncClient()
    monkeypatch.setattr(client, "get", mock_get)

    is_auth = await resolver.is_authorized_maintainer(
        repository="owner/repo",
        username="random_spammer",
        client=client
    )
    assert is_auth is False
