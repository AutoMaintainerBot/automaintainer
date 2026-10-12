import pytest
import pytest_asyncio
import httpx
from automaintainer.github.collaborator import GitHubCollaboratorResolver

@pytest.mark.asyncio
async def test_collaborator_resolver_approves_admin():
    resolver = GitHubCollaboratorResolver()

    def mock_transport(request: httpx.Request):
        if "permission" in str(request.url):
            return httpx.Response(200, json={"permission": "admin", "user": {"login": "trusted_maintainer"}})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as client:
        authorized = await resolver.is_authorized_maintainer(
            repository="testowner/testrepo",
            username="trusted_maintainer",
            token="ghs_dummy_token",
            client=client
        )
        assert authorized is True

@pytest.mark.asyncio
async def test_collaborator_resolver_denies_read_or_unauthorized_user():
    resolver = GitHubCollaboratorResolver()

    def mock_transport(request: httpx.Request):
        if "permission" in str(request.url):
            return httpx.Response(200, json={"permission": "read", "user": {"login": "random_user"}})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as client:
        authorized = await resolver.is_authorized_maintainer(
            repository="testowner/testrepo",
            username="random_user",
            token="ghs_dummy_token",
            client=client
        )
        assert authorized is False
