import pytest
from unittest.mock import AsyncMock, MagicMock
from automaintainer.github.git_data_client import GitHubGitDataClient, BranchConflictError
from automaintainer.github.executor import GitHubExecutor
from automaintainer.core.models import MutationIntent, MutationOp


@pytest.mark.asyncio
async def test_create_or_update_branch_409_conflict_diverged_raises_branch_conflict_error():
    """Verify that when a branch conflict (409) occurs and remote HEAD has diverged, BranchConflictError is raised if force=False."""
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()

    async def mock_patch(url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 409
        resp.text = "Conflict: non-fast-forward"
        return resp

    async def mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_other_diverged"}}
        return resp

    mock_client.patch = mock_patch
    mock_client.get = mock_get

    with pytest.raises(BranchConflictError) as excinfo:
        await client.create_or_update_branch(
            owner="testowner",
            repo="testrepo",
            branch_name="automaintainer/sess_123",
            commit_sha="sha_new",
            force=False,
            client=mock_client
        )
    assert "diverged" in str(excinfo.value)


@pytest.mark.asyncio
async def test_create_or_update_branch_409_conflict_idempotent_if_remote_matches():
    """Verify that if 409 occurs but remote HEAD already equals commit_sha, it returns cleanly."""
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()

    async def mock_patch(url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 409
        resp.text = "Conflict"
        return resp

    async def mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_new"}}
        return resp

    mock_client.patch = mock_patch
    mock_client.get = mock_get

    res = await client.create_or_update_branch(
        owner="testowner",
        repo="testrepo",
        branch_name="automaintainer/sess_123",
        commit_sha="sha_new",
        force=False,
        client=mock_client
    )
    assert res["ref"] == "refs/heads/automaintainer/sess_123"


@pytest.mark.asyncio
async def test_create_or_update_branch_409_conflict_falls_back_to_force_when_force_true():
    """Verify that if force=True is passed, a 409 conflict falls back to force PATCH."""
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()
    patch_calls = []

    async def mock_patch(url, headers=None, json=None, timeout=None):
        patch_calls.append(json)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_new"}}
        return resp

    mock_client.patch = mock_patch

    res = await client.create_or_update_branch(
        owner="testowner",
        repo="testrepo",
        branch_name="automaintainer/sess_123",
        commit_sha="sha_new",
        force=True,
        client=mock_client
    )

    assert res["ref"] == "refs/heads/automaintainer/sess_123"
    assert len(patch_calls) == 1
    assert patch_calls[0]["force"] is True


@pytest.mark.asyncio
async def test_create_or_update_branch_422_non_fast_forward_raises_branch_conflict_error():
    """Verify that when 422 occurs on non-fast-forward, BranchConflictError is raised if force=False."""
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()

    async def mock_patch(url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 422
        resp.text = "Update is not a fast forward"
        return resp

    async def mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_other"}}
        return resp

    mock_client.patch = mock_patch
    mock_client.get = mock_get

    with pytest.raises(BranchConflictError) as excinfo:
        await client.create_or_update_branch(
            owner="testowner",
            repo="testrepo",
            branch_name="automaintainer/sess_123",
            commit_sha="sha_new",
            force=False,
            client=mock_client
        )
    assert "diverged" in str(excinfo.value)


@pytest.mark.asyncio
async def test_create_or_update_branch_404_then_post_422_diverged_raises_branch_conflict_error():
    """Verify that when 404 -> POST 422 occurs (concurrent creation), BranchConflictError is raised if diverged and force=False."""
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()

    async def mock_patch(url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        return resp

    async def mock_post(url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 422
        resp.text = "Reference already exists"
        return resp

    async def mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_diverged"}}
        return resp

    mock_client.patch = mock_patch
    mock_client.post = mock_post
    mock_client.get = mock_get

    with pytest.raises(BranchConflictError) as excinfo:
        await client.create_or_update_branch(
            owner="testowner",
            repo="testrepo",
            branch_name="automaintainer/sess_123",
            commit_sha="sha_new",
            force=False,
            client=mock_client
        )
    assert "concurrently created" in str(excinfo.value)


@pytest.mark.asyncio
async def test_create_or_update_branch_404_then_post_422_falls_back_to_patch_force_when_force_true():
    """Verify that when 404 -> POST 422 occurs and force=True, it falls back to force PATCH."""
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()
    patch_calls = []

    async def mock_patch(url, headers=None, json=None, timeout=None):
        patch_calls.append(json)
        if len(patch_calls) == 1:
            resp = MagicMock()
            resp.status_code = 404
            resp.text = "Not Found"
            return resp
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_new"}}
        return resp

    async def mock_post(url, headers=None, json=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 422
        resp.text = "Reference already exists"
        return resp

    async def mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ref": "refs/heads/automaintainer/sess_123", "object": {"sha": "sha_diverged"}}
        return resp

    mock_client.patch = mock_patch
    mock_client.post = mock_post
    mock_client.get = mock_get

    res = await client.create_or_update_branch(
        owner="testowner",
        repo="testrepo",
        branch_name="automaintainer/sess_123",
        commit_sha="sha_new",
        force=True,
        client=mock_client
    )

    assert res["ref"] == "refs/heads/automaintainer/sess_123"
    assert len(patch_calls) == 2
    assert patch_calls[1]["force"] is True


@pytest.mark.asyncio
async def test_git_data_client_captures_rate_limit_headers():
    client = GitHubGitDataClient(token="ghp_test_token")
    mock_client = AsyncMock()

    async def mock_get(url, headers=None, timeout=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {
            "x-ratelimit-remaining": "4950",
            "x-ratelimit-limit": "5000",
            "x-ratelimit-reset": "1726000000",
            "x-ratelimit-used": "50",
            "retry-after": "5",
        }
        resp.json.return_value = {"object": {"sha": "sha_main_head"}}
        return resp

    mock_client.get = mock_get

    sha = await client.get_branch_head_sha("owner", "repo", "main", client=mock_client)
    assert sha == "sha_main_head"
    assert client.rate_limit_snapshot["remaining"] == 4950
    assert client.rate_limit_snapshot["limit"] == 5000
    assert client.rate_limit_snapshot["retry_after"] == 5.0


@pytest.mark.asyncio
async def test_executor_rate_limit_retry_on_429(monkeypatch):
    executor = GitHubExecutor(token="ghp_test_token")
    call_count = 0

    async def mock_request(client, method, url, max_retries=3, **kwargs):
        nonlocal call_count
        call_count += 1
        resp = MagicMock()
        if call_count == 1:
            resp.status_code = 429
            resp.headers = {"retry-after": "0.01", "x-ratelimit-remaining": "0"}
            resp.text = "Too Many Requests"
            executor.capture_rate_limit_headers(resp.headers)
            return await executor._send_request(client, method, url, max_retries=max_retries, **kwargs)
        resp.status_code = 200
        resp.headers = {"x-ratelimit-remaining": "4999"}
        resp.json.return_value = {"id": 1, "number": 42, "state": "open"}
        executor.capture_rate_limit_headers(resp.headers)
        return resp

    monkeypatch.setattr(executor, "_send_request", mock_request)

    intent = MutationIntent(
        session_id="sess_rt_1",
        actor="test",
        operation=MutationOp.OPEN_PR,
        repository="owner/repo",
        branch="automaintainer/sess_rt_1",
        pr_title="Title",
        pr_body="Body",
    )

    res = await executor.execute_mutation(intent)
    assert res["number"] == 42
    assert call_count == 2
