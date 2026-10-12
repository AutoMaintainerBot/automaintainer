"""Tests for RepositoryFingerprinter — language/package manager detection."""
import pytest
import base64
from unittest.mock import AsyncMock
import httpx

from automaintainer.discovery.repo_fingerprint import RepositoryFingerprinter


def _json_resp(data) -> httpx.Response:
    import json
    return httpx.Response(200, content=json.dumps(data).encode())


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


PYPROJECT_CONTENT = _b64("""
[project]
name = "mypackage"
[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
select = ["E", "F"]
""")

PKG_JSON_CONTENT = _b64('{"name":"pkg","scripts":{"test":"jest","lint":"eslint ."}}')


def _make_mock_client(tree_files: list, extra_responses: dict = None):
    """Build a mock AsyncClient with fine-grained URL routing."""
    extra_responses = extra_responses or {}

    async def mock_get(url, **kwargs):
        if "/git/ref/heads/" in url:
            return _json_resp({"object": {"sha": "abc123"}})
        if "/git/trees/" in url:
            return _json_resp({"tree": tree_files})
        for path, resp in extra_responses.items():
            if path in url:
                return resp
        if url.count("/") <= 6 and "github.com/repos/" in url:
            return _json_resp({"default_branch": "main"})
        return httpx.Response(404, content=b"not found")

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)
    return client


@pytest.mark.asyncio
async def test_python_project_detected():
    fp = RepositoryFingerprinter()
    tree = [
        {"path": "pyproject.toml", "type": "blob"},
        {"path": "README.md", "type": "blob"},
    ]
    extras = {
        "contents/pyproject.toml": _json_resp({"content": PYPROJECT_CONTENT, "encoding": "base64"}),
        "contents/.github/workflows": httpx.Response(404, content=b""),
    }
    client = _make_mock_client(tree, extras)
    result = await fp.build("owner", "repo", "token", client=client)

    assert "python" in result.language_stack
    assert result.commit_sha == "abc123"
    assert result.default_branch == "main"
    assert "pytest" in result.test_commands
    assert "ruff check ." in result.lint_commands


@pytest.mark.asyncio
async def test_rust_project_detected():
    fp = RepositoryFingerprinter()
    tree = [
        {"path": "Cargo.toml", "type": "blob"},
        {"path": "src", "type": "tree"},
    ]
    client = _make_mock_client(tree)
    result = await fp.build("owner", "repo", "token", client=client)

    assert "rust" in result.language_stack
    assert "cargo" in result.package_managers


@pytest.mark.asyncio
async def test_node_project_with_scripts_detected():
    fp = RepositoryFingerprinter()
    tree = [
        {"path": "package.json", "type": "blob"},
        {"path": "yarn.lock", "type": "blob"},
    ]
    extras = {
        "contents/package.json": _json_resp({"content": PKG_JSON_CONTENT, "encoding": "base64"}),
    }
    client = _make_mock_client(tree, extras)
    result = await fp.build("owner", "repo", "token", client=client)

    assert "javascript" in result.language_stack
    assert "yarn" in result.package_managers
    assert "npm test" in result.test_commands


@pytest.mark.asyncio
async def test_returns_empty_fingerprint_on_api_error():
    fp = RepositoryFingerprinter()

    async def mock_get(url, **kwargs):
        return httpx.Response(500, content=b"error")

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    result = await fp.build("owner", "repo", "token", client=client)
    assert result.language_stack == []
    assert result.commit_sha == ""
