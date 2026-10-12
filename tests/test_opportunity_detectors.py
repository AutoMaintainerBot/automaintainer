"""Tests for the 4 v1 opportunity detectors (all deterministic, no live HTTP)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from automaintainer.discovery.opportunity_detectors import (
    GitHubActionsVersionDetector,
    BrokenDocLinkDetector,
    PackageMetadataDetector,
    DependencyMetadataDetector,
    DetectedOpportunity,
)
from automaintainer.core.models import TaskType, RiskTier



def _make_response(status_code: int, json_data=None, text: str = "") -> httpx.Response:
    content = text.encode() if text else b""
    resp = httpx.Response(status_code, content=content)
    if json_data is not None:
        import json
        resp = httpx.Response(status_code, content=json.dumps(json_data).encode())
    return resp



WORKFLOW_OUTDATED = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v4
      - uses: actions/cache@v3
"""

WORKFLOW_CURRENT = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
"""


@pytest.mark.asyncio
async def test_actions_detector_finds_outdated_versions():
    detector = GitHubActionsVersionDetector()
    wf_list = [{"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml",
                "download_url": "https://raw.example.com/ci.yml"}]

    async def mock_get(url, **kwargs):
        url_str = str(url)
        if "contents/.github/workflows" in url_str:
            return _make_response(200, wf_list)
        if "raw.example.com" in url_str or "ci.yml" in url_str:
            import httpx as _httpx
            return _httpx.Response(200, text=WORKFLOW_OUTDATED)
        return _make_response(404)

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)

    assert len(results) == 1
    opp = results[0]
    assert opp.task_type == TaskType.GITHUB_ACTION_UPDATE
    assert opp.risk_tier == RiskTier.R1
    assert opp.confidence >= 0.9
    assert any("actions/checkout" in e for e in opp.evidence)
    assert any("v2" in e for e in opp.evidence)


@pytest.mark.asyncio
async def test_actions_detector_no_outdated_when_current():
    detector = GitHubActionsVersionDetector()
    wf_list = [{"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml",
                "download_url": "https://raw.example.com/ci.yml"}]

    async def mock_get(url, **kwargs):
        if "contents/.github/workflows" in url:
            return _make_response(200, wf_list)
        if "raw.example.com" in url:
            return _make_response(200, text=WORKFLOW_CURRENT)
        return _make_response(404)

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert results == []


@pytest.mark.asyncio
async def test_actions_detector_no_workflows_returns_empty():
    detector = GitHubActionsVersionDetector()

    async def mock_get(url, **kwargs):
        return _make_response(404)

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert results == []



import base64

README_WITH_BROKEN_LINK = "[Guide](docs/setup.md) and [Missing](nonexistent/file.md)"


@pytest.mark.asyncio
async def test_doc_link_detector_finds_broken_links():
    detector = BrokenDocLinkDetector()

    tree_data = {
        "tree": [
            {"path": "README.md", "type": "blob"},
            {"path": "docs/setup.md", "type": "blob"},
        ]
    }
    encoded = base64.b64encode(README_WITH_BROKEN_LINK.encode()).decode()
    readme_content = {"content": encoded, "encoding": "base64"}

    async def mock_get(url, **kwargs):
        if "git/trees" in url:
            return _make_response(200, tree_data)
        if "README.md" in url:
            return _make_response(200, readme_content)
        return _make_response(404)

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert len(results) == 1
    assert results[0].task_type == TaskType.DOCS_LINK_FIX
    assert any("nonexistent/file.md" in e for e in results[0].evidence)


@pytest.mark.asyncio
async def test_doc_link_detector_ignores_http_links():
    detector = BrokenDocLinkDetector()
    text = "[GitHub](https://github.com) and [Docs](https://docs.python.org)"
    encoded = base64.b64encode(text.encode()).decode()

    tree_data = {"tree": [{"path": "README.md", "type": "blob"}]}

    async def mock_get(url, **kwargs):
        if "git/trees" in url:
            return _make_response(200, tree_data)
        if "README.md" in url:
            return _make_response(200, {"content": encoded, "encoding": "base64"})
        return _make_response(404)

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert results == []   # http links are not checked



PYPROJECT_MISSING_FIELDS = """
[project]
name = "mypackage"
version = "0.0.0"
"""

PYPROJECT_COMPLETE = """
[project]
name = "mypackage"
version = "1.0.0"
description = "My package"
license = {text = "MIT"}
requires-python = ">=3.11"
readme = "README.md"
"""


@pytest.mark.asyncio
async def test_package_metadata_detector_finds_issues():
    detector = PackageMetadataDetector()
    encoded = base64.b64encode(PYPROJECT_MISSING_FIELDS.encode()).decode()

    async def mock_get(url, **kwargs):
        return _make_response(200, {"content": encoded, "encoding": "base64"})

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert len(results) == 1
    opp = results[0]
    assert opp.task_type == TaskType.PACKAGE_METADATA
    assert any("placeholder" in e.lower() or "0.0.0" in e for e in opp.evidence)


@pytest.mark.asyncio
async def test_package_metadata_detector_no_issues_when_complete():
    detector = PackageMetadataDetector()
    encoded = base64.b64encode(PYPROJECT_COMPLETE.encode()).decode()

    async def mock_get(url, **kwargs):
        return _make_response(200, {"content": encoded, "encoding": "base64"})

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert results == []



REQUIREMENTS_WITH_DUPLICATES = """
requests>=2.28.0
flask==3.0.0
requests>=2.30.0
pytest>=8.0
"""


@pytest.mark.asyncio
async def test_dependency_detector_finds_duplicates():
    detector = DependencyMetadataDetector()
    encoded = base64.b64encode(REQUIREMENTS_WITH_DUPLICATES.encode()).decode()

    async def mock_get(url, **kwargs):
        return _make_response(200, {"content": encoded, "encoding": "base64"})

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert len(results) == 1
    assert "requests" in results[0].evidence[0].lower()


@pytest.mark.asyncio
async def test_dependency_detector_no_duplicates():
    detector = DependencyMetadataDetector()
    clean = "requests>=2.28.0\nflask==3.0.0\npytest>=8.0\n"
    encoded = base64.b64encode(clean.encode()).decode()

    async def mock_get(url, **kwargs):
        return _make_response(200, {"content": encoded, "encoding": "base64"})

    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=mock_get)

    results = await detector.detect("owner", "repo", "token", client=client)
    assert results == []
