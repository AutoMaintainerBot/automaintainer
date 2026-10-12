import base64
import pytest
import httpx
from automaintainer.discovery.opportunity_detectors import PackageMetadataDetector


@pytest.mark.asyncio
async def test_package_metadata_detector_discovers_nested_pyproject_in_monorepo():
    """Verify PackageMetadataDetector scans nested pyproject.toml in monorepo packages."""
    detector = PackageMetadataDetector(api_base_url="https://mock.github")

    bad_pyproject = """[project]
name = "sub-package"
version = "0.0.0"
"""
    b64_bad = base64.b64encode(bad_pyproject.encode("utf-8")).decode("utf-8")

    good_pyproject = """[project]
name = "root-package"
version = "1.0.0"
description = "Good root package"
license = "MIT"
requires-python = ">=3.10"
readme = "README.md"
"""
    b64_good = base64.b64encode(good_pyproject.encode("utf-8")).decode("utf-8")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        if "/git/trees/HEAD" in url:
            return httpx.Response(200, json={
                "tree": [
                    {"path": "pyproject.toml", "type": "blob"},
                    {"path": "packages/service_a/pyproject.toml", "type": "blob"},
                    {"path": ".venv/lib/pyproject.toml", "type": "blob"},  # ignored
                ]
            })
        if "/contents/pyproject.toml" in url:
            return httpx.Response(200, json={"content": b64_good})
        if "/contents/packages/service_a/pyproject.toml" in url:
            return httpx.Response(200, json={"content": b64_bad})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        opps = await detector.detect("org", "monorepo", "ghp_tok", client=mock_client)

    assert len(opps) == 1
    assert opps[0].target_paths == ["packages/service_a/pyproject.toml"]
    assert "packages/service_a/pyproject.toml" in opps[0].summary
    assert any("license" in issue.lower() for issue in opps[0].evidence)
    assert any("packages/service_a" in r for r in opps[0].validation_recipe)
