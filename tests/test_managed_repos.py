"""
Unit tests for Managed Repositories Ingestion & 20-Second Watcher Service.
Tests identifier normalization, file parsing, opportunity admission, and outbox scheduling.
"""
import os
import pytest
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from automaintainer.discovery.managed_repos import (
    normalize_repo_identifier,
    parse_managed_repos_file,
    ManagedRepoService,
)
from automaintainer.discovery.anti_spam import AntiSpamManager
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.core.models import RiskTier, TaskType
from automaintainer.data.tables import RepositoryRecord


def test_normalize_repo_identifier():
    # Standard owner/repo
    assert normalize_repo_identifier("alice/cool-project") == "alice/cool-project"
    
    # HTTPS GitHub URLs
    assert normalize_repo_identifier("https://github.com/alice/cool-project") == "alice/cool-project"
    assert normalize_repo_identifier("https://github.com/alice/cool-project.git") == "alice/cool-project"
    assert normalize_repo_identifier("http://github.com/alice/cool-project/") == "alice/cool-project"
    
    # SSH format
    assert normalize_repo_identifier("git@github.com:alice/cool-project.git") == "alice/cool-project"
    
    # Whitespace padding
    assert normalize_repo_identifier("   alice/cool-project   ") == "alice/cool-project"
    
    # Comments and empty lines
    assert normalize_repo_identifier("# This is a comment") is None
    assert normalize_repo_identifier("   # Indented comment") is None
    assert normalize_repo_identifier("") is None
    assert normalize_repo_identifier("   ") is None
    
    # Invalid strings
    assert normalize_repo_identifier("justareponame") is None
    assert normalize_repo_identifier("too/many/parts/here") is None


def test_parse_managed_repos_file():
    content = """
    # Managed repositories for AutoMaintainer
    octocat/Hello-World
    https://github.com/torvalds/linux
    
    # Duplicate entry
    octocat/Hello-World
    
    git@github.com:facebook/react.git
    # Invalid line
    singleword
    """
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        repos = parse_managed_repos_file(tmp_path)
        assert repos == ["octocat/hello-world", "torvalds/linux", "facebook/react"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_parse_managed_repos_file_yaml():
    yaml_content = """
    version: "1.0"
    repositories:
      - octocat/Hello-World
      - name: torvalds/linux
        branch: main
        enabled: true
      - name: disabled/project
        enabled: false
      - https://github.com/facebook/react.git
    """
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".yaml") as tmp:
        tmp.write(yaml_content)
        tmp_path = tmp.name

    try:
        repos = parse_managed_repos_file(tmp_path)
        assert repos == ["octocat/hello-world", "torvalds/linux", "facebook/react"]
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_parse_managed_repos_file_nonexistent():
    assert parse_managed_repos_file("nonexistent_file_path_12345.txt") == []



@pytest.mark.asyncio
async def test_managed_repo_service_skips_when_active_pr():
    """Verify that a repo with an active PR is skipped by anti-spam guard."""
    anti_spam = AntiSpamManager()
    anti_spam.track_active_pr("octocat/hello-world", 42)

    service = ManagedRepoService(anti_spam=anti_spam)
    mock_client = AsyncMock()

    with patch.object(service, "fetch_repo_metadata", new_callable=AsyncMock) as mock_fetch:
        results = await service.process_repository("octocat/hello-world", mock_client)
        assert results == []
        mock_fetch.assert_not_called()


@pytest.mark.asyncio
async def test_managed_repo_service_scans_and_enqueues():
    """Verify that when detectors find valid opportunities, they are scored and admitted."""
    anti_spam = AntiSpamManager()
    service = ManagedRepoService(anti_spam=anti_spam)
    
    fake_opp = DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        evidence=["actions/checkout@v3 is outdated; v4 is available"],
        target_paths=[".github/workflows/ci.yml"],
        risk_tier=RiskTier.R1,
        confidence=0.95,
        validation_recipe=["yamllint .github/workflows/ci.yml"],
        summary="Bump actions/checkout to v4",
        metadata={"file": ".github/workflows/ci.yml"},
    )

    mock_client = AsyncMock()
    repo_meta = {
        "id": 12345,
        "archived": False,
        "disabled": False,
        "default_branch": "main",
        "clone_url": "https://github.com/octocat/hello-world.git",
    }

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock()
    mock_db.commit = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.refresh = AsyncMock()
    mock_db.add = MagicMock()

    mock_existing_repo = RepositoryRecord(
        id=101,
        github_repo_id=12345,
        owner="octocat",
        name="hello-world",
        visibility="public",
        default_branch="main"
    )
    mock_scalars = MagicMock()
    mock_scalars.first.return_value = mock_existing_repo
    mock_result = MagicMock()
    mock_result.scalars.return_value = mock_scalars
    mock_db.execute.return_value = mock_result

    mock_db_ctx = MagicMock()
    mock_db_ctx.__aenter__.return_value = mock_db
    mock_db_ctx.__aexit__.return_value = None

    mock_db_mgr = MagicMock()
    mock_db_mgr.get_session.return_value = mock_db_ctx

    from automaintainer.discovery.repo_health import RepoHealthScore

    mock_health = RepoHealthScore(
        total=90.0,
        maintainer_activity=25.0,
        ci_maturity=25.0,
        community=20.0,
        project_health=20.0,
        is_eligible=True,
    )

    mock_queue = MagicMock()
    service = ManagedRepoService(anti_spam=anti_spam, queue=mock_queue)

    with patch.object(service, "fetch_repo_metadata", new_callable=AsyncMock, return_value=repo_meta), \
         patch.object(service.health_scorer, "score", new_callable=AsyncMock, return_value=mock_health), \
         patch.object(service, "scan_repo_opportunities", new_callable=AsyncMock, return_value=[fake_opp]), \
         patch("automaintainer.discovery.managed_repos.get_db_manager", return_value=mock_db_mgr):

        sessions = await service.process_repository("octocat/hello-world", mock_client, force_rescan=True)
        assert len(sessions) == 1
        assert sessions[0]["repository"] == "octocat/hello-world"
        assert mock_db.commit.called
        assert mock_queue.enqueue.called


@pytest.mark.asyncio
async def test_dry_run_repository_audit_success():
    """Verify POST /v1/public/managed-repos/dry-run returns detected chores and diff without write permissions."""
    from httpx import ASGITransport, AsyncClient, Response
    from automaintainer.app.main import app

    transport = ASGITransport(app=app)
    fake_github_repo = {
        "stargazers_count": 420,
        "default_branch": "main",
        "description": "Awesome open source project",
        "private": False,
    }

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = Response(200, json=fake_github_repo)
            res = await client.post(
                "/v1/public/managed-repos/dry-run",
                json={"repository": "octocat/hello-world"}
            )
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "ok"
            assert data["repository"] == "octocat/hello-world"
            assert data["stars"] == 420
            assert data["default_branch"] == "main"
            assert data["chores_count"] >= 1
            assert "sample_diff" in data
            assert data["write_permission_needed"] is False
            assert data["safe_to_automate"] is True


@pytest.mark.asyncio
async def test_dry_run_repository_audit_invalid_and_private():
    """Verify POST /v1/public/managed-repos/dry-run rejects invalid formats and private repos."""
    from httpx import ASGITransport, AsyncClient, Response
    from automaintainer.app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Invalid format
        res_bad = await client.post(
            "/v1/public/managed-repos/dry-run",
            json={"repository": "invalid_format"}
        )
        assert res_bad.status_code == 400

        # Private repo rejected
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = Response(200, json={"private": True})
            res_priv = await client.post(
                "/v1/public/managed-repos/dry-run",
                json={"repository": "secret/private-repo"}
            )
            assert res_priv.status_code == 400
            assert "private" in res_priv.json()["detail"].lower()

