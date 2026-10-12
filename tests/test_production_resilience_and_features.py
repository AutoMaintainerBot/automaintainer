import asyncio
import json
import os
import tempfile
import time
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from automaintainer.core.models import FileDiff, MutationIntent, MutationOp, SessionState
from automaintainer.github.git_data_client import (
    GitHubGitDataClient,
    MergeConflictError,
    GitHubRateLimitError,
    UpstreamDriftError,
)
from automaintainer.github.executor import GitHubExecutor
from automaintainer.inference.batch_client import (
    GroqBatchClient,
    GroqBatchProcessor,
    BatchRequestItem,
)
from automaintainer.discovery.lockfile_detector import LockfileRefreshDetector
from automaintainer.discovery.opportunity_detectors import (
    DependencyMetadataDetector,
    LockfileOpportunityDetector,
)
from automaintainer.discovery.candidate_crawler import CandidateCrawler
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.queue.lease import QueuedJob, JobStatus



@pytest.mark.asyncio
async def test_push_changes_raises_merge_conflict_on_colliding_upstream_commits():
    """Verify push_changes detects collisions between candidate patch and upstream commits."""
    client_git = GitHubGitDataClient(token="ghs_test", api_base_url="https://mock.github")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        if "/git/ref/heads/main" in url:
            return httpx.Response(200, json={"object": {"sha": "sha_upstream_advanced"}})
        if "/compare/sha_initial_checkout...sha_upstream_advanced" in url:
            return httpx.Response(200, json={
                "status": "ahead",
                "files": [
                    {"filename": "package.json", "status": "modified"},
                    {"filename": "src/index.ts", "status": "modified"}
                ]
            })
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        with pytest.raises(MergeConflictError) as excinfo:
            await client_git.push_changes(
                owner="org",
                repo="repo",
                branch_name="automaintainer/sess_1",
                base_branch="main",
                files=[FileDiff(path="package.json", content='{"name": "test"}')],
                commit_message="update package.json",
                initial_base_sha="sha_initial_checkout",
                client=mock_client
            )
        assert "Merge conflict detected on upstream update" in str(excinfo.value)
        assert "package.json" in str(excinfo.value)


@pytest.mark.asyncio
async def test_push_changes_raises_upstream_drift_error_when_revalidation_required():
    """Verify push_changes raises UpstreamDriftError when upstream drifts and require_revalidation_on_drift=True (default)."""
    client_git = GitHubGitDataClient(token="ghs_test", api_base_url="https://mock.github")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        if "/git/ref/heads/main" in url:
            return httpx.Response(200, json={"object": {"sha": "sha_upstream_advanced"}})
        if "/compare/sha_initial_checkout...sha_upstream_advanced" in url:
            return httpx.Response(200, json={
                "status": "ahead",
                "files": [
                    {"filename": "README.md", "status": "modified"}
                ]
            })
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        with pytest.raises(UpstreamDriftError) as excinfo:
            await client_git.push_changes(
                owner="org",
                repo="repo",
                branch_name="automaintainer/sess_1",
                base_branch="main",
                files=[FileDiff(path="package.json", content='{"name": "test"}')],
                commit_message="update package.json",
                initial_base_sha="sha_initial_checkout",
                client=mock_client
            )
        assert "sha_upst" in str(excinfo.value)
        assert excinfo.value.current_head_sha == "sha_upstream_advanced"


@pytest.mark.asyncio
async def test_push_changes_cleanly_rebases_when_upstream_drift_is_disjoint():
    """Verify push_changes rebases cleanly onto advanced parent SHA when files do not collide and require_revalidation_on_drift=False."""
    client_git = GitHubGitDataClient(token="ghs_test", api_base_url="https://mock.github")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        if "/git/ref/heads/main" in url:
            return httpx.Response(200, json={"object": {"sha": "sha_upstream_advanced"}})
        if "/compare/sha_initial_checkout...sha_upstream_advanced" in url:
            return httpx.Response(200, json={
                "status": "ahead",
                "files": [
                    {"filename": "README.md", "status": "modified"}
                ]
            })
        if "/git/commits/sha_upstream_advanced" in url:
            return httpx.Response(200, json={"tree": {"sha": "tree_advanced"}})
        if "/git/blobs" in url:
            return httpx.Response(201, json={"sha": "blob_sha_1"})
        if "/git/trees" in url:
            return httpx.Response(201, json={"sha": "tree_new_sha"})
        if "/git/commits" in url:
            return httpx.Response(201, json={"sha": "commit_new_sha"})
        if "/git/refs/heads/automaintainer/sess_1" in url:
            return httpx.Response(200, json={"ref": "refs/heads/automaintainer/sess_1"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        res = await client_git.push_changes(
            owner="org",
            repo="repo",
            branch_name="automaintainer/sess_1",
            base_branch="main",
            files=[FileDiff(path="package.json", content='{"name": "test"}')],
            commit_message="update package.json",
            initial_base_sha="sha_initial_checkout",
            require_revalidation_on_drift=False,
            client=mock_client
        )
        assert res["commit_sha"] == "commit_new_sha"
        assert res["parent_sha"] == "sha_upstream_advanced"
        assert res["rebased_on_drift"] is True



@pytest.mark.asyncio
async def test_github_secondary_rate_limit_backoff_and_retry_success(monkeypatch):
    """Verify executor catches 403 secondary rate limit, parses Retry-After, sleeps, and succeeds."""
    mock_sleep = AsyncMock()
    monkeypatch.setattr("automaintainer.github.executor.asyncio.sleep", mock_sleep)
    monkeypatch.setattr("automaintainer.github.git_data_client.asyncio.sleep", mock_sleep)
    executor = GitHubExecutor(token="ghs_test", api_base_url="https://mock.github")
    call_count = 0

    def mock_transport(request: httpx.Request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(
                403,
                headers={"retry-after": "0.05"},
                text="You have exceeded a secondary rate limit. Please wait a few minutes before you try again."
            )
        return httpx.Response(201, json={"number": 42, "html_url": "https://github.com/org/repo/pull/42"})

    intent = MutationIntent(
        session_id="sess_ratelimit",
        actor="test",
        operation=MutationOp.OPEN_PR,
        repository="org/repo",
        branch="automaintainer/sess_ratelimit",
        pr_title="test",
        pr_body="test"
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        res = await executor.execute_mutation(intent, client=mock_client)
        assert res.get("number") == 42
        assert call_count == 2
        assert mock_sleep.called


@pytest.mark.asyncio
async def test_github_rate_limit_exhaustion_raises_github_rate_limit_error(monkeypatch):
    """Verify persistent rate limiting raises typed GitHubRateLimitError after retries exhausted."""
    mock_sleep = AsyncMock()
    monkeypatch.setattr("automaintainer.github.executor.asyncio.sleep", mock_sleep)
    monkeypatch.setattr("automaintainer.github.git_data_client.asyncio.sleep", mock_sleep)
    executor = GitHubExecutor(token="ghs_test", api_base_url="https://mock.github")

    def mock_transport(request: httpx.Request):
        return httpx.Response(
            429,
            headers={"retry-after": "0.01"},
            text="Too Many Requests"
        )

    intent = MutationIntent(
        session_id="sess_ratelimit_fail",
        actor="test",
        operation=MutationOp.OPEN_PR,
        repository="org/repo",
        branch="automaintainer/sess_ratelimit_fail",
        pr_title="test",
        pr_body="test"
    )

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        with pytest.raises(GitHubRateLimitError):
            await executor.execute_mutation(intent, client=mock_client)



@pytest.mark.asyncio
async def test_groq_batch_client_submit_and_poll():
    """Verify GroqBatchClient submit, status polling, and cancellation."""
    batch_client = GroqBatchClient(api_key="gsk_test", api_base_url="https://mock.groq/openai/v1")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        method = request.method.upper()
        if method == "POST" and url.endswith("/batches"):
            return httpx.Response(201, json={"id": "batch_test_123", "status": "validating"})
        if method == "GET" and "/batches/batch_test_123" in url:
            return httpx.Response(200, json={"id": "batch_test_123", "status": "completed", "output_file_id": "file_out_1"})
        if method == "POST" and "/batches/batch_test_123/cancel" in url:
            return httpx.Response(200, json={"id": "batch_test_123", "status": "cancelling"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        items = [BatchRequestItem(custom_id="req_1", body={"model": "llama-3.1-8b-instant"})]
        sub = await batch_client.submit_batch(items, client=mock_client)
        assert sub["id"] == "batch_test_123"

        status = await batch_client.get_batch_status("batch_test_123", client=mock_client)
        assert status["status"] == "completed"

        cancel = await batch_client.cancel_batch("batch_test_123", client=mock_client)
        assert cancel["status"] == "cancelling"


@pytest.mark.asyncio
async def test_groq_batch_processor_candidate_offline_pipeline():
    """Verify end-to-end GroqBatchProcessor candidate batch triage."""
    processor = GroqBatchProcessor(api_key="gsk_test", api_base_url="https://mock.groq/openai/v1")

    batch_output_jsonl = (
        '{"custom_id": "cand_101", "response": {"status_code": 200, "body": {"choices": [{"message": {"content": "{\\"maintenance_suitability\\": 0.92, \\"recommended_focus\\": \\"actions\\", \\"rationale\\": \\"healthy repo\\"}"}}]}}}\n'
    )

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        method = request.method.upper()
        if method == "POST" and url.endswith("/batches"):
            return httpx.Response(201, json={"id": "batch_candidates_999", "status": "in_progress"})
        if method == "GET" and "/batches/batch_candidates_999" in url:
            return httpx.Response(200, json={"id": "batch_candidates_999", "status": "completed", "output_file_id": "file_eval_999"})
        if method == "GET" and "/files/file_eval_999/content" in url:
            return httpx.Response(200, text=batch_output_jsonl)
        return httpx.Response(404)

    candidates = [
        {"id": 101, "full_name": "org/alpha", "description": "Core lib", "language": "Python", "stars": 500}
    ]

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        enriched = await processor.process_candidates_offline(
            candidates,
            poll_interval=0.01,
            timeout=5.0,
            client=mock_client
        )
        assert len(enriched) == 1
        assert "batch_evaluation" in enriched[0]
        assert enriched[0]["batch_evaluation"]["maintenance_suitability"] == 0.92
        assert enriched[0]["batch_evaluation"]["recommended_focus"] == "actions"



def test_monorepo_lockfile_detection_across_subdirectories():
    """Verify LockfileRefreshDetector detects manifests in subdirectories with scoped commands."""
    monorepo_files = [
        "README.md",
        "packages/frontend/package.json",
        "packages/backend/pyproject.toml",
        "crates/core/Cargo.toml",
        "node_modules/bad_dep/package.json",  # Must be ignored
    ]

    opps = LockfileRefreshDetector.detect_lockfile_opportunities(monorepo_files)
    assert len(opps) == 3

    opp_map = {o.manifest_path: o for o in opps}
    assert "packages/frontend/package.json" in opp_map
    assert opp_map["packages/frontend/package.json"].lockfile_path == "packages/frontend/package-lock.json"
    assert "npm --prefix packages/frontend install" in opp_map["packages/frontend/package.json"].regenerate_cmd

    assert "packages/backend/pyproject.toml" in opp_map
    assert opp_map["packages/backend/pyproject.toml"].lockfile_path == "packages/backend/poetry.lock"
    assert "cd packages/backend && poetry lock" in opp_map["packages/backend/pyproject.toml"].regenerate_cmd

    assert "crates/core/Cargo.toml" in opp_map
    assert opp_map["crates/core/Cargo.toml"].lockfile_path == "crates/core/Cargo.lock"
    assert "--manifest-path crates/core/Cargo.toml" in opp_map["crates/core/Cargo.toml"].regenerate_cmd


@pytest.mark.asyncio
async def test_monorepo_dependency_metadata_detector_subprojects():
    """Verify DependencyMetadataDetector scans duplicate dependencies in monorepo subprojects."""
    detector = DependencyMetadataDetector(api_base_url="https://mock.github")

    import base64
    content = "flask==2.0.1\nrequests>=2.25.0\nFlask==2.0.1\n"
    b64_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")

    def mock_transport(request: httpx.Request):
        url = str(request.url)
        if "/git/trees/HEAD" in url:
            return httpx.Response(200, json={
                "tree": [
                    {"path": "services/auth/requirements.txt", "type": "blob"},
                    {"path": "services/billing/requirements.txt", "type": "blob"}
                ]
            })
        if "/contents/services/auth/requirements.txt" in url:
            return httpx.Response(200, json={"content": b64_content})
        if "/contents/services/billing/requirements.txt" in url:
            clean_b64 = base64.b64encode(b"requests==2.28.0\n").decode("utf-8")
            return httpx.Response(200, json={"content": clean_b64})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)) as mock_client:
        opps = await detector.detect(owner="org", repo="monorepo", token="ghs_test", client=mock_client)
        assert len(opps) == 1
        assert opps[0].target_paths == ["services/auth/requirements.txt"]
        assert "flask" in opps[0].summary.lower()



@pytest.mark.asyncio
async def test_cleanup_stale_workspaces_removes_old_and_preserves_fresh():
    """Verify ContainerSandboxRuntime sweeps orphaned workspaces older than TTL."""
    runtime = ContainerSandboxRuntime(use_docker=False)
    temp_base = tempfile.gettempdir()

    stale_dir = tempfile.mkdtemp(prefix="automaintainer_ws_stale_")
    fresh_dir = tempfile.mkdtemp(prefix="automaintainer_ws_fresh_")

    try:
        two_hours_ago = time.time() - 7200
        os.utime(stale_dir, (two_hours_ago, two_hours_ago))

        cleaned = await runtime.cleanup_stale_workspaces(max_age_seconds=3600)
        assert cleaned >= 1
        assert not os.path.exists(stale_dir), "Expected stale workspace to be swept"
        assert os.path.exists(fresh_dir), "Expected fresh workspace to be preserved"
    finally:
        if os.path.exists(stale_dir):
            import shutil
            shutil.rmtree(stale_dir, ignore_errors=True)
        if os.path.exists(fresh_dir):
            import shutil
            shutil.rmtree(fresh_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_worker_daemon_startup_triggers_workspace_sweep():
    """Verify WorkerDaemon executes startup sweep upon start()."""
    mock_sandbox = MagicMock()
    mock_sandbox.cleanup_stale_workspaces = AsyncMock(return_value=3)

    daemon = WorkerDaemon(sandbox=mock_sandbox)
    await daemon.start(poll_interval=0.01, max_iterations=1)

    assert mock_sandbox.cleanup_stale_workspaces.called
