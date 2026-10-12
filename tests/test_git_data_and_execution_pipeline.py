import pytest
import httpx
from automaintainer.github.git_data_client import GitHubGitDataClient
from automaintainer.core.models import FileDiff, MutationIntent, MutationOp, PlannedDiff
from automaintainer.github.executor import GitHubExecutor
from automaintainer.validation.runner import ValidationRunner
from automaintainer.inference.schemas import PlannerOutput, ValidationStep
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.core.models import RiskTier

@pytest.mark.asyncio
async def test_git_data_client_push_pipeline(monkeypatch):
    """Verifies atomic Git Data API tree/commit/ref creation pipeline."""
    client = GitHubGitDataClient(token="ghp_fake_token")
    tree_payloads = []

    async def mock_get(url, *args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                if "/git/commits/" in url:
                    return {"tree": {"sha": "base_tree_sha_234"}}
                return {"object": {"sha": "head_parent_sha_123"}}
            def raise_for_status(self):
                pass
        return MockResp()

    async def mock_post(url, *args, **kwargs):
        if "/git/trees" in url:
            tree_payloads.append(kwargs.get("json"))

        class MockResp:
            status_code = 201
            def json(self):
                if "/git/blobs" in url:
                    return {"sha": "blob_sha_456"}
                elif "/git/trees" in url:
                    return {"sha": "tree_sha_789"}
                elif "/git/commits" in url:
                    return {"sha": "commit_sha_abc"}
                elif "/git/refs" in url:
                    return {"ref": "refs/heads/automaintainer/sess_1"}
                return {}
            def raise_for_status(self):
                pass
        return MockResp()

    async def mock_patch(url, *args, **kwargs):
        class MockResp:
            status_code = 200
            def json(self):
                return {"ref": "refs/heads/automaintainer/sess_1"}
            def raise_for_status(self):
                pass
        return MockResp()

    async_client = httpx.AsyncClient()
    monkeypatch.setattr(async_client, "get", mock_get)
    monkeypatch.setattr(async_client, "post", mock_post)
    monkeypatch.setattr(async_client, "patch", mock_patch)

    files = [FileDiff(path="README.md", content="# New Content\n")]
    res = await client.push_changes(
        owner="testowner",
        repo="testrepo",
        branch_name="automaintainer/sess_1",
        base_branch="main",
        files=files,
        commit_message="test: commit",
        client=async_client
    )

    assert res["commit_sha"] == "commit_sha_abc"
    assert res["tree_sha"] == "tree_sha_789"
    assert res["base_tree_sha"] == "base_tree_sha_234"
    assert res["parent_sha"] == "head_parent_sha_123"
    assert tree_payloads[0]["base_tree"] == "base_tree_sha_234"

@pytest.mark.asyncio
async def test_validation_runner_executes_sandbox_tests():
    """Verifies ValidationRunner executes test commands in sandbox."""
    sandbox = ContainerSandboxRuntime(use_docker=False)
    workspace = await sandbox.prepare_workspace("https://github.com/test/repo", "sha123")

    runner = ValidationRunner(sandbox=sandbox)
    plan = PlannerOutput(
        objective="Run python unit tests",
        task_type="test_repair",
        confidence=0.95,
        target_paths=["src/main.py"],
        proposed_edits=[],
        validation_steps=[
            ValidationStep(
                command="python -c \"print('test_suite_passed')\"",
                reason="Execute test suite",
                expected_outcome="exit 0"
            )
        ],
        risk_tier=RiskTier.R1
    )

    planned_diff = PlannedDiff(files=[FileDiff(path="src/main.py", lines_added=5)])
    new_contents = {"src/main.py": "print('ok')"}

    try:
        report = await runner.run(
            session_id="sess_test_val",
            plan=plan,
            planned_diff=planned_diff,
            new_file_contents=new_contents,
            workspace_id=workspace
        )

        assert report.passed is True
        test_gates = [g for g in report.gate_results if g.gate_name.startswith("test:")]
        assert len(test_gates) == 1
        assert test_gates[0].passed is True
        assert test_gates[0].exit_code == 0
    finally:
        await sandbox.destroy_workspace(workspace)
