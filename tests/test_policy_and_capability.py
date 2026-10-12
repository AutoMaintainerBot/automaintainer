import pytest
from automaintainer.core.models import (
    MutationIntent, MutationOp, SessionState, RiskTier, PlannedDiff, FileDiff, ResourceBoundCapability
)
from automaintainer.core.capability_broker import CapabilityBroker, CapabilityDeniedError
from automaintainer.core.policy_engine import PolicyEngine, PolicyViolation

def test_planner_cannot_request_git_mutations():
    intent = MutationIntent(
        session_id="sess_1",
        actor="planner",
        operation=MutationOp.CREATE_COMMIT,
        repository="owner/repo",
        branch="patch-1"
    )
    cap = ResourceBoundCapability(
        session_id="sess_1",
        repository_full_name="owner/repo",
        branch="patch-1",
        allowed_operations={MutationOp.CREATE_COMMIT},
        lease_epoch="epoch-1"
    )
    with pytest.raises(CapabilityDeniedError):
        CapabilityBroker.authorize_capability(intent, SessionState.PLANNING, actor_role="planner", capability=cap)

def test_patcher_can_request_commit_capability():
    intent = MutationIntent(
        session_id="sess_1",
        actor="patcher",
        operation=MutationOp.CREATE_COMMIT,
        repository="owner/repo",
        branch="patch-1"
    )
    cap = ResourceBoundCapability(
        session_id="sess_1",
        repository_full_name="owner/repo",
        branch="patch-1",
        allowed_operations={MutationOp.CREATE_COMMIT},
        lease_epoch="epoch-1"
    )
    assert CapabilityBroker.authorize_capability(intent, SessionState.WORKING, actor_role="patcher", capability=cap)

def test_policy_rejects_unexpected_files():
    engine = PolicyEngine()
    intent = MutationIntent(
        session_id="sess_1",
        actor="patcher",
        operation=MutationOp.CREATE_COMMIT,
        repository="owner/repo",
        branch="patch-1",
        diff=PlannedDiff(
            files=[
                FileDiff(path="package.json", lines_added=1, lines_deleted=1),
                FileDiff(path="unauthorized.py", lines_added=50, lines_deleted=0)
            ]
        )
    )
    passed, violations = engine.evaluate_post_policy(intent, expected_paths=["package.json"])
    assert not passed
    assert any("unexpected paths" in v for v in violations)

def test_policy_blocks_terminal_session_mutation():
    engine = PolicyEngine()
    intent = MutationIntent(
        session_id="sess_1",
        actor="patcher",
        operation=MutationOp.CREATE_COMMIT,
        repository="owner/repo",
        branch="patch-1"
    )
    passed, violations = engine.evaluate_pre_policy(intent, current_state=SessionState.MERGED)
    assert not passed
    assert any("terminal state" in v for v in violations)

def test_fork_capability_allows_commit_to_fork_and_pr_to_upstream():
    cap = ResourceBoundCapability(
        session_id="sess_fork_1",
        repository_full_name="AutoMaintainerBot/my-repo",
        upstream_repository_full_name="upstream-owner/my-repo",
        branch="automaintainer/sess_fork_1",
        allowed_operations={MutationOp.CREATE_BRANCH, MutationOp.CREATE_COMMIT, MutationOp.OPEN_PR},
        lease_epoch="epoch-1",
    )

    # 1. Commit to fork -> Allowed
    commit_intent = MutationIntent(
        session_id="sess_fork_1",
        actor="worker_daemon",
        operation=MutationOp.CREATE_COMMIT,
        repository="AutoMaintainerBot/my-repo",
        branch="automaintainer/sess_fork_1",
    )
    assert CapabilityBroker.authorize_capability(commit_intent, SessionState.WORKING, actor_role="patcher", capability=cap)

    # 2. Open PR on upstream -> Allowed
    pr_intent = MutationIntent(
        session_id="sess_fork_1",
        actor="pr_manager",
        operation=MutationOp.OPEN_PR,
        repository="upstream-owner/my-repo",
        branch="automaintainer/sess_fork_1",
    )
    assert CapabilityBroker.authorize_capability(pr_intent, SessionState.WORKING, actor_role="publisher", capability=cap)

def test_fork_capability_rejects_commit_to_upstream():
    cap = ResourceBoundCapability(
        session_id="sess_fork_1",
        repository_full_name="AutoMaintainerBot/my-repo",
        upstream_repository_full_name="upstream-owner/my-repo",
        branch="automaintainer/sess_fork_1",
        allowed_operations={MutationOp.CREATE_BRANCH, MutationOp.CREATE_COMMIT, MutationOp.OPEN_PR},
        lease_epoch="epoch-1",
    )

    # Direct commit attempt to upstream -> Rejected
    bad_commit_intent = MutationIntent(
        session_id="sess_fork_1",
        actor="worker_daemon",
        operation=MutationOp.CREATE_COMMIT,
        repository="upstream-owner/my-repo",
        branch="automaintainer/sess_fork_1",
    )
    with pytest.raises(CapabilityDeniedError, match="Direct mutation operation 'create_commit' is not permitted on upstream repository"):
        CapabilityBroker.authorize_capability(bad_commit_intent, SessionState.WORKING, actor_role="patcher", capability=cap)

def test_fork_capability_rejects_unrelated_repo():
    cap = ResourceBoundCapability(
        session_id="sess_fork_1",
        repository_full_name="AutoMaintainerBot/my-repo",
        upstream_repository_full_name="upstream-owner/my-repo",
        branch="automaintainer/sess_fork_1",
        allowed_operations={MutationOp.CREATE_BRANCH, MutationOp.CREATE_COMMIT, MutationOp.OPEN_PR},
        lease_epoch="epoch-1",
    )

    # Attempt against totally unrelated repository -> Rejected
    unrelated_intent = MutationIntent(
        session_id="sess_fork_1",
        actor="pr_manager",
        operation=MutationOp.OPEN_PR,
        repository="attacker/malicious-repo",
        branch="automaintainer/sess_fork_1",
    )
    with pytest.raises(CapabilityDeniedError, match="does not match capability repository"):
        CapabilityBroker.authorize_capability(unrelated_intent, SessionState.WORKING, actor_role="publisher", capability=cap)

