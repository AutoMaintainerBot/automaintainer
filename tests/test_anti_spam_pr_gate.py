"""
Tests for Issue 3:
- AntiSpamManager gate enforced in PullRequestManager.open_pr().
- PullRequestManager tracks active PR on success.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from automaintainer.core.models import RiskTier
from automaintainer.github.pr_manager import PullRequestManager, AntiSpamBlockedError
from automaintainer.discovery.anti_spam import AntiSpamManager
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.validation.runner import ValidationReport, GateResult


def _make_plan() -> PlannerOutput:
    return PlannerOutput(
        objective="Update GitHub Actions",
        task_type="github_action_update",
        confidence=0.95,
        target_paths=[".github/workflows/ci.yml"],
        proposed_edits=[
            ProposedEdit(
                path=".github/workflows/ci.yml",
                operation="regex_replace",
                rationale="Bump checkout",
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[ValidationStep(command="yamllint .", reason="lint", expected_outcome="ok")],
        risk_tier=RiskTier.R1,
        requires_human_approval=False,
    )


def _make_validation_report() -> ValidationReport:
    return ValidationReport(
        session_id="sess_spam_test",
        passed=True,
        is_safety_stop=False,
        gate_results=[GateResult(gate_name="syntax", passed=True)],
        summary="All gates passed",
    )


@pytest.mark.asyncio
async def test_open_pr_blocked_when_opted_out():
    """Verify open_pr raises AntiSpamBlockedError when repo is on opt-out blacklist."""
    anti_spam = AntiSpamManager()
    anti_spam.register_opt_out("blocked-org/repo")

    executor = MagicMock()
    gateway = MagicMock()
    manager = PullRequestManager(gateway=gateway, executor=executor, anti_spam=anti_spam)

    with pytest.raises(AntiSpamBlockedError, match="opt-out"):
        await manager.open_pr(
            session_id="sess_optout",
            repository="blocked-org/repo",
            branch_name="automaintainer/sess_optout",
            base_branch="main",
            plan=_make_plan(),
            validation_report=_make_validation_report(),
            risk_tier=RiskTier.R1,
            installation_token="tok",
            expected_paths=[".github/workflows/ci.yml"],
        )


@pytest.mark.asyncio
async def test_open_pr_blocked_when_in_cooldown():
    """Verify open_pr raises AntiSpamBlockedError when repo is in cooling-off period."""
    anti_spam = AntiSpamManager(cooldown_days=14)
    anti_spam.record_pr_rejection("cool-org/repo", days=14)

    executor = MagicMock()
    gateway = MagicMock()
    manager = PullRequestManager(gateway=gateway, executor=executor, anti_spam=anti_spam)

    with pytest.raises(AntiSpamBlockedError, match="cooling-off period"):
        await manager.open_pr(
            session_id="sess_cooldown",
            repository="cool-org/repo",
            branch_name="automaintainer/sess_cooldown",
            base_branch="main",
            plan=_make_plan(),
            validation_report=_make_validation_report(),
            risk_tier=RiskTier.R1,
            installation_token="tok",
            expected_paths=[".github/workflows/ci.yml"],
        )


@pytest.mark.asyncio
async def test_open_pr_blocked_when_active_pr_limit_reached():
    """Verify open_pr raises AntiSpamBlockedError when active PR count >= max limit."""
    anti_spam = AntiSpamManager(max_active_prs_per_repo=1)
    anti_spam.track_active_pr("active-org/repo", pr_number=42)

    executor = MagicMock()
    gateway = MagicMock()
    manager = PullRequestManager(gateway=gateway, executor=executor, anti_spam=anti_spam)

    with pytest.raises(AntiSpamBlockedError, match="active PR"):
        await manager.open_pr(
            session_id="sess_active_limit",
            repository="active-org/repo",
            branch_name="automaintainer/sess_active_limit",
            base_branch="main",
            plan=_make_plan(),
            validation_report=_make_validation_report(),
            risk_tier=RiskTier.R1,
            installation_token="tok",
            expected_paths=[".github/workflows/ci.yml"],
        )


@pytest.mark.asyncio
async def test_open_pr_succeeds_and_tracks_active_pr():
    """Verify open_pr tracks active PR when anti-spam checks pass."""
    anti_spam = AntiSpamManager()

    executor = MagicMock()
    gateway = MagicMock()
    gateway.submit_mutation = AsyncMock(return_value={"number": 105, "url": "https://github.com/ok-org/repo/pull/105"})

    manager = PullRequestManager(gateway=gateway, executor=executor, anti_spam=anti_spam)

    res = await manager.open_pr(
        session_id="sess_success",
        repository="ok-org/repo",
        branch_name="automaintainer/sess_success",
        base_branch="main",
        plan=_make_plan(),
        validation_report=_make_validation_report(),
        risk_tier=RiskTier.R1,
        installation_token="tok",
        expected_paths=[".github/workflows/ci.yml"],
    )

    assert res["number"] == 105
    assert 105 in anti_spam._active_prs.get("ok-org/repo", set())


@pytest.mark.asyncio
async def test_open_pr_blocked_when_hourly_limit_reached():
    """Verify open_pr blocks after max_prs_per_hour (default: 2 PRs per hour)."""
    anti_spam = AntiSpamManager(max_prs_per_hour=2)

    # Record 2 PR creations within the past hour
    anti_spam.record_pr_created("org1/repo1", pr_number=1)
    anti_spam.record_pr_created("org2/repo2", pr_number=2)

    executor = MagicMock()
    gateway = MagicMock()
    manager = PullRequestManager(gateway=gateway, executor=executor, anti_spam=anti_spam)

    # Attempting to open a 3rd PR in the same hour must be blocked
    with pytest.raises(AntiSpamBlockedError, match="Hourly PR limit reached"):
        await manager.open_pr(
            session_id="sess_hourly_blocked",
            repository="org3/repo3",
            branch_name="automaintainer/sess_hourly_blocked",
            base_branch="main",
            plan=_make_plan(),
            validation_report=_make_validation_report(),
            risk_tier=RiskTier.R1,
            installation_token="tok",
            expected_paths=[".github/workflows/ci.yml"],
        )


@pytest.mark.asyncio
async def test_hourly_limit_resets_after_one_hour():
    """Verify PR creation succeeds after older timestamps expire (> 1 hour)."""
    import time

    anti_spam = AntiSpamManager(max_prs_per_hour=2)
    # 2 PRs created 70 minutes ago
    two_hours_ago = time.time() - 4200
    anti_spam._pr_creation_timestamps = [two_hours_ago, two_hours_ago + 10]

    can_open, reason = anti_spam.can_open_pr("org/new-repo")
    assert can_open is True
    assert reason == "OK"


@pytest.mark.asyncio
async def test_managed_repo_exempt_from_circuit_breaker():
    """Verify managed repositories are exempt from Global Rejection Circuit Breaker."""
    anti_spam = AntiSpamManager()
    # Simulate 10 rejections in the past 24 hours
    for _ in range(10):
        anti_spam.record_pr_rejection("some-other-org/some-repo")

    # For public / unmanaged repo, circuit breaker is tripped
    can_open_public, reason_public = anti_spam.can_open_pr("random-org/random-repo", is_managed=False)
    assert can_open_public is False
    assert "Global Rejection Circuit Breaker tripped" in reason_public

    # For operator-managed repo, circuit breaker is bypassed
    can_open_managed, reason_managed = anti_spam.can_open_pr("my-org/my-managed-repo", is_managed=True)
    assert can_open_managed is True
    assert reason_managed == "OK"


@pytest.mark.asyncio
async def test_managed_repo_relaxed_hourly_rate_limit():
    """Verify managed repositories have relaxed hourly limit compared to public unmanaged repos."""
    anti_spam = AntiSpamManager(max_prs_per_hour=2)
    anti_spam.record_pr_created("org1/repo1", pr_number=1)
    anti_spam.record_pr_created("org2/repo2", pr_number=2)

    # Public unmanaged repo is blocked at 2 PRs/hr
    can_open_public, reason_public = anti_spam.can_open_pr("random-org/random-repo", is_managed=False)
    assert can_open_public is False
    assert "Hourly PR limit reached" in reason_public

    # Managed repo allows up to 20 PRs/hr
    can_open_managed, reason_managed = anti_spam.can_open_pr("my-org/my-managed-repo", is_managed=True)
    assert can_open_managed is True
    assert reason_managed == "OK"


@pytest.mark.asyncio
async def test_set_active_prs_syncs_github_live_state():
    """Verify set_active_prs correctly sets and clears active PRs."""
    anti_spam = AntiSpamManager()
    repo = "my-org/repo"
    anti_spam.track_active_pr(repo, 99)
    assert anti_spam.get_active_prs(repo) == {99}

    # GitHub reports 0 open PRs -> sync clears it
    anti_spam.set_active_prs(repo, set())
    assert anti_spam.get_active_prs(repo) == set()
    can_open, reason = anti_spam.can_open_pr(repo, is_managed=True)
    assert can_open is True


