"""Tests for OpportunityScorer formula and threshold decisions."""
import pytest

from automaintainer.core.models import TaskType, RiskTier
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.discovery.opportunity_scorer import OpportunityScorer, ThresholdDecision
from automaintainer.discovery.repo_health import RepoHealthScore, RepoHealthSignals


def _make_health(total: float, activity: float = 80.0, is_eligible: bool = True) -> RepoHealthScore:
    return RepoHealthScore(
        total=total,
        maintainer_activity=activity,
        ci_maturity=80.0,
        community=50.0,
        project_health=70.0,
        signals=RepoHealthSignals(recent_commit_days=10, has_ci_workflows=True),
        is_eligible=is_eligible,
        ineligibility_reason=None if is_eligible else "archived",
    )


def _make_opportunity(
    confidence: float = 0.95,
    risk_tier: RiskTier = RiskTier.R1,
    target_paths=None,
) -> DetectedOpportunity:
    return DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        evidence=["actions/checkout@v2 → v4"],
        target_paths=target_paths or [".github/workflows/ci.yml"],
        risk_tier=risk_tier,
        confidence=confidence,
        validation_recipe=["yamllint .github/workflows/"],
        summary="Outdated GitHub Actions",
    )


scorer = OpportunityScorer()


def test_high_confidence_low_risk_allows_autonomous():
    opp = _make_opportunity(confidence=0.95, risk_tier=RiskTier.R1)
    health = _make_health(total=85.0, activity=90.0)
    result = scorer.score(opp, health)

    assert result.threshold_decision == ThresholdDecision.ALLOW_AUTONOMOUS
    assert not result.requires_human_approval
    assert result.opportunity_score >= 0.70


def test_medium_confidence_allows_with_review():
    opp = _make_opportunity(confidence=0.55, risk_tier=RiskTier.R2)
    health = _make_health(total=60.0, activity=60.0)
    result = scorer.score(opp, health)

    assert result.threshold_decision in (
        ThresholdDecision.ALLOW_WITH_REVIEW,
        ThresholdDecision.PROPOSE_OR_SKIP,
    )


def test_low_confidence_proposes_or_skips():
    opp = _make_opportunity(confidence=0.30, risk_tier=RiskTier.R2)
    health = _make_health(total=30.0, activity=20.0)
    result = scorer.score(opp, health)

    assert result.threshold_decision in (
        ThresholdDecision.PROPOSE_OR_SKIP,
        ThresholdDecision.REJECT,
    )


def test_ineligible_repo_always_rejects():
    opp = _make_opportunity(confidence=0.99, risk_tier=RiskTier.R0)
    health = _make_health(total=0.0, is_eligible=False)
    result = scorer.score(opp, health)

    assert result.threshold_decision == ThresholdDecision.REJECT
    assert result.opportunity_score == 0.0


def test_r4_risk_always_rejects():
    opp = _make_opportunity(confidence=0.99, risk_tier=RiskTier.R4)
    health = _make_health(total=100.0, activity=100.0)
    result = scorer.score(opp, health)

    assert result.threshold_decision == ThresholdDecision.REJECT


def test_r5_risk_always_rejects():
    opp = _make_opportunity(confidence=0.99, risk_tier=RiskTier.R5)
    health = _make_health(total=100.0)
    result = scorer.score(opp, health)

    assert result.threshold_decision == ThresholdDecision.REJECT


def test_score_breakdown_is_present():
    opp = _make_opportunity()
    health = _make_health(total=75.0)
    result = scorer.score(opp, health)

    assert "final_score" in result.score_breakdown
    assert "risk_penalty" in result.score_breakdown
    assert 0.0 <= result.opportunity_score <= 1.0


def test_many_target_paths_reduces_change_value():
    paths_1 = [".github/workflows/ci.yml"]
    paths_many = [f"file_{i}.py" for i in range(10)]

    opp_1    = _make_opportunity(confidence=0.95, target_paths=paths_1)
    opp_many = _make_opportunity(confidence=0.95, target_paths=paths_many)
    health   = _make_health(total=85.0, activity=90.0)

    r1 = scorer.score(opp_1, health)
    r2 = scorer.score(opp_many, health)

    assert r1.opportunity_score > r2.opportunity_score
