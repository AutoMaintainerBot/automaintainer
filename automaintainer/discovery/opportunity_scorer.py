"""
Opportunity Scorer.
Implements the weighted formula and returns a threshold decision.

OpportunityScore = 0.20 * RepoHealth
                 + 0.15 * MaintainerActivity
                 + 0.20 * ProblemClarity
                 + 0.20 * FixConfidence
                 + 0.10 * ValidationStrength
                 + 0.10 * ChangeValue
                 - 0.05 * RiskPenalty
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from automaintainer.core.models import RiskTier
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.discovery.repo_health import RepoHealthScore


class ThresholdDecision(str, Enum):
    ALLOW_AUTONOMOUS   = "ALLOW_AUTONOMOUS"    # score >= 0.70 and risk <= R2
    ALLOW_WITH_REVIEW  = "ALLOW_WITH_REVIEW"   # score >= 0.50 and risk <= R3
    PROPOSE_OR_SKIP    = "PROPOSE_OR_SKIP"     # score < 0.50
    REJECT             = "REJECT"              # hard disqualification


@dataclass
class ScoredOpportunity:
    opportunity: DetectedOpportunity
    repo_health_score: float        # 0–100 normalised to 0–1 inside formula
    opportunity_score: float        # final weighted 0–1 score
    threshold_decision: ThresholdDecision
    requires_human_approval: bool
    score_breakdown: dict           # individual component values for audit


_RISK_PENALTY: dict = {
    RiskTier.R0: 0.0,
    RiskTier.R1: 0.0,
    RiskTier.R2: 0.1,
    RiskTier.R3: 0.3,
    RiskTier.R4: 1.0,   # blocked at policy layer; penalty ensures rejection here too
    RiskTier.R5: 1.0,
}

# Risk tier → maximum autonomous trust level
_MAX_AUTONOMOUS_RISK = RiskTier.R2


class OpportunityScorer:
    """
    Computes the weighted opportunity score and determines the
    threshold decision for a given detected opportunity + repo health score.

    Inputs from caller:
      - repo_health_score  (0–100, from RepositoryHealthScorer)
      - opportunity         (DetectedOpportunity from a detector)

    Derived inputs (computed internally from the opportunity fields):
      - MaintainerActivity: derived from repo_health.maintainer_activity
      - ProblemClarity:     opportunity.confidence * weight (confidence signals specificity)
      - FixConfidence:      opportunity.confidence (detector's own confidence)
      - ValidationStrength: 1.0 if validation_recipe is non-empty, else 0.5
      - ChangeValue:        inverse of number of target paths (fewer = cleaner)
      - RiskPenalty:        _RISK_PENALTY[opportunity.risk_tier]
    """

    def score(
        self,
        opportunity: DetectedOpportunity,
        repo_health: RepoHealthScore,
    ) -> ScoredOpportunity:
        # Hard reject if repo is ineligible
        if not repo_health.is_eligible:
            return ScoredOpportunity(
                opportunity=opportunity,
                repo_health_score=0.0,
                opportunity_score=0.0,
                threshold_decision=ThresholdDecision.REJECT,
                requires_human_approval=False,
                score_breakdown={"reason": repo_health.ineligibility_reason},
            )

        # Hard reject R4/R5
        if opportunity.risk_tier in (RiskTier.R4, RiskTier.R5):
            return ScoredOpportunity(
                opportunity=opportunity,
                repo_health_score=repo_health.total / 100.0,
                opportunity_score=0.0,
                threshold_decision=ThresholdDecision.REJECT,
                requires_human_approval=False,
                score_breakdown={"reason": f"Risk tier {opportunity.risk_tier} is forbidden"},
            )

        repo_health_norm      = repo_health.total / 100.0
        maintainer_activity   = repo_health.maintainer_activity / 100.0
        problem_clarity       = opportunity.confidence                 # detector's confidence
        fix_confidence        = opportunity.confidence
        validation_strength   = 1.0 if opportunity.validation_recipe else 0.4
        # ChangeValue: fewer target paths = higher value (capped)
        change_value          = max(0.0, 1.0 - (len(opportunity.target_paths) - 1) * 0.1)
        risk_penalty          = _RISK_PENALTY.get(opportunity.risk_tier, 0.5)

        raw_score = (
            0.20 * repo_health_norm
            + 0.15 * maintainer_activity
            + 0.20 * problem_clarity
            + 0.20 * fix_confidence
            + 0.10 * validation_strength
            + 0.10 * change_value
            - 0.05 * risk_penalty
        )
        # Clamp to [0, 1]
        final_score = max(0.0, min(1.0, raw_score))

        is_low_risk = opportunity.risk_tier in (RiskTier.R0, RiskTier.R1, RiskTier.R2)

        if final_score >= 0.70 and is_low_risk:
            decision = ThresholdDecision.ALLOW_AUTONOMOUS
            requires_approval = False
        elif final_score >= 0.50:
            decision = ThresholdDecision.ALLOW_WITH_REVIEW
            requires_approval = True
        else:
            decision = ThresholdDecision.PROPOSE_OR_SKIP
            requires_approval = True

        breakdown = {
            "repo_health_norm": round(repo_health_norm, 4),
            "maintainer_activity": round(maintainer_activity, 4),
            "problem_clarity": round(problem_clarity, 4),
            "fix_confidence": round(fix_confidence, 4),
            "validation_strength": round(validation_strength, 4),
            "change_value": round(change_value, 4),
            "risk_penalty": round(risk_penalty, 4),
            "raw_score": round(raw_score, 4),
            "final_score": round(final_score, 4),
        }

        return ScoredOpportunity(
            opportunity=opportunity,
            repo_health_score=repo_health_norm,
            opportunity_score=final_score,
            threshold_decision=decision,
            requires_human_approval=requires_approval,
            score_breakdown=breakdown,
        )
