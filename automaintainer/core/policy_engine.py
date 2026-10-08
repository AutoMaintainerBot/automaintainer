from typing import List, Tuple, Optional
from automaintainer.core.models import MutationIntent, MutationOp, RiskTier, SessionState, TERMINAL_STATES
from automaintainer.core.diff_firewall import DiffFirewall

class PolicyViolation(Exception):
    """Raised when policy checks fail."""
    pass

class PolicyEngine:
    """
    Two-Layer Policy Engine:
    - Pre-Policy: Evaluated before any task modification.
      Checks: Is session active? Is repo eligible? Is action class permitted? Is risk tier allowable?
    - Post-Policy: Evaluated after modification has taken place.
      Checks: Did generated diff strictly stay within expected target paths? Did DiffFirewall pass?
    """

    def __init__(self, firewall: Optional[DiffFirewall] = None):
        self.firewall = firewall or DiffFirewall()

    def evaluate_pre_policy(
        self,
        intent: MutationIntent,
        current_state: SessionState,
        is_maintainer_authorized: bool = True
    ) -> Tuple[bool, List[str]]:
        violations: List[str] = []

        if current_state in TERMINAL_STATES:
            violations.append(f"Session is in terminal state '{current_state.value}'; mutations are strictly prohibited")

        if intent.risk in [RiskTier.R4, RiskTier.R5]:
            violations.append(f"Risk tier '{intent.risk.value}' is prohibited for autonomous execution")

        if not is_maintainer_authorized:
            violations.append(f"Actor '{intent.actor}' is not authorized to direct mutations on repository '{intent.repository}'")

        return len(violations) == 0, violations

    def evaluate_post_policy(
        self,
        intent: MutationIntent,
        expected_paths: List[str]
    ) -> Tuple[bool, List[str]]:
        violations: List[str] = []

        if not intent.diff:
            # If no diff is provided for commit actions, that is a violation
            if intent.operation == MutationOp.CREATE_COMMIT:
                violations.append("Mutation operation requires diff object for post-policy verification")
            return len(violations) == 0, violations

        passed, firewall_violations = self.firewall.inspect(intent.diff)
        if not passed:
            violations.extend(firewall_violations)

        # Ensure patch did NOT touch any file that was not in the approved pre-plan
        diff_paths = {f.path.replace("\\", "/").lstrip("/") for f in intent.diff.files}
        normalized_expected = {p.replace("\\", "/").lstrip("/") for p in expected_paths}

        unexpected = diff_paths - normalized_expected
        if unexpected:
            violations.append(f"Patcher touched unexpected paths outside the approved plan: {sorted(list(unexpected))}")

        return len(violations) == 0, violations

    def enforce_pre(self, intent: MutationIntent, current_state: SessionState, is_maintainer_authorized: bool = True) -> None:
        passed, violations = self.evaluate_pre_policy(intent, current_state, is_maintainer_authorized)
        if not passed:
            raise PolicyViolation(f"Pre-Policy Violation: {'; '.join(violations)}")

    def enforce_post(self, intent: MutationIntent, expected_paths: List[str]) -> None:
        passed, violations = self.evaluate_post_policy(intent, expected_paths)
        if not passed:
            raise PolicyViolation(f"Post-Policy Violation: {'; '.join(violations)}")
