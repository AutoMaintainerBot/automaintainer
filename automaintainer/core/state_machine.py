from typing import Dict, Set, Tuple
from automaintainer.core.models import SessionState, TERMINAL_STATES

class InvalidStateTransitionError(Exception):
    """Raised when an illegal transition is attempted."""
    pass

class StaleSessionVersionError(Exception):
    """Raised when optimistic concurrency checks fail."""
    pass

class SessionStateMachine:
    """
    Finite State Machine with Optimistic Concurrency & Immutable Terminal State Enforcement.

    Enforces transition matrix:
    DISCOVERED -> ELIGIBLE, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    ELIGIBLE -> ANALYZING, CANCELLED, SAFETY_STOP, PAUSED
    ANALYZING -> PLANNING, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    PLANNING -> AWAITING_POLICY, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    AWAITING_POLICY -> WORKING, REJECTED, CANCELLED, SAFETY_STOP, PAUSED
    WORKING -> VALIDATING, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    VALIDATING -> PR_OPEN, WORKING (retry), REJECTED, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    PR_OPEN -> MAINTAINER_REVIEW, MERGED, REJECTED, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    MAINTAINER_REVIEW -> CHANGES_REQUESTED, MERGED, REJECTED, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    CHANGES_REQUESTED -> WORKING, REVALIDATING, REJECTED, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    REVALIDATING -> PR_OPEN, WORKING, REJECTED, EXPIRED, CANCELLED, SAFETY_STOP, PAUSED
    PAUSED -> ANALYZING, PLANNING, WORKING, VALIDATING, REVALIDATING, CANCELLED, SAFETY_STOP

    Terminal states (MERGED, REJECTED, EXPIRED, CANCELLED, SAFETY_STOP, COMPLETED):
    No transitions out of terminal states are permitted under any condition.
    """

    ALLOWED_TRANSITIONS: Dict[SessionState, Set[SessionState]] = {
        SessionState.DISCOVERED: {
            SessionState.ELIGIBLE, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.ELIGIBLE: {
            SessionState.ANALYZING, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.ANALYZING: {
            SessionState.PLANNING, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.PLANNING: {
            SessionState.AWAITING_POLICY, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.AWAITING_POLICY: {
            SessionState.WORKING, SessionState.REJECTED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.WORKING: {
            SessionState.VALIDATING, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.VALIDATING: {
            SessionState.PR_OPEN, SessionState.WORKING, SessionState.REJECTED, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.PR_OPEN: {
            SessionState.MAINTAINER_REVIEW, SessionState.MERGED, SessionState.REJECTED, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.MAINTAINER_REVIEW: {
            SessionState.CHANGES_REQUESTED, SessionState.MERGED, SessionState.REJECTED, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.CHANGES_REQUESTED: {
            SessionState.WORKING, SessionState.REVALIDATING, SessionState.REJECTED, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.REVALIDATING: {
            SessionState.PR_OPEN, SessionState.WORKING, SessionState.REJECTED, SessionState.EXPIRED, SessionState.CANCELLED, SessionState.SAFETY_STOP, SessionState.PAUSED
        },
        SessionState.PAUSED: {
            SessionState.ANALYZING, SessionState.PLANNING, SessionState.WORKING, SessionState.VALIDATING, SessionState.REVALIDATING, SessionState.CANCELLED, SessionState.SAFETY_STOP
        },
        SessionState.MERGED: set(),
        SessionState.REJECTED: set(),
        SessionState.EXPIRED: set(),
        SessionState.CANCELLED: set(),
        SessionState.SAFETY_STOP: set(),
        SessionState.COMPLETED: set(),
    }

    @classmethod
    def can_transition(cls, current_state: SessionState, target_state: SessionState) -> bool:
        if current_state in TERMINAL_STATES:
            return False
        return target_state in cls.ALLOWED_TRANSITIONS.get(current_state, set())

    @classmethod
    def validate_transition(cls, current_state: SessionState, target_state: SessionState) -> None:
        if current_state in TERMINAL_STATES:
            raise InvalidStateTransitionError(
                f"Session is in immutable terminal state '{current_state.value}'. No further transitions permitted."
            )
        allowed = cls.ALLOWED_TRANSITIONS.get(current_state, set())
        if target_state not in allowed:
            raise InvalidStateTransitionError(
                f"Illegal transition from '{current_state.value}' to '{target_state.value}'. Allowed: {[s.value for s in allowed]}"
            )
