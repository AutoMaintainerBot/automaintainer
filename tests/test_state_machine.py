import pytest
from automaintainer.core.models import SessionState, TERMINAL_STATES
from automaintainer.core.state_machine import SessionStateMachine, InvalidStateTransitionError

def test_valid_forward_transitions():
    assert SessionStateMachine.can_transition(SessionState.DISCOVERED, SessionState.ELIGIBLE)
    assert SessionStateMachine.can_transition(SessionState.ELIGIBLE, SessionState.ANALYZING)
    assert SessionStateMachine.can_transition(SessionState.ANALYZING, SessionState.PLANNING)
    assert SessionStateMachine.can_transition(SessionState.PLANNING, SessionState.AWAITING_POLICY)
    assert SessionStateMachine.can_transition(SessionState.AWAITING_POLICY, SessionState.WORKING)
    assert SessionStateMachine.can_transition(SessionState.WORKING, SessionState.VALIDATING)
    assert SessionStateMachine.can_transition(SessionState.VALIDATING, SessionState.PR_OPEN)

def test_terminal_states_are_immutable():
    for term in TERMINAL_STATES:
        assert not SessionStateMachine.can_transition(term, SessionState.WORKING)
        assert not SessionStateMachine.can_transition(term, SessionState.PR_OPEN)
        assert not SessionStateMachine.can_transition(term, SessionState.COMPLETED)

        with pytest.raises(InvalidStateTransitionError):
            SessionStateMachine.validate_transition(term, SessionState.WORKING)

def test_invalid_skip_transitions():
    assert not SessionStateMachine.can_transition(SessionState.DISCOVERED, SessionState.PR_OPEN)
    with pytest.raises(InvalidStateTransitionError):
        SessionStateMachine.validate_transition(SessionState.DISCOVERED, SessionState.PR_OPEN)
