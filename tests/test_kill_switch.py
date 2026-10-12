import pytest
import pytest_asyncio
from automaintainer.core.models import (
    MutationIntent, MutationOp, SessionState, RiskTier, ResourceBoundCapability
)
from automaintainer.core.kill_switch import KillSwitchManager, KillSwitchActiveError
from automaintainer.core.policy_engine import PolicyEngine
from automaintainer.github.mutation_gateway import GitHubMutationGateway
from automaintainer.github.executor import GitHubExecutor

@pytest.mark.asyncio
async def test_mutation_gateway_blocks_when_global_kill_active():
    kill_switch = KillSwitchManager()
    kill_switch.set_global_kill(True)
    gateway = GitHubMutationGateway(kill_switch=kill_switch)

    intent = MutationIntent(
        session_id="sess_kill_1",
        actor="patcher",
        operation=MutationOp.CREATE_COMMIT,
        repository="owner/repo",
        branch="patch-branch"
    )
    cap = ResourceBoundCapability(
        session_id="sess_kill_1",
        repository_full_name="owner/repo",
        branch="patch-branch",
        allowed_operations={MutationOp.CREATE_COMMIT},
        lease_epoch="epoch-1"
    )
    executor = GitHubExecutor(token="fake_token")

    with pytest.raises(KillSwitchActiveError, match="Global mutation kill switch is ACTIVE"):
        await gateway.submit_mutation(
            intent=intent,
            session_state=SessionState.WORKING,
            actor_role="patcher",
            expected_paths=[],
            is_maintainer_authorized=True,
            executor=executor,
            capability=cap
        )

@pytest.mark.asyncio
async def test_mutation_gateway_blocks_quarantined_repo():
    kill_switch = KillSwitchManager()
    kill_switch.quarantine_repository("malicious/repo")
    gateway = GitHubMutationGateway(kill_switch=kill_switch)

    intent = MutationIntent(
        session_id="sess_kill_2",
        actor="patcher",
        operation=MutationOp.CREATE_COMMIT,
        repository="malicious/repo",
        branch="patch-branch"
    )
    cap = ResourceBoundCapability(
        session_id="sess_kill_2",
        repository_full_name="malicious/repo",
        branch="patch-branch",
        allowed_operations={MutationOp.CREATE_COMMIT},
        lease_epoch="epoch-1"
    )
    executor = GitHubExecutor(token="fake_token")

    with pytest.raises(KillSwitchActiveError, match="Repository 'malicious/repo' is QUARANTINED"):
        await gateway.submit_mutation(
            intent=intent,
            session_state=SessionState.WORKING,
            actor_role="patcher",
            expected_paths=[],
            is_maintainer_authorized=True,
            executor=executor,
            capability=cap
        )
