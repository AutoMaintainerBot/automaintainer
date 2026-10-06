from __future__ import annotations
import asyncio
from typing import Dict, Any, List, Optional, Callable, Union, Awaitable
from automaintainer.core.models import MutationIntent, SessionState, ResourceBoundCapability
from automaintainer.core.capability_broker import CapabilityBroker, CapabilityDeniedError
from automaintainer.core.policy_engine import PolicyEngine
from automaintainer.core.kill_switch import KillSwitchManager, get_kill_switch_manager, KillSwitchActiveError
from automaintainer.github.executor import GitHubExecutor

class MutationRejectedError(Exception):
    """Raised when mutation is rejected at the gateway."""
    pass

class GitHubMutationGateway:
    """
    Gateway separating Agent Intent from GitHub Mutation.
    Defense-in-depth Sequence:
    1. Operator Emergency Kill Switches (Global, Repo, Operation)
    2. Mandatory ResourceBoundCapability & Active Lease Epoch Fencing Verification
    3. Capability Broker Check (Did this role have permission to request this op on this bound resource?)
    4. Pre-Policy Enforcement (Is this operation allowed in current session/risk tier?)
    5. Post-Policy Enforcement (Did the diff stay within expected bounds and pass DiffFirewall?)
    6. Dispatch to actual privileged Executor
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        kill_switch: Optional[KillSwitchManager] = None,
        lease_validator: Optional[Callable[[str, str], Union[bool, Awaitable[bool]]]] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.kill_switch = kill_switch or get_kill_switch_manager()
        self.lease_validator = lease_validator

    async def submit_mutation(
        self,
        intent: MutationIntent,
        session_state: SessionState,
        actor_role: str,
        expected_paths: List[str],
        is_maintainer_authorized: bool,
        executor: GitHubExecutor,
        capability: ResourceBoundCapability,
    ) -> Dict[str, Any]:
        self.kill_switch.enforce(repository=intent.repository, operation=intent.operation.value)

        if capability is None:
            raise CapabilityDeniedError(
                "ResourceBoundCapability is mandatory for all mutating operations through GitHubMutationGateway"
            )

        if not capability.lease_epoch:
            raise CapabilityDeniedError(
                "ResourceBoundCapability must possess a valid lease_epoch to fence mutations against lock loss"
            )

        if self.lease_validator is not None:
            res = self.lease_validator(capability.session_id, capability.lease_epoch)
            if asyncio.iscoroutine(res):
                is_valid = await res
            else:
                is_valid = bool(res)
            if not is_valid:
                raise CapabilityDeniedError(
                    f"Lease epoch fencing failed: lock ownership for session '{capability.session_id}' "
                    f"does not match active lease epoch '{capability.lease_epoch}'"
                )

        CapabilityBroker.authorize_capability(intent, session_state, actor_role, capability=capability)

        self.policy_engine.enforce_pre(intent, session_state, is_maintainer_authorized)

        self.policy_engine.enforce_post(intent, expected_paths)

        return await executor.execute_mutation(intent)
