import time
from typing import Optional, Set
from automaintainer.core.models import (
    MutationIntent, MutationOp, RiskTier, SessionState, TERMINAL_STATES,
    ResourceBoundCapability
)

class CapabilityDeniedError(Exception):
    """Raised when an agent attempts an unauthorized action."""
    pass

class CapabilityBroker:
    """
    Capability Boundary:
    Agents NEVER possess a mutating GitHub client.
    Instead, Agents output Intent (e.g. Planner proposes a dependency bump).
    The Capability Broker verifies whether the agent role is allowed to request
    this specific capability in the current session phase, AND binds the mutation
    to the specific resource (tenant, installation, repository, session, branch, base SHA).
    """

    # Role-based capability whitelist
    ROLE_ALLOWED_OPERATIONS = {
        "planner": set(),  # Planner produces intentions/plans, never mutations
        "reviewer": set(), # Reviewer inspects diffs, never mutates
        "scout": set(),    # Scout observes metadata
        "patcher": {MutationOp.CREATE_BRANCH, MutationOp.CREATE_COMMIT},
        "publisher": {MutationOp.OPEN_PR, MutationOp.UPDATE_PR, MutationOp.ADD_COMMENT},
        "collaborator": {MutationOp.ADD_COMMENT, MutationOp.UPDATE_PR},
        "terminator": {MutationOp.CLOSE_PR},
    }

    @classmethod
    def authorize_capability(
        cls,
        intent: MutationIntent,
        session_state: SessionState,
        actor_role: str,
        capability: ResourceBoundCapability,
    ) -> bool:
        if capability is None:
            raise CapabilityDeniedError("ResourceBoundCapability is mandatory for capability authorization")

        if session_state is None:
            raise CapabilityDeniedError("Cannot grant capability when session_state is None")

        # Terminal state invariant
        if session_state in TERMINAL_STATES:
            raise CapabilityDeniedError(
                f"Cannot grant capability '{intent.operation.value}' in terminal session state '{session_state.value}'"
            )

        allowed_ops = cls.ROLE_ALLOWED_OPERATIONS.get(actor_role.lower(), set())
        if intent.operation not in allowed_ops:
            raise CapabilityDeniedError(
                f"Actor role '{actor_role}' is not granted capability '{intent.operation.value}'"
            )

        # Resource-bound capability enforcement
        if intent.session_id != capability.session_id:
            raise CapabilityDeniedError(
                f"Mutation session_id '{intent.session_id}' does not match capability session_id '{capability.session_id}'"
            )

        if capability.repository_id is not None:
            if intent.repository_id != capability.repository_id:
                raise CapabilityDeniedError(
                    f"Mutation repository_id '{intent.repository_id}' does not match required capability repository_id '{capability.repository_id}'"
                )
        elif intent.repository_id is not None:
            raise CapabilityDeniedError(
                f"Mutation intent specifies repository_id '{intent.repository_id}' but capability does not permit binding to it"
            )

        if capability.installation_id is not None:
            if intent.installation_id != capability.installation_id:
                raise CapabilityDeniedError(
                    f"Mutation installation_id '{intent.installation_id}' does not match required capability installation_id '{capability.installation_id}'"
                )
        elif intent.installation_id is not None:
            raise CapabilityDeniedError(
                f"Mutation intent specifies installation_id '{intent.installation_id}' but capability does not permit binding to it"
            )

        target_repo = intent.repository.lower().strip()
        allowed_repos = {capability.repository_full_name.lower().strip()}
        if capability.upstream_repository_full_name:
            allowed_repos.add(capability.upstream_repository_full_name.lower().strip())

        if target_repo not in allowed_repos:
            raise CapabilityDeniedError(
                f"Mutation repository '{intent.repository}' does not match capability repository '{capability.repository_full_name}'"
            )

        if target_repo != capability.repository_full_name.lower().strip():
            if intent.operation not in {MutationOp.OPEN_PR, MutationOp.ADD_COMMENT, MutationOp.UPDATE_PR, MutationOp.CLOSE_PR}:
                raise CapabilityDeniedError(
                    f"Direct mutation operation '{intent.operation.value}' is not permitted on upstream repository '{intent.repository}'"
                )

        if intent.branch != capability.branch:
            raise CapabilityDeniedError(
                f"Mutation branch '{intent.branch}' does not match capability owned branch '{capability.branch}'"
            )

        if capability.allowed_operations and intent.operation not in capability.allowed_operations:
            raise CapabilityDeniedError(
                f"Operation '{intent.operation.value}' is not permitted by resource capability"
            )

        intent_base_sha = intent.metadata.get("initial_base_sha") or intent.metadata.get("base_sha")
        if intent_base_sha and capability.expected_base_sha and intent_base_sha != "HEAD":
            if intent_base_sha != capability.expected_base_sha:
                raise CapabilityDeniedError(
                    f"Mutation base SHA '{intent_base_sha}' does not match capability expected base SHA '{capability.expected_base_sha}'"
                )

        if capability.allowed_paths:
            allowed_set = {p.replace("\\", "/").strip().lower() for p in capability.allowed_paths}
            for tp in intent.target_paths:
                if tp.replace("\\", "/").strip().lower() not in allowed_set:
                    raise CapabilityDeniedError(
                        f"Target path '{tp}' exceeds authorized capability scope '{capability.allowed_paths}'"
                    )

        if capability.expires_at and time.time() > capability.expires_at:
            raise CapabilityDeniedError("Resource capability has expired")

        return True
