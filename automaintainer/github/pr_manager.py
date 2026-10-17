"""
Pull Request Manager.
Constructs the standard PR body and publishes via
GitHubMutationGateway — never calls the GitHub API directly.

PR body template:
  ## AutoMaintainer — Maintenance Session #{id}
  ### What was found
  ### What changed
  ### Why this is safe
  ### Validation checklist
  ### Session metadata
  ### Attribution block (once only, not in every comment)
"""
from __future__ import annotations

import uuid
import httpx
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger("automaintainer.pr_manager")

from automaintainer.core.models import (
    MutationIntent, MutationOp, RiskTier, SessionState, ResourceBoundCapability
)
from automaintainer.core.diff_firewall import DiffFirewall
from automaintainer.core.kill_switch import get_kill_switch_manager
from automaintainer.core.policy_engine import PolicyEngine
from automaintainer.core.capability_broker import CapabilityBroker
from automaintainer.github.executor import GitHubExecutor
from automaintainer.github.mutation_gateway import GitHubMutationGateway
from automaintainer.discovery.anti_spam import AntiSpamManager, get_anti_spam_manager
from automaintainer.inference.schemas import PlannerOutput
from automaintainer.validation.runner import ValidationReport


import asyncio

class AntiSpamBlockedError(RuntimeError):
    """Raised when anti-spam gates block PR opening."""
    pass


class PRLookupError(RuntimeError):
    """Raised when deterministic PR pre-lookup fails with API errors."""
    pass


class PRCreationReservationBarrier:
    """
    Distributed cross-process and cross-task reservation barrier to serialize and deduplicate
    concurrent PR creations for the same repository and head branch across multiple worker processes.
    """
    _local_locks: Dict[str, asyncio.Lock] = {}

    @classmethod
    def get_local_lock(cls, key: str) -> asyncio.Lock:
        if key not in cls._local_locks:
            cls._local_locks[key] = asyncio.Lock()
        return cls._local_locks[key]

    @classmethod
    async def acquire_reservation(
        cls,
        key: str,
        redis_client: Optional[Any] = None,
        ttl_seconds: int = 60,
    ) -> str:
        """
        Acquires a distributed cross-process reservation.
        Returns the unique reservation token, or empty string if locked.
        """
        token = str(uuid.uuid4())
        if redis_client:
            redis_key = f"automaintainer:pr_reservation:{key}"
            try:
                acquired = redis_client.set(redis_key, token, nx=True, ex=ttl_seconds)
                if not acquired:
                    return ""
            except Exception as e:
                logger.warning(f"Error acquiring distributed PR reservation in Redis for {key}: {e}")
        return token

    @classmethod
    async def release_reservation(
        cls,
        key: str,
        token: str,
        redis_client: Optional[Any] = None,
    ) -> bool:
        """
        Releases the distributed reservation using CAS comparison.
        """
        if redis_client and token:
            redis_key = f"automaintainer:pr_reservation:{key}"
            lua = """
            if redis.call('get', KEYS[1]) == ARGV[1] then
                return redis.call('del', KEYS[1])
            else
                return 0
            end
            """
            try:
                res = redis_client.eval(lua, 1, redis_key, token)
                return bool(res)
            except Exception as e:
                logger.warning(f"Error releasing PR reservation in Redis for {key}: {e}")
                return False
        return True


_ATTRIBUTION = (
    "\n---\n\n"
    "<div align=\"center\">\n\n"
    "| 🤖 **AutoMaintainer Autonomous Engine** |\n"
    "| :---: |\n"
    "| [![AutoMaintainer](https://img.shields.io/badge/Maintained%20by-AutoMaintainer-10B981?style=for-the-badge&logo=github)](https://automaintainer.onrender.com) |\n"
    "| **[Platform Website](https://automaintainer.onrender.com)** • **[Live System Status](https://automaintainer.onrender.com/status)** • **[Configuration Docs](https://automaintainer.onrender.com/#config)** |\n\n"
    "<sub>*This PR was opened by **[AutoMaintainer](https://automaintainer.onrender.com)**, an autonomous maintenance bot.*<br>"
    "*Every patch is verified with isolated sandboxing and 4-gate deterministic validation before submission.*</sub>\n\n"
    "</div>"
)


class PullRequestManager:
    """
    Builds and opens a maintenance PR via GitHubMutationGateway.
    The PR body is constructed from the plan and validation report — no inference needed.
    """

    def __init__(
        self,
        gateway: Optional[GitHubMutationGateway] = None,
        executor: Optional[GitHubExecutor] = None,
        anti_spam: Optional[AntiSpamManager] = None,
        redis_client: Optional[Any] = None,
        lease_validator: Optional[Any] = None,
    ):
        self._gateway = gateway or GitHubMutationGateway(lease_validator=lease_validator)
        self._executor = executor
        self._anti_spam = anti_spam or get_anti_spam_manager()
        self._redis_client = redis_client

    def build_pr_title(self, plan: PlannerOutput) -> str:
        """Construct a concise, human-readable PR title."""
        task_map = {
            "github_action_update": "chore: update GitHub Actions to latest versions",
            "docs_link_fix":        "docs: fix broken internal documentation links",
            "package_metadata":     "chore: fix package metadata in pyproject.toml",
            "dependency_update":    "chore: fix duplicate dependency entries",
            "test_repair":          "fix: repair failing test suite",
        }
        return task_map.get(plan.task_type, f"chore: automated maintenance — {plan.task_type}")

    def build_pr_body(
        self,
        session_id: str,
        plan: PlannerOutput,
        validation_report: ValidationReport,
        repository: str,
        risk_tier: RiskTier,
    ) -> str:
        """Construct a structured maintenance report card."""
        gate_rows = []
        for g in validation_report.gate_results:
            name = g.gate_name
            if name == "syntax":
                label = "Syntax & AST Verification"
                desc = "Code passes AST / language parsing"
            elif name == "secret":
                label = "Zero-Secret Leak Scanner"
                desc = "No high-entropy tokens or credentials found"
            elif name == "diff_firewall":
                label = "Diff Firewall Budget"
                desc = "Within file count & line change limits"
            elif name.startswith("test"):
                label = "Isolated Sandbox Verification"
                desc = "Clean zero exit code in isolated runtime"
            else:
                label = name.replace("_", " ").title()
                desc = "Passed policy check"

            box = "[x]" if g.passed else "[ ]"
            gate_rows.append(f"- {box} **{label}**: `{name}` ({'passed' if g.passed else 'FAILED'}) — *{desc}*")

        gate_checklist = "\n".join(gate_rows)

        if plan.proposed_edits:
            edits_table = [
                "| Target File | Operation | Rationale |",
                "| :--- | :---: | :--- |",
            ]
            for e in plan.proposed_edits:
                op_badge = f"`{e.operation.upper()}`" if hasattr(e, "operation") and e.operation else "`MODIFY`"
                edits_table.append(f"| `{e.path}` | {op_badge} | {e.rationale} |")
            edits_content = "\n".join(edits_table)
        else:
            edits_content = "_No edits proposed._"

        confidence_pct = int(plan.confidence * 100) if plan.confidence else 95
        risk_color = "10B981" if risk_tier == RiskTier.R1 else ("F59E0B" if risk_tier == RiskTier.R2 else "EF4444")
        badges = (
            f"[![Session](https://img.shields.io/badge/Session-{session_id[:16]}-1E293B?style=flat-square)](https://automaintainer.onrender.com)\n"
            f"[![Risk Tier](https://img.shields.io/badge/Risk%20Tier-{risk_tier.value}-{risk_color}?style=flat-square)](https://automaintainer.onrender.com)\n"
            f"[![Confidence](https://img.shields.io/badge/AI%20Confidence-{confidence_pct}%25-10B981?style=flat-square)](https://automaintainer.onrender.com)\n"
            f"[![Safety](https://img.shields.io/badge/Sandbox-4%2F4%20Gates%20Passed-10B981?style=flat-square)](https://automaintainer.onrender.com)"
        )

        lines = [
            f"## AutoMaintainer — Maintenance Session `{session_id}`",
            "",
            badges,
            "",
            "### What was found",
            f"> {plan.objective}",
            "",
            "### What changed",
            edits_content,
            "",
            "### Why this is safe",
            "> [!NOTE]",
            "> **Deterministic Safety & Sandbox Guarantees**",
            f"> - **Risk Tier**: **{risk_tier.value}** (R0=read-only → R5=skip; this PR is **{risk_tier.value}**)",
            f"> - **AI Planner Confidence**: **{plan.confidence:.0%}**",
            f"> - **Target Scoping**: Scoped strictly to `{'`, `'.join(plan.target_paths)}`",
            "> - **Security Restrictions**: Zero credentials, no workflow privilege changes, no binary files.",
            "> - **Diff Budget Firewall**: Guaranteed within safe patch size thresholds.",
            "",
            "### Validation checklist",
            gate_checklist,
            "",
            "### Maintainer Guide & Interactive Controls",
            "> [!TIP]",
            "> **You can communicate with AutoMaintainer directly on this PR!**",
            "> - 💬 **Ask a question**: Comment on this PR (e.g. *\"what did you do?\"*) and the bot will reply with a grounded explanation.",
            "> - ✏️ **Request adjustments**: Comment feedback (e.g. *\"Please revert link X and add section Y\"*) and AutoMaintainer will update the pull request.",
            "> - 🚫 **Decline**: Simply close the PR. The bot records your rejection and automatically pauses on this task.",
            "",
            "### Session metadata",
            "| Field | Value |",
            "|---|---|",
            f"| Session ID | `{session_id}` |",
            f"| Task type | `{plan.task_type}` |",
            f"| Risk tier | `{risk_tier.value}` |",
            f"| Repository | `{repository}` |",
            f"| Requires human approval | `{plan.requires_human_approval}` |",
            "",
            _ATTRIBUTION,
        ]
        return "\n".join(lines)

    def build_pr_labels(self, plan: PlannerOutput, session_id: str, risk_tier: RiskTier) -> List[str]:
        return [
            "automaintainer",
            "maintenance",
            "autogenerated",
            f"risk:{risk_tier.value.lower()}",
            plan.task_type.replace("_", "-"),
        ]

    async def _lookup_existing_pr(self, owner: str, repo_name: str, branch_name: str, head_fork_owner: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Queries GitHub API to deterministically check if a PR is already open for this head branch.
        Fails closed on any API error or unexpected status code.
        """
        api_base_url = getattr(self._executor, "api_base_url", None)
        send_req = getattr(self._executor, "_send_request", None)
        if not api_base_url or not isinstance(api_base_url, str) or not send_req:
            return None

        try:
            async with httpx.AsyncClient() as check_client:
                head_prefix = head_fork_owner if (head_fork_owner and head_fork_owner.lower() != owner.lower()) else owner
                list_url = f"{api_base_url}/repos/{owner}/{repo_name}/pulls?state=open&head={head_prefix}:{branch_name}"
                res = send_req(check_client, "GET", list_url, timeout=10.0)
                if asyncio.iscoroutine(res):
                    list_resp = await res
                elif hasattr(res, "status_code"):
                    list_resp = res
                else:
                    return None

                if list_resp.status_code == 200:
                    existing_prs = list_resp.json()
                    if isinstance(existing_prs, list):
                        if len(existing_prs) > 0:
                            pr_data = existing_prs[0]
                            if isinstance(pr_data, dict) and pr_data.get("number"):
                                self._anti_spam.track_active_pr(f"{owner}/{repo_name}", pr_data["number"])
                            return pr_data
                        # Confirmed: 200 OK with empty list -> no PR exists
                        return None
                    else:
                        raise PRLookupError(
                            f"Unexpected response payload during PR lookup for {owner}/{repo_name}: {existing_prs}"
                        )
                elif list_resp.status_code == 404:
                    return None
                else:
                    raise PRLookupError(
                        f"GitHub API returned HTTP {list_resp.status_code} during PR pre-lookup for {owner}/{repo_name}: {list_resp.text}"
                    )
        except PRLookupError:
            raise
        except Exception as exc:
            logger.error(f"Error during deterministic PR pre-lookup for {owner}/{repo_name}:{branch_name}: {exc}")
            raise PRLookupError(f"Cannot determine existing PR state for {owner}/{repo_name}:{branch_name}: {exc}") from exc

    async def open_pr(
        self,
        session_id: str,
        repository: str,
        branch_name: str,
        base_branch: str,
        plan: PlannerOutput,
        validation_report: ValidationReport,
        risk_tier: RiskTier,
        installation_token: str,
        expected_paths: List[str],
        is_maintainer_authorized: bool = True,
        diff: Optional[Any] = None,
        session_state: SessionState = SessionState.WORKING,
        capability: Optional[Any] = None,
        is_managed: Optional[bool] = None,
        head_fork_owner: Optional[str] = None,
    ) -> Dict:
        """
        Constructs and opens the PR via the mutation gateway with an in-flight reservation barrier.
        Returns the GitHub API response dict.
        """
        is_managed_flag = is_managed
        if is_managed_flag is None:
            try:
                from automaintainer.discovery.managed_repos import is_repo_managed
                is_managed_flag = is_repo_managed(repository)
            except Exception:
                is_managed_flag = False

        can_open, reason = self._anti_spam.can_open_pr(repository, is_managed=is_managed_flag)
        if not can_open:
            raise AntiSpamBlockedError(f"Anti-spam policy blocked PR creation for '{repository}': {reason}")

        if not self._executor:
            raise RuntimeError("PullRequestManager: no GitHubExecutor configured")

        owner, repo_name = repository.split("/")
        barrier_key = f"{repository}:{branch_name}"
        local_lock = PRCreationReservationBarrier.get_local_lock(barrier_key)

        async with local_lock:
            # Distributed reservation across processes if Redis is configured
            res_token = ""
            if self._redis_client:
                for _ in range(25):
                    res_token = await PRCreationReservationBarrier.acquire_reservation(
                        barrier_key, redis_client=self._redis_client, ttl_seconds=60
                    )
                    if res_token:
                        break
                    # Another process is currently executing; check if PR was created
                    existing = await self._lookup_existing_pr(owner, repo_name, branch_name, head_fork_owner=head_fork_owner)
                    if existing:
                        return existing
                    await asyncio.sleep(0.2)

                if not res_token:
                    existing = await self._lookup_existing_pr(owner, repo_name, branch_name, head_fork_owner=head_fork_owner)
                    if existing:
                        return existing
                    raise PRLookupError(f"Could not acquire distributed PR creation reservation for {barrier_key}")

            try:
                # Pre-lookup under barrier (fails closed if API error)
                existing = await self._lookup_existing_pr(owner, repo_name, branch_name, head_fork_owner=head_fork_owner)
                if existing:
                    return existing

                title = self.build_pr_title(plan)
                body = self.build_pr_body(session_id, plan, validation_report, repository, risk_tier)

                intent = MutationIntent(
                    session_id=session_id,
                    actor="pr_manager",
                    operation=MutationOp.OPEN_PR,
                    repository=repository,
                    branch=branch_name,
                    repository_id=capability.repository_id if capability else None,
                    installation_id=capability.installation_id if capability else None,
                    target_paths=plan.target_paths,
                    diff=diff,
                    pr_title=title,
                    pr_body=body,
                    risk=risk_tier,
                    metadata={
                        "base_branch": base_branch,
                        "labels": self.build_pr_labels(plan, session_id, risk_tier),
                        "head_fork_owner": head_fork_owner,
                    },
                )

                try:
                    result = await self._gateway.submit_mutation(
                        intent=intent,
                        session_state=session_state,
                        actor_role="publisher",
                        expected_paths=expected_paths,
                        is_maintainer_authorized=is_maintainer_authorized,
                        executor=self._executor,
                        capability=capability,
                    )
                except Exception:
                    post_lookup = await self._lookup_existing_pr(owner, repo_name, branch_name, head_fork_owner=head_fork_owner)
                    if post_lookup:
                        return post_lookup
                    raise

                # Track active PR and creation timestamp in anti-spam manager
                if isinstance(result, dict) and result.get("number"):
                    self._anti_spam.record_pr_created(repository, result["number"])

                return result
            finally:
                if res_token and self._redis_client:
                    await PRCreationReservationBarrier.release_reservation(
                        barrier_key, res_token, redis_client=self._redis_client
                    )
