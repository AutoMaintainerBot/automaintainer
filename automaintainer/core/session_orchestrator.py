"""
Session Orchestrator.
Top-level controller that advances a session through the canonical state machine.

State flow:
  DISCOVERED → ELIGIBLE → ANALYZING → PLANNING → AWAITING_POLICY
  → WORKING → VALIDATING → PR_OPEN → MAINTAINER_REVIEW
  → (CHANGES_REQUESTED → WORKING → REVALIDATING → PR_OPEN)*
  → MERGED | REJECTED | EXPIRED | CANCELLED | SAFETY_STOP

Invariants enforced here:
  - Every state transition goes through SessionStateMachine.validate_transition()
  - Every transition is persisted via optimistic concurrency
  - Every privileged decision is written to the audit log
  - Secrets never appear in audit details
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Union, Tuple
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from automaintainer.core.models import SessionState, TERMINAL_STATES, RiskTier, TaskType
from automaintainer.core.state_machine import SessionStateMachine, InvalidStateTransitionError
from automaintainer.core.kill_switch import get_kill_switch_manager
from automaintainer.discovery.anti_spam import get_anti_spam_manager
from automaintainer.inference.schemas import PlannerOutput
from automaintainer.data.repositories import SessionRepository
from automaintainer.data.tables import SessionRecord, ValidationRunRecord, PlanRecord, OpportunityRecord
from automaintainer.observability.audit import AuditService
from automaintainer.observability.metrics import get_metrics
import logging
logger = logging.getLogger("automaintainer.orchestrator")

from automaintainer.agents.planner import MaintenancePlanner, PlannerError, InferenceExhaustedError
from automaintainer.queue.redis_queue import get_partitioned_queue
from automaintainer.agents.patcher import MinimalPatcher
from automaintainer.agents.reviewer import IndependentDiffReviewer, ReviewRejectionError
from automaintainer.core.diff_firewall import DiffFirewall
from automaintainer.validation.runner import ValidationRunner, ValidationReport
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity

import hashlib
import json
import time


class SafetyStopError(Exception):
    """Raised to transition session to SAFETY_STOP."""


class OrchestratorError(Exception):
    """Non-recoverable orchestrator error."""


class SessionOrchestrator:
    """
    Wires all components into the full session lifecycle.

    Intended to be called by a worker process for one session at a time.
    All GitHub mutations go through GitHubMutationGateway (not called here directly;
    provided by the caller via keyword arguments).
    """

    def __init__(
        self,
        db: AsyncSession,
        planner: Optional[MaintenancePlanner] = None,
        patcher: Optional[MinimalPatcher] = None,
        reviewer: Optional[IndependentDiffReviewer] = None,
        validation_runner: Optional[ValidationRunner] = None,
    ):
        self._db          = db
        self._repo        = SessionRepository(db)
        self._audit       = AuditService(db)
        self._metrics     = get_metrics()
        self._planner     = planner or MaintenancePlanner()
        self._patcher     = patcher or MinimalPatcher()
        self._reviewer    = reviewer  # optional; None = skip review step
        self._validation  = validation_runner or ValidationRunner()
        self._fsm         = SessionStateMachine()


    async def advance(
        self,
        session_id: str,
        opportunity: Optional[DetectedOpportunity] = None,
        original_file_contents: Optional[Dict[str, str]] = None,
        installation_token: str = "",
    ) -> SessionRecord:
        """
        Advance a session from its current state to the next logical state.
        Returns the updated SessionRecord.
        """
        record = await self._repo.get_session(session_id)
        if record is None:
            raise OrchestratorError(f"Session {session_id} not found")

        current_state = SessionState(record.state)

        if current_state in TERMINAL_STATES:
            return record   # Nothing to do

        try:
            if current_state == SessionState.DISCOVERED:
                return await self._transition_to_eligible(record)
            elif current_state == SessionState.ELIGIBLE:
                return await self._transition_to_analyzing(record)
            elif current_state == SessionState.ANALYZING:
                return await self._transition_to_planning(record, opportunity)
            elif current_state == SessionState.PLANNING:
                return await self._transition_to_awaiting_policy(record)
            elif current_state == SessionState.AWAITING_POLICY:
                can_work, reject_reason, requires_approval = await self.evaluate_policy_gate(record)
                if reject_reason:
                    return await self._transition(record, SessionState.REJECTED, {
                        "reason": f"Policy gate rejected: {reject_reason}"
                    })
                elif not requires_approval and can_work:
                    return await self._transition_to_working(record)
                return record   # Waiting for human / policy gate — external trigger
            elif current_state == SessionState.WORKING:
                return await self._do_working(record, opportunity, original_file_contents)
            elif current_state == SessionState.VALIDATING:
                return await self._do_validating(record)
            elif current_state == SessionState.PR_OPEN:
                return await self.handle_maintainer_review(record)
            elif current_state == SessionState.MAINTAINER_REVIEW:
                return record   # Awaiting external review events / webhook
            elif current_state == SessionState.CHANGES_REQUESTED:
                return await self._transition(record, SessionState.WORKING, {
                    "reason": "Applying revisions requested by maintainer"
                })
            elif current_state == SessionState.REVALIDATING:
                return record   # Awaiting revalidation completion
            else:
                return record
        except SafetyStopError as exc:
            return await self._transition(record, SessionState.SAFETY_STOP, {
                "reason": str(exc)
            })
        except Exception as exc:
            await self._audit.record(
                session_id=session_id,
                actor_type="system",
                actor_id="session_orchestrator",
                action="advance_error",
                target=f"sessions/{session_id}",
                details={"error": str(exc), "state": record.state},
            )
            raise


    async def _transition_to_eligible(self, record: SessionRecord) -> SessionRecord:
        self._metrics.session_started()
        return await self._transition(record, SessionState.ELIGIBLE, {
            "reason": "Repository passed eligibility checks"
        })

    async def _transition_to_analyzing(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.ANALYZING, {
            "reason": "Beginning repository analysis"
        })

    async def _transition_to_planning(
        self,
        record: SessionRecord,
        opportunity: Optional[DetectedOpportunity],
    ) -> SessionRecord:
        if opportunity is None:
            raise OrchestratorError("Cannot plan without a DetectedOpportunity")
        try:
            plan = await self._planner.plan(opportunity, session_id=record.id)
        except InferenceExhaustedError as exc:
            raw_meta = None
            if hasattr(record, "metadata") and isinstance(record.metadata, dict):
                raw_meta = record.metadata
            elif hasattr(record, "metadata_json") and isinstance(record.metadata_json, dict):
                raw_meta = record.metadata_json
            elif hasattr(record, "budget_json") and isinstance(record.budget_json, dict):
                raw_meta = record.budget_json

            current_meta = dict(raw_meta or {})
            requeue_count = current_meta.get("requeue_count", 0)
            if requeue_count >= 5:
                return await self._transition(record, SessionState.SAFETY_STOP, {
                    "reason": f"AI gateway inference exhausted after {requeue_count} retries: {exc}"
                })

            requeue_count += 1
            backoff_sec = min(300, 30 * (2 ** (requeue_count - 1)))
            retry_after = time.time() + backoff_sec
            current_meta.update({
                "requeue_count": requeue_count,
                "requeue_reason": "inference_exhausted",
                "requeue_after": retry_after,
                "last_inference_error": str(exc),
            })
            record.metadata = current_meta
            if hasattr(record, "metadata_json"):
                record.metadata_json = current_meta
            await self._db.flush()

            try:
                queue = get_partitioned_queue()
                opp_payload = (
                    opportunity.model_dump()
                    if hasattr(opportunity, "model_dump")
                    else (opportunity.__dict__ if opportunity else {})
                )
                inferred_task_type = (
                    getattr(record, "task_type", None)
                    or (opportunity.task_type.value if hasattr(opportunity.task_type, "value") else str(opportunity.task_type))
                    if opportunity and hasattr(opportunity, "task_type") and opportunity.task_type
                    else "analysis"
                )
                queue.enqueue(
                    queue_name="analysis",
                    session_id=record.id,
                    task_type=inferred_task_type,
                    payload={
                        "session_id": record.id,
                        "opportunity": opp_payload,
                        "requeue_count": requeue_count,
                        "retry_after": retry_after,
                    },
                    dedupe_key=f"{record.id}:requeue:{requeue_count}"
                )
            except Exception as q_err:
                logger.warning(f"Could not re-queue session {record.id}: {q_err}")

            await self._audit.record(
                session_id=record.id,
                actor_type="system",
                actor_id="session_orchestrator",
                action="planning_requeued",
                target=f"sessions/{record.id}",
                details={
                    "requeue_count": requeue_count,
                    "retry_after": retry_after,
                    "error": str(exc)
                }
            )
            return record
        except PlannerError as exc:
            raise OrchestratorError(f"Planning failed: {exc}") from exc

        self._last_plan = plan

        plan_json = plan.model_dump()
        plan_hash = hashlib.sha256(json.dumps(plan_json, sort_keys=True).encode()).hexdigest()
        plan_record = PlanRecord(
            id=f"plan_{uuid.uuid4().hex}",
            session_id=record.id,
            plan_hash=plan_hash,
            plan_json=plan_json,
        )
        self._db.add(plan_record)
        await self._db.flush()

        return await self._transition(record, SessionState.PLANNING, {
            "plan_id": plan_record.id,
            "task_type": plan.task_type,
            "target_paths": plan.target_paths,
            "requires_human_approval": plan.requires_human_approval,
        })

    async def _transition_to_awaiting_policy(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.AWAITING_POLICY, {
            "reason": "Plan produced; awaiting policy gate"
        })

    async def _transition_to_working(
        self, record: SessionRecord, reason: str = "Policy gate passed; starting work"
    ) -> SessionRecord:
        return await self._transition(record, SessionState.WORKING, {
            "reason": reason
        })

    async def evaluate_policy_gate(
        self,
        record: SessionRecord,
        plan: Optional[PlannerOutput] = None,
        repository_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], bool]:
        """
        Evaluates policy gates for a session in AWAITING_POLICY:
        Returns (can_proceed_to_working, reject_reason, requires_human_approval).
        """
        kill_mgr = get_kill_switch_manager()
        if kill_mgr.is_global_kill_active():
            return False, "Global mutation kill switch is ACTIVE", False
        if repository_name and kill_mgr.is_repository_quarantined(repository_name):
            return False, f"Repository '{repository_name}' is QUARANTINED", False

        if repository_name:
            anti_spam = get_anti_spam_manager()
            if anti_spam.is_opted_out(repository_name):
                return False, f"Repository '{repository_name}' is opted out of bot interactions", False

            from automaintainer.discovery.managed_repos import parse_managed_repos_file
            from automaintainer.config import get_settings
            settings = get_settings()
            managed_list = parse_managed_repos_file(settings.MANAGED_REPOSITORIES_FILE)
            is_managed = repository_name.lower().strip() in [m.lower().strip() for m in managed_list]
            if not is_managed and anti_spam.is_in_cooldown(repository_name):
                return False, f"Repository '{repository_name}' is in cooling-off period", False

        effective_plan = plan or getattr(self, "_last_plan", None)
        if effective_plan is None:
            try:
                plan_stmt = select(PlanRecord).where(PlanRecord.session_id == record.id).order_by(PlanRecord.created_at.desc())
                res = await self._db.execute(plan_stmt)
                sc = res.scalars()
                if hasattr(sc, "__await__"):
                    sc = await sc
                p_rec = sc.first() if hasattr(sc, "first") else None
                if hasattr(p_rec, "__await__"):
                    p_rec = await p_rec
                if p_rec and hasattr(p_rec, "plan_json") and p_rec.plan_json:
                    effective_plan = PlannerOutput(**p_rec.plan_json)
            except Exception:
                effective_plan = None

        risk_str = record.risk_tier or (effective_plan.risk_tier.value if effective_plan and hasattr(effective_plan.risk_tier, "value") else "R2")
        if risk_str in (RiskTier.R4.value, RiskTier.R5.value):
            return False, None, True

        if effective_plan and effective_plan.requires_human_approval:
            return False, None, True

        return True, None, False

    async def coordinate_discovery_to_working(
        self,
        session_id: str,
        opportunity: Optional[DetectedOpportunity] = None,
        repository_name: Optional[str] = None,
    ) -> SessionRecord:
        """
        Automated coordinator that moves an admitted session from DISCOVERED
        through ELIGIBLE -> ANALYZING -> PLANNING -> AWAITING_POLICY -> (policy evaluation) -> WORKING.
        """
        record = await self._repo.get_session(session_id)
        if record is None:
            raise OrchestratorError(f"Session {session_id} not found")

        current = SessionState(record.state)

        if current == SessionState.DISCOVERED:
            record = await self._transition_to_eligible(record)
            current = SessionState(record.state)

        if current == SessionState.ELIGIBLE:
            record = await self._transition_to_analyzing(record)
            current = SessionState(record.state)

        if current == SessionState.ANALYZING:
            if opportunity is None:
                opp_stmt = select(OpportunityRecord).where(
                    OpportunityRecord.repository_id == record.repository_id
                ).order_by(OpportunityRecord.created_at.desc())
                opp_res = await self._db.execute(opp_stmt)
                opp_rec = opp_res.scalars().first()
                if opp_rec:
                    task_type_str = opp_rec.task_type
                    try:
                        t_type = TaskType(task_type_str)
                    except ValueError:
                        t_type = TaskType.PACKAGE_METADATA
                    opportunity = DetectedOpportunity(
                        task_type=t_type,
                        evidence=opp_rec.evidence_json or [],
                        target_paths=opp_rec.target_paths_json or ["pyproject.toml"],
                        risk_tier=RiskTier(opp_rec.risk_tier) if opp_rec.risk_tier in [r.value for r in RiskTier] else RiskTier.R2,
                        confidence=opp_rec.confidence or 0.95,
                        validation_recipe=["echo ok"],
                        summary=opp_rec.summary or "Automated maintenance update"
                    )
            record = await self._transition_to_planning(record, opportunity)
            current = SessionState(record.state)

        if current == SessionState.PLANNING:
            record = await self._transition_to_awaiting_policy(record)
            current = SessionState(record.state)

        if current == SessionState.AWAITING_POLICY:
            can_work, reject_reason, requires_approval = await self.evaluate_policy_gate(
                record, repository_name=repository_name
            )
            if reject_reason:
                return await self._transition(record, SessionState.REJECTED, {
                    "reason": f"Policy gate rejected: {reject_reason}"
                })
            elif requires_approval:
                return record
            elif can_work:
                return await self._transition_to_working(record)

        return record

    async def _do_working(
        self,
        record: SessionRecord,
        opportunity: Optional[DetectedOpportunity],
        original_file_contents: Optional[Dict[str, str]],
    ) -> SessionRecord:
        from automaintainer.execution.sandbox_interface import safe_workspace_path
        import difflib

        if original_file_contents is None and record.workspace_id and opportunity and opportunity.target_paths:
            import os
            original_file_contents = {}
            for path in opportunity.target_paths:
                full_path = safe_workspace_path(record.workspace_id, path)
                if os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        original_file_contents[path] = f.read()
                else:
                    original_file_contents[path] = ""

        if opportunity is None or original_file_contents is None:
            raise OrchestratorError("WORKING requires opportunity and original_file_contents")

        plan = await self._planner.plan(opportunity, session_id=record.id)

        patch_result = self._patcher.apply(plan, original_file_contents, opportunity)
        if not patch_result.success:
            raise OrchestratorError(f"Patcher errors: {'; '.join(patch_result.errors)}")

        firewall = DiffFirewall()
        passed, violations = firewall.inspect(patch_result.planned_diff)
        if not passed:
            raise SafetyStopError(f"DiffFirewall rejected diff: {'; '.join(violations)}")

        if record.workspace_id:
            import os
            for rel_path, new_content in patch_result.file_contents.items():
                full_path = safe_workspace_path(record.workspace_id, rel_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

        if self._reviewer is not None:
            diff_lines = []
            for f in patch_result.planned_diff.files:
                old_lines = original_file_contents.get(f.path, "").splitlines(keepends=True)
                new_lines = patch_result.file_contents.get(f.path, "").splitlines(keepends=True)
                unified = list(difflib.unified_diff(
                    old_lines, new_lines,
                    fromfile=f"a/{f.path}",
                    tofile=f"b/{f.path}"
                ))
                if unified:
                    diff_lines.extend(unified)
                else:
                    diff_lines.append(f"--- a/{f.path}\n+++ b/{f.path}\n(+{f.lines_added}/-{f.lines_deleted} lines)\n")
            diff_text = "".join(diff_lines)
            try:
                await self._reviewer.review(plan.objective, plan.target_paths, diff_text)
            except ReviewRejectionError as exc:
                raise OrchestratorError(f"Reviewer rejected diff: {exc}") from exc

        await self._audit.record(
            session_id=record.id,
            actor_type="agent",
            actor_id="patcher",
            action="apply_patch",
            target=f"sessions/{record.id}",
            details={
                "total_files": patch_result.planned_diff.total_files,
                "total_lines_added": patch_result.planned_diff.total_lines_added,
                "total_lines_deleted": patch_result.planned_diff.total_lines_deleted,
            },
        )

        return await self._transition(record, SessionState.VALIDATING, {
            "patch_files": patch_result.planned_diff.total_files
        })

    async def _do_validating(self, record: SessionRecord) -> SessionRecord:
        await self._audit.record(
            session_id=record.id,
            actor_type="system",
            actor_id="session_orchestrator",
            action="enter_validating",
            target=f"sessions/{record.id}",
            details={},
        )
        return record

    async def apply_validation_result(
        self,
        record_or_id: Union[SessionRecord, str],
        report: ValidationReport,
        auto_transition_pr_open: bool = True,
    ) -> SessionRecord:
        """Called by the worker after ValidationRunner.run() completes."""
        if isinstance(record_or_id, str):
            record = await self._repo.get_session(record_or_id)
            if record is None:
                raise OrchestratorError(f"Session {record_or_id} not found")
        else:
            record = record_or_id

        for gate in report.gate_results:
            vr = ValidationRunRecord(
                id=f"vrun_{uuid.uuid4().hex}",
                session_id=record.id,
                gate_name=gate.gate_name,
                passed=gate.passed,
                command=gate.command,
                duration_seconds=gate.duration_seconds,
                details_json=gate.details,
            )
            self._db.add(vr)
        await self._db.flush()

        if report.is_safety_stop:
            self._metrics.safety_stop()
            return await self._transition(record, SessionState.SAFETY_STOP, {
                "reason": report.summary
            })
        elif not report.passed:
            self._metrics.validation_failed()
            return await self._transition(record, SessionState.REJECTED, {
                "reason": report.summary,
                "failed_gates": report.failed_gates(),
            })
        else:
            self._metrics.validation_passed()
            if auto_transition_pr_open:
                return await self._transition(record, SessionState.PR_OPEN, {
                    "reason": "All validation gates passed"
                })
            return record

    async def handle_maintainer_review(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.MAINTAINER_REVIEW, {"source": "pr_published"})

    async def handle_revalidating(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.REVALIDATING, {"source": "revalidation_started"})

    async def handle_safety_stop(self, record: SessionRecord, reason: str) -> SessionRecord:
        self._metrics.safety_stop()
        return await self._transition(record, SessionState.SAFETY_STOP, {"reason": reason})

    async def handle_expired(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.EXPIRED, {"reason": "Session TTL expired"})

    async def handle_pr_merged(self, record: SessionRecord) -> SessionRecord:
        self._metrics.pr_merged()
        return await self._transition(record, SessionState.MERGED, {"source": "github_webhook"})

    async def handle_pr_closed(self, record: SessionRecord) -> SessionRecord:
        self._metrics.pr_rejected()
        return await self._transition(record, SessionState.REJECTED, {"source": "github_webhook"})

    async def handle_changes_requested(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.CHANGES_REQUESTED, {
            "source": "maintainer_review"
        })

    async def cancel(self, record: SessionRecord) -> SessionRecord:
        return await self._transition(record, SessionState.CANCELLED, {
            "source": "operator_request"
        })

    async def transition(
        self,
        session_id: str,
        target_state: SessionState,
        actor: str = "system",
        reason: str = "",
        details: Optional[Dict] = None,
    ) -> SessionRecord:
        """Explicit external/worker driven transition helper."""
        record = await self._repo.get_session(session_id)
        if record is None:
            raise OrchestratorError(f"Session {session_id} not found")
        data = {"actor": actor, "reason": reason}
        if details:
            data.update(details)
        return await self._transition(record, target_state, data)


    async def _transition(
        self,
        record: SessionRecord,
        target_state: SessionState,
        details: Dict,
    ) -> SessionRecord:
        current = SessionState(record.state)
        self._fsm.validate_transition(current, target_state)

        updated = await self._repo.transition_state_optimistic(
            session_id=record.id,
            expected_state=current,
            target_state=target_state,
            expected_version=record.version,
        )

        await self._audit.record(
            session_id=record.id,
            actor_type="system",
            actor_id="session_orchestrator",
            action="transition_state",
            target=f"sessions/{record.id}",
            details={"from": current.value, "to": target_state.value, **details},
        )
        await self._db.commit()
        return updated
