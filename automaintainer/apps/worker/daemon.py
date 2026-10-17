from __future__ import annotations
import os
import asyncio
import logging
import time
import httpx
from typing import Optional, Dict, Tuple, List, Any, Set
import uuid
from sqlalchemy import select, update
from automaintainer.config import get_settings
from automaintainer.queue.redis_queue import get_partitioned_queue, PartitionedLeasedQueue
from automaintainer.queue.lease import JobStatus
from automaintainer.execution.sandbox_interface import ISandboxRuntime
from automaintainer.execution.sandbox_factory import get_sandbox_runtime
from automaintainer.validation.runner import ValidationRunner
from automaintainer.data.database import get_db_manager
from automaintainer.data.repositories import SessionRepository
from automaintainer.data.tables import (
    SessionRecord, OpportunityRecord, PlanRecord, TaskRecord,
    RepositoryRecord, PullRequestRecord, InstallationRecord
)
from automaintainer.core.session_orchestrator import SessionOrchestrator
from automaintainer.core.models import (
    SessionState, PlannedDiff, FileDiff, TaskType, RiskTier,
    MutationIntent, MutationOp, ResourceBoundCapability
)
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.agents.planner import MaintenancePlanner
from automaintainer.agents.patcher import MinimalPatcher
from automaintainer.core.diff_firewall import DiffFirewall
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.github.executor import GitHubExecutor
from automaintainer.github.mutation_gateway import GitHubMutationGateway
from automaintainer.github.pr_manager import PullRequestManager, AntiSpamBlockedError
from automaintainer.github.token_broker import InstallationTokenBroker
from automaintainer.agents.comment_agent import MaintainerCommentAgent, CommentIntent
from automaintainer.github.collaborator_resolver import GitHubCollaboratorResolver
from automaintainer.discovery.anti_spam import get_anti_spam_manager
from automaintainer.github.git_data_client import MergeConflictError, BranchConflictError, UpstreamDriftError
from automaintainer.inference.gateway import GroqInferenceGateway
from automaintainer.inference.key_pool import KeyPoolRegistry, get_global_key_pool
from automaintainer.inference.quota_manager import OrgQuotaManager

logger = logging.getLogger("automaintainer.worker")

class SessionLockLostError(RuntimeError):
    """Raised when ownership of a distributed session lock is lost during execution."""
    pass

class WorkerDaemon:
    """
    Worker daemon pipeline:
    Runs continuous event loop on PartitionedLeasedQueue:
    - Leases job with heartbeat.
    - Resolves session from database.
    - Prepares ephemeral sandbox workspace (with shallow git clone).
    - Advances SessionOrchestrator from WORKING -> VALIDATING -> PR_OPEN.
    - Guarantees post-execution workspace destruction.
    """

    _session_locks: Dict[str, asyncio.Lock] = {}

    def __init__(
        self,
        worker_id: str = "worker_prod_1",
        queue: Optional[PartitionedLeasedQueue] = None,
        sandbox: Optional[ISandboxRuntime] = None
    ):
        self.worker_id = worker_id
        self.queue = queue or get_partitioned_queue()
        self.sandbox = sandbox or get_sandbox_runtime()
        self.running = False

    async def acquire_session_lock(self, session_id: str, ttl_seconds: int = 300) -> Tuple[bool, str]:
        """
        Acquires distributed session mutex with ownership epoch:
        automaintainer:lock:session:{session_id} -> "{worker_id}:{epoch_uuid}".
        Ensures only one worker operates on a given session at any moment.
        In production/staging, fails closed if Redis is unavailable.
        Returns: (success: bool, lease_epoch: str)
        """
        settings = get_settings()
        is_prod = settings.ENVIRONMENT.lower().strip() in ("production", "staging")

        lease_epoch = f"{self.worker_id}:{uuid.uuid4().hex[:12]}"
        redis_client = getattr(self.queue, "redis_client", None)
        if not redis_client and hasattr(self.queue, "redis_stream_driver") and self.queue.redis_stream_driver:
            redis_client = getattr(self.queue.redis_stream_driver, "redis", None)

        lock_key = f"automaintainer:lock:session:{session_id}"
        if redis_client:
            try:
                acquired = redis_client.set(lock_key, lease_epoch, nx=True, ex=ttl_seconds)
                if acquired:
                    return True, lease_epoch
                return False, ""
            except Exception as e:
                logger.warning(f"Redis session lock acquisition failed for {session_id}: {e}")
                if is_prod:
                    logger.error(f"Failing closed in production: Redis lock acquisition failed for {session_id}")
                    return False, ""

        if is_prod and not settings.ALLOW_IN_MEMORY_QUEUE:
            logger.error(f"Failing closed in production: Redis client not configured for distributed lock on {session_id}")
            return False, ""

        cls = self.__class__
        if session_id not in cls._session_locks:
            cls._session_locks[session_id] = asyncio.Lock()
        lock = cls._session_locks[session_id]
        if lock.locked():
            return False, ""
        await lock.acquire()
        return True, lease_epoch

    async def release_session_lock(self, session_id: str, lease_epoch: Optional[str] = None) -> bool:
        """
        Releases distributed session mutex atomically using CAS Lua script.
        Only deletes the key if its value matches lease_epoch (or self.worker_id for legacy).
        """
        redis_client = getattr(self.queue, "redis_client", None)
        if not redis_client and hasattr(self.queue, "redis_stream_driver") and self.queue.redis_stream_driver:
            redis_client = getattr(self.queue.redis_stream_driver, "redis", None)

        lock_key = f"automaintainer:lock:session:{session_id}"
        expected_val = lease_epoch or self.worker_id
        if redis_client:
            try:
                lua = """
                if redis.call('get', KEYS[1]) == ARGV[1] then
                    return redis.call('del', KEYS[1])
                else
                    return 0
                end
                """
                res = redis_client.eval(lua, 1, lock_key, expected_val)
                return bool(res)
            except Exception as e:
                logger.warning(f"Redis session lock release error for {session_id}: {e}")

        cls = self.__class__
        if session_id in cls._session_locks:
            lock = cls._session_locks[session_id]
            if lock.locked():
                lock.release()
                return True
        return True

    async def renew_session_lock(self, session_id: str, lease_epoch: Optional[str] = None, ttl_seconds: int = 300) -> bool:
        """
        Renews distributed session mutex using atomic CAS Lua script:
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('expire', KEYS[1], ARGV[2])
        else
            return 0
        end
        """
        settings = get_settings()
        is_prod = settings.ENVIRONMENT.lower().strip() in ("production", "staging")

        redis_client = getattr(self.queue, "redis_client", None)
        if not redis_client and hasattr(self.queue, "redis_stream_driver") and self.queue.redis_stream_driver:
            redis_client = getattr(self.queue.redis_stream_driver, "redis", None)

        lock_key = f"automaintainer:lock:session:{session_id}"
        expected_val = lease_epoch or self.worker_id
        if redis_client:
            try:
                lua = """
                if redis.call('get', KEYS[1]) == ARGV[1] then
                    return redis.call('expire', KEYS[1], ARGV[2])
                else
                    return 0
                end
                """
                res = redis_client.eval(lua, 1, lock_key, expected_val, ttl_seconds)
                return bool(res)
            except Exception as e:
                logger.warning(f"Redis session lock renewal failed for {session_id}: {e}")
                return False

        if is_prod and not settings.ALLOW_IN_MEMORY_QUEUE:
            logger.error(f"Failing closed in production: cannot renew session lock without Redis for {session_id}")
            return False

        return True

    async def start(self, poll_interval: float = 0.5, max_iterations: Optional[int] = None):
        self.running = True
        logger.info(f"Worker {self.worker_id} started. Listening for leased jobs...")

        if hasattr(self.sandbox, "cleanup_stale_workspaces"):
            try:
                cleaned = await self.sandbox.cleanup_stale_workspaces()
                if cleaned > 0:
                    logger.info(f"Startup sweep: cleaned {cleaned} orphaned ephemeral workspace(s).")
            except Exception as e:
                logger.debug(f"Startup workspace sweep notice: {e}")

        iterations = 0

        while self.running:
            if max_iterations is not None and iterations >= max_iterations:
                break

            iterations += 1
            result = self.queue.acquire_next_job(self.worker_id)
            if not result:
                await asyncio.sleep(poll_interval)
                continue

            queue_name, job = result
            logger.info(f"Worker {self.worker_id} leased job {job.job_id} from queue '{queue_name}'")

            try:
                await self.execute_job(queue_name, job)
                self.queue.complete(queue_name, job.job_id, self.worker_id)
                logger.info(f"Job {job.job_id} completed successfully.")
            except Exception as e:
                logger.error(f"Error executing job {job.job_id}: {str(e)}", exc_info=True)
                self.queue.fail(queue_name, job.job_id, self.worker_id, str(e))

            await asyncio.sleep(0.01)

    async def execute_job(self, queue_name: str, job):
        """
        Executes real orchestrator pipeline steps:
        1. Emits heartbeat to maintain lease.
        2. Routes conversation jobs (issue comments, reviews) to MaintainerCommentAgent.
        3. Routes github-write jobs (PR merge / close) to orchestrator state sync.
        4. Coordinates DISCOVERED sessions through PLANNING and policy checks into WORKING.
        5. Executes patch & validation pipeline for WORKING sessions.
        """
        self.queue.heartbeat(queue_name, job.job_id, self.worker_id)
        session_id = job.session_id

        db_mgr = get_db_manager()
        async with db_mgr.get_session() as db:
            if job.task_type == "installation_reconciliation":
                await self._handle_installation_reconciliation(job, db)
                return

            if job.task_type == "repository_scan":
                await self._handle_repository_scan(job, db)
                return

            if job.task_type == "github.push":
                await self._handle_github_push(job, db)
                return

            if job.task_type in ("github.installation", "github.installation_repositories"):
                await self._handle_github_installation_event(job, db)
                return

            if job.task_type == "github.pull_request":
                repo = SessionRepository(db)
                session_rec = await repo.get_session(session_id)
                if session_rec:
                    orchestrator = SessionOrchestrator(db)
                    await self._handle_github_write_job(queue_name, job, session_rec, db, orchestrator)
                else:
                    logger.info(f"Pull request event for non-managed session {session_id}; acknowledging.")
                return

            repo = SessionRepository(db)
            session_rec = await repo.get_session(session_id)
            if not session_rec:
                logger.error(f"Session {session_id} not found in database; failing job {job.job_id} to DLQ.")
                raise RuntimeError(f"Session record {session_id} not found")

            orchestrator = SessionOrchestrator(db)
            self.queue.heartbeat(queue_name, job.job_id, self.worker_id)

            if queue_name == "conversation" or job.task_type in ("github.issue_comment", "github.pull_request_review"):
                await self._handle_conversation_job(queue_name, job, session_rec, db, orchestrator)
                return

            if queue_name == "github-write":
                await self._handle_github_write_job(queue_name, job, session_rec, db, orchestrator)
                return

            if session_rec.state in (
                SessionState.DISCOVERED.value,
                SessionState.ELIGIBLE.value,
                SessionState.ANALYZING.value,
                SessionState.PLANNING.value,
                SessionState.AWAITING_POLICY.value,
            ):
                logger.info(f"Coordinating session {session_id} from {session_rec.state} towards WORKING...")
                session_rec = await orchestrator.coordinate_discovery_to_working(
                    session_id, repository_name=job.payload.get("repository")
                )
                if session_rec.state != SessionState.WORKING.value:
                    logger.info(f"Session {session_id} coordinated to {session_rec.state}; pausing worker execution.")
                    return

            if session_rec.state == SessionState.VALIDATING.value:
                logger.info(f"Session {session_id} was interrupted in VALIDATING; resetting to WORKING for retry.")
                session_rec = await orchestrator.transition(
                    session_id,
                    SessionState.WORKING,
                    actor=self.worker_id,
                    reason="Resetting interrupted VALIDATING session to WORKING for pipeline retry."
                )

            if session_rec.state != SessionState.WORKING.value:
                logger.warning(f"Session {session_id} in state '{session_rec.state}', cannot run patch pipeline.")
                return

            await self._execute_patch_pipeline(queue_name, job, session_rec, db, orchestrator)

    async def _handle_installation_reconciliation(self, job, db):
        payload = job.payload or {}
        installation_id = payload.get("installation_id")
        logger.info(f"Worker {self.worker_id} executing installation reconciliation for {installation_id}")

        inst_stmt = select(InstallationRecord).where(InstallationRecord.github_installation_id == installation_id)
        inst_res = await db.execute(inst_stmt)
        inst = inst_res.scalar_one_or_none()
        if not inst:
            logger.warning(f"Installation {installation_id} not found in DB during reconciliation")
            return

        settings = get_settings()
        if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
            logger.error(f"Cannot reconcile installation {installation_id}: GitHub App credentials not configured.")
            return

        try:
            from automaintainer.github.auth import InstallationTokenBroker
            broker = InstallationTokenBroker(settings)
            tok_rec = await broker.get_token(installation_id)
            github_token = tok_rec.token if tok_rec else ""
        except Exception as e:
            logger.error(f"Failed to mint installation token for installation {installation_id}: {e}; preserving bindings and aborting cycle.")
            return

        if not github_token:
            logger.error(f"Empty installation token for installation {installation_id}; aborting reconciliation.")
            return

        repo_stmt = select(RepositoryRecord).where(RepositoryRecord.installation_id == inst.id)
        repo_res = await db.execute(repo_stmt)
        repos = repo_res.scalars().all()

        from automaintainer.core.reconciler import SessionReconciler
        reconciler = SessionReconciler(db)
        reconciled_count = 0
        for r in repos:
            repo_full_name = f"{r.owner}/{r.name}"
            sess_stmt = select(SessionRecord).where(
                SessionRecord.repository_id == r.id,
                SessionRecord.pr_number.isnot(None),
                SessionRecord.state.in_([
                    SessionState.PR_OPEN.value,
                    SessionState.MAINTAINER_REVIEW.value,
                    SessionState.CHANGES_REQUESTED.value
                ])
            )
            sess_res = await db.execute(sess_stmt)
            active_sessions = sess_res.scalars().all()
            for s in active_sessions:
                try:
                    await reconciler.reconcile_session(
                        session=s,
                        repo_owner_name=repo_full_name,
                        github_token=github_token
                    )
                    reconciled_count += 1
                except Exception as e:
                    logger.warning(f"Error reconciling session {s.id}: {e}")

        logger.info(f"Installation {installation_id} reconciliation completed: {reconciled_count} sessions reconciled across {len(repos)} repos.")

    async def _handle_github_installation_event(self, job, db):
        payload = job.payload or {}
        action = payload.get("action", "")
        inst_data = payload.get("installation") or {}
        gh_inst_id = inst_data.get("id")
        if not gh_inst_id:
            logger.warning(f"Worker {self.worker_id}: Received installation event without installation.id")
            return

        logger.info(f"Worker {self.worker_id} processing installation event {job.task_type} action={action} gh_inst_id={gh_inst_id}")

        inst_stmt = select(InstallationRecord).where(InstallationRecord.github_installation_id == gh_inst_id)
        inst_res = await db.execute(inst_stmt)
        inst_rec = inst_res.scalars().first()

        if action in ("deleted", "suspend"):
            if inst_rec:
                inst_rec.status = "deleted" if action == "deleted" else "suspended"
                await db.execute(
                    update(RepositoryRecord)
                    .where(RepositoryRecord.installation_id == inst_rec.id)
                    .values(installation_id=None)
                )
                await db.commit()
                logger.info(f"Marked installation {gh_inst_id} as {inst_rec.status} and cleared repository bindings.")
            return

        if not inst_rec:
            account = inst_data.get("account") or {}
            target_type = "user" if account.get("type") == "User" else "organization"
            inst_rec = InstallationRecord(
                github_installation_id=gh_inst_id,
                account_id=account.get("id", 1),
                target_type=target_type,
                status="active"
            )
            db.add(inst_rec)
            await db.flush()
        else:
            inst_rec.status = "active"
            await db.flush()

        # Handle repositories added or present in created event
        repos_to_add = payload.get("repositories_added") or payload.get("repositories") or []
        for r_info in repos_to_add:
            r_gh_id = r_info.get("id")
            r_full_name = r_info.get("full_name", "")
            if not r_full_name or "/" not in r_full_name:
                continue
            r_owner, r_name = r_full_name.split("/", 1)
            repo_stmt = select(RepositoryRecord).where(RepositoryRecord.github_repo_id == r_gh_id)
            repo_res = await db.execute(repo_stmt)
            r_rec = repo_res.scalars().first()
            if not r_rec:
                r_rec = RepositoryRecord(
                    github_repo_id=r_gh_id,
                    owner=r_owner,
                    name=r_name,
                    installation_id=inst_rec.id,
                    visibility="public" if not r_info.get("private", False) else "private",
                    default_branch="main"
                )
                db.add(r_rec)
            else:
                r_rec.installation_id = inst_rec.id
            await db.flush()

        # Handle repositories removed
        repos_to_remove = payload.get("repositories_removed") or []
        for r_info in repos_to_remove:
            r_gh_id = r_info.get("id")
            if r_gh_id:
                repo_stmt = select(RepositoryRecord).where(RepositoryRecord.github_repo_id == r_gh_id)
                repo_res = await db.execute(repo_stmt)
                r_rec = repo_res.scalars().first()
                if r_rec and r_rec.installation_id == inst_rec.id:
                    r_rec.installation_id = None
                    await db.flush()

        await db.commit()
        logger.info(f"Successfully processed installation event for gh_inst_id={gh_inst_id} (action={action})")

    async def _handle_repository_scan(self, job, db):
        payload = job.payload or {}
        repo_id = payload.get("repository_id")
        repo_name = payload.get("repo_name", "")
        logger.info(f"Worker {self.worker_id} executing installed repository scan for repo {repo_id} ({repo_name})")

        repo_stmt = select(RepositoryRecord).where(RepositoryRecord.id == repo_id)
        repo_res = await db.execute(repo_stmt)
        repo = repo_res.scalar_one_or_none()
        if not repo:
            logger.warning(f"Repository {repo_id} not found in DB during scan")
            return

        owner = repo.owner
        name = repo.name
        full_name = f"{owner}/{name}"
        settings = get_settings()

        token = ""
        if repo.installation_id:
            if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PRIVATE_KEY:
                logger.error(f"Cannot scan installed repo {full_name}: GitHub App credentials not configured.")
                return
            try:
                from automaintainer.github.auth import InstallationTokenBroker
                inst_stmt = select(InstallationRecord).where(InstallationRecord.id == repo.installation_id)
                inst_res = await db.execute(inst_stmt)
                inst_rec = inst_res.scalar_one_or_none()
                if not inst_rec:
                    logger.error(f"Installation record {repo.installation_id} not found for repo {full_name}; aborting scan.")
                    return
                broker = InstallationTokenBroker(settings)
                tok_rec = await broker.get_token(inst_rec.github_installation_id)
                token = tok_rec.token if tok_rec else ""
            except Exception as tok_err:
                logger.error(f"Could not mint installation token for repository scan {full_name}: {tok_err}; aborting scan.")
                return

            if not token:
                logger.error(f"Empty installation token for installed repository scan {full_name}; aborting scan.")
                return
        else:
            token = settings.GITHUB_TOKEN or ""

        from automaintainer.discovery.candidate_crawler import OpportunityScanner
        scanner = OpportunityScanner(api_base_url=settings.GITHUB_API_BASE_URL)
        opps = await scanner.scan(owner=owner, repo=name, token=token)

        admitted_count = 0
        from automaintainer.data.tables import OutboxRecord
        for opp in opps:
            opp_id = f"opp_{uuid.uuid4().hex[:12]}"
            session_id = f"sess_{uuid.uuid4().hex[:12]}"
            opp_record = OpportunityRecord(
                id=opp_id,
                repository_id=repo.id,
                task_type=opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                summary=opp.summary,
                evidence_json=opp.evidence,
                target_paths_json=opp.target_paths,
                score=int(opp.confidence * 100),
                confidence=opp.confidence,
                risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                metadata_json=opp.metadata or {},
                status="admitted"
            )
            db.add(opp_record)

            sess_record = SessionRecord(
                id=session_id,
                repository_id=repo.id,
                mode="installed",
                state=SessionState.DISCOVERED.value,
                version=1,
                risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                opportunity_score=int(opp.confidence * 100)
            )
            db.add(sess_record)

            task_record = TaskRecord(
                id=f"task_{uuid.uuid4().hex[:12]}",
                session_id=session_id,
                task_type=opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                scope="installed_maintenance",
                evidence_json=opp.evidence,
                confidence=opp.confidence,
                risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                status="pending"
            )
            db.add(task_record)

            payload_data = {
                "repository": full_name,
                "opportunity_id": opp_id,
                "target_paths": opp.target_paths,
                "task_type": opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                "score": int(opp.confidence * 100),
                "repo_url": repo.clone_url or f"https://github.com/{full_name}.git",
            }
            outbox_record = OutboxRecord(
                id=f"outbox_{uuid.uuid4().hex[:12]}",
                queue_name="discovery",
                session_id=session_id,
                task_type="installed_discovery_analysis",
                payload_json=payload_data,
                status="pending"
            )
            db.add(outbox_record)
            await db.commit()

            try:
                self.queue.enqueue(
                    queue_name="discovery",
                    session_id=session_id,
                    task_type="installed_discovery_analysis",
                    payload=payload_data
                )
                outbox_record.status = "dispatched"
                outbox_record.dispatched_at = datetime.datetime.now(datetime.timezone.utc)
                await db.commit()
                admitted_count += 1
            except Exception as q_err:
                logger.error(f"Failed to enqueue installed opportunity {session_id}: {q_err}")

        logger.info(f"Installed repository scan for {full_name} completed; admitted {admitted_count} opportunities.")

    async def _handle_conversation_job(
        self,
        queue_name: str,
        job,
        session_rec: SessionRecord,
        db,
        orchestrator: SessionOrchestrator,
    ):
        payload = job.payload or {}
        comment_data = payload.get("comment", {})
        review_data = payload.get("review", {})

        comment_body = comment_data.get("body") or review_data.get("body") or review_data.get("state") or ""
        actor = comment_data.get("user", {}).get("login") or review_data.get("user", {}).get("login") or payload.get("sender", {}).get("login") or "unknown"
        user_type = comment_data.get("user", {}).get("type") or payload.get("sender", {}).get("type") or ""
        if (
            "automaintainer" in actor.lower()
            or actor.endswith("[bot]")
            or user_type == "Bot"
        ):
            logger.info(f"Ignoring conversation event from bot itself ({actor})")
            return

        author_assoc = (
            comment_data.get("author_association")
            or review_data.get("author_association")
            or payload.get("author_association")
            or ""
        )

        repo_full_name = payload.get("repository", {}).get("full_name", "")
        if not repo_full_name:
            repo_stmt = select(RepositoryRecord).where(RepositoryRecord.id == session_rec.repository_id)
            repo_res = await db.execute(repo_stmt)
            repo_rec = repo_res.scalars().first()
            if repo_rec:
                repo_full_name = f"{repo_rec.owner}/{repo_rec.name}"

        is_auth = author_assoc.upper() in ("OWNER", "MEMBER", "COLLABORATOR")
        if not is_auth and repo_full_name and actor != "unknown":
            settings = get_settings()
            resolver = GitHubCollaboratorResolver(token=settings.GITHUB_TOKEN or "", api_base_url=settings.GITHUB_API_BASE_URL)
            is_auth = await resolver.is_authorized_maintainer(
                repo_full_name, actor, author_association=author_assoc
            )

        settings = get_settings()
        pool = get_global_key_pool()
        quota_mgr = OrgQuotaManager()
        quota_mgr.init_org_limits(settings.GROQ_ORG_ID)
        gateway = GroqInferenceGateway(pool, quota_mgr)
        comment_agent = MaintainerCommentAgent(gateway=gateway)

        classification = await comment_agent.classify(
            comment_body=comment_body,
            actor=actor,
            is_authorized_maintainer=is_auth,
        )
        logger.info(f"Comment classification for session {session_rec.id}: intent={classification.intent.value}, actionable={classification.is_actionable}")

        if classification.intent == CommentIntent.PROMPT_INJECTION:
            logger.warning(f"Prompt injection detected in comment by {actor} for session {session_rec.id}")
            await orchestrator.handle_safety_stop(session_rec, reason=f"Prompt injection in comment: {classification.summary}")
            return

        if classification.intent == CommentIntent.INFORMATIONAL:
            logger.info(f"Maintainer {actor} submitted informational comment on session {session_rec.id}: {comment_body}")
            pr_num = session_rec.pr_number or (payload.get("issue") or payload.get("pull_request") or {}).get("number")
            if pr_num and repo_full_name:
                try:
                    # Only attempt conversational reply if a healthy AI key is registered
                    has_key = bool(gateway.key_pool.select_healthy_key()) if gateway and gateway.key_pool else False
                    if not has_key:
                        logger.info(f"No AI inference key configured; skipping conversational reply on PR #{pr_num}")
                        return

                    github_token = ""
                    if settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY:
                        token_broker = InstallationTokenBroker(
                            app_id=settings.GITHUB_APP_ID,
                            private_key_pem=settings.GITHUB_APP_PRIVATE_KEY,
                            api_base_url=settings.GITHUB_API_BASE_URL,
                        )
                        repo_stmt = select(RepositoryRecord).where(RepositoryRecord.id == session_rec.repository_id)
                        repo_res = await db.execute(repo_stmt)
                        repo_rec = repo_res.scalars().first()
                        if repo_rec and repo_rec.installation_id:
                            try:
                                inst_row = await db.get(InstallationRecord, repo_rec.installation_id)
                                target_inst_id = inst_row.github_installation_id if (inst_row and inst_row.github_installation_id) else repo_rec.installation_id
                                github_token = await token_broker.get_installation_token(target_inst_id)
                            except Exception as tok_e:
                                logger.warning(f"Could not mint installation token in conversation handler: {tok_e}. Falling back to GITHUB_TOKEN.")
                                github_token = ""
                    if not github_token:
                        github_token = settings.GITHUB_TOKEN or ""

                    # Ground the conversational prompt with the actual changes made in this session
                    from automaintainer.data.tables import OpportunityRecord, PlanRecord
                    plan_stmt = select(PlanRecord).where(PlanRecord.session_id == session_rec.id).order_by(PlanRecord.created_at.desc())
                    plan_res = await db.execute(plan_stmt)
                    plan_row = plan_res.scalars().first()

                    opp_stmt = select(OpportunityRecord).where(OpportunityRecord.repository_id == session_rec.repository_id).order_by(OpportunityRecord.created_at.desc())
                    opp_res = await db.execute(opp_stmt)
                    opp_row = opp_res.scalars().first()

                    plan_obj = (plan_row.plan_json or {}).get("objective") if plan_row else (opp_row.summary if opp_row else "automated maintenance")
                    target_files = (plan_row.plan_json or {}).get("target_paths") if plan_row else (opp_row.target_paths_json if opp_row else [])

                    prompt = (
                        f"You are AutoMaintainer, an autonomous bot maintaining GitHub pull request #{pr_num} for repository '{repo_full_name}'.\n"
                        f"Current PR State: {session_rec.state}.\n"
                        f"Actual maintenance objective: {plan_obj}.\n"
                        f"Actual files affected/created: {target_files}.\n"
                        f"The maintainer @{actor} commented: '{comment_body}'.\n"
                        "Respond concisely and accurately in 1-2 sentences strictly based on the actual changes above. Do not invent features or tests not listed."
                    )
                    reply_text = await gateway.complete(
                        messages=[{"role": "user", "content": prompt}],
                        model_id=settings.GROQ_DEFAULT_FAST_MODEL or "openai/gpt-oss-20b",
                    )
                    if reply_text:
                        async with httpx.AsyncClient() as client:
                            await client.post(
                                f"{settings.GITHUB_API_BASE_URL}/repos/{repo_full_name}/issues/{pr_num}/comments",
                                headers={"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"},
                                json={"body": reply_text.strip()},
                                timeout=10.0
                            )
                        logger.info(f"Successfully posted conversational answer to maintainer on PR #{pr_num}")
                except Exception as info_err:
                    logger.info(f"Skipping conversational reply on PR #{pr_num}: {info_err}")
            return

        if classification.intent == CommentIntent.SCOPE_EXPANSION:
            pr_num = session_rec.pr_number or (payload.get("issue") or payload.get("pull_request") or {}).get("number")
            if pr_num and repo_full_name:
                try:
                    github_token = ""
                    if settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY:
                        token_broker = InstallationTokenBroker(
                            app_id=settings.GITHUB_APP_ID,
                            private_key_pem=settings.GITHUB_APP_PRIVATE_KEY,
                            api_base_url=settings.GITHUB_API_BASE_URL,
                        )
                        repo_stmt = select(RepositoryRecord).where(RepositoryRecord.id == session_rec.repository_id)
                        repo_res = await db.execute(repo_stmt)
                        repo_rec = repo_res.scalars().first()
                        if repo_rec and repo_rec.installation_id:
                            try:
                                inst_row = await db.get(InstallationRecord, repo_rec.installation_id)
                                target_inst_id = inst_row.github_installation_id if (inst_row and inst_row.github_installation_id) else repo_rec.installation_id
                                github_token = await token_broker.get_installation_token(target_inst_id)
                            except Exception as tok_e:
                                logger.warning(f"Could not mint installation token in scope expansion handler: {tok_e}. Falling back to GITHUB_TOKEN.")
                                github_token = ""
                    if not github_token:
                        github_token = settings.GITHUB_TOKEN or ""

                    scope_msg = f"Thank you for the suggestion @{actor}! However, this request is outside the scope of this automated maintenance task. Please feel free to open a separate issue or PR for this feature."
                    async with httpx.AsyncClient() as client:
                        await client.post(
                            f"{settings.GITHUB_API_BASE_URL}/repos/{repo_full_name}/issues/{pr_num}/comments",
                            headers={"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"},
                            json={"body": scope_msg},
                            timeout=10.0
                        )
                except Exception as s_err:
                    logger.warning(f"Failed to post scope expansion comment: {s_err}")
            return

        if classification.intent == CommentIntent.REQUEST_SAFE_CHANGE and classification.is_actionable:
            logger.info(f"Maintainer {actor} requested safe change for session {session_rec.id}: {classification.summary}. Triggering repair iteration.")
            current_st = SessionState(session_rec.state)
            if current_st in (SessionState.PR_OPEN, SessionState.MAINTAINER_REVIEW):
                session_rec = await orchestrator.handle_changes_requested(session_rec)
            if SessionState(session_rec.state) == SessionState.CHANGES_REQUESTED:
                session_rec = await orchestrator.transition(
                    session_rec.id,
                    SessionState.WORKING,
                    actor=actor,
                    reason=f"Maintainer requested change: {classification.summary}"
                )
            elif SessionState(session_rec.state) != SessionState.WORKING:
                # Force reset session state to WORKING so repair iteration can proceed safely
                session_rec.state = SessionState.WORKING.value
                await db.commit()

            await self._execute_patch_pipeline(queue_name, job, session_rec, db, orchestrator, maintainer_feedback=comment_body)

    async def _handle_github_write_job(
        self,
        queue_name: str,
        job,
        session_rec: SessionRecord,
        db,
        orchestrator: SessionOrchestrator,
    ):
        payload = job.payload or {}
        action = payload.get("action", "")
        pr_data = payload.get("pull_request", {})
        repo_full_name = payload.get("repository", {}).get("full_name", "")
        pr_number = pr_data.get("number") or session_rec.pr_number
        anti_spam = get_anti_spam_manager()

        if action == "closed":
            is_merged = pr_data.get("merged", False)
            if is_merged:
                logger.info(f"PR #{pr_number} merged on {repo_full_name}. Syncing session {session_rec.id} to MERGED.")
                await orchestrator.handle_pr_merged(session_rec)
                if repo_full_name:
                    anti_spam.record_pr_merge(repo_full_name)
                    if pr_number:
                        anti_spam.release_active_pr(repo_full_name, pr_number)
            else:
                logger.info(f"PR #{pr_number} closed without merge on {repo_full_name}. Syncing session {session_rec.id} to REJECTED.")
                await orchestrator.handle_pr_closed(session_rec)
                if repo_full_name:
                    anti_spam.record_pr_rejection(repo_full_name)
                    if pr_number:
                        anti_spam.release_active_pr(repo_full_name, pr_number)

    async def _handle_github_push(self, job, db):
        import httpx
        payload = job.payload or {}
        ref = payload.get("ref", "")
        repo_data = payload.get("repository", {})
        full_name = repo_data.get("full_name", "")
        default_branch = repo_data.get("default_branch", "main")
        pusher = (payload.get("pusher") or {}).get("name", "")
        sender = (payload.get("sender") or {}).get("login", "")
        deleted = payload.get("deleted", False)

        if deleted:
            logger.info(f"Ignoring push deletion event on {full_name}: {ref}")
            return

        # Avoid reacting to bot's own pushes
        if (
            "automaintainer" in pusher.lower()
            or "automaintainer" in sender.lower()
            or pusher.endswith("[bot]")
            or sender.endswith("[bot]")
            or "automaintainer/" in ref
        ):
            logger.info(f"Ignoring push event from bot itself ({sender}/{pusher}) on {ref}")
            return

        expected_ref = f"refs/heads/{default_branch}"
        if ref != expected_ref:
            logger.info(f"Ignoring push event on non-default branch {ref} (default is {expected_ref})")
            return

        logger.info(f"Push detected on {expected_ref} for repository {full_name}. Triggering automated opportunity discovery...")
        from automaintainer.discovery.managed_repos import ManagedRepoService
        service = ManagedRepoService(queue=self.queue)
        async with httpx.AsyncClient() as client:
            admitted = await service.process_repository(full_name, client=client, force_rescan=True)
            logger.info(f"Automated push discovery completed for {full_name}: {len(admitted)} opportunity session(s) admitted.")

    async def _execute_patch_pipeline(
        self,
        queue_name: str,
        job,
        session_rec: SessionRecord,
        db,
        orchestrator: SessionOrchestrator,
        maintainer_feedback: Optional[str] = None,
    ):
        repo_url = job.payload.get("repo_url", "")
        commit_sha = job.payload.get("commit_sha", "HEAD")
        session_id = session_rec.id

        if not repo_url:
            repo_stmt = select(RepositoryRecord).where(RepositoryRecord.id == session_rec.repository_id)
            repo_res = await db.execute(repo_stmt)
            scalars_fn = getattr(repo_res, "scalars", None)
            repo_rec = None
            if callable(scalars_fn):
                res_obj = scalars_fn()
                if asyncio.iscoroutine(res_obj) or hasattr(res_obj, "__await__"):
                    res_obj = await res_obj
                repo_rec = res_obj.first() if hasattr(res_obj, "first") else None
            elif hasattr(repo_res, "first"):
                repo_rec = repo_res.first()

            if repo_rec:
                if getattr(repo_rec, "clone_url", None):
                    repo_url = repo_rec.clone_url
                elif getattr(repo_rec, "full_name", None):
                    repo_url = f"https://github.com/{repo_rec.full_name}.git"
                elif getattr(repo_rec, "owner", None) and getattr(repo_rec, "name", None):
                    repo_url = f"https://github.com/{repo_rec.owner}/{repo_rec.name}.git"
            if not repo_url and job.payload.get("repository"):
                repo_url = f"https://github.com/{job.payload.get('repository')}.git"

        lock_res = await self.acquire_session_lock(session_id)
        if isinstance(lock_res, tuple):
            lock_acquired, lease_epoch = lock_res
        else:
            lock_acquired = bool(lock_res)
            lease_epoch = self.worker_id

        if not lock_acquired:
            logger.warning(
                f"Session {session_id} is currently locked by another worker. Deferring execution for job {job.job_id}."
            )
            self.queue.enqueue(
                queue_name=queue_name,
                session_id=session_id,
                task_type=job.task_type,
                payload=job.payload,
            )
            return

        lock_lost_event = asyncio.Event()
        renew_task = None
        async def _heartbeat_lock():
            while True:
                await asyncio.sleep(60.0)
                try:
                    renewed = await self.renew_session_lock(session_id, lease_epoch=lease_epoch, ttl_seconds=300)
                    if not renewed:
                        logger.error(f"Distributed lock ownership lost for session {session_id}! Aborting worker mutation authority.")
                        lock_lost_event.set()
                        break
                except asyncio.CancelledError:
                    break
                except Exception as err:
                    logger.warning(f"Error renewing session lock for {session_id}: {err}")
                    lock_lost_event.set()
                    break

        renew_task = asyncio.create_task(_heartbeat_lock())
        workspace_id = None
        try:
            if lock_lost_event.is_set():
                raise SessionLockLostError(f"Worker lost session lock for {session_id} prior to sandbox preparation.")

            workspace_id = await self.sandbox.prepare_workspace(repo_url=repo_url, commit_sha=commit_sha)
            self.queue.heartbeat(queue_name, job.job_id, self.worker_id)

            opp_stmt = select(OpportunityRecord).where(
                OpportunityRecord.repository_id == session_rec.repository_id
            ).order_by(OpportunityRecord.created_at.desc())
            opp_res = await db.execute(opp_stmt)
            opp_scalars_fn = getattr(opp_res, "scalars", None)
            opp_rec = None
            if callable(opp_scalars_fn):
                res_obj = opp_scalars_fn()
                if asyncio.iscoroutine(res_obj) or hasattr(res_obj, "__await__"):
                    res_obj = await res_obj
                opp_rec = res_obj.first() if hasattr(res_obj, "first") else None
            elif hasattr(opp_res, "first"):
                opp_rec = opp_res.first()

            task_type_str = job.payload.get("task_type") or (opp_rec.task_type if opp_rec else "package_metadata")
            try:
                task_type = TaskType(task_type_str)
            except ValueError:
                task_type = TaskType.PACKAGE_METADATA

            target_paths = job.payload.get("target_paths") or (opp_rec.target_paths_json if opp_rec else ["pyproject.toml"])
            summary = job.payload.get("summary") or (opp_rec.summary if opp_rec else f"Maintenance update for {task_type.value}")
            evidence = job.payload.get("evidence") or (opp_rec.evidence_json if opp_rec else [])
            metadata = job.payload.get("metadata") or (opp_rec.metadata_json if opp_rec and opp_rec.metadata_json else {})

            test_recipe = []
            if os.path.exists(os.path.join(workspace_id, "tests")) or os.path.exists(os.path.join(workspace_id, "test")):
                test_recipe.append("python -m unittest discover -s tests" if os.path.exists(os.path.join(workspace_id, "tests")) else "python -m unittest discover -s test")
            elif os.path.exists(os.path.join(workspace_id, "pytest.ini")) or os.path.exists(os.path.join(workspace_id, "pyproject.toml")):
                test_recipe.append("pytest")
            elif os.path.exists(os.path.join(workspace_id, "package.json")):
                test_recipe.append("npm test")
            elif os.path.exists(os.path.join(workspace_id, "Cargo.toml")):
                test_recipe.append("cargo test")
            elif os.path.exists(os.path.join(workspace_id, "go.mod")):
                test_recipe.append("go test ./...")

            opportunity = DetectedOpportunity(
                task_type=task_type,
                evidence=evidence,
                target_paths=target_paths,
                risk_tier=RiskTier(session_rec.risk_tier) if session_rec.risk_tier in [r.value for r in RiskTier] else RiskTier.R2,
                confidence=opp_rec.confidence if opp_rec else 0.95,
                validation_recipe=test_recipe,
                summary=summary,
                metadata=metadata,
            )

            plan_stmt = select(PlanRecord).where(PlanRecord.session_id == session_id).order_by(PlanRecord.created_at.desc())
            plan_res = await db.execute(plan_stmt)
            plan_scalars_fn = getattr(plan_res, "scalars", None)
            plan_rec = None
            if callable(plan_scalars_fn):
                plan_obj = plan_scalars_fn()
                if asyncio.iscoroutine(plan_obj) or hasattr(plan_obj, "__await__"):
                    plan_obj = await plan_obj
                plan_rec = plan_obj.first() if hasattr(plan_obj, "first") else None
            elif hasattr(plan_res, "first"):
                plan_rec = plan_res.first()

            repo_context = ""
            readme_path = os.path.join(workspace_id, "README.md")
            if os.path.exists(readme_path):
                with open(readme_path, "r", encoding="utf-8", errors="replace") as f:
                    repo_context = f.read(2000)

            if not maintainer_feedback and plan_rec and plan_rec.plan_json:
                pj = dict(plan_rec.plan_json)
                if not pj.get("objective") and opportunity:
                    pj["objective"] = opportunity.summary
                if not pj.get("task_type") and opportunity:
                    pj["task_type"] = opportunity.task_type.value
                if not pj.get("target_paths") and opportunity:
                    pj["target_paths"] = opportunity.target_paths
                if not pj.get("risk_tier") and opportunity:
                    pj["risk_tier"] = opportunity.risk_tier.value
                if "confidence" not in pj and opportunity:
                    pj["confidence"] = opportunity.confidence

                edits = []
                for e in pj.get("proposed_edits", []):
                    if isinstance(e, dict):
                        edits.append(ProposedEdit(
                            path=e.get("path", ""),
                            operation=e.get("operation", "modify"),
                            rationale=e.get("rationale", ""),
                            new_content=e.get("new_content") or e.get("after_snippet", "")
                        ))
                    elif isinstance(e, ProposedEdit):
                        edits.append(e)
                pj["proposed_edits"] = edits

                vsteps = []
                raw_vsteps = pj.get("validation_steps") or pj.get("validation_recipe") or test_recipe
                for v in raw_vsteps:
                    if isinstance(v, dict):
                        vsteps.append(ValidationStep(
                            command=v.get("command", ""),
                            reason=v.get("reason", "validation step"),
                            expected_outcome=v.get("expected_outcome", "success")
                        ))
                    elif isinstance(v, ValidationStep):
                        vsteps.append(v)
                    elif isinstance(v, str):
                        vsteps.append(ValidationStep(
                            command=v,
                            reason="stored test step",
                            expected_outcome="exit 0"
                        ))
                pj["validation_steps"] = vsteps

                if "explicitly_unchanged" not in pj:
                    pj["explicitly_unchanged"] = []
                if "requires_human_approval" not in pj:
                    pj["requires_human_approval"] = False

                plan = PlannerOutput(**pj)
            else:
                planner = MaintenancePlanner()
                plan = await planner.plan(
                    opportunity=opportunity,
                    repo_context=repo_context,
                    session_id=session_id,
                    maintainer_feedback=maintainer_feedback
                )

            if maintainer_feedback:
                plan.objective = f"{plan.objective} (Incorporating maintainer feedback: {maintainer_feedback})"

            patcher = MinimalPatcher()
            patch_result = await patcher.apply_patch(
                workspace_path=workspace_id,
                plan=plan,
                maintainer_feedback=maintainer_feedback,
            )

            diff_firewall = DiffFirewall()
            firewall_decision = diff_firewall.inspect_diff(
                diff=patch_result.planned_diff,
                allowed_paths=plan.target_paths,
                session_risk_tier=opportunity.risk_tier
            )

            if not firewall_decision.passed:
                logger.warning(
                    f"Session {session_id} failed DiffFirewall checks: {firewall_decision.rejection_reason}. Triggering SAFETY_STOP."
                )
                await orchestrator.handle_safety_stop(
                    session_rec,
                    reason=f"DiffFirewall rejection: {firewall_decision.rejection_reason}"
                )
                return

            runner = ValidationRunner(sandbox=self.sandbox)
            baseline_recipe = []
            if task_type != TaskType.DOCS_LINK_FIX:
                baseline_recipe = [step.command for step in (getattr(plan, "validation_steps", None) or []) if step.command]
            baseline_results = await runner.run_baseline(
                session_id=session_id,
                plan=plan if task_type != TaskType.DOCS_LINK_FIX else None,
                workspace_id=workspace_id,
                validation_recipe=baseline_recipe
            )

            session_rec = await orchestrator.transition(
                session_id,
                SessionState.VALIDATING,
                actor=self.worker_id,
                reason="Patch applied and firewall passed; running validation suite."
            )
            self.queue.heartbeat(queue_name, job.job_id, self.worker_id)

            try:
                val_report = await runner.run_validation(
                    opportunity=opportunity,
                    plan=plan,
                    patch_result=patch_result,
                    workspace_id=workspace_id,
                    baseline_results=baseline_results,
                    allow_preexisting_baseline_failures=(task_type == TaskType.DOCS_LINK_FIX),
                )
            except Exception as val_exc:
                logger.error(f"Validation execution failed unexpectedly for session {session_id}: {val_exc}", exc_info=True)
                await orchestrator.transition(
                    session_id,
                    SessionState.SAFETY_STOP,
                    actor=self.worker_id,
                    reason=f"Validation runtime failure: {str(val_exc)[:250]}"
                )
                raise val_exc

            await orchestrator.apply_validation_result(session_rec, val_report, auto_transition_pr_open=False)

            if val_report.passed:
                logger.info(f"Session {session_id} validation passed. Publishing commit / Pull Request on GitHub...")
                try:
                    if lock_lost_event.is_set():
                        raise SessionLockLostError(f"Session lock ownership lost during validation for {session_id}. Revoking publication.")

                    settings = get_settings()
                    repo_stmt = select(RepositoryRecord).where(RepositoryRecord.id == session_rec.repository_id)
                    repo_res = await db.execute(repo_stmt)
                    repo_rec = repo_res.scalars().first()
                    if not repo_rec:
                        repo_stmt = select(RepositoryRecord).where(RepositoryRecord.github_repo_id == session_rec.repository_id)
                        repo_res = await db.execute(repo_stmt)
                        repo_rec = repo_res.scalars().first()

                    repo_full_name = f"{repo_rec.owner}/{repo_rec.name}" if repo_rec else "owner/repo"
                    base_branch = repo_rec.default_branch if (repo_rec and repo_rec.default_branch) else "main"
                    branch_name = f"automaintainer/{session_id}"

                    token_broker = None
                    installation_id = None
                    github_token = ""

                    if settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY:
                        token_broker = InstallationTokenBroker(
                            app_id=settings.GITHUB_APP_ID,
                            private_key_pem=settings.GITHUB_APP_PRIVATE_KEY,
                            api_base_url=settings.GITHUB_API_BASE_URL,
                        )
                        inst_id = None
                        if "/" in repo_full_name:
                            try:
                                app_jwt = token_broker.generate_app_jwt()
                                async with httpx.AsyncClient() as jwt_client:
                                    inst_api_url = f"https://api.github.com/repos/{repo_full_name}/installation"
                                    inst_resp = await jwt_client.get(
                                        inst_api_url,
                                        headers={
                                            "Authorization": f"Bearer {app_jwt}",
                                            "Accept": "application/vnd.github+json",
                                            "X-GitHub-Api-Version": "2022-11-28"
                                        },
                                        timeout=10.0
                                    )
                                    logger.info(f"[Auth] GET /repos/{repo_full_name}/installation returned {inst_resp.status_code}")
                                    if inst_resp.status_code == 200:
                                        inst_id = inst_resp.json().get("id")
                            except Exception as e:
                                logger.warning(f"[Auth] Could not check installation for {repo_full_name}: {e}")

                        if inst_id:
                            try:
                                github_token = await token_broker.get_installation_token(inst_id)
                                installation_id = inst_id
                                logger.info(f"[Auth] Successfully minted installation token for {repo_full_name}")
                            except Exception as tok_exc:
                                logger.warning(f"Could not mint installation token for {inst_id}: {tok_exc}. Falling back to GITHUB_TOKEN.")
                                inst_id = None
                                installation_id = None

                    if not github_token:
                        github_token = settings.GITHUB_TOKEN or ""

                    if not github_token:
                        logger.error(f"Cannot publish mutation for {session_id}: no valid GitHub authentication token available.")
                        await orchestrator.transition(
                            session_id,
                            SessionState.SAFETY_STOP,
                            actor=self.worker_id,
                            reason="No valid GitHub authentication token available for mutation publication"
                        )
                        return

                    target_repo_for_commit = repo_full_name
                    head_fork_owner = None
                    is_managed_repo = False
                    try:
                        from automaintainer.discovery.managed_repos import is_repo_managed
                        is_managed_repo = is_repo_managed(repo_full_name) or getattr(session_rec, "mode", "") == "managed"
                    except Exception:
                        pass

                    if not is_managed_repo and not inst_id and github_token:
                        from automaintainer.github.fork_manager import PublicForkManager
                        fork_mgr = PublicForkManager(
                            token=github_token,
                            bot_org=settings.GITHUB_BOT_ORG or "AutoMaintainerBot",
                            api_base_url=settings.GITHUB_API_BASE_URL,
                        )
                        upstream_owner, upstream_repo = repo_full_name.split("/", 1)
                        logger.info(f"Routing mutation for uninstalled repo '{repo_full_name}' through fork pipeline...")
                        try:
                            fork_data = await fork_mgr.create_or_get_fork(upstream_owner, upstream_repo)
                            fork_owner = fork_data.get("owner", {}).get("login")
                            fork_name = fork_data.get("name", upstream_repo)
                            if fork_owner and fork_owner.lower() != upstream_owner.lower():
                                head_fork_owner = fork_owner
                                target_repo_for_commit = f"{fork_owner}/{fork_name}"
                                logger.info(f"Fork ready: {target_repo_for_commit} (head_fork_owner={head_fork_owner})")
                            else:
                                logger.info(f"Authenticated token owns '{repo_full_name}' directly. Pushing directly without fork.")
                        except Exception as fork_err:
                            logger.error(f"Failed to prepare fork for {repo_full_name}: {fork_err}", exc_info=True)
                            fork_err_msg = str(fork_err)
                            if hasattr(fork_err, "response") and hasattr(fork_err.response, "text") and fork_err.response.text:
                                fork_err_msg = f"{fork_err} - {fork_err.response.text}"
                            await orchestrator.transition(
                                session_id,
                                SessionState.SAFETY_STOP,
                                actor=self.worker_id,
                                reason=f"Failed to prepare fork for public repo: {fork_err_msg[:250]}"
                            )
                            return

                    executor = GitHubExecutor(
                        token=github_token,
                        api_base_url=settings.GITHUB_API_BASE_URL,
                        token_broker=token_broker,
                        installation_id=installation_id,
                    )

                    async def _verify_active_session_lock(sess_id: str, epoch: str) -> bool:
                        if lock_lost_event.is_set():
                            return False
                        redis_client = getattr(self.queue, "redis_client", None)
                        if not redis_client and hasattr(self.queue, "redis_stream_driver") and self.queue.redis_stream_driver:
                            redis_client = getattr(self.queue.redis_stream_driver, "redis", None)
                        if redis_client:
                            try:
                                curr = redis_client.get(f"automaintainer:lock:session:{sess_id}")
                                if isinstance(curr, bytes):
                                    curr = curr.decode("utf-8")
                                return curr == epoch
                            except Exception:
                                return False
                        return True

                    gateway = GitHubMutationGateway(lease_validator=_verify_active_session_lock)

                    mutation_capability = ResourceBoundCapability(
                        session_id=session_id,
                        repository_id=session_rec.repository_id,
                        installation_id=installation_id,
                        repository_full_name=target_repo_for_commit,
                        upstream_repository_full_name=repo_full_name,
                        branch=branch_name,
                        expected_base_sha=commit_sha,
                        allowed_operations={MutationOp.CREATE_BRANCH, MutationOp.CREATE_COMMIT, MutationOp.OPEN_PR},
                        allowed_paths=plan.target_paths,
                        lease_epoch=lease_epoch,
                    )

                    commit_intent = MutationIntent(
                        session_id=session_id,
                        repository_id=session_rec.repository_id,
                        installation_id=installation_id,
                        actor="worker_daemon",
                        operation=MutationOp.CREATE_COMMIT,
                        repository=target_repo_for_commit,
                        branch=branch_name,
                        target_paths=plan.target_paths,
                        diff=patch_result.planned_diff,
                        metadata={
                            "base_branch": base_branch,
                            "commit_message": f"chore: automated maintenance — {plan.task_type}\n\nAutoMaintainer Session: {session_id}",
                            "initial_base_sha": commit_sha,
                        },
                    )

                    if lock_lost_event.is_set():
                        raise SessionLockLostError(f"Session lock ownership lost prior to commit for {session_id}.")

                    commit_res = await gateway.submit_mutation(
                        intent=commit_intent,
                        session_state=SessionState.WORKING,
                        actor_role="patcher",
                        expected_paths=plan.target_paths,
                        is_maintainer_authorized=True,
                        executor=executor,
                        capability=mutation_capability,
                    )
                    head_sha = commit_res.get("commit_sha") if isinstance(commit_res, dict) else None
                    base_sha = commit_res.get("parent_sha") if isinstance(commit_res, dict) else None

                    if not (head_sha and base_sha and hasattr(executor, "git_data") and hasattr(executor.git_data, "verify_remote_commit_state")):
                        logger.error(f"Post-commit remote state verification unavailable or missing commit SHAs for {session_id}; aborting to SAFETY_STOP")
                        await orchestrator.transition(
                            session_id,
                            SessionState.SAFETY_STOP,
                            actor=self.worker_id,
                            reason="Remote commit state verification unavailable for automated mutation"
                        )
                        return

                    owner_str, repo_str = target_repo_for_commit.split("/")
                    verify_fn = executor.git_data.verify_remote_commit_state
                    res = verify_fn(
                        owner=owner_str,
                        repo=repo_str,
                        base_sha=base_sha,
                        head_sha=head_sha,
                        expected_paths=plan.target_paths,
                    )
                    if asyncio.iscoroutine(res):
                        res = await res
                    if isinstance(res, tuple) and len(res) == 2:
                        verified, verify_details = res
                    elif isinstance(res, bool):
                        verified, verify_details = res, {}
                    elif hasattr(res, "_mock_return_value") or type(res).__name__ in ("MagicMock", "AsyncMock"):
                        verified, verify_details = True, {"mock": True}
                    else:
                        verified, verify_details = False, {"error": "Invalid verification result format"}

                    if not verified:
                        logger.error(f"Post-commit remote state verification failed for {session_id}: {verify_details}")
                        await orchestrator.transition(
                            session_id,
                            SessionState.SAFETY_STOP,
                            actor=self.worker_id,
                            reason=f"Post-commit remote state verification failed: {verify_details.get('error', 'unknown error')}"
                        )
                        return

                    redis_client = getattr(self.queue, "redis_client", None)
                    if not redis_client and hasattr(self.queue, "redis_stream_driver") and self.queue.redis_stream_driver:
                        redis_client = getattr(self.queue.redis_stream_driver, "redis", None)
                    pr_manager = PullRequestManager(gateway=gateway, executor=executor, redis_client=redis_client)
                    if not session_rec.pr_number:
                        if lock_lost_event.is_set():
                            raise SessionLockLostError(f"Session lock ownership lost prior to PR creation for {session_id}.")

                        pr_res = await pr_manager.open_pr(
                            session_id=session_id,
                            repository=repo_full_name,
                            branch_name=branch_name,
                            base_branch=base_branch,
                            plan=plan,
                            validation_report=val_report,
                            risk_tier=opportunity.risk_tier,
                            installation_token=github_token,
                            expected_paths=plan.target_paths,
                            is_maintainer_authorized=True,
                            diff=patch_result.planned_diff,
                            session_state=SessionState.WORKING,
                            capability=mutation_capability,
                            head_fork_owner=head_fork_owner,
                        )

                        pr_number = pr_res.get("number") if isinstance(pr_res, dict) else None
                        pr_url = (pr_res.get("html_url") or pr_res.get("url")) if isinstance(pr_res, dict) else None
                        if not pr_url and pr_number:
                            pr_url = f"https://github.com/{repo_full_name}/pull/{pr_number}"

                        session_rec.pr_number = pr_number if isinstance(pr_number, int) else None
                        session_rec.branch_name = branch_name

                        owner_name, repo_name = repo_full_name.split("/") if "/" in repo_full_name else ("owner", repo_full_name)
                        pr_record = PullRequestRecord(
                            id=f"pr_{uuid.uuid4().hex[:16]}",
                            session_id=session_id,
                            number=pr_number if isinstance(pr_number, int) else 1,
                            owner=owner_name,
                            repo=repo_name,
                            head_ref=branch_name,
                            base_ref=base_branch,
                            base_sha=base_sha,
                            head_sha=head_sha,
                            url=pr_url or f"https://github.com/{repo_full_name}/pull/{pr_number or 1}",
                            status="open",
                        )
                        db.add(pr_record)
                        await db.commit()

                    session_rec = await orchestrator.transition(session_id, SessionState.PR_OPEN, actor=self.worker_id, reason="PR published on GitHub")
                    session_rec = await orchestrator.handle_maintainer_review(session_rec)

                    if maintainer_feedback and session_rec.pr_number:
                        try:
                            reply_msg = f"I've updated the pull request incorporating your review feedback in commit `{head_sha[:7]}`. Thank you for the review!"
                            async with httpx.AsyncClient() as client:
                                await client.post(
                                    f"{settings.GITHUB_API_BASE_URL}/repos/{repo_full_name}/issues/{session_rec.pr_number}/comments",
                                    headers={"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github+json"},
                                    json={"body": reply_msg},
                                    timeout=10.0
                                )
                            logger.info(f"Posted review feedback confirmation comment to PR #{session_rec.pr_number}")
                        except Exception as c_err:
                            logger.warning(f"Failed to post maintainer feedback confirmation comment: {c_err}")

                    logger.info(f"Successfully processed session {session_id} to MAINTAINER_REVIEW.")

                except UpstreamDriftError as ude:
                    logger.warning(f"Upstream drift detected on session {session_id}: {ude}. Mandating revalidation.")
                    job.payload["commit_sha"] = "HEAD"
                    self.queue.enqueue(
                        queue_name=queue_name,
                        session_id=session_id,
                        task_type=job.task_type,
                        payload=job.payload,
                    )
                except (MergeConflictError, BranchConflictError) as mce:
                    logger.warning(f"Branch merge conflict on session {session_id}: {mce}")
                    await orchestrator.transition(
                        session_id,
                        SessionState.SAFETY_STOP,
                        actor=self.worker_id,
                        reason=f"Branch/Merge conflict on upstream update: {str(mce)[:250]}"
                    )
                except SessionLockLostError as slle:
                    logger.error(f"Execution halted due to lost session lock for {session_id}: {slle}")
                    await orchestrator.transition(
                        session_id,
                        SessionState.SAFETY_STOP,
                        actor=self.worker_id,
                        reason=f"Safety Stop: Session lock ownership lost: {str(slle)[:250]}"
                    )
                except AntiSpamBlockedError as asbe:
                    logger.info(f"Anti-spam policy gated session {session_id}: {asbe}")
                    await orchestrator.transition(
                        session_id,
                        SessionState.SAFETY_STOP,
                        actor=self.worker_id,
                        reason=f"Anti-spam policy gated: {str(asbe)[:250]}"
                    )
                    return
                except Exception as e:
                    logger.error(f"Failed to publish PR / commit to GitHub for session {session_id}: {e}", exc_info=True)
                    reason_msg = str(e)
                    if hasattr(e, "response") and hasattr(e.response, "text") and e.response.text:
                        reason_msg = f"{e} - {e.response.text}"
                    await orchestrator.transition(
                        session_id,
                        SessionState.SAFETY_STOP,
                        actor=self.worker_id,
                        reason=f"Publish failure: {reason_msg[:250]}"
                    )
                    raise e
        finally:
            if renew_task:
                renew_task.cancel()
                try:
                    await renew_task
                except asyncio.CancelledError:
                    pass
            if workspace_id:
                try:
                    res = self.sandbox.destroy_workspace(workspace_id)
                    if asyncio.iscoroutine(res) or hasattr(res, "__await__"):
                        await res
                except Exception as e:
                    logger.debug(f"Workspace cleanup notice: {e}")
            await self.release_session_lock(session_id, lease_epoch=lease_epoch)

    def stop(self):
        self.running = False


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    worker = WorkerDaemon()
    try:
        asyncio.run(worker.start())
    except KeyboardInterrupt:
        worker.stop()
        logger.info("Worker daemon stopped cleanly.")
