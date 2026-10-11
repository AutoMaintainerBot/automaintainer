import json
import logging
import time
from typing import Optional, List
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import StreamingResponse
import asyncio
from pydantic import BaseModel
from sqlalchemy import select
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import SessionRecord, TaskRecord, PullRequestRecord, ArtifactRecord, EventRecord, WorkspaceRecord, RepositoryRecord, InstallationRecord
from automaintainer.data.repositories import SessionRepository
from enum import Enum
from automaintainer.core.models import SessionState, TERMINAL_STATES, RiskTier
from automaintainer.app.auth import require_role, UserRole, AuthUser, get_current_user, is_platform_admin
from automaintainer.queue.redis_queue import get_partitioned_queue
from automaintainer.execution.sandbox_factory import get_sandbox_runtime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/sessions", tags=["Sessions"])

class SessionMode(str, Enum):
    INSTALLED = "installed"
    PUBLIC = "public"
    AD_HOC = "ad-hoc"
    MANAGED = "managed"

async def verify_session_tenant_access(record: SessionRecord, user: AuthUser, db) -> None:
    """
    Multi-tenant isolation: verify caller's account_id matches repository installation owner.
    Explicit domain chain: User.account_id -> InstallationRecord.account_id -> InstallationRecord.id -> RepositoryRecord.installation_id.
    Platform-level administrative bypass requires is_platform_admin(user) (security-admin or platform-operator with account_id==0).
    """
    if is_platform_admin(user):
        return

    # Check repository -> installation -> account_id
    repo_rec = await db.get(RepositoryRecord, record.repository_id)
    if not repo_rec or not repo_rec.installation_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: repository not found or unmanaged"
        )
    inst_rec = await db.get(InstallationRecord, repo_rec.installation_id)
    if not inst_rec or inst_rec.account_id != user.account_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: session belongs to another tenant"
        )

class ArtifactDetailResponse(BaseModel):
    id: str
    session_id: str
    artifact_type: str
    object_key: str
    sha256: str
    retention_until: Optional[str] = None
    created_at: Optional[str] = None

class SessionDetailResponse(BaseModel):
    id: str
    repository_id: int
    mode: str
    state: str
    version: int
    risk_tier: str
    opportunity_score: float
    workspace_id: Optional[str] = None
    branch_name: Optional[str] = None
    pr_number: Optional[int] = None
    is_terminal: bool

class CreateSessionRequest(BaseModel):
    session_id: str
    repository_id: int
    mode: SessionMode = SessionMode.INSTALLED
    risk_tier: RiskTier = RiskTier.R2

@router.get("", response_model=List[SessionDetailResponse])
async def list_sessions(
    state: Optional[str] = None,
    mode: Optional[str] = None,
    user: AuthUser = Depends(get_current_user)
):
    """GET /v1/sessions - List sessions with filters, strictly scoped to caller tenant in SQL."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        if is_platform_admin(user):
            stmt = select(SessionRecord)
        else:
            stmt = (
                select(SessionRecord)
                .join(RepositoryRecord, RepositoryRecord.id == SessionRecord.repository_id)
                .join(InstallationRecord, InstallationRecord.id == RepositoryRecord.installation_id)
                .where(InstallationRecord.account_id == user.account_id)
            )

        if state:
            stmt = stmt.where(SessionRecord.state == state)
        if mode:
            stmt = stmt.where(SessionRecord.mode == mode)

        result = await db.execute(stmt)
        records = result.scalars().all()

        return [
            SessionDetailResponse(
                id=r.id,
                repository_id=r.repository_id,
                mode=r.mode,
                state=r.state,
                version=r.version,
                risk_tier=r.risk_tier,
                opportunity_score=r.opportunity_score,
                workspace_id=r.workspace_id,
                branch_name=r.branch_name,
                pr_number=r.pr_number,
                is_terminal=SessionState(r.state) in TERMINAL_STATES
            )
            for r in records
        ]

@router.post("", status_code=status.HTTP_201_CREATED, response_model=SessionDetailResponse)
async def create_session(
    req: CreateSessionRequest,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN, UserRole.MAINTAINER]))
):
    """POST /v1/sessions - Initialize a new maintenance session with repository tenant authorization."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        existing = await repo.get_session(req.session_id)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Session with ID '{req.session_id}' already exists."
            )

        # Multi-tenant authorization: verify repository exists and belongs to caller's tenant
        repo_rec = await db.get(RepositoryRecord, req.repository_id)
        if not repo_rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Repository with ID {req.repository_id} not found."
            )

        if not is_platform_admin(user):
            if not repo_rec.installation_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: repository has no associated installation"
                )
            inst_rec = await db.get(InstallationRecord, repo_rec.installation_id)
            if not inst_rec or inst_rec.account_id != user.account_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: repository does not belong to caller's tenant"
                )

        new_session = await repo.create_session(
            session_id=req.session_id,
            repository_id=req.repository_id,
            mode=req.mode.value if hasattr(req.mode, "value") else str(req.mode),
            risk_tier=req.risk_tier.value if hasattr(req.risk_tier, "value") else str(req.risk_tier)
        )
        return SessionDetailResponse(
            id=new_session.id,
            repository_id=new_session.repository_id,
            mode=new_session.mode,
            state=new_session.state,
            version=new_session.version,
            risk_tier=new_session.risk_tier,
            opportunity_score=new_session.opportunity_score,
            workspace_id=new_session.workspace_id,
            branch_name=new_session.branch_name,
            pr_number=new_session.pr_number,
            is_terminal=False
        )

@router.get("/{session_id}", response_model=SessionDetailResponse)
async def get_session(session_id: str, user: AuthUser = Depends(get_current_user)):
    """GET /v1/sessions/{id} - Detailed session inspection with tenant guard."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)

        return SessionDetailResponse(
            id=record.id,
            repository_id=record.repository_id,
            mode=record.mode,
            state=record.state,
            version=record.version,
            risk_tier=record.risk_tier,
            opportunity_score=record.opportunity_score,
            workspace_id=record.workspace_id,
            branch_name=record.branch_name,
            pr_number=record.pr_number,
            is_terminal=SessionState(record.state) in TERMINAL_STATES
        )

@router.post("/{session_id}/terminate")
@router.post("/{session_id}/cancel")
async def terminate_or_cancel_session(
    session_id: str,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/sessions/{id}/terminate and /cancel - Operator emergency abort and workspace teardown."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)

        current_state = SessionState(record.state)
        if current_state in TERMINAL_STATES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session is already in terminal state")

        # Teardown sandbox workspace if active
        destruction_succeeded = True
        destruction_error = None
        if record.workspace_id:
            try:
                sandbox = get_sandbox_runtime()
                await sandbox.destroy_workspace(record.workspace_id)
            except Exception as e:
                destruction_succeeded = False
                destruction_error = str(e)
                logger.error(f"Sandbox destruction failed for workspace '{record.workspace_id}': {e}")

        # Distinguish destroyed vs destroy_failed in database records
        ws_status = "destroyed" if destruction_succeeded else "destroy_failed"
        ws_stmt = select(WorkspaceRecord).where(WorkspaceRecord.session_id == session_id)
        ws_res = await db.execute(ws_stmt)
        for ws in ws_res.scalars().all():
            ws.status = ws_status

        updated = await repo.transition_state_optimistic(
            session_id=session_id,
            expected_state=current_state,
            target_state=SessionState.CANCELLED,
            expected_version=record.version
        )
        res_data = {
            "status": "terminated",
            "session_id": updated.id,
            "state": updated.state,
            "version": updated.version,
            "workspace_status": ws_status,
        }
        if destruction_error:
            res_data["destruction_error"] = destruction_error
        return res_data

@router.post("/{session_id}/pause")
async def pause_session(
    session_id: str,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN, UserRole.MAINTAINER]))
):
    """POST /v1/sessions/{id}/pause - Real pause: atomic state transition to PAUSED with metadata."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)
        current_state = SessionState(record.state)
        if current_state in TERMINAL_STATES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot pause a session in terminal state")
        if current_state == SessionState.PAUSED:
            return {"status": "paused", "session_id": session_id, "state": record.state}

        # Atomically update metadata and transition state in a single optimistic operation
        meta = dict(record.metadata_json or {})
        meta["paused_from_state"] = record.state

        updated = await repo.transition_state_optimistic(
            session_id=session_id,
            expected_state=current_state,
            target_state=SessionState.PAUSED,
            expected_version=record.version,
            metadata_update=meta
        )
        return {"status": "paused", "session_id": session_id, "state": updated.state, "version": updated.version}

@router.post("/{session_id}/resume")
async def resume_session(
    session_id: str,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN, UserRole.MAINTAINER]))
):
    """POST /v1/sessions/{id}/resume - Real resume: re-enter active pipeline from PAUSED state with queue failure rollback."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)
        current_state = SessionState(record.state)

        # Enforce that only PAUSED sessions can be resumed
        if current_state != SessionState.PAUSED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot resume session in state '{record.state}'; session must be in PAUSED state."
            )

        target_state = SessionState.WORKING
        meta = record.metadata_json or {}
        prev_state = meta.get("paused_from_state")
        if prev_state and prev_state in (
            SessionState.ANALYZING.value,
            SessionState.PLANNING.value,
            SessionState.WORKING.value,
            SessionState.VALIDATING.value,
            SessionState.REVALIDATING.value
        ):
            target_state = SessionState(prev_state)

        updated = await repo.transition_state_optimistic(
            session_id=session_id,
            expected_state=current_state,
            target_state=target_state,
            expected_version=record.version
        )

        # Enqueue session to continue execution; revert state if queue dispatch fails
        try:
            queue = get_partitioned_queue()
            queue.enqueue(
                queue_name="analysis",
                session_id=session_id,
                task_type="session_resumed",
                payload={"session_id": session_id, "repository_id": record.repository_id}
            )
        except Exception as q_err:
            logger.error(f"Failed to enqueue resumed session {session_id}: {q_err}. Rolling back state to PAUSED.")
            await repo.transition_state_optimistic(
                session_id=session_id,
                expected_state=target_state,
                target_state=SessionState.PAUSED,
                expected_version=updated.version
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Queue dispatch failed: {q_err}. Session state reverted to PAUSED."
            )

        return {"status": "resumed", "session_id": session_id, "state": updated.state, "version": updated.version}

@router.get("/{session_id}/events")
async def get_session_events(session_id: str, user: AuthUser = Depends(get_current_user)):
    """GET /v1/sessions/{id}/events - Audit and event stream for a session."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)

        stmt = select(EventRecord).where(EventRecord.session_id == session_id)
        res = await db.execute(stmt)
        events = res.scalars().all()
        return [
            {
                "id": e.id,
                "delivery_id": e.delivery_id,
                "event_type": e.event_type,
                "source": e.source,
                "received_at": e.received_at.isoformat() if e.received_at else None
            }
            for e in events
        ]

@router.get("/{session_id}/tasks")
async def list_session_tasks(session_id: str, user: AuthUser = Depends(get_current_user)):
    """GET /v1/sessions/{id}/tasks - List individual tasks within a session."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)

        stmt = select(TaskRecord).where(TaskRecord.session_id == session_id)
        res = await db.execute(stmt)
        tasks = res.scalars().all()
        return [
            {
                "id": t.id,
                "task_type": t.task_type,
                "status": t.status,
                "confidence": t.confidence,
                "risk_tier": t.risk_tier
            }
            for t in tasks
        ]

@router.get("/{session_id}/artifacts", response_model=List[ArtifactDetailResponse])
async def list_session_artifacts(session_id: str, user: AuthUser = Depends(get_current_user)):
    """GET /v1/sessions/{id}/artifacts - List all stored artifacts (diffs, logs, sboms, reports)."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)

        stmt = select(ArtifactRecord).where(ArtifactRecord.session_id == session_id)
        res = await db.execute(stmt)
        artifacts = res.scalars().all()
        return [
            ArtifactDetailResponse(
                id=a.id,
                session_id=a.session_id,
                artifact_type=a.artifact_type,
                object_key=a.object_key,
                sha256=a.sha256,
                retention_until=a.retention_until.isoformat() if a.retention_until else None,
                created_at=a.created_at.isoformat() if hasattr(a, "created_at") and a.created_at else None
            )
            for a in artifacts
        ]

@router.get("/{session_id}/pr")
async def get_session_pr_status(session_id: str, user: AuthUser = Depends(get_current_user)):
    """GET /v1/sessions/{id}/pr - Detailed status of the associated pull request."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id} not found")
        await verify_session_tenant_access(record, user, db)

        stmt = select(PullRequestRecord).where(PullRequestRecord.session_id == session_id)
        res = await db.execute(stmt)
        pr = res.scalar_one_or_none()
        if not pr:
            return {"has_pr": False, "session_id": session_id}
        return {
            "has_pr": True,
            "session_id": session_id,
            "pr_number": pr.number,
            "url": pr.url,
            "status": pr.status,
            "head_sha": pr.head_sha
        }

@router.get("/{session_id}/stream")
async def stream_session_progress(session_id: str, user: AuthUser = Depends(get_current_user)):
    """
    Server-Sent Events (SSE) stream for live dashboard updates.
    Streams audit and event records from the database for the active session.
    """
    async def event_generator():
        db_mgr = get_db_manager()
        seen_events = set()

        async with db_mgr.get_session() as db:
            repo = SessionRepository(db)
            rec = await repo.get_session(session_id)
            if not rec:
                yield f"data: {json.dumps({'error': 'Session not found', 'session_id': session_id})}\n\n"
                return
            await verify_session_tenant_access(rec, user, db)
            yield f"data: {json.dumps({'session_id': session_id, 'state': rec.state, 'version': rec.version, 'message': f'Connected to session stream: State {rec.state}', 'timestamp': time.time()})}\n\n"

        for _ in range(30):
            async with db_mgr.get_session() as db:
                repo = SessionRepository(db)
                rec = await repo.get_session(session_id)
                if not rec:
                    break

                # Stream real events from EventRecord
                stmt = select(EventRecord).where(EventRecord.session_id == session_id).order_by(EventRecord.received_at.asc())
                res = await db.execute(stmt)
                events = res.scalars().all()

                for ev in events:
                    if ev.id not in seen_events:
                        seen_events.add(ev.id)
                        data = {
                            "session_id": session_id,
                            "event_id": ev.id,
                            "event_type": ev.event_type,
                            "source": ev.source,
                            "state": rec.state,
                            "message": f"Event {ev.event_type} from {ev.source}",
                            "timestamp": ev.received_at.isoformat() if ev.received_at else str(time.time())
                        }
                        yield f"data: {json.dumps(data)}\n\n"

                if SessionState(rec.state) in TERMINAL_STATES:
                    yield f"data: {json.dumps({'session_id': session_id, 'state': rec.state, 'is_terminal': True, 'message': f'Session reached terminal state: {rec.state}', 'timestamp': time.time()})}\n\n"
                    break

            await asyncio.sleep(1.0)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.post("/{session_id}/pr/retry")
async def retry_pr_operation(
    session_id: str,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/sessions/{id}/pr/retry - Retry opening or updating PR after transient failure."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo = SessionRepository(db)
        record = await repo.get_session(session_id)
        if not record:
            raise HTTPException(status_code=404, detail="Session not found")
        if SessionState(record.state) in TERMINAL_STATES:
            raise HTTPException(status_code=400, detail=f"Cannot retry session in terminal state '{record.state}'")

        # Enqueue real retry job into priority queue
        queue = get_partitioned_queue()
        job = queue.enqueue(
            queue_name="github-write",
            session_id=session_id,
            task_type="pr_operation_retry",
            payload={
                "session_id": session_id,
                "repository_id": record.repository_id,
                "action": "retry_pr",
                "requested_by": user.username
            }
        )

        return {
            "status": "retry_scheduled",
            "session_id": session_id,
            "job_id": job.job_id if job else None,
            "queue": "github-write"
        }

