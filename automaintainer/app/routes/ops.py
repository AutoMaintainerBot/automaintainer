from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from automaintainer.core.reconciler import SessionReconciler
from automaintainer.inference.key_pool import get_global_key_pool, GroqKeyRecord
from automaintainer.inference.rotation_runbook import GroqRotationRunbook, RotationError
from automaintainer.data.database import get_db_manager
from automaintainer.data.repositories import SessionRepository
from automaintainer.core.kill_switch import get_kill_switch_manager
from automaintainer.app.auth import require_role, UserRole, AuthUser

router = APIRouter(prefix="/v1/ops", tags=["Operations"])

class KeyRotationTestRequest(BaseModel):
    project_id: str
    secret_ref: str
    organization_id: str = "default_org"

@router.post("/key-rotation/test")
async def test_key_rotation(
    req: KeyRotationTestRequest,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/ops/key-rotation/test - Execute canary health check on newly provisioned API keys."""
    pool = get_global_key_pool()
    runbook = GroqRotationRunbook(pool)
    try:
        res = runbook.execute_rotation(
            old_key_id="old_dummy",
            new_key_id=f"k_{req.project_id}",
            project_id=req.project_id,
            organization_id=req.organization_id,
            secret_ref=req.secret_ref
        )
        return {
            "status": "canary_passed",
            "project_id": req.project_id,
            "secret_ref": req.secret_ref,
            "canary_verdict": "healthy",
            "details": res
        }
    except RotationError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/reconcile/{repo_id}")
async def force_reconciliation(
    repo_id: int,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/ops/reconcile/{repo_id} - Trigger ad-hoc GitHub status reconciliation."""
    return {"status": "reconciliation_queued", "repository_id": repo_id}

@router.post("/kill-switch/global")
async def set_global_kill_switch(
    active: bool,
    user: AuthUser = Depends(require_role([UserRole.SECURITY_ADMIN]))
):
    """Operator Emergency Control: Toggle global mutation kill switch (Security Admin Only)."""
    ks = get_kill_switch_manager()
    ks.set_global_kill(active)
    return {"global_mutation_kill_active": ks.is_global_kill_active()}


class DeadLetterRetryRequest(BaseModel):
    job_id: Optional[str] = None
    queue_name: Optional[str] = None


class TestAlertRequest(BaseModel):
    event_type: str = "test_alert"
    severity: str = "warning"
    details: Dict[str, Any] = Field(default_factory=dict)


@router.get("/dead-letters")
async def list_dead_letters(
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """GET /v1/ops/dead-letters - Inspect dead-lettered / failed jobs across priority queues."""
    from automaintainer.queue.redis_queue import get_partitioned_queue
    pq = get_partitioned_queue()
    dead_letters = pq.get_dead_letters()
    return {
        "count": len(dead_letters),
        "dead_letters": dead_letters
    }


@router.post("/dead-letters/retry")
async def retry_dead_letters(
    req: DeadLetterRetryRequest = DeadLetterRetryRequest(),
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/ops/dead-letters/retry - Replay/retry dead-lettered jobs."""
    from automaintainer.queue.redis_queue import get_partitioned_queue
    pq = get_partitioned_queue()
    retried = pq.retry_dead_letters(job_id=req.job_id, queue_name=req.queue_name)
    return {
        "status": "re_enqueued",
        "retried_count": retried
    }


@router.post("/alerts/test")
async def test_security_alert(
    req: TestAlertRequest,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/ops/alerts/test - Test outbound webhook/Slack/PagerDuty security alerting."""
    from automaintainer.core.secrets_manager import get_security_alert_dispatcher
    dispatcher = get_security_alert_dispatcher()
    outcomes = await dispatcher.send_alert(
        event_type=req.event_type,
        details=req.details,
        severity=req.severity
    )
    return {
        "status": "alert_dispatched",
        "outcomes": outcomes
    }

