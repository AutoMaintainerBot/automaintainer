from typing import List, Optional
import uuid
from fastapi import APIRouter, HTTPException, status, Depends, Header
from pydantic import BaseModel
from sqlalchemy import select
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import InstallationRecord
from automaintainer.app.auth import get_current_user, require_role, AuthUser, UserRole, is_platform_admin
from automaintainer.queue.redis_queue import get_partitioned_queue

router = APIRouter(prefix="/v1/installations", tags=["Installations"])

class InstallationResponse(BaseModel):
    id: int
    github_installation_id: int
    account_id: int
    target_type: str
    status: str

@router.get("", response_model=List[InstallationResponse])
async def list_installations(
    user: AuthUser = Depends(get_current_user)
):
    """GET /v1/installations - List registered GitHub App installations, strictly tenant-scoped."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        if is_platform_admin(user):
            stmt = select(InstallationRecord)
        else:
            stmt = select(InstallationRecord).where(InstallationRecord.account_id == user.account_id)

        res = await db.execute(stmt)
        records = res.scalars().all()
        return [
            InstallationResponse(
                id=r.id,
                github_installation_id=r.github_installation_id,
                account_id=r.account_id,
                target_type=r.target_type,
                status=r.status
            )
            for r in records
        ]

@router.post("/{installation_id}/reconcile")
async def reconcile_installation(
    installation_id: int,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.MAINTAINER, UserRole.PLATFORM_OPERATOR, UserRole.SECURITY_ADMIN])),
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key")
):
    """POST /v1/installations/{id}/reconcile - Enqueue reconciliation job for an authorized installation."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        stmt = select(InstallationRecord).where(InstallationRecord.github_installation_id == installation_id)
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Installation not found")

        if not is_platform_admin(user) and record.account_id != user.account_id:
            raise HTTPException(status_code=403, detail="Access denied: installation belongs to another tenant")

        # Durably enqueue reconciliation job with UUID or idempotency key to prevent collision
        queue = get_partitioned_queue()
        sess_suffix = x_idempotency_key if x_idempotency_key else uuid.uuid4().hex[:12]
        job_id = queue.enqueue(
            queue_name="default",
            session_id=f"reconcile_inst_{installation_id}_{sess_suffix}",
            task_type="installation_reconciliation",
            payload={
                "installation_id": installation_id,
                "account_id": record.account_id
            }
        )
        return {
            "status": "reconciliation_queued",
            "installation_id": installation_id,
            "job_id": job_id
        }
