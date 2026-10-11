from typing import Optional, List
import uuid
from fastapi import APIRouter, HTTPException, status, Depends, Header
from pydantic import BaseModel
from sqlalchemy import select
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import RepositoryRecord, InstallationRecord
from automaintainer.app.auth import get_current_user, require_role, AuthUser, UserRole, is_platform_admin
from automaintainer.queue.redis_queue import get_partitioned_queue

router = APIRouter(prefix="/v1/repositories", tags=["Repositories"])

class RepositoryDetailResponse(BaseModel):
    id: int
    github_repo_id: int
    owner: str
    name: str
    visibility: str
    default_branch: str
    archived: bool
    health_score: float
    fingerprint: dict
    installation_id: Optional[int] = None

@router.get("", response_model=List[RepositoryDetailResponse])
async def list_repositories(
    installation_id: Optional[int] = None,
    owner: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    user: AuthUser = Depends(get_current_user)
):
    """GET /v1/repositories - List repositories scoped strictly to caller tenant unless platform admin."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        if is_platform_admin(user):
            stmt = select(RepositoryRecord)
        else:
            stmt = (
                select(RepositoryRecord)
                .join(InstallationRecord, InstallationRecord.id == RepositoryRecord.installation_id)
                .where(InstallationRecord.account_id == user.account_id)
            )

        if installation_id is not None:
            stmt = stmt.where(RepositoryRecord.installation_id == installation_id)
        if owner is not None:
            stmt = stmt.where(RepositoryRecord.owner == owner)

        stmt = stmt.limit(limit).offset(offset)
        res = await db.execute(stmt)
        records = res.scalars().all()
        return [
            RepositoryDetailResponse(
                id=rec.id,
                github_repo_id=rec.github_repo_id,
                owner=rec.owner,
                name=rec.name,
                visibility=rec.visibility,
                default_branch=rec.default_branch,
                archived=rec.archived,
                health_score=rec.health_score,
                fingerprint=rec.fingerprint_json or {},
                installation_id=rec.installation_id
            )
            for rec in records
        ]

@router.get("/{repo_id}", response_model=RepositoryDetailResponse)
async def get_repository_detail(
    repo_id: int,
    user: AuthUser = Depends(get_current_user)
):
    """GET /v1/repositories/{id} - Fetch single repository detail with anti-enumeration tenant guard."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        stmt = select(RepositoryRecord).where(RepositoryRecord.id == repo_id)
        res = await db.execute(stmt)
        rec = res.scalar_one_or_none()
        if not rec:
            raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")

        # Non-platform admins can only view repositories belonging to their tenant installations
        if not is_platform_admin(user):
            if not rec.installation_id:
                raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
            inst_stmt = select(InstallationRecord).where(InstallationRecord.id == rec.installation_id)
            inst_res = await db.execute(inst_stmt)
            inst = inst_res.scalar_one_or_none()
            if not inst or inst.account_id != user.account_id:
                raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")

        return RepositoryDetailResponse(
            id=rec.id,
            github_repo_id=rec.github_repo_id,
            owner=rec.owner,
            name=rec.name,
            visibility=rec.visibility,
            default_branch=rec.default_branch,
            archived=rec.archived,
            health_score=rec.health_score,
            fingerprint=rec.fingerprint_json or {},
            installation_id=rec.installation_id
        )

@router.post("/{repo_id}/scan")
async def trigger_repository_scan(
    repo_id: int,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.MAINTAINER, UserRole.PLATFORM_OPERATOR, UserRole.SECURITY_ADMIN])),
    x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key")
):
    """POST /v1/repositories/{id}/scan - Request ad-hoc repository scan and durably enqueue scan job."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        stmt = select(RepositoryRecord).where(RepositoryRecord.id == repo_id)
        res = await db.execute(stmt)
        rec = res.scalar_one_or_none()
        if not rec:
            raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")

        # Multi-tenant verification
        if not is_platform_admin(user):
            if not rec.installation_id:
                raise HTTPException(status_code=403, detail="Access denied: repository has no active installation")
            inst_stmt = select(InstallationRecord).where(InstallationRecord.id == rec.installation_id)
            inst_res = await db.execute(inst_stmt)
            inst = inst_res.scalar_one_or_none()
            if not inst or inst.account_id != user.account_id:
                raise HTTPException(status_code=403, detail="Access denied: repository belongs to another tenant")

        if rec.archived:
            raise HTTPException(status_code=400, detail="Cannot scan an archived repository")

        # Durably enqueue scan job in the partitioned queue with UUID or idempotency key
        queue = get_partitioned_queue()
        sess_suffix = x_idempotency_key if x_idempotency_key else uuid.uuid4().hex[:12]
        job_id = queue.enqueue(
            queue_name="analysis",
            session_id=f"scan_repo_{repo_id}_{sess_suffix}",
            task_type="repository_scan",
            payload={
                "repository_id": repo_id,
                "repo_name": f"{rec.owner}/{rec.name}",
                "default_branch": rec.default_branch
            }
        )
        return {"status": "scan_scheduled", "repository_id": repo_id, "job_id": job_id}
