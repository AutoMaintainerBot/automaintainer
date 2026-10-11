from typing import List, Optional
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy import select
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import OpportunityRecord, SessionRecord, RepositoryRecord, InstallationRecord
from automaintainer.data.repositories import SessionRepository
from automaintainer.core.models import SessionState
from automaintainer.app.auth import get_current_user, require_role, AuthUser, UserRole, is_platform_admin

router = APIRouter(prefix="/v1/opportunities", tags=["Opportunities"])

class OpportunityResponse(BaseModel):
    id: str
    repository_id: int
    task_type: str
    summary: Optional[str] = None
    score: float
    confidence: float
    risk_tier: str
    status: str

@router.get("", response_model=List[OpportunityResponse])
async def list_opportunities(
    repository_id: Optional[int] = None,
    status: Optional[str] = None,
    user: AuthUser = Depends(get_current_user)
):
    """GET /v1/opportunities - List detected maintenance opportunities scoped to tenant."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        if is_platform_admin(user):
            stmt = select(OpportunityRecord)
        else:
            stmt = (
                select(OpportunityRecord)
                .join(RepositoryRecord, RepositoryRecord.id == OpportunityRecord.repository_id)
                .join(InstallationRecord, InstallationRecord.id == RepositoryRecord.installation_id)
                .where(InstallationRecord.account_id == user.account_id)
            )

        if repository_id:
            stmt = stmt.where(OpportunityRecord.repository_id == repository_id)
        if status:
            stmt = stmt.where(OpportunityRecord.status == status)

        res = await db.execute(stmt)
        records = res.scalars().all()
        return [
            OpportunityResponse(
                id=r.id,
                repository_id=r.repository_id,
                task_type=r.task_type,
                summary=r.summary,
                score=r.score,
                confidence=r.confidence,
                risk_tier=r.risk_tier,
                status=r.status
            )
            for r in records
        ]

@router.get("/{opportunity_id}", response_model=OpportunityResponse)
async def get_opportunity(
    opportunity_id: str,
    user: AuthUser = Depends(get_current_user)
):
    """GET /v1/opportunities/{id} - Get single opportunity detail with tenant authorization."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        stmt = select(OpportunityRecord).where(OpportunityRecord.id == opportunity_id)
        res = await db.execute(stmt)
        rec = res.scalar_one_or_none()
        if not rec:
            raise HTTPException(status_code=404, detail=f"Opportunity {opportunity_id} not found")

        if not is_platform_admin(user):
            repo_rec = await db.get(RepositoryRecord, rec.repository_id)
            if not repo_rec or not repo_rec.installation_id:
                raise HTTPException(status_code=404, detail=f"Opportunity {opportunity_id} not found")
            inst_rec = await db.get(InstallationRecord, repo_rec.installation_id)
            if not inst_rec or inst_rec.account_id != user.account_id:
                raise HTTPException(status_code=404, detail=f"Opportunity {opportunity_id} not found")

        return OpportunityResponse(
            id=rec.id,
            repository_id=rec.repository_id,
            task_type=rec.task_type,
            summary=rec.summary,
            score=rec.score,
            confidence=rec.confidence,
            risk_tier=rec.risk_tier,
            status=rec.status
        )

@router.post("/{opportunity_id}/session", status_code=status.HTTP_201_CREATED)
async def create_session_from_opportunity(
    opportunity_id: str,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.MAINTAINER, UserRole.PLATFORM_OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """POST /v1/opportunities/{id}/session - Spawn maintenance session from opportunity."""
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        stmt = select(OpportunityRecord).where(OpportunityRecord.id == opportunity_id)
        res = await db.execute(stmt)
        rec = res.scalar_one_or_none()
        if not rec:
            raise HTTPException(status_code=404, detail=f"Opportunity {opportunity_id} not found")

        if not is_platform_admin(user):
            repo_rec = await db.get(RepositoryRecord, rec.repository_id)
            if not repo_rec or not repo_rec.installation_id:
                raise HTTPException(status_code=403, detail="Access denied: repository has no active installation")
            inst_rec = await db.get(InstallationRecord, repo_rec.installation_id)
            if not inst_rec or inst_rec.account_id != user.account_id:
                raise HTTPException(status_code=403, detail="Access denied: repository belongs to another tenant")

        repo = SessionRepository(db)
        session_id = f"sess_opp_{opportunity_id[:8]}"
        session_rec = await repo.create_session(session_id, rec.repository_id, mode="installed" if not is_platform_admin(user) else "public")

        rec.status = "session_created"
        await db.commit()

        return {
            "status": "session_created",
            "session_id": session_rec.id,
            "opportunity_id": opportunity_id,
            "repository_id": rec.repository_id
        }
