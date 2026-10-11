from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy import select
from automaintainer.core.models import MutationIntent, MutationOp, RiskTier, SessionState, PlannedDiff, FileDiff
from automaintainer.core.policy_engine import PolicyEngine
from automaintainer.core.diff_firewall import DiffFirewall
from automaintainer.core.repo_config import RepoConfigEngine, RepoConfig
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import RepositoryRecord, InstallationRecord, RepoPolicyRecord
from automaintainer.app.auth import get_current_user, require_role, AuthUser, UserRole, is_platform_admin

router = APIRouter(prefix="/v1/policies", tags=["Policies"])

class PolicyEvaluationRequest(BaseModel):
    repository: str
    operation: MutationOp
    target_paths: List[str]
    risk_tier: RiskTier = RiskTier.R2
    session_state: SessionState = SessionState.WORKING
    actor: str = "patcher"
    diff_files: Optional[List[Dict[str, Any]]] = None
    repo_yaml_config: Optional[str] = None

class PolicyEvaluationResponse(BaseModel):
    allowed: bool
    violations: List[str]
    effective_limits: Dict[str, Any]
    simulation: bool = True

class EffectivePolicyResponse(BaseModel):
    repository_id: int
    autonomy: str
    allowed_classes: List[str]
    excluded_paths: List[str]
    effective_limits: Dict[str, Any]

@router.get("")
async def list_policies(user: AuthUser = Depends(get_current_user)):
    """GET /v1/policies - List platform hard limits and policy definitions."""
    return {
        "platform_limits": {
            "ceiling_max_files": RepoConfigEngine.PLATFORM_CEILING_MAX_FILES,
            "ceiling_max_lines": RepoConfigEngine.PLATFORM_CEILING_MAX_LINES,
            "mandatory_forbidden_patterns": RepoConfigEngine.PLATFORM_MANDATORY_DENIED_PATHS
        }
    }

@router.post("/evaluate", response_model=PolicyEvaluationResponse)
@router.post("/simulate", response_model=PolicyEvaluationResponse)
async def evaluate_or_simulate_policy(
    req: PolicyEvaluationRequest,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.MAINTAINER, UserRole.PLATFORM_OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """
    POST /v1/policies/evaluate or /v1/policies/simulate - Test proposed actions & diffs against simulated policy.
    """
    repo_cfg = RepoConfigEngine.parse_yaml(req.repo_yaml_config) if req.repo_yaml_config else RepoConfig()
    effective = RepoConfigEngine.merge_with_platform_ceilings(repo_cfg)

    firewall = DiffFirewall(
        max_files=effective["max_files"],
        max_lines_added=effective["max_changed_lines"],
        max_lines_deleted=effective["max_changed_lines"]
    )
    engine = PolicyEngine(firewall=firewall)

    planned_diff = None
    if req.diff_files:
        files = [
            FileDiff(
                path=f.get("path", ""),
                lines_added=f.get("lines_added", 0),
                lines_deleted=f.get("lines_deleted", 0),
                is_binary=f.get("is_binary", False),
                is_symlink=f.get("is_symlink", False)
            )
            for f in req.diff_files
        ]
        planned_diff = PlannedDiff(files=files)

    intent = MutationIntent(
        session_id="test_session",
        actor=req.actor,
        operation=req.operation,
        repository=req.repository,
        branch="test_branch",
        target_paths=req.target_paths,
        diff=planned_diff,
        risk=req.risk_tier
    )

    all_violations = []

    # Pre-policy check
    pre_ok, pre_violations = engine.evaluate_pre_policy(intent, req.session_state)
    if not pre_ok:
        all_violations.extend(pre_violations)

    # Post-policy check
    post_ok, post_violations = engine.evaluate_post_policy(intent, expected_paths=req.target_paths)
    if not post_ok:
        all_violations.extend(post_violations)

    return PolicyEvaluationResponse(
        allowed=len(all_violations) == 0,
        violations=all_violations,
        effective_limits=effective,
        simulation=True
    )

@router.get("/effective/{repo_id}", response_model=EffectivePolicyResponse)
async def get_effective_repo_policy(
    repo_id: int,
    user: AuthUser = Depends(get_current_user)
):
    """
    GET /v1/policies/effective/{repo_id} - Authoritative effective policy for a repository.
    Strictly verifies caller has access to the repository's tenant.
    """
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        repo_rec = await db.get(RepositoryRecord, repo_id)
        if not repo_rec:
            raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")

        if not is_platform_admin(user):
            if not repo_rec.installation_id:
                raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")
            inst_rec = await db.get(InstallationRecord, repo_rec.installation_id)
            if not inst_rec or inst_rec.account_id != user.account_id:
                raise HTTPException(status_code=404, detail=f"Repository {repo_id} not found")

        stmt = select(RepoPolicyRecord).where(RepoPolicyRecord.repo_id == repo_id)
        res = await db.execute(stmt)
        policy_rec = res.scalar_one_or_none()

        repo_cfg = RepoConfig()
        autonomy = "supervised"
        allowed_classes = []
        excluded_paths = []
        if policy_rec:
            autonomy = policy_rec.autonomy
            allowed_classes = policy_rec.allowed_classes_json or []
            excluded_paths = policy_rec.excluded_paths_json or []

        effective = RepoConfigEngine.merge_with_platform_ceilings(repo_cfg)

        return EffectivePolicyResponse(
            repository_id=repo_id,
            autonomy=autonomy,
            allowed_classes=allowed_classes,
            excluded_paths=excluded_paths,
            effective_limits=effective
        )
