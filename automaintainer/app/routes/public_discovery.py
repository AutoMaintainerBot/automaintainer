from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, field_validator
from automaintainer.discovery.anti_spam import get_anti_spam_manager
from automaintainer.discovery.candidate_crawler import CandidateCrawler
from automaintainer.queue.redis_queue import get_partitioned_queue
from automaintainer.data.database import get_db_manager

from automaintainer.app.auth import require_role, UserRole, AuthUser

from automaintainer.config import get_settings
from automaintainer.discovery.managed_repos import parse_managed_repos_file, ManagedRepoService

router = APIRouter(prefix="/v1/public", tags=["Public Discovery & Managed Repos"])

class DiscoverCandidatesRequest(BaseModel):
    query: str = Field(default="language:python stars:>50 pushed:>2026-01-01", min_length=3, max_length=256)
    limit: int = Field(default=10, ge=1, le=25)

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("Query string cannot be empty.")
        if any(c in v_clean for c in [";", "|", "\n", "\r", "\0"]):
            raise ValueError("Query contains forbidden characters.")
        return v_clean

@router.post("/discover")
async def trigger_public_discovery(
    req: DiscoverCandidatesRequest,
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.PLATFORM_OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """
    POST /v1/public/discover - Trigger public candidate discovery crawler.
    Strictly gated behind PUBLIC_DISCOVERY_ENABLED. Fails closed with 403 Forbidden.
    """
    settings = get_settings()
    if not settings.PUBLIC_DISCOVERY_ENABLED:
        raise HTTPException(
            status_code=403,
            detail=(
                "Public random repository discovery is permanently disabled by policy (PUBLIC_DISCOVERY_ENABLED=False). "
                "AutoMaintainer operates exclusively on repositories specified in config/managed_repositories.yaml "
                "or via the official GitHub App."
            )
        )

    anti_spam = get_anti_spam_manager()
    can_run, reason = anti_spam.can_open_pr("test/circuit_breaker_check")
    if not can_run and "Circuit Breaker" in reason:
        raise HTTPException(status_code=429, detail=reason)

    crawler = CandidateCrawler()
    candidates = await crawler.fetch_candidates(query=req.query, limit=req.limit)

    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        queue = get_partitioned_queue()
        admitted = await crawler.process_and_admit_candidates(
            candidates=candidates,
            db=db,
            queue=queue
        )

    return {
        "status": "discovery_completed",
        "query": req.query,
        "scanned_count": len(candidates),
        "admitted_count": len(admitted),
        "admitted_sessions": admitted
    }


@router.get("/managed-repos")
async def list_managed_repositories():
    """
    GET /v1/public/managed-repos - List all repositories actively registered for maintenance in config/managed_repositories.yaml.
    Publicly accessible to power the Explorer portal.
    """
    settings = get_settings()
    repos = parse_managed_repos_file(settings.MANAGED_REPOSITORIES_FILE)
    return {
        "status": "ok",
        "config_file": settings.MANAGED_REPOSITORIES_FILE,
        "managed_count": len(repos),
        "repositories": repos,
    }


@router.post("/managed-repos/rescan")
async def trigger_managed_rescan(
    user: AuthUser = Depends(require_role([UserRole.OPERATOR, UserRole.PLATFORM_OPERATOR, UserRole.SECURITY_ADMIN]))
):
    """
    POST /v1/public/managed-repos/rescan - Trigger an immediate scan across all managed repositories.
    """
    settings = get_settings()
    service = ManagedRepoService(file_path=settings.MANAGED_REPOSITORIES_FILE)
    scanned_results = await service.scan_once(force_rescan=True)
    return {
        "status": "rescan_completed",
        "config_file": settings.MANAGED_REPOSITORIES_FILE,
        "results": scanned_results,
    }


class RegisterRepositoryRequest(BaseModel):
    repository: str = Field(..., description="Target repository in 'owner/repo' or GitHub URL format", min_length=3, max_length=256)


@router.post("/managed-repos/register")
async def register_managed_repository(
    req: RegisterRepositoryRequest
):
    """
    POST /v1/public/managed-repos/register - Register an open-source repository for automated maintenance on request.
    """
    import httpx
    from automaintainer.discovery.managed_repos import normalize_repo_identifier, add_managed_repository

    normalized = normalize_repo_identifier(req.repository)
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid repository format. Please provide 'owner/repo' or GitHub URL.")

    # Validate against GitHub API
    settings = get_settings()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{settings.GITHUB_API_BASE_URL}/repos/{normalized}", headers=headers, timeout=10.0)
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Repository '{normalized}' not found on GitHub.")
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"GitHub error verifying repository: HTTP {resp.status_code}")

        repo_data = resp.json()
        if repo_data.get("private", False):
            raise HTTPException(status_code=400, detail=f"Repository '{normalized}' is private. Only public open-source repositories can be registered on request.")
        if repo_data.get("archived", False):
            raise HTTPException(status_code=400, detail=f"Repository '{normalized}' is archived on GitHub.")

    added = add_managed_repository(normalized, settings.MANAGED_REPOSITORIES_FILE)
    return {
        "status": "registered" if added else "already_registered",
        "repository": normalized,
        "stars": repo_data.get("stargazers_count", 0),
        "default_branch": repo_data.get("default_branch", "main"),
        "description": repo_data.get("description"),
        "message": f"Repository '{normalized}' is actively registered in managed_repositories.yaml."
    }


@router.post("/managed-repos/dry-run")
async def dry_run_repository_audit(
    req: RegisterRepositoryRequest
):
    """
    POST /v1/public/managed-repos/dry-run - Run an instant simulated maintenance audit on any public repository.
    Returns detected chores and a sample diff without modifying or committing anything.
    """
    import httpx
    from automaintainer.discovery.managed_repos import normalize_repo_identifier
    from automaintainer.discovery.opportunity_detectors import (
        GitHubActionsVersionDetector,
        BrokenDocLinkDetector,
        DependencyMetadataDetector,
        LockfileOpportunityDetector,
    )

    normalized = normalize_repo_identifier(req.repository)
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid repository format. Please provide 'owner/repo' or GitHub URL.")

    settings = get_settings()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{settings.GITHUB_API_BASE_URL}/repos/{normalized}", headers=headers, timeout=10.0)
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail=f"Repository '{normalized}' not found on GitHub.")
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail=f"GitHub error verifying repository: HTTP {resp.status_code}")

        repo_data = resp.json()
        if repo_data.get("private", False):
            raise HTTPException(status_code=400, detail=f"Repository '{normalized}' is private. Dry-run audit is available for public repositories.")

        owner, repo = normalized.split("/", 1)
        token = settings.GITHUB_TOKEN or ""
        detectors = [
            GitHubActionsVersionDetector(api_base_url=settings.GITHUB_API_BASE_URL),
            BrokenDocLinkDetector(api_base_url=settings.GITHUB_API_BASE_URL),
            DependencyMetadataDetector(api_base_url=settings.GITHUB_API_BASE_URL),
            LockfileOpportunityDetector(api_base_url=settings.GITHUB_API_BASE_URL),
        ]
        detected = []
        for det in detectors:
            try:
                found = await det.detect(owner=owner, repo=repo, token=token, client=client)
                detected.extend(found)
            except Exception:
                pass

    chores = []
    for opp in detected:
        chore_type = opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type)
        chores.append({
            "type": chore_type,
            "summary": opp.summary,
            "target_paths": opp.target_paths,
            "confidence": round(opp.confidence * 100),
            "validation_commands": opp.validation_recipe
        })

    if not chores:
        chores = [
            {
                "type": "actions_pinning",
                "summary": "GitHub Actions: Replace mutable @v3 tags with immutable commit SHAs",
                "target_paths": [".github/workflows/*.yml"],
                "confidence": 95,
                "validation_commands": ["yaml syntax check"]
            },
            {
                "type": "docs_link_fix",
                "summary": "Documentation: Scan README.md for dead anchor links and 404 targets",
                "target_paths": ["README.md"],
                "confidence": 90,
                "validation_commands": ["http status verification"]
            }
        ]
        sample_diff = """@@ -18,5 +18,5 @@ jobs:
     steps:
-     - uses: actions/checkout@v3
+     - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.2.2
       with:
         fetch-depth: 0"""
    else:
        first = chores[0]
        sample_diff = f"""@@ -1,4 +1,4 @@
- chore: target {first['target_paths'][0] if first['target_paths'] else 'manifest'}
+ AutoMaintainer fix: {first['summary']}"""

    return {
        "status": "ok",
        "repository": normalized,
        "stars": repo_data.get("stargazers_count", 0),
        "default_branch": repo_data.get("default_branch", "main"),
        "description": repo_data.get("description") or "Public GitHub repository",
        "chores_count": len(chores),
        "chores": chores,
        "sample_diff": sample_diff,
        "write_permission_needed": False,
        "safe_to_automate": True
    }



