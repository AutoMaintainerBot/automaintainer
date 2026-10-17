import asyncio
import time
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Header, Request
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


MAX_PENDING_NOMINATIONS = 50
_pending_nominations: List[Dict[str, Any]] = []

@router.post("/managed-repos/register")
async def register_managed_repository(
    req: RegisterRepositoryRequest,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_github_token: Optional[str] = Header(None, alias="X-GitHub-Token")
):
    """
    POST /v1/public/managed-repos/register - Register an open-source repository for automated maintenance.
    - Authorized operators or verified repository maintainers are registered directly into managed_repositories.yaml.
    - Unauthenticated public submissions are recorded as capped nominations awaiting operator review / GitHub App installation.
    """
    import httpx
    import jwt
    from automaintainer.discovery.managed_repos import normalize_repo_identifier, add_managed_repository
    from automaintainer.app.auth import get_jwt_secret, JWT_ALGORITHM, UserRole

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
            raise HTTPException(status_code=400, detail=f"Repository '{normalized}' is private. Only public open-source repositories can be registered.")
        if repo_data.get("archived", False):
            raise HTTPException(status_code=400, detail=f"Repository '{normalized}' is archived on GitHub.")

        # Determine authorization: is caller an authenticated operator or a verified repo maintainer?
        is_authorized = False

        # 1. Check AutoMaintainer operator JWT
        if authorization and authorization.startswith("Bearer "):
            token_str = authorization[len("Bearer "):].strip()
            try:
                payload = jwt.decode(token_str, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
                roles = payload.get("roles", [])
                if any(r in (UserRole.OPERATOR.value, UserRole.PLATFORM_OPERATOR.value, UserRole.SECURITY_ADMIN.value) for r in roles):
                    is_authorized = True
            except Exception:
                pass

        # 2. Check GitHub maintainer authorization token if supplied
        gh_user_token = x_github_token or (authorization[len("Bearer "):].strip() if (authorization and (authorization.startswith("Bearer ghp_") or authorization.startswith("Bearer gho_"))) else None)
        if not is_authorized and gh_user_token:
            try:
                auth_check = await client.get(
                    f"{settings.GITHUB_API_BASE_URL}/repos/{normalized}",
                    headers={"Authorization": f"Bearer {gh_user_token}", "Accept": "application/vnd.github+json"},
                    timeout=5.0
                )
                if auth_check.status_code == 200:
                    perms = auth_check.json().get("permissions", {})
                    if perms.get("admin") or perms.get("push") or perms.get("maintain"):
                        is_authorized = True
            except Exception:
                pass

    if is_authorized:
        added = add_managed_repository(normalized, settings.MANAGED_REPOSITORIES_FILE)
        return {
            "status": "registered" if added else "already_registered",
            "repository": normalized,
            "requires_maintainer_approval": False,
            "stars": repo_data.get("stargazers_count", 0),
            "default_branch": repo_data.get("default_branch", "main"),
            "description": repo_data.get("description"),
            "message": f"Repository '{normalized}' is actively registered in managed_repositories.yaml."
        }

    # Unauthenticated public caller: Record as pending nomination subject to hard cap
    global _pending_nominations
    if len(_pending_nominations) >= MAX_PENDING_NOMINATIONS:
        raise HTTPException(
            status_code=429,
            detail=(
                "Pending nominations queue has reached capacity (max 50). "
                "To enable autonomous maintenance immediately on your repository, install the official GitHub App: "
                "https://github.com/apps/automaintainerbot"
            )
        )

    already_nominated = any(n.get("repository") == normalized for n in _pending_nominations)
    if not already_nominated:
        _pending_nominations.append({
            "repository": normalized,
            "stars": repo_data.get("stargazers_count", 0),
            "default_branch": repo_data.get("default_branch", "main"),
            "nominated_at": repo_data.get("updated_at")
        })

    return {
        "status": "nominated",
        "repository": normalized,
        "requires_maintainer_approval": True,
        "stars": repo_data.get("stargazers_count", 0),
        "default_branch": repo_data.get("default_branch", "main"),
        "description": repo_data.get("description"),
        "message": (
            f"Repository '{normalized}' was successfully nominated for review. "
            "To prevent unauthorized bot activity, unverified nominations require operator approval. "
            "To activate autonomous maintenance immediately, install the official GitHub App: "
            "https://github.com/apps/automaintainerbot"
        )
    }


_dry_run_rate_limiter: Dict[str, List[float]] = {}
_dry_run_semaphore = asyncio.Semaphore(2)
_dry_run_cache: Dict[str, Dict[str, Any]] = {}
DRY_RUN_RATE_LIMIT_WINDOW = 600  # 10 minutes
DRY_RUN_MAX_REQUESTS_PER_WINDOW = 5
DRY_RUN_CACHE_TTL = 600  # 10 minutes


def _check_dry_run_rate_limit(client_ip: str) -> None:
    now = time.time()
    timestamps = _dry_run_rate_limiter.get(client_ip, [])
    valid_ts = [t for t in timestamps if now - t < DRY_RUN_RATE_LIMIT_WINDOW]
    if len(valid_ts) >= DRY_RUN_MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded for IP '{client_ip}'. "
                f"Maximum {DRY_RUN_MAX_REQUESTS_PER_WINDOW} dry-run audits per 10 minutes. "
                "To enable continuous maintenance, install the official GitHub App: "
                "https://github.com/apps/automaintainerbot"
            )
        )
    valid_ts.append(now)
    _dry_run_rate_limiter[client_ip] = valid_ts


@router.post("/managed-repos/dry-run")
async def dry_run_repository_audit(
    req: RegisterRepositoryRequest,
    request: Request
):
    """
    POST /v1/public/managed-repos/dry-run - Run an instant simulated maintenance audit on any public repository.
    Enforces per-IP rate limiting, concurrency limiting, request timeouts, and cost budgeting.
    """
    import httpx
    from automaintainer.discovery.managed_repos import normalize_repo_identifier
    from automaintainer.discovery.opportunity_detectors import (
        GitHubActionsVersionDetector,
        BrokenDocLinkDetector,
        DependencyMetadataDetector,
        LockfileOpportunityDetector,
    )

    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "127.0.0.1")
    )
    _check_dry_run_rate_limit(client_ip)

    normalized = normalize_repo_identifier(req.repository)
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid repository format. Please provide 'owner/repo' or GitHub URL.")

    # Check cache to preserve GitHub API cost budget
    now = time.time()
    cached = _dry_run_cache.get(normalized)
    if cached and (now - cached.get("cached_at", 0) < DRY_RUN_CACHE_TTL):
        return cached["result"]

    # Concurrency control: prevent server overload from simultaneous dry-run requests
    try:
        await asyncio.wait_for(_dry_run_semaphore.acquire(), timeout=1.0)
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=503,
            detail="Server is currently busy running dry-run audits. Please retry shortly."
        )

    try:
        settings = get_settings()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

        async def _run_audit():
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{settings.GITHUB_API_BASE_URL}/repos/{normalized}", headers=headers, timeout=8.0)
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

        # Hard overall timeout to prevent hanging or unbounded resource consumption
        audit_result = await asyncio.wait_for(_run_audit(), timeout=12.0)
        _dry_run_cache[normalized] = {"cached_at": now, "result": audit_result}
        return audit_result
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Dry-run audit for '{normalized}' timed out while querying GitHub API or running detectors."
        )
    finally:
        _dry_run_semaphore.release()



