from contextlib import asynccontextmanager
import asyncio
import os
import time
import secrets
import logging
import shutil
from fastapi import FastAPI, Response, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from automaintainer.app.auth import get_current_user, AuthUser
from automaintainer.app.routes.webhooks import router as webhooks_router
from automaintainer.app.routes.sessions import router as sessions_router
from automaintainer.app.routes.opportunities import router as opportunities_router
from automaintainer.app.routes.installations import router as installations_router
from automaintainer.app.routes.repositories import router as repositories_router
from automaintainer.app.routes.policies import router as policies_router
from automaintainer.app.routes.inference import router as inference_router
from automaintainer.app.routes.ops import router as ops_router
from automaintainer.app.routes.public_discovery import router as discovery_router
from automaintainer.data.database import get_db_manager
from automaintainer.core.reconciler import SessionReconciler
from automaintainer.observability.metrics_exporter import PrometheusMetricsExporter
from automaintainer.config import get_settings
from automaintainer.discovery.managed_repos import background_managed_repos_loop

logger = logging.getLogger("automaintainer.reconciler")

# Server Process Start Timestamp
SERVER_START_TIME = time.time()

# Background Task handles
reconciler_task = None
managed_repos_task = None


async def background_reconciler_loop():
    """
    Background reconciler daemon.
    Queries database for active sessions with open pull requests.
    Calls SessionReconciler against GitHub to detect external merges, closures, or drift.
    """
    settings = get_settings()
    db_mgr = get_db_manager()

    while True:
        try:
            # Reconcile PR states and maintainer comments every 20 seconds
            await asyncio.sleep(20)

            # Distributed leader election via Redis if available
            from automaintainer.queue.redis_queue import get_partitioned_queue
            pq = get_partitioned_queue()
            redis_client = getattr(pq, "redis_client", None)
            if redis_client:
                leader_key = "automaintainer:leader:reconciler"
                try:
                    is_leader = redis_client.set(leader_key, "active", nx=True, ex=110)
                    if not is_leader:
                        logger.debug("Another instance holds reconciliation leadership; skipping cycle.")
                        continue
                except Exception as l_err:
                    logger.warning(f"Failed to check reconciler leadership in Redis: {l_err}")

            async with db_mgr.get_session() as db:
                reconciler = SessionReconciler(db, github_api_base=settings.GITHUB_API_BASE_URL)
                active_sessions = await reconciler.get_active_sessions_with_prs()
                
                for session in active_sessions:
                    try:
                        from automaintainer.data.tables import RepositoryRecord
                        repo_rec = await db.get(RepositoryRecord, session.repository_id)
                        if repo_rec:
                            repo_full_name = f"{repo_rec.owner}/{repo_rec.name}"
                        else:
                            repo_full_name = f"repo_{session.repository_id}/project"

                        # Retrieve token using broker - fail closed for GitHub App repos
                        github_token = ""
                        if repo_rec and repo_rec.installation_id:
                            if not settings.GITHUB_APP_PRIVATE_KEY:
                                logger.warning(f"Session {session.id}: repository {repo_full_name} requires GitHub App installation token, but private key is not configured. Skipping reconciliation.")
                                continue
                            try:
                                from automaintainer.github.auth import InstallationTokenBroker
                                from automaintainer.data.tables import InstallationRecord
                                inst_row = await db.get(InstallationRecord, repo_rec.installation_id)
                                target_inst_id = inst_row.github_installation_id if (inst_row and inst_row.github_installation_id) else repo_rec.installation_id
                                broker = InstallationTokenBroker(settings)
                                token_rec = await broker.get_token(target_inst_id)
                                github_token = token_rec.token
                            except Exception as tok_err:
                                logger.warning(f"Session {session.id}: failed to mint installation token for {repo_full_name}: {tok_err}. Falling back to GITHUB_TOKEN.")
                                if settings.GITHUB_TOKEN:
                                    github_token = settings.GITHUB_TOKEN
                                    repo_rec.installation_id = None
                                    await db.commit()
                                else:
                                    continue
                        else:
                            github_token = settings.GITHUB_TOKEN or ""

                        await reconciler.reconcile_session(
                            session=session,
                            repo_owner_name=repo_full_name,
                            github_token=github_token
                        )
                    except Exception as err:
                        logger.warning(f"Reconciliation error on session {session.id}: {str(err)}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Reconciler loop encountered error: {str(e)}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize schema / connection pool at startup
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    # Start scheduled background daemons
    global reconciler_task, managed_repos_task, worker_task
    from automaintainer.apps.worker.daemon import WorkerDaemon
    worker_daemon = WorkerDaemon(worker_id="embedded_worker")
    worker_task = asyncio.create_task(worker_daemon.start())
    reconciler_task = asyncio.create_task(background_reconciler_loop())
    managed_repos_task = asyncio.create_task(background_managed_repos_loop())

    yield

    # Shutdown background daemons cleanly
    worker_daemon.running = False
    for task in (worker_task, reconciler_task, managed_repos_task):
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # Dispose connection pool cleanly at shutdown
    await db_mgr.close()

app = FastAPI(
    title="AutoMaintainer Engine",
    description="Automated Open Source Repository Maintenance Platform",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan
)

security_basic = HTTPBasic()

def require_admin_credentials(credentials: HTTPBasicCredentials = Depends(security_basic)):
    settings = get_settings()
    if not settings.ADMIN_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin access is disabled. Configure the ADMIN_PASSWORD environment variable to enable it.",
        )
    is_user_ok = secrets.compare_digest(credentials.username, settings.ADMIN_USERNAME)
    is_pass_ok = secrets.compare_digest(credentials.password, settings.ADMIN_PASSWORD)
    if not (is_user_ok and is_pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized admin access",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Protected Documentation Endpoints
@app.get("/docs", include_in_schema=False)
async def get_protected_docs(username: str = Depends(require_admin_credentials)):
    return get_swagger_ui_html(openapi_url=app.openapi_url, title=f"{app.title} - Swagger UI")

@app.get("/redoc", include_in_schema=False)
async def get_protected_redoc(username: str = Depends(require_admin_credentials)):
    return get_redoc_html(openapi_url=app.openapi_url, title=f"{app.title} - ReDoc")

# Attach all API routes
app.include_router(webhooks_router)
app.include_router(sessions_router)
app.include_router(opportunities_router)
app.include_router(installations_router)
app.include_router(repositories_router)
app.include_router(policies_router)
app.include_router(inference_router)
app.include_router(ops_router)
app.include_router(discovery_router)

# Mount Static Assets
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", include_in_schema=False)
async def serve_public_landing_page():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "AutoMaintainer Platform Operational"}

@app.get("/admin", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def serve_admin_dashboard(username: str = Depends(require_admin_credentials)):
    admin_path = os.path.join(static_dir, "admin.html")
    if os.path.exists(admin_path):
        return FileResponse(admin_path)
    return {"message": "Admin Mission Control Operational"}

@app.get("/status", include_in_schema=False)
async def serve_status_page():
    status_path = os.path.join(static_dir, "status.html")
    if os.path.exists(status_path):
        return FileResponse(status_path)
    return {"message": "AutoMaintainer Status Page"}

@app.get("/register", include_in_schema=False)
@app.get("/onboard", include_in_schema=False)
async def redirect_register_page():
    return RedirectResponse(url="/#onboard", status_code=307)

@app.get("/diag", include_in_schema=False)
async def service_diagnostics():
    import os
    from automaintainer.inference.key_pool import get_global_key_pool
    pool = get_global_key_pool()

    secret_files = []
    for sdir in ("/etc/secrets", "/secrets"):
        if os.path.exists(sdir):
            try:
                secret_files.extend(os.listdir(sdir))
            except Exception:
                pass

    matching_env_names = [
        k for k in sorted(os.environ.keys())
        if any(term in k.upper() for term in ("GROQ", "CEREBRAS", "GOOGLE", "GEMINI", "KEY", "TOKEN", "SECRET", "API"))
    ]

    anti_spam_status = {}
    managed_repos = []
    try:
        from automaintainer.discovery.anti_spam import get_anti_spam_manager
        from automaintainer.discovery.managed_repos import is_repo_managed, parse_managed_repos_file
        anti_spam = get_anti_spam_manager()
        test_repo = "abhinav00anand/automaintainer-sandbox-test"
        can_open_m, reason_m = anti_spam.can_open_pr(test_repo, is_managed=True)
        can_open_u, reason_u = anti_spam.can_open_pr(test_repo, is_managed=False)
        managed_repos = parse_managed_repos_file(get_settings().MANAGED_REPOSITORIES_FILE)
        anti_spam_status = {
            "test_repo": test_repo,
            "is_managed": is_repo_managed(test_repo),
            "can_open_managed": can_open_m,
            "reason_managed": reason_m,
            "can_open_unmanaged": can_open_u,
            "reason_unmanaged": reason_u,
            "active_prs": {k: list(v) for k, v in anti_spam._active_prs.items()},
            "rejection_outcomes_count": len(anti_spam._pr_outcomes),
            "recent_hourly_prs": len([ts for ts in anti_spam._pr_creation_timestamps if ts > time.time() - 3600]),
        }
    except Exception as e:
        anti_spam_status = {"error": str(e)}

    github_token_diag = {}
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                u_resp = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {gh_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    timeout=5.0
                )
                github_token_diag = {
                    "user_status": u_resp.status_code,
                    "login": u_resp.json().get("login") if u_resp.status_code == 200 else None,
                    "scopes": u_resp.headers.get("x-oauth-scopes"),
                    "accepted_scopes": u_resp.headers.get("x-accepted-oauth-scopes"),
                }
                if u_resp.status_code != 200:
                    github_token_diag["user_error"] = u_resp.text

                r_resp = await client.get(
                    "https://api.github.com/repos/abhinav00anand/automaintainer-sandbox-test",
                    headers={
                        "Authorization": f"Bearer {gh_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    timeout=5.0
                )
                if r_resp.status_code == 200:
                    rdata = r_resp.json()
                    github_token_diag["repo_permissions"] = rdata.get("permissions")
                else:
                    github_token_diag["repo_check"] = f"{r_resp.status_code}: {r_resp.text}"

                # Test fork permission against AutoMaintainerBot
                f_resp = await client.post(
                    "https://api.github.com/repos/abhinav00anand/automaintainer-sandbox-test/forks",
                    headers={
                        "Authorization": f"Bearer {gh_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    json={"organization": "AutoMaintainerBot"},
                    timeout=8.0
                )
                try:
                    github_token_diag["fork_test"] = {"status": f_resp.status_code, "data": f_resp.json()}
                except Exception:
                    github_token_diag["fork_test"] = {"status": f_resp.status_code, "text": f_resp.text}
        except Exception as e:
            github_token_diag = {"exception": str(e)}

    return {
        "matching_env_names": matching_env_names,
        "secret_files_found": secret_files,
        "has_groq_env": any(k.upper().startswith("GROQ_API_KEY") for k in os.environ),
        "has_google_env": any(k.upper().startswith("GOOGLE_API_KEY") or k.upper().startswith("GEMINI_API_KEY") for k in os.environ),
        "has_cerebras_env": any(k.upper().startswith("CEREBRAS_API_KEY") for k in os.environ),
        "has_github_app_id": bool(os.environ.get("GITHUB_APP_ID")),
        "has_github_app_key": bool(os.environ.get("GITHUB_APP_PRIVATE_KEY")),
        "has_github_token": bool(os.environ.get("GITHUB_TOKEN")),
        "bot_org": get_settings().GITHUB_BOT_ORG,
        "github_token_diag": github_token_diag,
        "available_providers": pool.get_available_providers(),
        "active_keys_count": len(pool.get_active_keys()),
        "pool_registered_keys": [{"id": k.key_id, "provider": k.provider, "status": k.status.value} for k in pool._keys.values()],
        "managed_repositories": managed_repos,
        "anti_spam_status": anti_spam_status,
        "commit": "v1.3.6_token_fallback_reconcile",
    }

@app.get("/health/live")
@app.get("/v1/health/live")
async def health_live():
    """Liveness probe: verifies control plane process is responsive."""
    return {
        "status": "alive",
        "service": "automaintainer-control-plane",
        "version": "1.0.0"
    }

@app.get("/health/ready")
@app.get("/v1/health/ready")
@app.get("/v1/health")
@app.get("/health")
@app.get("/v1/ops/health")
async def health_ready(request: Request = None):
    """
    Readiness probe: thoroughly verifies that critical dependencies are operational:
    1. Database connectivity
    2. Redis distributed queue connectivity (when QUEUE_BACKEND=redis)
    3. Sandbox runtime availability
    """
    from sqlalchemy import text
    from fastapi import status
    from fastapi.responses import JSONResponse

    # When accessed directly from a web browser without format=json, serve the visual status dashboard
    if request:
        accept = request.headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept and request.query_params.get("format") != "json":
            status_path = os.path.join(static_dir, "status.html")
            if os.path.exists(status_path):
                return FileResponse(status_path)

    settings = get_settings()
    checks = {
        "database": False,
        "queue": False,
        "sandbox": True,
    }
    errors = []

    try:
        db_mgr = get_db_manager()
        async with db_mgr.get_session() as db:
            await db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as db_err:
        errors.append(f"Database error: {db_err}")

    if settings.QUEUE_BACKEND == "redis":
        try:
            from automaintainer.queue.redis_queue import get_partitioned_queue
            pq = get_partitioned_queue()
            if pq.redis_client:
                pq.redis_client.ping()
                checks["queue"] = True
            elif settings.ALLOW_IN_MEMORY_QUEUE:
                checks["queue"] = True
            else:
                errors.append("Redis client not initialized and in-memory queue is disabled.")
        except Exception as redis_err:
            if settings.ALLOW_IN_MEMORY_QUEUE:
                checks["queue"] = True
            else:
                errors.append(f"Redis queue error: {redis_err}")
    else:
        checks["queue"] = True

    # Sandbox Check: verify runtime initialization and check docker only if present on host PATH
    docker_bin = shutil.which("docker")
    if docker_bin and settings.ENVIRONMENT in ("production", "staging") and not settings.ALLOW_HOST_SUBPROCESS:
        try:
            import subprocess
            proc = subprocess.run([docker_bin, "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
            if proc.returncode != 0:
                logging.getLogger("automaintainer").warning("Docker CLI exists but daemon is unresponsive; using ephemeral sandbox fallback.")
        except Exception as sand_err:
            logging.getLogger("automaintainer").warning(f"Docker probe warning: {sand_err}")

    try:
        from automaintainer.execution.sandbox_factory import get_sandbox_runtime
        sandbox = get_sandbox_runtime()
        if not sandbox:
            checks["sandbox"] = False
            errors.append("Sandbox runtime failed to initialize.")
        else:
            checks["sandbox"] = True
    except Exception as s_init_err:
        checks["sandbox"] = False
        errors.append(f"Sandbox runtime initialization error: {s_init_err}")

    is_healthy = checks["database"] and checks["queue"] and checks["sandbox"]
    status_code = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE

    now = time.time()
    uptime_sec = int(now - SERVER_START_TIME)

    payload = {
        "status": "healthy" if is_healthy else "degraded",
        "service": "automaintainer-control-plane",
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": uptime_sec,
        "started_at": int(SERVER_START_TIME),
        "server_time": int(now),
        "checks": checks,
    }
    if errors:
        payload["errors"] = errors

    return JSONResponse(status_code=status_code, content=payload)

@app.get("/v1/ops/inference-status")
async def get_ops_inference_status():
    """Public inference engine operational status probe (no internal secrets/tokens leaked)."""
    settings = get_settings()
    from automaintainer.inference.key_pool import get_global_key_pool
    pool = get_global_key_pool()
    active_providers = pool.get_available_providers()
    provider_available = (
        len(active_providers) > 0
        or bool(settings.CEREBRAS_API_KEY)
        or bool(settings.GROQ_API_KEY)
        or bool(settings.GOOGLE_API_KEY)
    )
    primary_provider = settings.INFERENCE_PROVIDER_PRIORITY[0] if settings.INFERENCE_PROVIDER_PRIORITY else "cerebras"
    return {
        "status": "healthy" if provider_available else "degraded",
        "primary_provider": primary_provider,
        "active_providers": active_providers,
        "configured_priority": settings.INFERENCE_PROVIDER_PRIORITY,
        "key_rotation_active": True,
        "supported_models": {
            "cerebras": ["llama3.1-70b", "llama3.3-70b"],
            "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
            "google": ["gemini-2.0-flash", "gemini-1.5-pro"]
        }
    }

@app.get("/metrics-summary")
async def metrics_summary(user: AuthUser = Depends(get_current_user)):
    """Real-time telemetry summary for web dashboard."""
    from sqlalchemy import select, func
    from automaintainer.data.tables import SessionRecord, OpportunityRecord, PullRequestRecord, ValidationRunRecord
    from automaintainer.observability.metrics import get_metrics
    metrics = get_metrics()
    db_mgr = get_db_manager()
    async with db_mgr.get_session() as db:
        sess_count = (await db.execute(select(func.count(SessionRecord.id)))).scalar_one()
        opp_count = (await db.execute(select(func.count(OpportunityRecord.id)))).scalar_one()
        pr_open_count = (await db.execute(select(func.count(PullRequestRecord.id)).where(PullRequestRecord.status == "open"))).scalar_one()
        pr_merged_count = (await db.execute(select(func.count(PullRequestRecord.id)).where(PullRequestRecord.status == "merged"))).scalar_one()

        # Real validation pass rate calculation
        total_runs = (await db.execute(select(func.count(ValidationRunRecord.id)))).scalar_one()
        passed_runs = (await db.execute(select(func.count(ValidationRunRecord.id)).where(ValidationRunRecord.passed == True))).scalar_one()
        pass_rate = round(passed_runs / total_runs, 2) if total_runs > 0 else 1.0

        candidates_scanned = metrics.get("candidates_scanned") or opp_count

        return {
            "candidates_scanned": candidates_scanned,
            "opportunities_found": opp_count,
            "active_sessions": sess_count,
            "prs_opened": pr_open_count,
            "prs_merged": pr_merged_count,
            "validation_pass_rate": pass_rate
        }

@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus /metrics scrape endpoint."""
    exporter = PrometheusMetricsExporter()
    content = exporter.generate_prometheus_text()
    return Response(content=content, media_type="text/plain; version=0.0.4")

