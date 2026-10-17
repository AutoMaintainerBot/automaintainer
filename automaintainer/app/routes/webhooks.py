import json
import uuid
from typing import Optional
from fastapi import APIRouter, Header, Request, HTTPException, status, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from automaintainer.github.webhook_verifier import GitHubWebhookVerifier, WebhookVerificationError
from automaintainer.queue.lease import LeasedTaskQueue
from automaintainer.config import get_settings, Settings
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import EventRecord, PullRequestRecord, SessionRecord, RepositoryRecord, InstallationRecord
from automaintainer.core.models import SessionState
from automaintainer.queue.redis_queue import get_partitioned_queue

router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])

def _resolve_session_id(event_type: str, payload: dict) -> Optional[str]:
    """Resolves canonical maintenance session ID from GitHub webhook payload context."""
    pr = payload.get("pull_request")
    if pr and isinstance(pr, dict):
        head_ref = pr.get("head", {}).get("ref", "")
        if "automaintainer/" in head_ref:
            return head_ref.split("automaintainer/")[-1].strip()

    ref = payload.get("ref", "")
    if "automaintainer/" in ref:
        return ref.split("automaintainer/")[-1].strip()

    check_run = payload.get("check_run")
    if check_run and isinstance(check_run, dict):
        head_branch = check_run.get("check_suite", {}).get("head_branch", "")
        if "automaintainer/" in head_branch:
            return head_branch.split("automaintainer/")[-1].strip()

    return None

@router.get("/github")
@router.get("")
async def github_webhook_info():
    """Information endpoint explaining GitHub Webhook ingress configuration."""
    return {
        "status": "listening",
        "service": "AutoMaintainer GitHub Webhook Receiver",
        "webhook_url": "https://automaintainer.onrender.com/v1/webhooks/github",
        "method": "POST",
        "supported_events": ["issues", "pull_request", "push", "check_run", "installation", "installation_repositories"],
        "authentication": "HMAC-SHA256 signature verification via X-Hub-Signature-256 header"
    }

@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def handle_github_webhook(
    request: Request,
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    settings: Settings = Depends(get_settings),
):
    """
    Production Ingress Webhook Handler:
    1. Rejects missing delivery or signature headers.
    2. Reads raw request byte stream before deserializing JSON.
    3. Executes constant-time HMAC-SHA256 verification using injected secret.
    4. Enforces durable database-backed deduplication on X-GitHub-Delivery.
    5. Resolves true session identity from git/PR metadata.
    6. Dispatches task asynchronously to prioritized durable queue.
    """
    if not x_github_delivery:
        raise HTTPException(status_code=400, detail="Missing X-GitHub-Delivery header")

    raw_body = await request.body()

    try:
        GitHubWebhookVerifier.verify(
            raw_body=raw_body,
            signature_header=x_hub_signature_256,
            secret=settings.GITHUB_WEBHOOK_SECRET
        )
    except WebhookVerificationError as e:
        raise HTTPException(status_code=401, detail=str(e))

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    sender = payload.get("sender", {}).get("login", "")
    sender_type = payload.get("sender", {}).get("type", "")
    if sender_type == "Bot" or sender.endswith("[bot]") or "automaintainer" in sender.lower():
        return {"status": "ignored", "reason": f"Self/bot event from {sender}"}

    repo_dict = payload.get("repository") or {}
    repo_full = repo_dict.get("full_name", "")
    owner, rname = repo_full.split("/", 1) if "/" in repo_full else ("unknown", "unknown")
    github_repo_id = repo_dict.get("id")

    resolved_session_id = _resolve_session_id(x_github_event or "", payload)
    
    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    db_mgr = get_db_manager()
    is_redelivery = False

    async with db_mgr.get_session() as session:
        pr_num = None
        if payload.get("pull_request"):
            pr_num = payload["pull_request"].get("number")
        elif payload.get("issue") and payload["issue"].get("pull_request"):
            pr_num = payload["issue"].get("number")

        # If not resolved from branch ref, check PullRequestRecord by number bound strictly to repository
        if not resolved_session_id and pr_num and owner != "unknown" and rname != "unknown":
            stmt = select(PullRequestRecord.session_id).where(
                PullRequestRecord.number == pr_num,
                PullRequestRecord.owner == owner,
                PullRequestRecord.repo == rname
            )
            res = await session.execute(stmt)
            resolved_session_id = res.scalar_one_or_none()

            # If not found in DB, resolve directly from GitHub PR API
            if not resolved_session_id:
                inst_id = (payload.get("installation") or {}).get("id")
                if repo_full and inst_id:
                    try:
                        from automaintainer.github.auth import InstallationTokenBroker
                        broker = InstallationTokenBroker(settings)
                        token = await broker.get_installation_token(inst_id)
                        import httpx
                        async with httpx.AsyncClient() as gh_client:
                            pr_resp = await gh_client.get(
                                f"{settings.GITHUB_API_BASE_URL}/repos/{repo_full}/pulls/{pr_num}",
                                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                                timeout=10.0
                            )
                            if pr_resp.status_code == 200:
                                head_ref = pr_resp.json().get("head", {}).get("ref", "")
                                if "automaintainer/" in head_ref:
                                    resolved_session_id = head_ref.split("automaintainer/")[-1].strip()
                    except Exception:
                        pass

        if resolved_session_id:
            sess_stmt = select(SessionRecord).where(SessionRecord.id == resolved_session_id)
            sess_res = await session.execute(sess_stmt)
            existing_sess = sess_res.scalars().first()
            if existing_sess:
                # Anti-spoofing check: ensure existing session belongs to this event's repository
                repo_check_stmt = select(RepositoryRecord).where(RepositoryRecord.id == existing_sess.repository_id)
                repo_check_res = await session.execute(repo_check_stmt)
                existing_repo = repo_check_res.scalars().first()
                if existing_repo:
                    if (owner != "unknown" and existing_repo.owner != owner) or (rname != "unknown" and existing_repo.name != rname):
                        # Cross-repository mismatch detected: reject binding
                        resolved_session_id = None

            if resolved_session_id and not existing_sess:
                repo_lookup = select(RepositoryRecord).where(
                    RepositoryRecord.owner == owner,
                    RepositoryRecord.name == rname
                )
                repo_l_res = await session.execute(repo_lookup)
                r_rec = repo_l_res.scalars().first()
                if not r_rec:
                    repo_id_val = github_repo_id or 999999
                    inst_id = (payload.get("installation") or {}).get("id")
                    inst_db_id = None
                    if inst_id:
                        inst_lookup = select(InstallationRecord).where(InstallationRecord.github_installation_id == inst_id)
                        inst_l_res = await session.execute(inst_lookup)
                        inst_rec = inst_l_res.scalars().first()
                        if not inst_rec:
                            inst_rec = InstallationRecord(
                                github_installation_id=inst_id,
                                account_id=payload.get("repository", {}).get("owner", {}).get("id") or 1,
                                target_type="user",
                                status="active",
                            )
                            session.add(inst_rec)
                            await session.flush()
                        inst_db_id = inst_rec.id
                    r_rec = RepositoryRecord(
                        github_repo_id=repo_id_val,
                        installation_id=inst_db_id,
                        owner=owner,
                        name=rname,
                        visibility="public",
                        default_branch="main",
                    )
                    session.add(r_rec)
                    await session.flush()

                new_sess = SessionRecord(
                    id=resolved_session_id,
                    repository_id=r_rec.id,
                    mode="managed",
                    state=SessionState.MAINTAINER_REVIEW.value,
                    version=1,
                )
                session.add(new_sess)
                await session.flush()

                if pr_num:
                    pr_lookup = select(PullRequestRecord).where(
                        PullRequestRecord.number == pr_num,
                        PullRequestRecord.owner == owner,
                        PullRequestRecord.repo == rname
                    )
                    pr_l_res = await session.execute(pr_lookup)
                    if not pr_l_res.scalars().first():
                        pr_rec = PullRequestRecord(
                            id=f"pr_{uuid.uuid4().hex[:16]}",
                            session_id=resolved_session_id,
                            number=pr_num,
                            owner=owner,
                            repo=rname,
                            head_ref=f"automaintainer/{resolved_session_id}",
                            base_ref="main",
                            url=f"https://github.com/{owner}/{rname}/pull/{pr_num}",
                            status="open",
                        )
                        session.add(pr_rec)
                        await session.flush()

        session_id_to_store = resolved_session_id or f"sess_evt_{x_github_delivery[:8]}"
        try:
            event_record = EventRecord(
                id=event_id,
                delivery_id=x_github_delivery,
                session_id=session_id_to_store,
                event_type=f"github.{x_github_event or 'unknown'}",
                source="github",
                payload_ref=None
            )
            session.add(event_record)
            await session.commit()
        except IntegrityError:
            await session.rollback()
            is_redelivery = True

            # Inspect existing delivery & associated session state
            existing_event_stmt = select(EventRecord).where(EventRecord.delivery_id == x_github_delivery)
            existing_event_res = await session.execute(existing_event_stmt)
            existing_event = existing_event_res.scalar_one_or_none()

            existing_session = None
            if existing_event and existing_event.session_id:
                session_id_to_store = existing_event.session_id
                sess_stmt = select(SessionRecord).where(SessionRecord.id == existing_event.session_id)
                sess_res = await session.execute(sess_stmt)
                existing_session = sess_res.scalar_one_or_none()

            # If previous processing already successfully completed, do not re-enqueue
            completed_states = (
                SessionState.PR_OPEN.value,
                SessionState.MAINTAINER_REVIEW.value,
                SessionState.MERGED.value,
            )
            if existing_session and existing_session.state in completed_states:
                return {"status": "already_processed", "delivery_id": x_github_delivery}

    # - conversation: issue_comment, pull_request_review (highest human-facing)
    # - validation: check_run, check_suite, workflow_run
    # - github-write: push, pull_request state changes
    # - analysis: installation, repository lifecycle
    queue_name = "analysis"
    if x_github_event in ("issue_comment", "pull_request_review"):
        action = payload.get("action", "")
        if action not in ("created", "submitted"):
            return {"status": "ignored", "reason": f"Non-actionable comment/review action: {action}"}
        queue_name = "conversation"
    elif x_github_event in ("check_run", "check_suite", "workflow_run"):
        queue_name = "validation"
    elif x_github_event in ("push", "pull_request"):
        queue_name = "github-write"

    partitioned_queue = get_partitioned_queue()
    partitioned_queue.enqueue(
        queue_name=queue_name,
        session_id=session_id_to_store,
        task_type=f"github.{x_github_event or 'unknown'}",
        payload=payload,
        dedupe_key=x_github_delivery
    )

    repo_name = payload.get("repository", {}).get("full_name", "unknown")
    status_label = "re-enqueued" if is_redelivery else "enqueued"
    resp = {
        "status": status_label,
        "delivery_id": x_github_delivery,
        "session_id": session_id_to_store,
        "queue": queue_name,
        "event": x_github_event,
        "repository": repo_name,
    }
    if is_redelivery:
        resp["reason"] = "Redelivery of incomplete or crashed job"
    return resp
