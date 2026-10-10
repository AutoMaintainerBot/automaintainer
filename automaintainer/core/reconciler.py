from typing import List, Dict, Any, Optional
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from automaintainer.data.tables import SessionRecord
from automaintainer.core.models import SessionState, TERMINAL_STATES
from automaintainer.data.repositories import SessionRepository

class SessionReconciler:
    """
    Background Reconciliation Loop:
    Periodically queries GitHub PR status for all non-terminal sessions.
    Repairs state drift caused by dropped webhooks or external maintainer actions
    (e.g., maintainer merges or closes PR manually directly on GitHub).
    """

    def __init__(self, db_session: AsyncSession, github_api_base: str = "https://api.github.com"):
        self.db = db_session
        self.repo = SessionRepository(db_session)
        self.github_api_base = github_api_base.rstrip("/")

    async def get_active_sessions_with_prs(self) -> List[SessionRecord]:
        """Fetch all sessions that have open PRs and are not in terminal state."""
        stmt = select(SessionRecord).where(
            SessionRecord.state.not_in([s.value for s in TERMINAL_STATES]),
            SessionRecord.pr_number.is_not(None)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def reconcile_session(
        self,
        session: SessionRecord,
        repo_owner_name: str,
        github_token: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> Optional[SessionState]:
        """
        Polls GitHub /repos/{owner}/{repo}/pulls/{number} and reconciles local state.
        """
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        url = f"{self.github_api_base}/repos/{repo_owner_name}/pulls/{session.pr_number}"

        async def _check(c: httpx.AsyncClient):
            resp = await c.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 404:
                # PR deleted or inaccessible -> transition to REJECTED/CANCELLED
                try:
                    from automaintainer.discovery.anti_spam import get_anti_spam_manager
                    anti_spam = get_anti_spam_manager()
                    if session.pr_number:
                        anti_spam.release_active_pr(repo_owner_name, session.pr_number)
                except Exception:
                    pass
                return await self.repo.transition_state_optimistic(
                    session_id=session.id,
                    expected_state=SessionState(session.state),
                    target_state=SessionState.REJECTED,
                    expected_version=session.version
                )
            resp.raise_for_status()
            data = resp.json()

            is_merged = data.get("merged", False)
            gh_state = data.get("state", "open")  # open | closed

            target_state = None
            if is_merged:
                target_state = SessionState.MERGED
            elif gh_state == "closed":
                target_state = SessionState.REJECTED

            if target_state:
                try:
                    from automaintainer.discovery.anti_spam import get_anti_spam_manager
                    anti_spam = get_anti_spam_manager()
                    if session.pr_number:
                        anti_spam.release_active_pr(repo_owner_name, session.pr_number)
                    if target_state == SessionState.MERGED:
                        anti_spam.record_pr_merge(repo_owner_name)
                    else:
                        anti_spam.record_pr_rejection(repo_owner_name)
                except Exception:
                    pass

                return await self.repo.transition_state_optimistic(
                    session_id=session.id,
                    expected_state=SessionState(session.state),
                    target_state=target_state,
                    expected_version=session.version
                )

            if gh_state == "open" and session.pr_number:
                # Poll for maintainer comments on open PR (supports uninstalled/fork repos without webhooks)
                try:
                    comments_url = f"{self.github_api_base}/repos/{repo_owner_name}/issues/{session.pr_number}/comments"
                    c_resp = await c.get(comments_url, headers=headers, timeout=10.0)
                    if c_resp.status_code == 200:
                        comments = c_resp.json()
                        if isinstance(comments, list):
                            from automaintainer.data.tables import EventRecord
                            from automaintainer.queue.redis_queue import get_partitioned_queue
                            import uuid

                            pq = get_partitioned_queue()
                            for comment in comments:
                                c_id = comment.get("id")
                                if not c_id:
                                    continue
                                c_user = (comment.get("user") or {}).get("login", "")
                                if "automaintainer" in c_user.lower() or c_user.endswith("[bot]") or (comment.get("user") or {}).get("type") == "Bot":
                                    continue

                                delivery_id = f"reconcile_comment_{c_id}"
                                ev_stmt = select(EventRecord.id).where(EventRecord.delivery_id == delivery_id)
                                ev_res = await self.db.execute(ev_stmt)
                                if ev_res.scalar_one_or_none():
                                    continue

                                event_record = EventRecord(
                                    id=f"evt_{uuid.uuid4().hex[:12]}",
                                    delivery_id=delivery_id,
                                    session_id=session.id,
                                    event_type="github.issue_comment",
                                    source="reconciler",
                                    payload_ref=None,
                                )
                                self.db.add(event_record)
                                await self.db.commit()

                                comment_payload = {
                                    "action": "created",
                                    "issue": {"number": session.pr_number, "pull_request": {}},
                                    "pull_request": {"number": session.pr_number},
                                    "comment": comment,
                                    "repository": {"full_name": repo_owner_name},
                                    "sender": comment.get("user"),
                                }
                                pq.enqueue(
                                    queue_name="conversation",
                                    session_id=session.id,
                                    task_type="github.issue_comment",
                                    payload=comment_payload,
                                    dedupe_key=delivery_id,
                                )
                except Exception:
                    pass

            return None

        if client:
            return await _check(client)
        else:
            async with httpx.AsyncClient() as c:
                return await _check(c)
