import datetime
import logging
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from automaintainer.discovery.anti_spam import get_anti_spam_manager
from automaintainer.discovery.repo_health import RepositoryHealthScorer, RepoHealthScore
from automaintainer.discovery.repo_fingerprint import RepositoryFingerprinter
from automaintainer.discovery.opportunity_detectors import (
    BaseDetector,
    DetectedOpportunity,
    GitHubActionsVersionDetector,
    BrokenDocLinkDetector,
    PackageMetadataDetector,
    DependencyMetadataDetector,
    LockfileOpportunityDetector,
)
from automaintainer.discovery.opportunity_scorer import OpportunityScorer, ScoredOpportunity, ThresholdDecision
from automaintainer.queue.redis_queue import get_partitioned_queue, PartitionedLeasedQueue
from automaintainer.data.tables import OpportunityRecord, SessionRecord, TaskRecord, RepositoryRecord, OutboxRecord
from automaintainer.core.models import SessionState

logger = logging.getLogger(__name__)

class OpportunityScanner:
    """Runs a suite of static opportunity detectors against a target repository."""
    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")
        self.detectors: List[BaseDetector] = [
            GitHubActionsVersionDetector(api_base_url=self.api_base_url),
            BrokenDocLinkDetector(api_base_url=self.api_base_url),
            PackageMetadataDetector(api_base_url=self.api_base_url),
            DependencyMetadataDetector(api_base_url=self.api_base_url),
            LockfileOpportunityDetector(api_base_url=self.api_base_url),
        ]
        self.last_failures: List[Dict[str, str]] = []

    async def scan(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None
    ) -> List[DetectedOpportunity]:
        all_opps: List[DetectedOpportunity] = []
        self.last_failures = []
        for detector in self.detectors:
            try:
                found = await detector.detect(owner=owner, repo=repo, token=token, client=client)
                all_opps.extend(found)
            except Exception as e:
                logger.warning(f"Detector {detector.__class__.__name__} failed on {owner}/{repo}: {e}")
                self.last_failures.append({"detector": detector.__class__.__name__, "error": str(e)})
                continue
        return all_opps

class CandidateCrawler:
    """
    Public Discovery Candidate Ingestion & Session Admission Engine:
    - Queries GitHub Search API.
    - Runs complete 10-step ingestion & admission bridge:
      Candidate -> Hard Exclusion -> Fingerprint -> Detect -> Score -> Filter (score >= 80) -> Persist -> Enqueue.
    """

    def __init__(self, github_token: Optional[str] = None, token: Optional[str] = None, api_base_url: str = "https://api.github.com"):
        self.token = github_token or token or ""
        self.api_base_url = api_base_url.rstrip("/")
        self.anti_spam = get_anti_spam_manager()
        self.fingerprinter = RepositoryFingerprinter(api_base_url=self.api_base_url)
        self.health_scorer = RepositoryHealthScorer(api_base_url=self.api_base_url)
        self.scanner = OpportunityScanner(api_base_url=self.api_base_url)
        self.scorer = OpportunityScorer()

    async def fetch_candidates(self, query: str = "language:python stars:>100", limit: int = 10) -> List[Dict[str, Any]]:
        from automaintainer.config import get_settings
        settings = get_settings()
        if not getattr(settings, "PUBLIC_DISCOVERY_ENABLED", False):
            logger.info("Public candidate discovery is disabled by policy (PUBLIC_DISCOVERY_ENABLED=False). Refusing to search external repos.")
            return []

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        url = f"{self.api_base_url}/search/repositories?q={query}&sort=updated&order=desc&per_page={limit}"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=10.0)
                if resp.status_code != 200:
                    return []
                data = resp.json()
                return data.get("items", [])
        except Exception:
            return []

    def filter_candidate(self, repo_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Hard Exclusion Filters"""
        from automaintainer.config import get_settings
        settings = get_settings()
        if not getattr(settings, "PUBLIC_DISCOVERY_ENABLED", False):
            return False, "Public candidate discovery is disabled by policy (PUBLIC_DISCOVERY_ENABLED=False)"

        full_name = repo_data.get("full_name", "")
        if repo_data.get("archived", False):
            return False, "Repository is archived"

        if repo_data.get("disabled", False):
            return False, "Repository is disabled"

        if repo_data.get("size", 0) == 0:
            return False, "Repository is empty"

        can_open, reason = self.anti_spam.can_open_pr(full_name)
        if not can_open:
            return False, reason

        return True, "OK"

    async def process_and_admit_candidates(
        self,
        candidates: List[Dict[str, Any]],
        db: Optional[AsyncSession] = None,
        queue: Optional[PartitionedLeasedQueue] = None,
        client: Optional[httpx.AsyncClient] = None
    ) -> List[Dict[str, Any]]:
        """
        Candidate admission pipeline bridge:
        Applies filter -> Fingerprints -> Scans -> Scores -> Persists -> Enqueues.
        """
        admitted = []
        target_queue = queue or get_partitioned_queue()

        for cand in candidates:
            passed, reason = self.filter_candidate(cand)
            if not passed:
                continue

            full_name = cand.get("full_name", "")
            if "/" not in full_name:
                continue
            owner, repo = full_name.split("/", 1)
            repo_id = cand.get("id", 1000)

            try:
                fingerprint = await self.fingerprinter.build(owner, repo, self.token, client=client)
            except Exception:
                continue

            try:
                health_score = await self.health_scorer.score(owner, repo, self.token, client=client)
            except Exception as e:
                logger.warning(f"Failed to score repository health for {owner}/{repo}: {e}")
                continue

            if not health_score.is_eligible:
                continue

            try:
                detected_opps = await self.scanner.scan(owner, repo, self.token, client=client)
            except Exception as e:
                logger.warning(f"Failed to scan opportunities for {owner}/{repo}: {e}")
                detected_opps = []

            for opp in detected_opps:
                scored = self.scorer.score(opp, health_score)
                normalized_score = scored.opportunity_score * 100.0

                # Score threshold check (score >= 80 or ALLOW_AUTONOMOUS)
                if normalized_score >= 80.0 or scored.threshold_decision == ThresholdDecision.ALLOW_AUTONOMOUS:
                    session_id = f"sess_pub_{uuid.uuid4().hex[:12]}"
                    opp_id = f"opp_{uuid.uuid4().hex[:12]}"
                    repo_url = f"https://github.com/{full_name}.git"

                    payload = {
                        "repository": full_name,
                        "repo_url": repo_url,
                        "opportunity_id": opp_id,
                        "target_paths": opp.target_paths,
                        "task_type": opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                        "score": normalized_score,
                    }

                    outbox_record = None
                    # Persist record in database if session provided
                    if db is not None:
                        # Ensure repository record exists by external github_repo_id
                        repo_stmt = select(RepositoryRecord).where(RepositoryRecord.github_repo_id == repo_id)
                        repo_res = await db.execute(repo_stmt)
                        repo_record = repo_res.scalars().first()
                        if not repo_record:
                            repo_record = RepositoryRecord(
                                github_repo_id=repo_id,
                                owner=owner,
                                name=repo,
                                visibility="public",
                            )
                            db.add(repo_record)
                            await db.flush()

                        internal_repo_id = repo_record.id

                        opp_record = OpportunityRecord(
                            id=opp_id,
                            repository_id=internal_repo_id,
                            task_type=opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                            summary=opp.summary,
                            evidence_json=opp.evidence,
                            target_paths_json=opp.target_paths,
                            score=normalized_score,
                            confidence=opp.confidence,
                            risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                            metadata_json=opp.metadata or {},
                            status="admitted"
                        )
                        db.add(opp_record)

                        sess_record = SessionRecord(
                            id=session_id,
                            repository_id=internal_repo_id,
                            mode="public",
                            state=SessionState.DISCOVERED.value,
                            version=1,
                            risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                            opportunity_score=normalized_score
                        )
                        db.add(sess_record)

                        task_record = TaskRecord(
                            id=f"task_{uuid.uuid4().hex[:12]}",
                            session_id=session_id,
                            task_type=opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                            scope="public_maintenance",
                            evidence_json=opp.evidence,
                            confidence=opp.confidence,
                            risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                            status="pending"
                        )
                        db.add(task_record)

                        outbox_record = OutboxRecord(
                            id=f"outbox_{uuid.uuid4().hex[:12]}",
                            queue_name="discovery",
                            session_id=session_id,
                            task_type="public_discovery_analysis",
                            payload_json=payload,
                            status="pending"
                        )
                        db.add(outbox_record)
                        await db.commit()

                    # Enqueue discovery/analysis job into priority queue
                    try:
                        target_queue.enqueue(
                            queue_name="discovery",
                            session_id=session_id,
                            task_type="public_discovery_analysis",
                            payload=payload
                        )
                        if db is not None and outbox_record is not None:
                            outbox_record.status = "dispatched"
                            outbox_record.dispatched_at = datetime.datetime.now(datetime.timezone.utc)
                            await db.commit()
                    except Exception as q_err:
                        logger.error(f"Failed to dispatch outbox message {session_id} to queue: {q_err}")

                    admitted.append({
                        "repository": full_name,
                        "session_id": session_id,
                        "opportunity_id": opp_id,
                        "task_type": opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                        "score": normalized_score,
                        "decision": scored.threshold_decision.value
                    })

        return admitted

    async def evaluate_candidates_batch(
        self,
        candidates: List[Dict[str, Any]],
        model_id: str = "llama-3.1-8b-instant",
        timeout: float = 60.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluates discovered public repository candidates using the Groq Batch API
        to conserve real-time inference rate limits.
        """
        from automaintainer.inference.batch_client import GroqBatchProcessor
        processor = GroqBatchProcessor()
        return await processor.process_candidates_offline(
            candidates=candidates,
            model_id=model_id,
            timeout=timeout,
            client=client,
        )
