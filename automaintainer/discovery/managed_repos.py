"""
Managed Repositories Ingestion & 20-Second Watcher Service.

Allows operators and repository maintainers to specify a text file (e.g. managed_repositories.txt)
containing repositories to maintain. The service checks the file every 20 seconds,
discovers opportunities exclusively for those listed repositories, and enqueues maintenance sessions.
"""
from __future__ import annotations

import os
import re
import time
import uuid
import logging
import asyncio
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from automaintainer.config import get_settings
from automaintainer.discovery.anti_spam import get_anti_spam_manager, AntiSpamManager
from automaintainer.discovery.opportunity_detectors import (
    DetectedOpportunity,
    GitHubActionsVersionDetector,
    BrokenDocLinkDetector,
    PackageMetadataDetector,
    DependencyMetadataDetector,
    LockfileOpportunityDetector,
    BaseDetector,
)
from automaintainer.discovery.opportunity_scorer import OpportunityScorer, ThresholdDecision
from automaintainer.discovery.repo_fingerprint import RepositoryFingerprinter
from automaintainer.discovery.repo_health import RepositoryHealthScorer
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import (
    RepositoryRecord,
    OpportunityRecord,
    SessionRecord,
    TaskRecord,
    OutboxRecord,
    InstallationRecord,
)
from automaintainer.core.models import SessionState
from automaintainer.queue.redis_queue import get_partitioned_queue, PartitionedLeasedQueue

logger = logging.getLogger("automaintainer.managed_repos")


def normalize_repo_identifier(raw_entry: str) -> Optional[str]:
    """
    Normalizes a repository line entry into standard 'owner/repo' format.
    Handles:
      - 'owner/repo'
      - 'https://github.com/owner/repo'
      - 'http://github.com/owner/repo'
      - 'git@github.com:owner/repo.git'
      - Trims whitespace and trailing '.git'
    Returns None if line is a comment (#), blank, or invalid.
    """
    line = raw_entry.strip()
    if not line or line.startswith("#"):
        return None

    # Strip URL prefixes
    line = re.sub(r"^https?://github\.com/", "", line, flags=re.IGNORECASE)
    line = re.sub(r"^git@github\.com:", "", line, flags=re.IGNORECASE)

    # Strip .git suffix and trailing slash
    line = re.sub(r"\.git/?$", "", line, flags=re.IGNORECASE).rstrip("/")

    parts = line.split("/")
    if len(parts) == 2 and parts[0].strip() and parts[1].strip():
        return f"{parts[0].strip().lower()}/{parts[1].strip().lower()}"

    return None


def parse_managed_repos_file(file_path: str) -> List[str]:
    """
    Reads the managed repositories file (YAML or plaintext) and returns a list of unique 'owner/repo' names.
    Supports:
      - YAML format (e.g. config/managed_repositories.yaml):
          repositories:
            - owner/repo
            - name: owner/repo
              enabled: true
      - Plaintext line-by-line format.
    """
    resolved_path = file_path
    default_file = get_settings().MANAGED_REPOSITORIES_FILE
    if not os.path.exists(resolved_path) and (not file_path or os.path.basename(file_path) == os.path.basename(default_file)):
        fallbacks = [
            os.path.join("config", "managed_repositories.yaml"),
            os.path.join("config", "managed_repositories.yml"),
            os.path.join("config", "managed_repositories.txt"),
            "managed_repositories.yaml",
            "managed_repositories.txt",
        ]
        for fb in fallbacks:
            if os.path.exists(fb):
                resolved_path = fb
                break

    if not os.path.exists(resolved_path):
        default_file = get_settings().MANAGED_REPOSITORIES_FILE
        if os.path.abspath(file_path) == os.path.abspath(default_file) or os.path.basename(file_path) == os.path.basename(default_file):
            try:
                parent_dir = os.path.dirname(file_path)
                if parent_dir:
                    os.makedirs(parent_dir, exist_ok=True)
                starter_content = "version: \"1.0\"\n\nrepositories:\n  # - owner/repository\n"
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(starter_content)
                logger.info(f"Created template managed repositories file at '{file_path}'")
            except Exception as e:
                logger.warning(f"Could not create starter managed repositories file '{file_path}': {e}")
        return []

    repos: List[str] = []
    seen: Set[str] = set()

    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            raw_content = f.read()

        parsed_yaml = None
        if resolved_path.endswith((".yaml", ".yml")) or "repositories:" in raw_content:
            try:
                import yaml
                parsed_yaml = yaml.safe_load(raw_content)
            except Exception as y_err:
                logger.debug(f"YAML parse fallback to line reader for '{resolved_path}': {y_err}")

        if isinstance(parsed_yaml, dict) and "repositories" in parsed_yaml:
            entries = parsed_yaml.get("repositories") or []
            for item in entries:
                raw_identifier = None
                if isinstance(item, str):
                    raw_identifier = item
                elif isinstance(item, dict):
                    if item.get("enabled", True) is not False:
                        raw_identifier = item.get("name") or item.get("repo") or item.get("url")
                if raw_identifier:
                    normalized = normalize_repo_identifier(str(raw_identifier))
                    if normalized and normalized not in seen:
                        seen.add(normalized)
                        repos.append(normalized)
        elif isinstance(parsed_yaml, list):
            for item in parsed_yaml:
                if isinstance(item, str):
                    normalized = normalize_repo_identifier(item)
                    if normalized and normalized not in seen:
                        seen.add(normalized)
                        repos.append(normalized)
        else:
            for line in raw_content.splitlines():
                normalized = normalize_repo_identifier(line)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    repos.append(normalized)
    except Exception as e:
        logger.error(f"Error reading managed repositories file '{resolved_path}': {e}")

    return repos


def is_repo_managed(repo_full_name: str, file_path: Optional[str] = None) -> bool:
    """Checks whether a repository is in the operator's managed repositories file."""
    try:
        path = file_path or get_settings().MANAGED_REPOSITORIES_FILE
        repos = parse_managed_repos_file(path)
        normalized = normalize_repo_identifier(repo_full_name)
        return (normalized in repos) if normalized else False
    except Exception:
        return False


def add_managed_repository(repo_identifier: str, file_path: Optional[str] = None) -> bool:
    """
    Appends a new repository identifier to the managed repositories file if not already present.
    Returns True if newly added, False if already registered.
    """
    normalized = normalize_repo_identifier(repo_identifier)
    if not normalized:
        raise ValueError(f"Invalid repository identifier: {repo_identifier}")

    settings = get_settings()
    target_path = file_path or settings.MANAGED_REPOSITORIES_FILE
    if not os.path.exists(target_path):
        parent_dir = os.path.dirname(target_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(f"version: \"1.0\"\n\nrepositories:\n  - {normalized}\n")
        return True

    existing = parse_managed_repos_file(target_path)
    if normalized.lower() in [r.lower() for r in existing]:
        return False

    with open(target_path, "r", encoding="utf-8") as f:
        content = f.read()

    if "repositories:" in content:
        updated = content.rstrip() + f"\n  - {normalized}\n"
    else:
        updated = content.rstrip() + f"\n\nrepositories:\n  - {normalized}\n"

    with open(target_path, "w", encoding="utf-8") as f:
        f.write(updated)
    return True


class ManagedRepoService:
    """
    Autonomous engine that monitors and maintains repositories specified in the managed file.
    Runs every 20 seconds, verifies safety constraints, scans for maintenance opportunities,
    and enqueues sessions for the worker daemon.
    """

    def __init__(
        self,
        file_path: Optional[str] = None,
        poll_interval: Optional[int] = None,
        token: Optional[str] = None,
        api_base_url: Optional[str] = None,
        anti_spam: Optional[AntiSpamManager] = None,
        queue: Optional[PartitionedLeasedQueue] = None,
    ):
        settings = get_settings()
        self.file_path = file_path or settings.MANAGED_REPOSITORIES_FILE
        self.poll_interval = poll_interval or settings.MANAGED_REPOSITORIES_POLL_INTERVAL
        self.token = token if token is not None else (settings.GITHUB_TOKEN or "")
        self.api_base_url = (api_base_url or settings.GITHUB_API_BASE_URL).rstrip("/")
        self.anti_spam = anti_spam or get_anti_spam_manager()
        self.queue = queue or get_partitioned_queue()
        self.scorer = OpportunityScorer()
        self.fingerprinter = RepositoryFingerprinter(api_base_url=self.api_base_url)
        self.health_scorer = RepositoryHealthScorer(api_base_url=self.api_base_url)

        self.detectors: List[BaseDetector] = [
            GitHubActionsVersionDetector(api_base_url=self.api_base_url),
            BrokenDocLinkDetector(api_base_url=self.api_base_url),
            PackageMetadataDetector(api_base_url=self.api_base_url),
            DependencyMetadataDetector(api_base_url=self.api_base_url),
            LockfileOpportunityDetector(api_base_url=self.api_base_url),
        ]

        # In-memory throttle to rescan each managed repo at most once every 15 minutes unless new
        self._last_scan_timestamp: Dict[str, float] = {}

    async def fetch_repo_metadata(
        self,
        owner: str,
        repo: str,
        client: httpx.AsyncClient,
        token: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Queries GitHub API for repository metadata."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        tok = token if token is not None else self.token
        if tok:
            headers["Authorization"] = f"Bearer {tok}"

        url = f"{self.api_base_url}/repos/{owner}/{repo}"
        try:
            resp = await client.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                logger.warning(f"Managed repository '{owner}/{repo}' not found on GitHub (HTTP 404).")
                return None
            elif resp.status_code == 403:
                err_msg = resp.text[:200]
                try:
                    err_msg = resp.json().get("message", err_msg)
                except Exception:
                    pass
                logger.warning(
                    f"GitHub returned HTTP 403 for '{owner}/{repo}': {err_msg}. "
                    "Unauthenticated cloud queries hit GitHub's 60 req/hr IP rate limit. "
                    "To fix, install the GitHub App on this repo or set GITHUB_TOKEN in environment."
                )
                return None
            else:
                logger.warning(f"GitHub returned HTTP {resp.status_code} when querying '{owner}/{repo}'.")
                return None
        except Exception as e:
            logger.warning(f"Network error querying '{owner}/{repo}': {e}")
            return None

    async def scan_repo_opportunities(
        self,
        owner: str,
        repo: str,
        client: httpx.AsyncClient,
        token: Optional[str] = None,
    ) -> List[DetectedOpportunity]:
        """Runs detectors against the given repository."""
        tok = token if token is not None else self.token
        opportunities: List[DetectedOpportunity] = []
        for detector in self.detectors:
            try:
                found = await detector.detect(owner=owner, repo=repo, token=tok, client=client)
                opportunities.extend(found)
            except Exception as e:
                logger.warning(f"Detector {detector.__class__.__name__} failed on {owner}/{repo}: {e}")
        return opportunities

    async def process_repository(
        self,
        full_name: str,
        client: httpx.AsyncClient,
        force_rescan: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Processes a single repository from the managed file:
        Checks anti-spam rules -> Fetches metadata -> Detects -> Scores -> Persists & Enqueues.
        """
        now = time.time()
        last_scanned = self._last_scan_timestamp.get(full_name, 0.0)
        # Respect configured poll interval (default 20s)
        min_rescan = max(20.0, float(self.poll_interval))
        if not force_rescan and (now - last_scanned < min_rescan):
            return []

        owner, repo = full_name.split("/", 1)
        token_to_use = self.token
        discovered_inst_id: Optional[int] = None
        settings = get_settings()
        if not token_to_use and settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY:
            try:
                from automaintainer.github.auth import InstallationTokenBroker
                broker = InstallationTokenBroker(settings)
                app_jwt = broker.generate_app_jwt()
                inst_resp = await client.get(
                    f"{self.api_base_url}/repos/{full_name}/installation",
                    headers={
                        "Authorization": f"Bearer {app_jwt}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    timeout=10.0
                )
                logger.info(f"Installation lookup for {full_name} status: {inst_resp.status_code}")
                if inst_resp.status_code == 200:
                    inst_id = inst_resp.json().get("id")
                    try:
                        token_to_use = await broker.get_installation_token(inst_id)
                        discovered_inst_id = inst_id
                        logger.info(f"Minted token for managed repo {full_name}")
                    except Exception as tok_err:
                        logger.warning(f"Could not mint installation token for {full_name} ({inst_id}): {tok_err}. Falling back to GITHUB_TOKEN.")
                        token_to_use = None
                        discovered_inst_id = None
                elif inst_resp.status_code == 404:
                    logger.info(f"GitHub App is not installed on '{full_name}'. Falling back to GITHUB_TOKEN.")
            except Exception as e:
                logger.debug(f"Could not mint installation token for {full_name}: {e}")

        if not token_to_use and settings.GITHUB_TOKEN:
            token_to_use = settings.GITHUB_TOKEN
            logger.info(f"Using GITHUB_TOKEN fallback for scanning uninstalled repo '{full_name}'.")

        # Synchronize in-memory active PR tracking with GitHub live state
        try:
            sync_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
            if token_to_use:
                sync_headers["Authorization"] = f"Bearer {token_to_use}"
            pulls_resp = await client.get(
                f"{self.api_base_url}/repos/{full_name}/pulls?state=open",
                headers=sync_headers,
                timeout=10.0
            )
            if pulls_resp.status_code == 200:
                open_prs = pulls_resp.json()
                open_numbers = {p["number"] for p in open_prs if isinstance(p, dict) and "number" in p}
                self.anti_spam.set_active_prs(full_name, open_numbers)
        except Exception as sync_err:
            logger.debug(f"Could not sync open PRs from GitHub for {full_name}: {sync_err}")

        # 1. Anti-spam check (cooldowns, active PR limits, hourly rate limits)
        is_managed = is_repo_managed(full_name, file_path=self.file_path)
        can_open, reason = self.anti_spam.can_open_pr(full_name, is_managed=is_managed)
        if not can_open:
            logger.info(f"Skipping managed repository '{full_name}': {reason}")
            self._last_scan_timestamp[full_name] = now
            return []

        repo_data = await self.fetch_repo_metadata(owner, repo, client, token=token_to_use)
        if not repo_data:
            self._last_scan_timestamp[full_name] = now
            return []

        if repo_data.get("archived", False) or repo_data.get("disabled", False):
            logger.info(f"Skipping '{full_name}': repository is archived or disabled.")
            self._last_scan_timestamp[full_name] = now
            return []

        # Update last scanned timestamp
        self._last_scan_timestamp[full_name] = now

        # 2. Score health
        try:
            health_score = await self.health_scorer.score(owner, repo, token_to_use, client=client)
        except Exception as e:
            logger.warning(f"Health score calculation failed for '{full_name}': {e}")
            return []

        # 3. Detect opportunities
        detected = await self.scan_repo_opportunities(owner, repo, client, token=token_to_use)
        if not detected:
            logger.debug(f"No maintenance opportunities detected for '{full_name}'.")
            return []

        admitted_sessions: List[Dict[str, Any]] = []
        repo_id = repo_data.get("id", 1000)
        repo_url = repo_data.get("clone_url", f"https://github.com/{full_name}.git")

        db_mgr = get_db_manager()
        async with db_mgr.get_session() as db:
            # Ensure InstallationRecord exists if we discovered an installation_id
            db_installation_id = None
            if discovered_inst_id:
                inst_stmt = select(InstallationRecord).where(InstallationRecord.github_installation_id == discovered_inst_id)
                inst_res = await db.execute(inst_stmt)
                inst_rec = inst_res.scalars().first()
                if not inst_rec:
                    owner_dict = repo_data.get("owner") or {}
                    owner_id = owner_dict.get("id", 1)
                    target_type = "user" if owner_dict.get("type") == "User" else "organization"
                    inst_rec = InstallationRecord(
                        github_installation_id=discovered_inst_id,
                        account_id=owner_id,
                        target_type=target_type,
                        status="active"
                    )
                    db.add(inst_rec)
                    await db.flush()
                else:
                    inst_rec.status = "active"
                    await db.flush()
                db_installation_id = inst_rec.id

            # Ensure RepositoryRecord exists and reflects the live installation state
            repo_stmt = select(RepositoryRecord).where(RepositoryRecord.github_repo_id == repo_id)
            res = await db.execute(repo_stmt)
            repo_record = res.scalars().first()
            if not repo_record:
                repo_record = RepositoryRecord(
                    github_repo_id=repo_id,
                    owner=owner,
                    name=repo,
                    installation_id=db_installation_id,
                    visibility="public" if not repo_data.get("private", False) else "private",
                    default_branch=repo_data.get("default_branch", "main"),
                )
                db.add(repo_record)
                await db.flush()
            else:
                # Live sync: if GitHub App is installed, bind it. If uninstalled on GitHub, clear it.
                repo_record.installation_id = db_installation_id
                await db.flush()

            internal_repo_id = repo_record.id

            for opp in detected:
                scored = self.scorer.score(opp, health_score)
                normalized_score = scored.opportunity_score * 100.0

                if normalized_score >= 80.0 or scored.threshold_decision == ThresholdDecision.ALLOW_AUTONOMOUS:
                    session_id = f"sess_managed_{uuid.uuid4().hex[:12]}"
                    opp_id = f"opp_{uuid.uuid4().hex[:12]}"

                    payload = {
                        "session_id": session_id,
                        "repository": full_name,
                        "repo_url": repo_url,
                        "opportunity_id": opp_id,
                        "target_paths": opp.target_paths,
                        "task_type": opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                        "score": normalized_score,
                        "metadata": opp.metadata or {},
                    }

                    opp_rec = OpportunityRecord(
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
                        status="admitted",
                    )
                    db.add(opp_rec)

                    sess_rec = SessionRecord(
                        id=session_id,
                        repository_id=internal_repo_id,
                        mode="managed",
                        state=SessionState.DISCOVERED.value,
                        version=1,
                        risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                        opportunity_score=normalized_score,
                    )
                    db.add(sess_rec)

                    task_rec = TaskRecord(
                        id=f"task_{uuid.uuid4().hex[:12]}",
                        session_id=session_id,
                        task_type=opp.task_type.value if hasattr(opp.task_type, "value") else str(opp.task_type),
                        scope="managed_maintenance",
                        evidence_json=opp.evidence,
                        confidence=opp.confidence,
                        risk_tier=opp.risk_tier.value if hasattr(opp.risk_tier, "value") else str(opp.risk_tier),
                        status="pending",
                    )
                    db.add(task_rec)

                    outbox_rec = OutboxRecord(
                        id=f"outbox_{uuid.uuid4().hex[:12]}",
                        queue_name="discovery",
                        session_id=session_id,
                        task_type="managed_discovery_analysis",
                        payload_json=payload,
                        status="pending",
                    )
                    db.add(outbox_rec)
                    await db.commit()

                    # Enqueue into discovery worker queue
                    try:
                        self.queue.enqueue(
                            queue_name="discovery",
                            session_id=session_id,
                            task_type="managed_discovery_analysis",
                            payload=payload,
                        )
                        outbox_rec.status = "dispatched"
                        outbox_rec.dispatched_at = datetime.now(timezone.utc)
                        await db.commit()
                        logger.info(f"Successfully enqueued maintenance session '{session_id}' for '{full_name}'")
                    except Exception as q_err:
                        logger.error(f"Failed to enqueue managed session for {full_name}: {q_err}")

                    admitted_sessions.append(payload)
                    # Enqueue only the top opportunity per run to respect the 1-active-PR policy
                    break

        return admitted_sessions

    async def poll_once(self, client: Optional[httpx.AsyncClient] = None, force_rescan: bool = False) -> List[Dict[str, Any]]:
        """
        Reads managed_repositories file and processes all listed repositories.
        """
        managed_repos = parse_managed_repos_file(self.file_path)
        if not managed_repos:
            return []

        results: List[Dict[str, Any]] = []
        if client:
            for repo in managed_repos:
                admitted = await self.process_repository(repo, client=client, force_rescan=force_rescan)
                results.extend(admitted)
        else:
            async with httpx.AsyncClient() as new_client:
                for repo in managed_repos:
                    admitted = await self.process_repository(repo, client=new_client, force_rescan=force_rescan)
                    results.extend(admitted)

        return results

    async def scan_once(self, client: Optional[httpx.AsyncClient] = None, force_rescan: bool = False) -> List[Dict[str, Any]]:
        """Alias for poll_once."""
        return await self.poll_once(client=client, force_rescan=force_rescan)


async def background_managed_repos_loop():
    """
    Continuous background loop that monitors managed_repositories.txt every 20 seconds.
    """
    settings = get_settings()
    service = ManagedRepoService(
        file_path=settings.MANAGED_REPOSITORIES_FILE,
        poll_interval=settings.MANAGED_REPOSITORIES_POLL_INTERVAL,
    )
    interval = max(5, service.poll_interval)
    logger.info(f"Managed repositories watcher loop started (polling '{service.file_path}' every {interval}s)")

    while True:
        try:
            await service.poll_once()
        except asyncio.CancelledError:
            logger.info("Managed repositories watcher loop cancelled.")
            break
        except Exception as e:
            logger.error(f"Error in managed repositories watcher loop: {e}", exc_info=True)

        await asyncio.sleep(interval)
