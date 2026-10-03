"""
Duplicate PR Checker.
Fingerprints a task by (repository_id + task_type + sorted target paths hash)
and checks the events/opportunities tables to prevent re-opening the same PR
within the configured cooldown window.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from automaintainer.data.tables import OpportunityRecord


def compute_task_fingerprint(repository_id: int, task_type: str, target_paths: List[str]) -> str:
    """
    SHA-256 fingerprint of (repository_id, task_type, sorted target paths).
    Identical tasks on the same repo produce the same fingerprint.
    """
    canonical = f"{repository_id}|{task_type}|{'|'.join(sorted(target_paths))}"
    return hashlib.sha256(canonical.encode()).hexdigest()


class DuplicatePRChecker:
    """
    Prevents opening duplicate PRs for the same maintenance task on the same repo.
    Checks the opportunities table for recently completed sessions with the same fingerprint.

    Cooldown window: 7 days by default (configurable).
    """

    def __init__(self, db: AsyncSession, cooldown_days: int = 7):
        self._db = db
        self._cooldown_days = cooldown_days

    async def is_duplicate(
        self,
        repository_id: int,
        task_type: str,
        target_paths: List[str],
    ) -> bool:
        """
        Returns True if a session_created opportunity with the same fingerprint
        exists within the cooldown window.
        """
        fingerprint = compute_task_fingerprint(repository_id, task_type, target_paths)
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._cooldown_days)

        # Check for recently created sessions with matching metadata
        stmt = select(OpportunityRecord).where(
            OpportunityRecord.repository_id == repository_id,
            OpportunityRecord.task_type == task_type,
            OpportunityRecord.status == "session_created",
            OpportunityRecord.detected_at >= cutoff,
        )
        result = await self._db.execute(stmt)
        candidates = result.scalars().all()

        for candidate in candidates:
            paths = candidate.target_paths_json or []
            candidate_fp = compute_task_fingerprint(repository_id, task_type, paths)
            if candidate_fp == fingerprint:
                return True
        return False

    async def check_or_raise(
        self,
        repository_id: int,
        task_type: str,
        target_paths: List[str],
    ) -> None:
        """Raises ValueError if a duplicate is detected."""
        if await self.is_duplicate(repository_id, task_type, target_paths):
            raise ValueError(
                f"Duplicate PR prevention: a session for task_type='{task_type}' "
                f"on repository {repository_id} targeting {target_paths} was already "
                f"created within the last {self._cooldown_days} days."
            )
