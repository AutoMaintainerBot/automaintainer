from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy import select, update, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from automaintainer.data.tables import OutboxRecord, utc_now
from automaintainer.data.database import get_db_manager
from automaintainer.queue.redis_queue import PartitionedLeasedQueue, get_partitioned_queue

logger = logging.getLogger("automaintainer.outbox")


class OutboxDispatcher:
    """
    Production-grade Transactional Outbox Dispatcher.
    Guarantees reliable, at-least-once message publication from relational database transactions
    into durable partitioned task queues / Redis streams with:
    - Row-level claim locks (FOR UPDATE SKIP LOCKED on PostgreSQL)
    - Lease-timeout crash recovery for orphaned / crashed workers
    - Bounded retries and Dead Letter status assignment
    - Clean deduplication and idempotency
    """

    def __init__(
        self,
        dispatcher_id: Optional[str] = None,
        queue: Optional[PartitionedLeasedQueue] = None,
        db_manager: Optional[DatabaseManager] = None,
        max_retries: int = 5,
        claim_timeout_seconds: float = 60.0,
    ):
        self.dispatcher_id = dispatcher_id or f"dispatcher_{uuid.uuid4().hex[:8]}"
        self.queue = queue or get_partitioned_queue()
        self.db_manager = db_manager
        self.max_retries = max_retries
        self.claim_timeout_seconds = claim_timeout_seconds
        self.running = False

    async def claim_and_dispatch_batch(self, batch_size: int = 50) -> int:
        """
        Claims a batch of pending or expired outbox messages and dispatches them to the queue.
        Returns the count of successfully dispatched messages.
        """
        db_mgr = self.db_manager or get_db_manager()
        now = utc_now()
        dispatched_count = 0

        async with db_mgr.get_session() as db:
            query = (
                select(OutboxRecord)
                .where(
                    or_(
                        OutboxRecord.status == "pending",
                        and_(
                            OutboxRecord.status == "claimed",
                            OutboxRecord.claim_expires_at < now,
                        ),
                    ),
                    OutboxRecord.retry_count < self.max_retries,
                )
                .order_by(OutboxRecord.created_at.asc())
                .limit(batch_size)
            )

            if not str(db_mgr.db_url).startswith("sqlite"):
                query = query.with_for_update(skip_locked=True)

            res = await db.execute(query)
            records = res.scalars().all()

            if not records:
                return 0

            claim_expiry = now + timedelta(seconds=self.claim_timeout_seconds)
            claimed_records: List[OutboxRecord] = []
            for rec in records:
                rec.status = "claimed"
                rec.claim_worker_id = self.dispatcher_id
                rec.claim_expires_at = claim_expiry
                claimed_records.append(rec)

            await db.commit()

            for rec in claimed_records:
                try:
                    self.queue.enqueue(
                        queue_name=rec.queue_name,
                        session_id=rec.session_id or f"outbox_sess_{rec.id}",
                        task_type=rec.task_type or "outbox_task",
                        payload=rec.payload_json or {},
                        dedupe_key=rec.idempotency_key or rec.id,
                    )
                    rec.status = "dispatched"
                    rec.dispatched_at = utc_now()
                    rec.error_message = None
                    dispatched_count += 1
                except Exception as exc:
                    rec.retry_count += 1
                    rec.error_message = str(exc)[:500]
                    if rec.retry_count >= self.max_retries:
                        rec.status = "dead_letter"
                        logger.error(
                            f"Outbox message {rec.id} exhausted {self.max_retries} retries; moved to dead_letter: {exc}"
                        )
                    else:
                        rec.status = "pending"
                        rec.claim_expires_at = None
                        logger.warning(
                            f"Outbox message {rec.id} failed dispatch (attempt {rec.retry_count}/{self.max_retries}): {exc}"
                        )

            await db.commit()

        return dispatched_count

    async def start(self, poll_interval: float = 1.0, max_iterations: Optional[int] = None):
        """Runs the continuous outbox polling & dispatch loop."""
        self.running = True
        iterations = 0
        logger.info(f"OutboxDispatcher {self.dispatcher_id} started (poll={poll_interval}s)")

        while self.running:
            if max_iterations is not None and iterations >= max_iterations:
                break
            iterations += 1

            try:
                dispatched = await self.claim_and_dispatch_batch(batch_size=50)
                if dispatched == 0:
                    await asyncio.sleep(poll_interval)
            except Exception as e:
                logger.error(f"Error in OutboxDispatcher loop: {e}", exc_info=True)
                await asyncio.sleep(poll_interval)

    def stop(self):
        self.running = False
