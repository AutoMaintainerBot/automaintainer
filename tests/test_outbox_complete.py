import asyncio
import uuid
from datetime import datetime, timezone, timedelta
import pytest
import pytest_asyncio
from sqlalchemy import select

from automaintainer.data.database import DatabaseManager
from automaintainer.data.tables import Base, OutboxRecord, utc_now
from automaintainer.core.outbox import OutboxDispatcher
from automaintainer.queue.redis_queue import PartitionedLeasedQueue

@pytest_asyncio.fixture
async def test_db_mgr(tmp_path):
    db_file = tmp_path / f"test_outbox_{uuid.uuid4().hex[:8]}.db"
    mgr = DatabaseManager(f"sqlite+aiosqlite:///{db_file}")
    await mgr.init_models()
    yield mgr
    await mgr.close()

@pytest.mark.asyncio
async def test_outbox_producer_and_dispatch_success(test_db_mgr):
    queue = PartitionedLeasedQueue()
    dispatcher = OutboxDispatcher(dispatcher_id="disp_1", queue=queue, db_manager=test_db_mgr)

    async with test_db_mgr.get_session() as db:
        msg = OutboxRecord(
            id=f"msg_{uuid.uuid4().hex[:8]}",
            idempotency_key="idemp_1",
            queue_name="maintenance",
            session_id="sess_100",
            task_type="patch",
            payload_json={"package": "requests", "version": "2.31.0"},
            status="pending"
        )
        db.add(msg)
        await db.commit()

    dispatched = await dispatcher.claim_and_dispatch_batch(batch_size=10)
    assert dispatched == 1

    async with test_db_mgr.get_session() as db:
        res = await db.execute(select(OutboxRecord).where(OutboxRecord.idempotency_key == "idemp_1"))
        record = res.scalar_one()
        assert record.status == "dispatched"
        assert record.dispatched_at is not None
        assert record.error_message is None

    job_res = queue.acquire_next_job("worker_1")
    assert job_res is not None
    q_name, job = job_res
    assert job.session_id == "sess_100"
    assert job.payload["package"] == "requests"

@pytest.mark.asyncio
async def test_outbox_claim_timeout_and_recovery(test_db_mgr):
    queue = PartitionedLeasedQueue()
    crashed_dispatcher = OutboxDispatcher(dispatcher_id="crashed_disp", queue=queue, db_manager=test_db_mgr, claim_timeout_seconds=0.1)
    healthy_dispatcher = OutboxDispatcher(dispatcher_id="healthy_disp", queue=queue, db_manager=test_db_mgr)

    past_time = utc_now() - timedelta(seconds=10)
    async with test_db_mgr.get_session() as db:
        msg = OutboxRecord(
            id=f"msg_{uuid.uuid4().hex[:8]}",
            idempotency_key="idemp_expired",
            queue_name="maintenance",
            session_id="sess_200",
            task_type="patch",
            payload_json={"test": True},
            status="claimed",
            claim_worker_id="crashed_disp",
            claim_expires_at=past_time
        )
        db.add(msg)
        await db.commit()

    dispatched = await healthy_dispatcher.claim_and_dispatch_batch(batch_size=10)
    assert dispatched == 1

    async with test_db_mgr.get_session() as db:
        res = await db.execute(select(OutboxRecord).where(OutboxRecord.idempotency_key == "idemp_expired"))
        record = res.scalar_one()
        assert record.status == "dispatched"
        assert record.claim_worker_id == "healthy_disp"

@pytest.mark.asyncio
async def test_outbox_dead_letter_routing_after_retries(test_db_mgr):
    class FailingQueue:
        def enqueue(self, *args, **kwargs):
            raise ConnectionError("Queue unreachable")

    dispatcher = OutboxDispatcher(dispatcher_id="disp_fail", queue=FailingQueue(), db_manager=test_db_mgr, max_retries=2)

    async with test_db_mgr.get_session() as db:
        msg = OutboxRecord(
            id=f"msg_{uuid.uuid4().hex[:8]}",
            idempotency_key="idemp_poison",
            queue_name="maintenance",
            session_id="sess_poison",
            task_type="poison_task",
            payload_json={},
            status="pending",
            retry_count=0
        )
        db.add(msg)
        await db.commit()

    await dispatcher.claim_and_dispatch_batch(batch_size=10)
    async with test_db_mgr.get_session() as db:
        res = await db.execute(select(OutboxRecord).where(OutboxRecord.idempotency_key == "idemp_poison"))
        rec = res.scalar_one()
        assert rec.status == "pending"
        assert rec.retry_count == 1
        assert "Queue unreachable" in rec.error_message

    await dispatcher.claim_and_dispatch_batch(batch_size=10)
    async with test_db_mgr.get_session() as db:
        res = await db.execute(select(OutboxRecord).where(OutboxRecord.idempotency_key == "idemp_poison"))
        rec = res.scalar_one()
        assert rec.status == "dead_letter"
        assert rec.retry_count == 2
