import time
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from automaintainer.queue.lease import QueuedJob, JobStatus, LeasedTaskQueue

logger = logging.getLogger("automaintainer.queue")

class RedisStreamLeasedQueue:
    """
    Production Redis Streams Driver:
    - Uses Redis Streams with Consumer Groups (XGROUP, XADD, XREADGROUP, XACK, XAUTOCLAIM).
    - Ensures tasks are partitioned across multiple distributed worker containers.
    - Employs XAUTOCLAIM to recover tasks from crashed or stalled workers whose leases expired.
    """
    CONSUMER_GROUP = "automaintainer-workers"

    def __init__(self, redis_client, priority_queues: List[str], default_lease_seconds: float = 30.0):
        self.redis = redis_client
        self.priority_queues = priority_queues
        self.default_lease_seconds = default_lease_seconds
        self._init_consumer_groups()

    def _stream_key(self, queue_name: str) -> str:
        return f"automaintainer:stream:{queue_name}"

    def _lease_key(self, job_id: str) -> str:
        return f"automaintainer:lease:{job_id}"

    def _init_consumer_groups(self):
        for q in self.priority_queues:
            stream_key = self._stream_key(q)
            try:
                self.redis.xgroup_create(stream_key, self.CONSUMER_GROUP, id="0", mkstream=True)
            except Exception as e:
                # Group might already exist (BUSYGROUP)
                pass

    def enqueue(
        self,
        queue_name: str,
        session_id: str,
        task_type: str,
        payload: dict,
        dedupe_key: Optional[str] = None
    ) -> Optional[QueuedJob]:
        stream_key = self._stream_key(queue_name)
        job_id = f"{queue_name}_{session_id}_{int(time.time() * 1000)}"
        fields = {
            "job_id": job_id,
            "session_id": session_id,
            "task_type": task_type,
            "payload": json.dumps(payload),
            "dedupe_key": dedupe_key or "",
            "enqueued_at": str(time.time()),
        }
        msg_id = self.redis.xadd(stream_key, fields)
        msg_id_str = str(msg_id) if isinstance(msg_id, str) else msg_id.decode("utf-8")

        # Initialize authoritative job metadata hash
        meta_key = f"automaintainer:job_meta:{msg_id_str}"
        try:
            self.redis.hset(meta_key, "session_id", session_id)
            self.redis.hset(meta_key, "task_type", task_type)
            self.redis.hset(meta_key, "payload", json.dumps(payload))
            self.redis.hset(meta_key, "queue_name", queue_name)
            self.redis.hset(meta_key, "attempt", 0)
            self.redis.expire(meta_key, 86400)
        except Exception:
            pass

        return QueuedJob(
            job_id=msg_id_str,
            session_id=session_id,
            task_type=task_type,
            payload=payload,
            dedupe_key=dedupe_key,
            enqueued_at=time.time(),
            status=JobStatus.QUEUED,
            attempt=0
        )

    def acquire_next_job(self, worker_id: str) -> Optional[Tuple[str, QueuedJob]]:
        """
        Scans streams in priority order.
        1. Checks for expired/abandoned pending jobs using XAUTOCLAIM.
        2. Reads next unacknowledged job using XREADGROUP.
        """
        min_idle_ms = int(self.default_lease_seconds * 1000)

        for queue_name in self.priority_queues:
            stream_key = self._stream_key(queue_name)

            try:
                claim_res = self.redis.xautoclaim(
                    stream_key,
                    self.CONSUMER_GROUP,
                    worker_id,
                    min_idle_time=min_idle_ms,
                    start_id="0-0",
                    count=1
                )
                if claim_res and len(claim_res) > 1 and claim_res[1]:
                    messages = claim_res[1]
                    msg_id, data = messages[0]
                    job = self._parse_job(msg_id, data, worker_id)
                    if job:
                        return queue_name, job
            except Exception:
                pass

            try:
                entries = self.redis.xreadgroup(
                    groupname=self.CONSUMER_GROUP,
                    consumername=worker_id,
                    streams={stream_key: ">"},
                    count=1,
                    block=10
                )
                if entries:
                    stream_name, messages = entries[0]
                    if messages:
                        msg_id, data = messages[0]
                        job = self._parse_job(msg_id, data, worker_id)
                        if job:
                            return queue_name, job
            except Exception as e:
                logger.error(f"Error reading from Redis Stream {stream_key}: {e}")
                continue

        return None

    def _parse_job(self, msg_id, raw_data: dict, worker_id: str) -> Optional[QueuedJob]:
        data = {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in raw_data.items()
        }
        job_id_str = msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id)
        try:
            payload = json.loads(data.get("payload", "{}"))
        except Exception:
            payload = {}

        # Authoritative attempt count synchronization
        meta_key = f"automaintainer:job_meta:{job_id_str}"
        attempt = 0
        try:
            val = self.redis.hget(meta_key, "attempt")
            if val is not None:
                attempt = int(val.decode("utf-8") if isinstance(val, bytes) else val)
        except Exception:
            attempt = 0

        # Set lease in Redis
        lease_key = self._lease_key(job_id_str)
        self.redis.setex(lease_key, int(self.default_lease_seconds), worker_id)

        return QueuedJob(
            job_id=job_id_str,
            session_id=data.get("session_id", ""),
            task_type=data.get("task_type", ""),
            payload=payload,
            dedupe_key=data.get("dedupe_key") or None,
            enqueued_at=float(data.get("enqueued_at", time.time())),
            status=JobStatus.LEASED,
            leased_by=worker_id,
            lease_expires_at=time.time() + self.default_lease_seconds,
            heartbeat_count=1,
            attempt=attempt
        )

    HEARTBEAT_LUA = """
    local current = redis.call('get', KEYS[1])
    if current == ARGV[1] then
        redis.call('expire', KEYS[1], tonumber(ARGV[2]))
        return 1
    else
        return 0
    end
    """

    def heartbeat(self, queue_name: str, job_id: str, worker_id: str) -> bool:
        """Atomic Compare-And-Set lease heartbeat: only extends if current lease belongs to worker_id."""
        lease_key = self._lease_key(job_id)
        try:
            res = self.redis.eval(self.HEARTBEAT_LUA, 1, lease_key, worker_id, int(self.default_lease_seconds))
            return bool(res == 1)
        except Exception:
            # Fallback for client adapters without eval support
            val = self.redis.get(lease_key)
            if val is not None:
                decoded = val.decode("utf-8") if isinstance(val, bytes) else str(val)
                if decoded == worker_id:
                    self.redis.setex(lease_key, int(self.default_lease_seconds), worker_id)
                    return True
            return False

    def fail(self, queue_name: str, job_id: str, worker_id: str, error_message: str = "", max_retries: int = 3) -> bool:
        """
        Handles job failure in Redis stream:
        - If attempt < max_retries: releases lease so worker re-claim / retry can occur.
        - If attempt >= max_retries: moves job to DEAD_LETTER stream and XACKs from active queue.
        """
        lease_key = self._lease_key(job_id)
        val = self.redis.get(lease_key)
        if val is not None:
            decoded = val.decode("utf-8") if isinstance(val, bytes) else str(val)
            if decoded != worker_id:
                return False

        meta_key = f"automaintainer:job_meta:{job_id}"
        session_id = ""
        task_type = ""
        payload_str = "{}"
        try:
            attempt = self.redis.hincrby(meta_key, "attempt", 1)
            self.redis.hset(meta_key, "last_error", error_message or "Unknown error")
            self.redis.hset(meta_key, "queue_name", queue_name)
            s_val = self.redis.hget(meta_key, "session_id")
            session_id = s_val.decode("utf-8") if isinstance(s_val, bytes) else str(s_val or "")
            t_val = self.redis.hget(meta_key, "task_type")
            task_type = t_val.decode("utf-8") if isinstance(t_val, bytes) else str(t_val or "")
            p_val = self.redis.hget(meta_key, "payload")
            payload_str = p_val.decode("utf-8") if isinstance(p_val, bytes) else str(p_val or "{}")
            self.redis.expire(meta_key, 86400)
        except Exception:
            attempt = 1

        stream_key = self._stream_key(queue_name)
        if attempt >= max_retries:
            # Reached max retries -> route to Dead-Letter Queue
            dl_stream = "automaintainer:stream:dead_letters"
            try:
                self.redis.xadd(dl_stream, {
                    "job_id": job_id,
                    "queue_name": queue_name,
                    "session_id": session_id,
                    "task_type": task_type,
                    "payload": payload_str,
                    "worker_id": worker_id,
                    "error": error_message,
                    "attempt": str(attempt),
                    "dead_lettered_at": str(time.time()),
                })
            except Exception as e:
                logger.error(f"Failed to write to dead-letter stream: {e}")

            # XACK and purge lease to remove from active processing
            try:
                self.redis.xack(stream_key, self.CONSUMER_GROUP, job_id)
            except Exception:
                pass
            self.redis.delete(lease_key)
            return True
        else:
            # Under retry limit: release lease so job can be reclaimed by XAUTOCLAIM / next worker
            self.redis.delete(lease_key)
            return True

    def ack(self, queue_name: str, job_id: str) -> bool:
        stream_key = self._stream_key(queue_name)
        lease_key = self._lease_key(job_id)
        self.redis.xack(stream_key, self.CONSUMER_GROUP, job_id)
        self.redis.delete(lease_key)
        return True

class PartitionedLeasedQueue:
    """
    Dedicated partitioned priority queues:
      - github-write (Highest, strictly rate-limited)
      - conversation (Highest, human-facing)
      - patch (High)
      - validation (High)
      - cleanup (High)
      - analysis (Medium)
      - discovery (Low)
    """

    PRIORITY_ORDER = [
        "github-write",
        "conversation",
        "patch",
        "validation",
        "cleanup",
        "analysis",
        "discovery"
    ]

    def __init__(self, default_lease_seconds: float = 30.0, redis_client=None):
        self.default_lease_seconds = default_lease_seconds
        self.redis_client = redis_client
        self.redis_stream_driver: Optional[RedisStreamLeasedQueue] = None

        if self.redis_client:
            try:
                self.redis_stream_driver = RedisStreamLeasedQueue(
                    redis_client=self.redis_client,
                    priority_queues=self.PRIORITY_ORDER,
                    default_lease_seconds=default_lease_seconds
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Redis Stream driver, using in-memory fallback: {e}")

        # In-memory queues (used if redis driver is not configured or fails)
        self.queues: Dict[str, LeasedTaskQueue] = {
            name: LeasedTaskQueue(default_lease_seconds=default_lease_seconds)
            for name in self.PRIORITY_ORDER
        }

    def enqueue(self, queue_name: str, session_id: str, task_type: str, payload: dict, dedupe_key: Optional[str] = None) -> Optional[QueuedJob]:
        if self.redis_stream_driver:
            return self.redis_stream_driver.enqueue(queue_name, session_id, task_type, payload, dedupe_key)
        target_queue = self.queues.get(queue_name, self.queues["analysis"])
        return target_queue.enqueue(session_id=session_id, task_type=task_type, payload=payload, dedupe_key=dedupe_key)

    def acquire_next_job(self, worker_id: str) -> Optional[Tuple[str, QueuedJob]]:
        if self.redis_stream_driver:
            return self.redis_stream_driver.acquire_next_job(worker_id)
        for queue_name in self.PRIORITY_ORDER:
            q = self.queues[queue_name]
            job = q.acquire_lease(worker_id=worker_id)
            if job:
                return queue_name, job
        return None

    def complete(self, queue_name: str, job_id: str, worker_id: str) -> bool:
        if self.redis_stream_driver:
            return self.redis_stream_driver.ack(queue_name, job_id)
        if queue_name in self.queues:
            return self.queues[queue_name].complete(job_id, worker_id)
        return False

    def fail(self, queue_name: str, job_id: str, worker_id: str, error_message: str = "") -> bool:
        if self.redis_stream_driver:
            return self.redis_stream_driver.fail(queue_name, job_id, worker_id, error_message)
        if queue_name in self.queues:
            return self.queues[queue_name].fail(job_id, worker_id, error_message)
        return False

    def heartbeat(self, queue_name: str, job_id: str, worker_id: str) -> bool:
        if self.redis_stream_driver:
            return self.redis_stream_driver.heartbeat(queue_name, job_id, worker_id)
        if queue_name in self.queues:
            return self.queues[queue_name].heartbeat(job_id, worker_id)
        return False

    def ack(self, queue_name: str, job_id: str) -> bool:
        if self.redis_stream_driver:
            return self.redis_stream_driver.ack(queue_name, job_id)
        return True

    def get_dead_letters(self) -> List[Dict[str, Any]]:
        """Collects all dead-lettered or failed jobs across partitioned queues (in-memory + Redis stream)."""
        results = []
        # In-memory dead letters
        for q_name, q in self.queues.items():
            for job in q.get_dead_letters():
                results.append({
                    "queue_name": q_name,
                    "job_id": job.job_id,
                    "session_id": job.session_id,
                    "task_type": job.task_type,
                    "status": job.status.value if hasattr(job.status, "value") else str(job.status),
                    "attempt": job.attempt,
                    "max_retries": job.max_retries,
                    "enqueued_at": job.enqueued_at,
                    "payload": job.payload,
                })

        # Redis dead-letter stream
        if self.redis_stream_driver and hasattr(self.redis_stream_driver, "redis") and self.redis_stream_driver.redis:
            try:
                dl_entries = self.redis_stream_driver.redis.xrange("automaintainer:stream:dead_letters", count=100)
                for entry_id, data in dl_entries:
                    parsed = {
                        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                        for k, v in data.items()
                    }
                    results.append({
                        "queue_name": parsed.get("queue_name", "unknown"),
                        "job_id": parsed.get("job_id", str(entry_id)),
                        "session_id": parsed.get("session_id", ""),
                        "task_type": parsed.get("task_type", "dead_letter"),
                        "status": "DEAD_LETTER",
                        "attempt": int(parsed.get("attempt", 3)),
                        "max_retries": 3,
                        "enqueued_at": float(parsed.get("dead_lettered_at", time.time())),
                        "payload": {"error": parsed.get("error", "")},
                    })
            except Exception as dl_err:
                logger.debug(f"Could not read Redis dead-letter stream: {dl_err}")

        return results

    def retry_dead_letters(self, job_id: Optional[str] = None, queue_name: Optional[str] = None) -> int:
        """Resets dead-lettered jobs to PENDING/QUEUED across in-memory and Redis stream."""
        retried = 0
        for q_name, q in self.queues.items():
            if queue_name is None or q_name == queue_name:
                retried += q.retry_dead_letters(job_id=job_id)

        if self.redis_stream_driver and hasattr(self.redis_stream_driver, "redis") and self.redis_stream_driver.redis:
            try:
                dl_entries = self.redis_stream_driver.redis.xrange("automaintainer:stream:dead_letters", count=100)
                for entry_id, data in dl_entries:
                    parsed = {
                        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                        for k, v in data.items()
                    }
                    target_jid = parsed.get("job_id", str(entry_id))
                    target_q = parsed.get("queue_name", "analysis")
                    if job_id is not None and target_jid != job_id:
                        continue
                    if queue_name is not None and target_q != queue_name:
                        continue

                    try:
                        payload = json.loads(parsed.get("payload", "{}"))
                    except Exception:
                        payload = {}

                    # Re-enqueue back to target active queue
                    self.redis_stream_driver.enqueue(
                        queue_name=target_q,
                        session_id=parsed.get("session_id", ""),
                        task_type=parsed.get("task_type", ""),
                        payload=payload
                    )
                    # Delete from dead-letter stream
                    self.redis_stream_driver.redis.xdel("automaintainer:stream:dead_letters", entry_id)
                    # Reset attempt metadata
                    meta_key = f"automaintainer:job_meta:{target_jid}"
                    self.redis_stream_driver.redis.delete(meta_key)
                    retried += 1
            except Exception as e:
                logger.error(f"Error replaying Redis dead-letter stream: {e}")

        return retried

_partitioned_queue: Optional[PartitionedLeasedQueue] = None
def get_partitioned_queue() -> PartitionedLeasedQueue:
    global _partitioned_queue
    if _partitioned_queue is None:
        from automaintainer.config import get_settings
        settings = get_settings()
        redis_client = None

        if settings.QUEUE_BACKEND == "redis":
            if not settings.REDIS_URL and not settings.ALLOW_IN_MEMORY_QUEUE:
                raise RuntimeError("FATAL: QUEUE_BACKEND is configured as 'redis' but REDIS_URL is not set. In-memory fallback is disabled in this environment.")
            if settings.REDIS_URL:
                try:
                    import redis
                    redis_client = redis.from_url(settings.REDIS_URL)
                    redis_client.ping()
                except Exception as e:
                    if not settings.ALLOW_IN_MEMORY_QUEUE:
                        raise RuntimeError(f"FATAL: Redis queue connection to {settings.REDIS_URL} failed ({e}). In-memory fallback is disabled. Refusing to start in unsafe state.") from e
                    logger.warning(f"Could not connect to Redis at {settings.REDIS_URL}: {e}. Falling back to in-memory queue per configuration.")

        _partitioned_queue = PartitionedLeasedQueue(redis_client=redis_client)
    return _partitioned_queue
