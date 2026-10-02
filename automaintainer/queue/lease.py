from __future__ import annotations
import time
import uuid
from typing import Dict, Optional, List
from enum import Enum
from pydantic import BaseModel, Field

class JobStatus(str, Enum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"

class QueuedJob(BaseModel):
    job_id: str = Field(default_factory=lambda: f"job_{uuid.uuid4().hex[:12]}")
    session_id: str
    task_type: str
    payload: dict
    status: JobStatus = JobStatus.PENDING
    attempt: int = 0
    max_retries: int = 3
    lease_owner: Optional[str] = None
    leased_by: Optional[str] = None
    lease_expires_at: Optional[float] = None
    created_at: float = Field(default_factory=time.time)
    enqueued_at: float = Field(default_factory=time.time)
    dedupe_key: Optional[str] = None
    heartbeat_count: int = 0
    error_message: Optional[str] = None

class LeasedTaskQueue:
    """
    Durable Leased Task Queue:
    - Guarantees crash recoverability: if a worker dies, lease expires and job returns to PENDING.
    - Workers send heartbeats to renew leases.
    - Dead-letter handling on max retry exhaustion.
    """

    def __init__(self, default_lease_seconds: float = 30.0):
        self.default_lease_seconds = default_lease_seconds
        self._jobs: Dict[str, QueuedJob] = {}
        self._dedupe_index: Dict[str, str] = {}

    def enqueue(self, session_id: str, task_type: str, payload: dict, dedupe_key: Optional[str] = None) -> Optional[QueuedJob]:
        if dedupe_key and dedupe_key in self._dedupe_index:
            existing_job_id = self._dedupe_index[dedupe_key]
            existing_job = self._jobs.get(existing_job_id)
            if existing_job and existing_job.status in (JobStatus.DEAD_LETTER, JobStatus.FAILED):
                existing_job.status = JobStatus.PENDING
                existing_job.attempt = 0
                existing_job.lease_owner = None
                existing_job.lease_expires_at = None
                existing_job.error_message = None
                return existing_job
            return existing_job

        job = QueuedJob(
            session_id=session_id,
            task_type=task_type,
            payload=payload,
            dedupe_key=dedupe_key
        )
        self._jobs[job.job_id] = job
        if dedupe_key:
            self._dedupe_index[dedupe_key] = job.job_id
        return job

    def acquire_lease(self, worker_id: str) -> Optional[QueuedJob]:
        now = time.time()
        for job in self._jobs.values():
            # Check for PENDING or EXPIRED lease
            if job.status == JobStatus.PENDING or (
                job.status in [JobStatus.LEASED, JobStatus.RUNNING] and job.lease_expires_at and job.lease_expires_at < now
            ):
                if job.attempt >= job.max_retries:
                    job.status = JobStatus.DEAD_LETTER
                    continue

                job.status = JobStatus.LEASED
                job.lease_owner = worker_id
                job.lease_expires_at = now + self.default_lease_seconds
                job.attempt += 1
                return job
        return None

    def heartbeat(self, job_id: str, worker_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job and job.lease_owner == worker_id and job.status in [JobStatus.LEASED, JobStatus.RUNNING]:
            job.status = JobStatus.RUNNING
            job.lease_expires_at = time.time() + self.default_lease_seconds
            return True
        return False

    def complete(self, job_id: str, worker_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job and job.lease_owner == worker_id:
            job.status = JobStatus.SUCCEEDED
            job.lease_expires_at = None
            return True
        return False

    def fail(self, job_id: str, worker_id: str, error: str = "") -> bool:
        job = self._jobs.get(job_id)
        if job and job.lease_owner == worker_id:
            if job.attempt >= job.max_retries:
                job.status = JobStatus.DEAD_LETTER
            else:
                job.status = JobStatus.PENDING
            job.lease_owner = None
            job.lease_expires_at = None
            return True
        return False

    def get_dead_letters(self) -> List[QueuedJob]:
        return [job for job in self._jobs.values() if job.status in (JobStatus.DEAD_LETTER, JobStatus.FAILED)]

    def retry_dead_letters(self, job_id: Optional[str] = None) -> int:
        count = 0
        for j in self._jobs.values():
            if j.status in (JobStatus.DEAD_LETTER, JobStatus.FAILED):
                if job_id is None or j.job_id == job_id:
                    j.status = JobStatus.PENDING
                    j.attempt = 0
                    j.lease_owner = None
                    j.lease_expires_at = None
                    count += 1
        return count
