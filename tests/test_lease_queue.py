import time
import pytest
from automaintainer.queue.lease import LeasedTaskQueue, JobStatus

def test_leased_queue_crash_recovery():
    queue = LeasedTaskQueue(default_lease_seconds=0.2)
    queue.enqueue(session_id="sess_abc", task_type="analyze", payload={"repo": "owner/repo"})

    job1 = queue.acquire_lease(worker_id="worker_node_1")
    assert job1 is not None
    assert job1.status == JobStatus.LEASED
    assert job1.attempt == 1

    assert queue.acquire_lease(worker_id="worker_node_2") is None

    time.sleep(0.25)

    job2 = queue.acquire_lease(worker_id="worker_node_2")
    assert job2 is not None
    assert job2.job_id == job1.job_id
    assert job2.lease_owner == "worker_node_2"
    assert job2.attempt == 2

    assert queue.complete(job_id=job2.job_id, worker_id="worker_node_2") is True
    assert job2.status == JobStatus.SUCCEEDED
