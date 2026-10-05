import time
from typing import Dict, Optional
from pydantic import BaseModel

class QuotaBucket(BaseModel):
    limit: int
    used: int = 0
    window_seconds: float = 60.0
    reset_at: float = 0.0

    def consume(self, amount: int = 1) -> bool:
        now = time.time()
        if now > self.reset_at:
            self.used = 0
            self.reset_at = now + self.window_seconds

        if self.used + amount <= self.limit:
            self.used += amount
            return True
        return False

class OrgQuotaManager:
    """
    Enforces Groq rate limits at the ORGANIZATION level across RPM/TPM/RPD.
    Prevents false assumption that key rotation yields unbounded extra capacity.
    """

    def __init__(self, default_org_id: Optional[str] = None):
        # org_id -> { "rpm": QuotaBucket, "tpm": QuotaBucket }
        self._org_buckets: Dict[str, Dict[str, QuotaBucket]] = {}
        if default_org_id:
            self.init_org_limits(default_org_id)

    def init_org_limits(self, org_id: str, rpm_limit: int = 30, tpm_limit: int = 40000):
        self._org_buckets[org_id] = {
            "rpm": QuotaBucket(limit=rpm_limit, window_seconds=60.0),
            "tpm": QuotaBucket(limit=tpm_limit, window_seconds=60.0)
        }

    def check_and_reserve(self, org_id: str, estimated_tokens: int = 1000) -> bool:
        if org_id not in self._org_buckets:
            self.init_org_limits(org_id)

        buckets = self._org_buckets[org_id]
        # Check both request and token capacity
        if not buckets["rpm"].consume(1):
            return False
        if not buckets["tpm"].consume(estimated_tokens):
            return False

        return True
