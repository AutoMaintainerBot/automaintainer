import time
from typing import Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field

class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DRAINING = "DRAINING"
    REVOKED = "REVOKED"
    QUARANTINED = "QUARANTINED"

class ProviderKeyRecord(BaseModel):
    """
    Metadata and rolling runtime metrics for an LLM provider API key (Groq, Cerebras, Google).
    Key pooling provides credential hygiene, automatic key rotation on 429/failures, and multi-provider failover.
    """
    key_id: str
    provider: str = "groq"  # "groq" | "cerebras" | "google"
    organization_id: str = "default_org"
    project_id: str = "default"
    secret_ref: str
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: float = Field(default_factory=time.time)
    last_success_at: Optional[float] = None
    last_failure_at: Optional[float] = None
    error_count: int = 0
    total_requests: int = 0
    recent_429_count: int = 0
    recent_5xx_count: int = 0
    in_flight_requests: int = 0
    latency_samples: List[float] = Field(default_factory=list)
    remaining_requests: Optional[int] = None
    remaining_tokens: Optional[int] = None
    reset_time: Optional[float] = None
    canary_weight: float = 1.0  # 1.0 = normal production, 0.1 = canary rollout

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_count / self.total_requests

    @property
    def p95_latency_ms(self) -> float:
        if not self.latency_samples:
            return 150.0
        s = sorted(self.latency_samples)
        idx = int(0.95 * len(s))
        return s[min(idx, len(s) - 1)]

    @property
    def p50_latency_ms(self) -> float:
        if not self.latency_samples:
            return 100.0
        s = sorted(self.latency_samples)
        return s[len(s) // 2]

    def update_rate_limits(
        self,
        remaining_requests: Optional[int] = None,
        remaining_tokens: Optional[int] = None,
        reset_time: Optional[float] = None
    ) -> None:
        if remaining_requests is not None:
            self.remaining_requests = remaining_requests
        if remaining_tokens is not None:
            self.remaining_tokens = remaining_tokens
        if reset_time is not None:
            self.reset_time = reset_time

    def calculate_score(self) -> float:
        """
        Routing score based on verified provider health, remaining tokens/requests,
        true p95 latency, in-flight concurrency load, and canary state.
        """
        # If reset time passed or cooldown elapsed, recover draining status
        now = time.time()
        if self.status == KeyStatus.DRAINING:
            if (self.reset_time and now > self.reset_time) or (not self.reset_time and self.last_failure_at and (now - self.last_failure_at > 60.0)):
                self.status = KeyStatus.ACTIVE
                self.recent_429_count = 0
                self.reset_time = None

        if self.status == KeyStatus.QUARANTINED:
            # Auto-recover quarantined keys after 180s cooldown to prevent permanent lockouts
            if self.last_failure_at and (now - self.last_failure_at > 180.0):
                self.status = KeyStatus.ACTIVE
                self.error_count = 0
                self.total_requests = 1

        if self.status != KeyStatus.ACTIVE:
            return -1000.0

        health = 100.0
        if self.error_rate > 0.20:
            health = 0.0
        elif self.error_rate > 0.05:
            health = 50.0

        quota_score = 50.0
        if self.remaining_tokens is not None and self.remaining_tokens < 5000:
            quota_score = 5.0
        elif self.remaining_requests is not None and self.remaining_requests < 10:
            quota_score = 10.0

        latency_penalty = 0.05 * self.p95_latency_ms
        error_penalty = 120.0 * self.error_rate + (50.0 * self.recent_429_count) + (100.0 * self.recent_5xx_count)
        load_penalty = 15.0 * self.in_flight_requests

        raw_score = health + quota_score - latency_penalty - error_penalty - load_penalty
        return max(raw_score, 0.0) * self.canary_weight


# Backward-compatible alias
GroqKeyRecord = ProviderKeyRecord


class KeyPoolRegistry:
    """Manages multi-provider LLM keys (Groq, Cerebras, Google) for rotation, draining and fault isolation."""

    def __init__(self):
        self._keys: Dict[str, ProviderKeyRecord] = {}

    def register_key(self, record: ProviderKeyRecord) -> None:
        self._keys[record.key_id] = record

    def get_key(self, key_id: str) -> Optional[ProviderKeyRecord]:
        return self._keys.get(key_id)

    def get_active_keys(self, provider: Optional[str] = None) -> List[ProviderKeyRecord]:
        return [
            k for k in self._keys.values()
            if k.status == KeyStatus.ACTIVE
            and (provider is None or k.provider.lower() == provider.lower())
        ]

    def get_available_providers(self) -> List[str]:
        """Returns sorted unique list of providers that have at least one active key."""
        active = self.get_active_keys()
        return list(dict.fromkeys(k.provider.lower() for k in active))

    def select_healthy_key(
        self,
        provider: Optional[str] = None,
        project_id: Optional[str] = None
    ) -> Optional[ProviderKeyRecord]:
        """
        Selects highest-scoring healthy key for the requested provider.
        If a key was previously draining but its reset_time has passed, it is recovered.
        """
        candidates = [
            k for k in self._keys.values()
            if (provider is None or k.provider.lower() == provider.lower())
            and (project_id is None or k.project_id == project_id)
        ]
        # Check active or recoverable
        healthy = [k for k in candidates if k.calculate_score() >= 0.0]
        if not healthy:
            # Resiliency: If all candidates are draining/quarantined, select the one
            # with the oldest failure time and force a trial recovery rather than hard-failing forever.
            recoverable = [k for k in candidates if k.status != KeyStatus.REVOKED]
            if recoverable:
                recoverable.sort(key=lambda k: k.last_failure_at or 0.0)
                emergency_key = recoverable[0]
                emergency_key.status = KeyStatus.ACTIVE
                emergency_key.recent_429_count = 0
                return emergency_key
            return None

        # Sort by highest score; lowest in-flight requests as tiebreaker
        healthy.sort(key=lambda k: (k.calculate_score(), -k.in_flight_requests), reverse=True)
        return healthy[0]

    def mark_draining(self, key_id: str, cooldown_seconds: float = 60.0) -> None:
        if key_id in self._keys:
            key = self._keys[key_id]
            key.status = KeyStatus.DRAINING
            if not key.reset_time or key.reset_time < time.time():
                key.reset_time = time.time() + cooldown_seconds

    def mark_revoked(self, key_id: str) -> None:
        if key_id in self._keys:
            self._keys[key_id].status = KeyStatus.REVOKED

    def mark_quarantined(self, key_id: str) -> None:
        if key_id in self._keys:
            self._keys[key_id].status = KeyStatus.QUARANTINED

    def record_outcome(
        self,
        key_id: str,
        success: bool,
        latency_ms: float = 150.0,
        status_code: int = 200
    ) -> None:
        key = self._keys.get(key_id)
        if not key:
            return
        key.total_requests += 1
        key.latency_samples.append(latency_ms)
        if len(key.latency_samples) > 50:
            key.latency_samples.pop(0)

        if success:
            key.last_success_at = time.time()
            if key.recent_429_count > 0:
                key.recent_429_count -= 1
        else:
            key.error_count += 1
            key.last_failure_at = time.time()
            if status_code == 429:
                key.recent_429_count += 1
            elif status_code >= 500:
                key.recent_5xx_count += 1
            elif status_code in (401, 403):
                key.status = KeyStatus.QUARANTINED

            if key.error_rate > 0.5 and key.total_requests >= 5:
                key.status = KeyStatus.QUARANTINED

    def populate_from_settings(self, settings) -> None:
        """Auto-registers configured keys for Groq, Cerebras, and Google from settings."""
        registered_refs = {k.secret_ref for k in self._keys.values()}

        def _add_keys(provider: str, single_key: Optional[str], multi_keys: Optional[str]):
            keys_to_add = []
            if multi_keys:
                for k in multi_keys.split(","):
                    k_clean = k.strip()
                    if k_clean and k_clean not in keys_to_add:
                        keys_to_add.append(k_clean)
            if single_key and single_key.strip() and single_key.strip() not in keys_to_add:
                keys_to_add.append(single_key.strip())

            for idx, raw_key in enumerate(keys_to_add, 1):
                if raw_key not in registered_refs:
                    kid = f"{provider}_key_{idx}"
                    self.register_key(
                        ProviderKeyRecord(
                            key_id=kid,
                            provider=provider,
                            organization_id=getattr(settings, f"{provider.upper()}_ORG_ID", "default_org"),
                            project_id="default",
                            secret_ref=raw_key,
                        )
                    )
                    registered_refs.add(raw_key)

        import os
        # 1. Cerebras Keys
        if getattr(settings, "CEREBRAS_ENABLED", True):
            cerebras_single = getattr(settings, "CEREBRAS_API_KEY", None) or os.environ.get("CEREBRAS_API_KEY") or os.environ.get("CEREBRAS_KEY")
            cerebras_multi = getattr(settings, "CEREBRAS_API_KEYS", None) or os.environ.get("CEREBRAS_API_KEYS")
            _add_keys("cerebras", cerebras_single, cerebras_multi)

        # 2. Groq Keys
        if getattr(settings, "GROQ_ENABLED", True):
            groq_single = getattr(settings, "GROQ_API_KEY", None) or os.environ.get("GROQ_API_KEY") or os.environ.get("GROQ_KEY") or os.environ.get("GROQ_API_SECRET")
            groq_multi = getattr(settings, "GROQ_API_KEYS", None) or os.environ.get("GROQ_API_KEYS")
            _add_keys("groq", groq_single, groq_multi)

        # 3. Google Gemini Keys
        if getattr(settings, "GOOGLE_ENABLED", True):
            google_single = (
                getattr(settings, "GOOGLE_API_KEY", None)
                or getattr(settings, "GEMINI_API_KEY", None)
                or os.environ.get("GOOGLE_API_KEY")
                or os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GEMINI_KEY")
            )
            google_multi = getattr(settings, "GOOGLE_API_KEYS", None) or os.environ.get("GOOGLE_API_KEYS") or os.environ.get("GEMINI_API_KEYS")
            _add_keys("google", google_single, google_multi)

        # 4. Scan os.environ for numbered keys (e.g. GROQ_API_KEY1, GROQ_API_KEY_1, CEREBRAS_API_KEY1, etc.)
        import os, re
        numbered_pattern = re.compile(r"^(GROQ|GOOGLE|GEMINI|CEREBRAS)_API_KEYS?_?(\d+)$")

        for env_k, env_v in os.environ.items():
            k_upper = env_k.upper().strip()
            v_clean = env_v.strip()
            if not v_clean:
                continue
            match = numbered_pattern.match(k_upper)
            if match:
                raw_prov = match.group(1).lower()
                prov = "google" if raw_prov == "gemini" else raw_prov
                if v_clean not in registered_refs:
                    kid = f"{prov}_{env_k.lower()}"
                    self.register_key(
                        ProviderKeyRecord(
                            key_id=kid,
                            provider=prov,
                            organization_id=getattr(settings, f"{prov.upper()}_ORG_ID", "default_org"),
                            project_id="default",
                            secret_ref=v_clean,
                        )
                    )
                    registered_refs.add(v_clean)



_global_key_pool: Optional[KeyPoolRegistry] = None

def get_global_key_pool() -> KeyPoolRegistry:
    global _global_key_pool
    if _global_key_pool is None:
        _global_key_pool = KeyPoolRegistry()
        try:
            from automaintainer.config import get_settings
            _global_key_pool.populate_from_settings(get_settings())
        except Exception:
            pass
    return _global_key_pool

