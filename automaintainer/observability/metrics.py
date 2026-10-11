"""
Metrics Collector.
In-process atomic counters for key product metrics.
Designed to be lightweight; in production these would be exported to
Prometheus/OpenTelemetry. The /v1/metrics-summary endpoint reads these counters.
"""
import threading
from typing import Dict


class MetricsCollector:
    """
    Thread-safe, in-process counter registry.

    Tracked counters (all monotonically increasing):
      opportunities_discovered_total
      pr_opened_total
      pr_merged_total
      pr_rejected_total
      safety_stop_total
      validation_pass_total
      validation_fail_total
      duplicate_pr_prevented_total
      inference_calls_total
      inference_rate_limited_total
      session_started_total
      session_completed_total
    """

    _COUNTER_NAMES = [
        "opportunities_discovered_total",
        "pr_opened_total",
        "pr_merged_total",
        "pr_rejected_total",
        "safety_stop_total",
        "validation_pass_total",
        "validation_fail_total",
        "duplicate_pr_prevented_total",
        "inference_calls_total",
        "inference_rate_limited_total",
        "session_started_total",
        "session_completed_total",
    ]

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = {name: 0 for name in self._COUNTER_NAMES}

    def increment(self, name: str, amount: int = 1) -> None:
        """Atomically increment a named counter."""
        with self._lock:
            if name not in self._counters:
                self._counters[name] = 0
            self._counters[name] += amount

    def get(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def snapshot(self) -> Dict[str, int]:
        """Return a copy of all current counter values."""
        with self._lock:
            return dict(self._counters)


    def opportunity_discovered(self) -> None:
        self.increment("opportunities_discovered_total")

    def pr_opened(self) -> None:
        self.increment("pr_opened_total")

    def pr_merged(self) -> None:
        self.increment("pr_merged_total")

    def pr_rejected(self) -> None:
        self.increment("pr_rejected_total")

    def safety_stop(self) -> None:
        self.increment("safety_stop_total")

    def validation_passed(self) -> None:
        self.increment("validation_pass_total")

    def validation_failed(self) -> None:
        self.increment("validation_fail_total")

    def duplicate_prevented(self) -> None:
        self.increment("duplicate_pr_prevented_total")

    def inference_called(self) -> None:
        self.increment("inference_calls_total")

    def inference_rate_limited(self) -> None:
        self.increment("inference_rate_limited_total")

    def session_started(self) -> None:
        self.increment("session_started_total")

    def session_completed(self) -> None:
        self.increment("session_completed_total")

    @property
    def validation_pass_rate(self) -> float:
        with self._lock:
            total = self._counters["validation_pass_total"] + self._counters["validation_fail_total"]
            if total == 0:
                return 0.0
            return round(self._counters["validation_pass_total"] / total, 4)


# Module-level singleton
_collector: MetricsCollector = MetricsCollector()


def get_metrics() -> MetricsCollector:
    return _collector
