import time
from typing import Dict, Set, Optional, List
from datetime import datetime, timezone, timedelta

class AntiSpamManager:
    """
    Defensive anti-spam safeguards:
    1. Cooldown Registry: 7-30 days cooldown after PR rejection/closure.
    2. Per-Repository Daily PR Budget: <= 1 active PR per upstream repository.
    3. Global Hourly Rate Limit: <= 2 PRs per hour (configurable defensive ceiling).
    4. Global Rejection Circuit Breaker: Freezes autonomous submissions if rejection rate > 60%.
    5. Repository Opt-Out Registry: Global and per-org blacklist for repositories requesting no bot interactions.
    """

    def __init__(
        self,
        cooldown_days: int = 14,
        max_active_prs_per_repo: int = 1,
        max_prs_per_hour: int = 2,
    ):
        self.cooldown_days = cooldown_days
        self.max_active_prs_per_repo = max_active_prs_per_repo
        self.max_prs_per_hour = max_prs_per_hour
        # repo_full_name -> cooldown_until (datetime)
        self._cooldowns: Dict[str, datetime] = {}
        # repo_full_name -> set of active pr numbers
        self._active_prs: Dict[str, Set[int]] = {}
        # Opt-out blacklist
        self._opt_outs: Set[str] = set()
        # Rolling metrics for circuit breaker
        self._pr_outcomes = [] # list of (timestamp, outcome) outcome: "merged"|"rejected"
        # Timestamps of PR creations for hourly rate limiting
        self._pr_creation_timestamps: List[float] = []
        self._repo_pr_timestamps: Dict[str, List[float]] = {}

    def register_opt_out(self, repo_or_org: str) -> None:
        self._opt_outs.add(repo_or_org.lower().strip())

    def is_opted_out(self, repo_full_name: str) -> bool:
        normalized = repo_full_name.lower().strip()
        if normalized in self._opt_outs:
            return True
        # Check org part
        if "/" in normalized:
            org = normalized.split("/")[0]
            if org in self._opt_outs:
                return True
        return False

    def record_pr_rejection(self, repo_full_name: str, days: Optional[int] = None) -> None:
        duration = days or self.cooldown_days
        until = datetime.now(timezone.utc) + timedelta(days=duration)
        self._cooldowns[repo_full_name.lower().strip()] = until
        self._pr_outcomes.append((time.time(), "rejected"))

    def record_pr_merge(self, repo_full_name: str) -> None:
        self._pr_outcomes.append((time.time(), "merged"))

    def is_in_cooldown(self, repo_full_name: str) -> bool:
        until = self._cooldowns.get(repo_full_name.lower().strip())
        if not until:
            return False
        return datetime.now(timezone.utc) < until

    def record_pr_created(self, repo_full_name: str, pr_number: Optional[int] = None) -> None:
        """Records a new PR creation event with timestamp for hourly rate limiting."""
        now = time.time()
        self._pr_creation_timestamps.append(now)
        normalized = repo_full_name.lower().strip()
        if normalized not in self._repo_pr_timestamps:
            self._repo_pr_timestamps[normalized] = []
        self._repo_pr_timestamps[normalized].append(now)

        # Prune timestamps older than 24h
        cutoff = now - 86400
        self._pr_creation_timestamps = [ts for ts in self._pr_creation_timestamps if ts > cutoff]
        self._repo_pr_timestamps[normalized] = [ts for ts in self._repo_pr_timestamps[normalized] if ts > cutoff]

        if pr_number is not None:
            self.track_active_pr(repo_full_name, pr_number, record_creation=False)

    def track_active_pr(self, repo_full_name: str, pr_number: int, record_creation: bool = True) -> None:
        normalized = repo_full_name.lower().strip()
        if normalized not in self._active_prs:
            self._active_prs[normalized] = set()
        self._active_prs[normalized].add(pr_number)
        if record_creation:
            now = time.time()
            self._pr_creation_timestamps.append(now)
            if normalized not in self._repo_pr_timestamps:
                self._repo_pr_timestamps[normalized] = []
            self._repo_pr_timestamps[normalized].append(now)

    def release_active_pr(self, repo_full_name: str, pr_number: int) -> None:
        normalized = repo_full_name.lower().strip()
        if normalized in self._active_prs:
            self._active_prs[normalized].discard(pr_number)

    def set_active_prs(self, repo_full_name: str, pr_numbers: Set[int]) -> None:
        """Sets active PR numbers directly, typically synced from GitHub live state."""
        normalized = repo_full_name.lower().strip()
        self._active_prs[normalized] = set(pr_numbers)

    def get_active_prs(self, repo_full_name: str) -> Set[int]:
        normalized = repo_full_name.lower().strip()
        return set(self._active_prs.get(normalized, set()))

    def clear_active_prs(self, repo_full_name: str) -> None:
        normalized = repo_full_name.lower().strip()
        self._active_prs.pop(normalized, None)

    def reset_circuit_breaker(self) -> None:
        """Clears rejection history and PR timestamps (for testing / admin reset)."""
        self._pr_outcomes.clear()
        self._pr_creation_timestamps.clear()

    def clear_cooldown(self, repo_full_name: str) -> None:
        self._cooldowns.pop(repo_full_name.lower().strip(), None)

    def can_open_pr(self, repo_full_name: str, is_managed: bool = False) -> tuple[bool, str]:
        normalized = repo_full_name.lower().strip()

        if self.is_opted_out(normalized):
            return False, f"Repository '{repo_full_name}' is registered on the bot opt-out list."

        if not is_managed and self.is_in_cooldown(normalized):
            until = self._cooldowns[normalized]
            return False, f"Repository '{repo_full_name}' is in cooling-off period until {until.isoformat()}."

        active_count = len(self._active_prs.get(normalized, set()))
        if active_count >= self.max_active_prs_per_repo:
            return False, f"Repository '{repo_full_name}' already has {active_count} active PR(s), limit is {self.max_active_prs_per_repo}."

        # Check Hourly PR Creation Rate Limit
        # Managed repositories have a relaxed limit (20/hr) vs public unverified repos
        now = time.time()
        one_hour_ago = now - 3600
        recent_hourly = [ts for ts in self._pr_creation_timestamps if ts > one_hour_ago]
        effective_hourly_limit = 20 if is_managed else self.max_prs_per_hour
        if len(recent_hourly) >= effective_hourly_limit:
            return False, f"Hourly PR limit reached ({len(recent_hourly)} PR(s) created in the last hour, limit is {effective_hourly_limit})."

        # Check Global Rejection Circuit Breaker (rolling window of last 20 PRs)
        # Managed repositories are operator-authorized and exempt from public crawler circuit breaker
        if not is_managed:
            recent = [o for ts, o in self._pr_outcomes if now - ts < 86400 * 7]  # 7 days
            if len(recent) >= 10:
                rejections = sum(1 for o in recent if o == "rejected")
                rate = rejections / len(recent)
                if rate > 0.60:
                    return False, f"Global Rejection Circuit Breaker tripped (rejection rate {rate*100:.1f}% > 60%). Halting public PR submissions."

        return True, "OK"

# Singleton
_anti_spam: Optional[AntiSpamManager] = None
def get_anti_spam_manager() -> AntiSpamManager:
    global _anti_spam
    if _anti_spam is None:
        try:
            from automaintainer.config import get_settings
            settings = get_settings()
            max_prs = getattr(settings, "MAX_PRS_PER_HOUR", 2)
            _anti_spam = AntiSpamManager(max_prs_per_hour=max_prs)
        except Exception:
            _anti_spam = AntiSpamManager()
    return _anti_spam
