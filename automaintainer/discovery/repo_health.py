"""
Repository Health Scorer.
Computes a composite health score from GitHub API signals WITHOUT executing any repo code.
Hard rejects: archived repos, repos with no commits in 3+ years.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
import httpx


@dataclass
class RepoHealthSignals:
    recent_commit_days: int = 999          # Days since last push to default branch
    open_issues: int = 0
    closed_prs_last_90d: int = 0          # PR engagement signal
    has_ci_workflows: bool = False
    is_archived: bool = False
    is_fork: bool = False
    has_contributing_md: bool = False
    star_count: int = 0
    fork_count: int = 0


@dataclass
class RepoHealthScore:
    total: float = 0.0                     # 0-100, used as the RepoHealth component
    maintainer_activity: float = 0.0
    ci_maturity: float = 0.0
    community: float = 0.0
    project_health: float = 0.0
    signals: RepoHealthSignals = field(default_factory=RepoHealthSignals)
    is_eligible: bool = True
    ineligibility_reason: Optional[str] = None


class RepositoryHealthScorer:
    """
    Queries GitHub REST API to gather health signals and produce a 0–100 composite score.
    The total is used as the `RepoHealth` weight in the OpportunityScore formula.
    """

    def __init__(self, api_base_url: str = "https://api.github.com"):
        self.api_base_url = api_base_url.rstrip("/")

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token and token.strip():
            headers["Authorization"] = f"Bearer {token.strip()}"
        return headers

    async def fetch_signals(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> RepoHealthSignals:
        signals = RepoHealthSignals()
        headers = self._headers(token)

        async def _fetch(c: httpx.AsyncClient) -> RepoHealthSignals:
            repo_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}",
                headers=headers, timeout=10.0,
            )
            if repo_resp.status_code != 200:
                return signals
            repo_data = repo_resp.json()

            signals.is_archived = repo_data.get("archived", False)
            signals.is_fork = repo_data.get("fork", False)
            signals.star_count = repo_data.get("stargazers_count", 0)
            signals.fork_count = repo_data.get("forks_count", 0)
            signals.open_issues = repo_data.get("open_issues_count", 0)

            pushed_at = repo_data.get("pushed_at")
            if pushed_at:
                pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                signals.recent_commit_days = (datetime.now(timezone.utc) - pushed).days

            wf_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/contents/.github/workflows",
                headers=headers, timeout=10.0,
            )
            signals.has_ci_workflows = wf_resp.status_code == 200

            contrib_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/contents/CONTRIBUTING.md",
                headers=headers, timeout=10.0,
            )
            signals.has_contributing_md = contrib_resp.status_code == 200

            since = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
            prs_resp = await c.get(
                f"{self.api_base_url}/repos/{owner}/{repo}/pulls",
                headers=headers,
                params={"state": "closed", "per_page": 20},
                timeout=10.0,
            )
            if prs_resp.status_code == 200:
                signals.closed_prs_last_90d = len(prs_resp.json())

            return signals

        if client:
            return await _fetch(client)
        async with httpx.AsyncClient() as c:
            return await _fetch(c)

    def compute_score(self, signals: RepoHealthSignals) -> RepoHealthScore:
        # Hard eligibility: archived repos are never touched
        if signals.is_archived:
            return RepoHealthScore(
                total=0.0, is_eligible=False,
                ineligibility_reason="Repository is archived",
                signals=signals,
            )
        # Dead project: no activity in 3 years — skip
        if signals.recent_commit_days > 1095:
            return RepoHealthScore(
                total=0.0, is_eligible=False,
                ineligibility_reason="No activity in over 3 years",
                signals=signals,
            )

        # Maintainer activity (0–100): recency-weighted
        if signals.recent_commit_days <= 7:
            activity = 100.0
        elif signals.recent_commit_days <= 30:
            activity = 85.0
        elif signals.recent_commit_days <= 90:
            activity = 65.0
        elif signals.recent_commit_days <= 365:
            activity = 35.0
        else:
            activity = 15.0

        # PR responsiveness boost
        if signals.closed_prs_last_90d >= 5:
            activity = min(100.0, activity + 15.0)
        elif signals.closed_prs_last_90d >= 2:
            activity = min(100.0, activity + 8.0)

        # CI maturity
        ci = 80.0 if signals.has_ci_workflows else 20.0

        # Community
        community = min(100.0, signals.star_count / 10.0 + signals.fork_count / 5.0)

        # Project health
        project_health = 50.0
        if signals.has_contributing_md:
            project_health += 20.0
        if not signals.is_fork:
            project_health += 30.0

        total = (
            0.35 * activity
            + 0.25 * ci
            + 0.20 * min(project_health, 100.0)
            + 0.20 * min(community, 100.0)
        )

        return RepoHealthScore(
            total=round(total, 2),
            maintainer_activity=round(activity, 2),
            ci_maturity=round(ci, 2),
            community=round(community, 2),
            project_health=round(project_health, 2),
            signals=signals,
            is_eligible=True,
        )

    async def score(
        self,
        owner: str,
        repo: str,
        token: str,
        client: Optional[httpx.AsyncClient] = None,
    ) -> RepoHealthScore:
        signals = await self.fetch_signals(owner, repo, token, client=client)
        return self.compute_score(signals)
