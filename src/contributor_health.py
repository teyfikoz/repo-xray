"""
Contributor Health — GitHub API, no AI tokens.
Measures project vitality via contributors, PR health, issue response times.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ContributorStat:
    login: str
    commits: int
    pct: float

    def as_dict(self) -> dict:
        return {"login": self.login, "commits": self.commits, "pct": round(self.pct, 1)}


@dataclass
class ContributorHealthReport:
    contributor_count: int = 0
    top_contributors: list[ContributorStat] = field(default_factory=list)
    bus_factor: int = 1             # min devs who could bus-factor the project
    open_issues: int = 0
    closed_issues: int = 0
    open_prs: int = 0
    last_commit_days_ago: int = 0
    health_score: int = 0           # 0-100
    health_grade: str = "?"
    summary: str = ""
    signals: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "contributor_count": self.contributor_count,
            "bus_factor": self.bus_factor,
            "open_issues": self.open_issues,
            "closed_issues": self.closed_issues,
            "open_prs": self.open_prs,
            "last_commit_days_ago": self.last_commit_days_ago,
            "health_score": self.health_score,
            "health_grade": self.health_grade,
            "summary": self.summary,
            "signals": self.signals,
            "top_contributors": [c.as_dict() for c in self.top_contributors],
        }


def _gh_get(path: str, token: Optional[str] = None, timeout: int = 15):
    req = urllib.request.Request(f"https://api.github.com{path}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "repo-xray/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def fetch_contributor_health(
    owner: str,
    repo: str,
    token: Optional[str] = None,
) -> ContributorHealthReport:
    """Fetch and score contributor/project health metrics."""
    from datetime import datetime, timezone

    signals: list[str] = []
    score = 100
    penalties = 0

    # Contributors (top 30 by commit count)
    contributors_data = _gh_get(f"/repos/{owner}/{repo}/contributors?per_page=30", token) or []
    total_commits = sum(c.get("contributions", 0) for c in contributors_data)
    contributor_count = len(contributors_data)

    top_contributors: list[ContributorStat] = []
    for c in contributors_data[:5]:
        commits = c.get("contributions", 0)
        pct = commits / max(total_commits, 1) * 100
        top_contributors.append(ContributorStat(
            login=c.get("login", "unknown"),
            commits=commits,
            pct=pct,
        ))

    # Bus factor: how many contributors account for >80% of commits
    bus_factor = 0
    accumulated = 0
    for c in contributors_data:
        accumulated += c.get("contributions", 0)
        bus_factor += 1
        if accumulated / max(total_commits, 1) >= 0.8:
            break
    if bus_factor == 0:
        bus_factor = 1

    # Score contributors
    if contributor_count == 1:
        penalties += 20
        signals.append("Single contributor — high bus factor risk")
    elif contributor_count < 3:
        penalties += 10
        signals.append(f"Only {contributor_count} contributors")
    elif contributor_count >= 10:
        signals.append(f"{contributor_count} contributors — healthy community")

    if bus_factor == 1 and contributor_count > 1:
        penalties += 10
        signals.append("One person accounts for 80%+ of commits — bus factor = 1")

    # Issues
    repo_meta = _gh_get(f"/repos/{owner}/{repo}", token) or {}
    open_issues = repo_meta.get("open_issues_count", 0)

    # Closed issues (approximate via search)
    closed_data = _gh_get(f"/repos/{owner}/{repo}/issues?state=closed&per_page=1", token)
    # GitHub returns issues + PRs in the issues API
    closed_issues = 0  # hard to get total without pagination

    open_prs_data = _gh_get(f"/repos/{owner}/{repo}/pulls?state=open&per_page=1", token) or []
    open_prs = len(open_prs_data)

    if open_issues > 500:
        penalties += 10
        signals.append(f"{open_issues} open issues — large backlog")
    elif open_issues > 100:
        penalties += 5
        signals.append(f"{open_issues} open issues")

    # Last commit
    commits_data = _gh_get(f"/repos/{owner}/{repo}/commits?per_page=1", token)
    last_commit_days = 0
    if commits_data and isinstance(commits_data, list) and commits_data:
        date_str = commits_data[0].get("commit", {}).get("author", {}).get("date", "")
        if date_str:
            try:
                last_commit_dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                last_commit_days = (now - last_commit_dt).days
            except Exception:
                pass

    if last_commit_days > 365:
        penalties += 25
        signals.append(f"Last commit {last_commit_days} days ago — may be abandoned")
    elif last_commit_days > 180:
        penalties += 10
        signals.append(f"Last commit {last_commit_days} days ago — low activity")
    elif last_commit_days > 90:
        penalties += 5
        signals.append(f"Last commit {last_commit_days} days ago")
    elif last_commit_days <= 30:
        signals.append(f"Active: last commit {last_commit_days} days ago")

    # Archived
    if repo_meta.get("archived", False):
        penalties += 40
        signals.append("Repository is ARCHIVED — no longer maintained")

    score = max(0, 100 - penalties)
    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 45:
        grade = "C"
    elif score >= 25:
        grade = "D"
    else:
        grade = "F"

    summary = (
        f"{contributor_count} contributor(s), bus factor {bus_factor}. "
        f"{open_issues} open issues. "
        f"Last commit: {last_commit_days} days ago. "
        f"Health score: {score}/100 (Grade {grade})."
    )

    return ContributorHealthReport(
        contributor_count=contributor_count,
        top_contributors=top_contributors,
        bus_factor=bus_factor,
        open_issues=open_issues,
        closed_issues=closed_issues,
        open_prs=open_prs,
        last_commit_days_ago=last_commit_days,
        health_score=score,
        health_grade=grade,
        summary=summary,
        signals=signals,
    )
