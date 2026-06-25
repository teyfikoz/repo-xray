"""
Multi-Repo Comparison — fetch + static-analyse 2-5 repos side by side.
AI comparison narrative uses one additional Groq call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from .fetcher import RepoData, fetch_repo
from .security_audit import audit_security, SecurityReport
from .tech_debt import score_tech_debt, TechDebtReport
from .api_surface import extract_api_surface, ApiSurfaceReport
from .dep_risk import analyse_dependencies, DepRiskReport
from .cost_estimator import estimate_cost, CostEstimate


@dataclass
class RepoSnapshot:
    repo: RepoData
    security: SecurityReport
    tech_debt: TechDebtReport
    api_surface: ApiSurfaceReport
    dep_risk: DepRiskReport
    cost: CostEstimate

    def summary_dict(self) -> dict:
        return {
            "name": self.repo.full_name,
            "url": self.repo.url,
            "stars": self.repo.stars,
            "forks": self.repo.forks,
            "language": self.repo.language,
            "topics": self.repo.topics,
            "files_analysed": len(self.repo.files),
            "security_score": self.security.score,
            "security_grade": self.security.grade,
            "security_issues": len(self.security.findings),
            "tech_debt_score": self.tech_debt.score,
            "tech_debt_grade": self.tech_debt.grade,
            "total_loc": self.tech_debt.total_loc,
            "test_ratio_pct": self.tech_debt.test_ratio_pct,
            "api_endpoints": self.api_surface.count,
            "api_frameworks": self.api_surface.frameworks,
            "dep_risk_score": self.dep_risk.risk_score,
            "dep_risk_grade": self.dep_risk.grade,
            "total_deps": self.dep_risk.total_deps,
            "risky_deps": len(self.dep_risk.findings),
            "rebuild_cost_senior": self.cost.senior_usd,
            "duration_weeks_solo": self.cost.duration_weeks_solo,
        }


@dataclass
class ComparisonReport:
    snapshots: list[RepoSnapshot] = field(default_factory=list)
    ai_narrative: str = ""
    winner_overall: str = ""
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "repos": [s.summary_dict() for s in self.snapshots],
            "ai_narrative": self.ai_narrative,
            "winner_overall": self.winner_overall,
            "summary": self.summary,
        }


def _snapshot(repo: RepoData) -> RepoSnapshot:
    return RepoSnapshot(
        repo=repo,
        security=audit_security(repo),
        tech_debt=score_tech_debt(repo),
        api_surface=extract_api_surface(repo),
        dep_risk=analyse_dependencies(repo),
        cost=estimate_cost(repo),
    )


_COMPARE_PROMPT = """You are an expert software architect comparing multiple GitHub repositories.
Given the structured comparison data below, write a concise 3-4 paragraph analysis covering:
1. Technical quality differences (security, tech debt, test coverage)
2. Architecture and complexity comparison
3. Which repo you recommend and why
4. One surprising observation

Be direct and opinionated. Plain text only, no bullet points, no markdown.

COMPARISON DATA:
"""


def compare_repos(
    urls: list[str],
    github_token: Optional[str] = None,
    groq_api_key: Optional[str] = None,
    hf_api_key: Optional[str] = None,
    verbose: bool = False,
) -> ComparisonReport:
    """Fetch, analyse, and compare 2-5 GitHub repos."""
    if len(urls) < 2:
        raise ValueError("Need at least 2 URLs to compare")
    if len(urls) > 5:
        raise ValueError("Maximum 5 repos for comparison")

    snapshots: list[RepoSnapshot] = []
    for url in urls:
        if verbose:
            print(f"  Fetching {url}...")
        repo = fetch_repo(url, token=github_token, verbose=False)
        snap = _snapshot(repo)
        snapshots.append(snap)
        if verbose:
            print(f"  Analysed {repo.full_name} — sec:{snap.security.score} debt:{snap.tech_debt.score}")

    # Determine overall winner (highest combined score)
    def combined_score(s: RepoSnapshot) -> float:
        return (s.security.score * 0.3 + s.tech_debt.score * 0.3 +
                s.dep_risk.risk_score * 0.2 + min(s.tech_debt.test_ratio_pct * 2, 100) * 0.2)

    best = max(snapshots, key=combined_score)

    # Optional AI narrative
    ai_narrative = ""
    import json
    comparison_data = json.dumps([s.summary_dict() for s in snapshots], indent=2)

    import os
    import urllib.request
    import urllib.error

    groq_key = groq_api_key or os.environ.get("GROQ_API_KEY", "")
    hf_key = hf_api_key or os.environ.get("HF_API_TOKEN", "")

    if groq_key or hf_key:
        try:
            messages = [
                {"role": "system", "content": "You are an expert software architect. Be concise and direct."},
                {"role": "user", "content": _COMPARE_PROMPT + comparison_data},
            ]
            payload: dict = {
                "model": "llama-3.3-70b-versatile",
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 600,
            }
            if groq_key:
                data = json.dumps(payload).encode()
                req = urllib.request.Request(
                    "https://api.groq.com/openai/v1/chat/completions",
                    data=data,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {groq_key}",
                        "User-Agent": "OpenAI/Python 1.0.0",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    result = json.loads(resp.read())
                    ai_narrative = result["choices"][0]["message"]["content"] or ""
        except Exception as e:
            if verbose:
                print(f"  AI narrative failed: {e}")

    names = [s.repo.full_name for s in snapshots]
    summary = (
        f"Compared {len(snapshots)} repos: {' vs '.join(names)}. "
        f"Overall recommendation: {best.repo.full_name} "
        f"(combined score {combined_score(best):.0f}/100)."
    )

    return ComparisonReport(
        snapshots=snapshots,
        ai_narrative=ai_narrative,
        winner_overall=best.repo.full_name,
        summary=summary,
    )
