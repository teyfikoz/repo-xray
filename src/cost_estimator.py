"""
Cost Estimator — static analysis, zero AI tokens.
Estimates rebuild cost based on LOC, complexity, and market rates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from .fetcher import RepoData

# ── Hourly rates (USD, 2025 market) ─────────────────────────────────────────
RATE_JUNIOR = 25        # Upwork/Fiverr junior dev
RATE_SENIOR = 90        # Senior freelancer
RATE_AGENCY = 200       # Agency/consulting

# ── Complexity multipliers per file type ─────────────────────────────────────
# LOC / MULTIPLIER ≈ effective hours
_COMPLEXITY: dict[str, float] = {
    ".py": 0.012,
    ".go": 0.010,
    ".rs": 0.015,
    ".java": 0.010,
    ".kt": 0.012,
    ".cs": 0.010,
    ".ts": 0.010,
    ".tsx": 0.012,
    ".js": 0.008,
    ".jsx": 0.010,
    ".vue": 0.012,
    ".svelte": 0.012,
    ".rb": 0.010,
    ".php": 0.008,
    ".swift": 0.012,
    ".cpp": 0.015,
    ".c": 0.015,
    ".html": 0.004,
    ".css": 0.003,
    ".scss": 0.004,
    ".sql": 0.008,
    ".sh": 0.006,
    ".yaml": 0.003,
    ".yml": 0.003,
    ".toml": 0.002,
    ".json": 0.002,
    ".md": 0.001,
    ".graphql": 0.006,
    ".prisma": 0.006,
}

# ── Architecture complexity bonus ─────────────────────────────────────────────
_ARCH_SIGNALS: dict[str, float] = {
    "docker-compose": 1.15,
    "kubernetes": 1.3,
    ".github/workflows": 1.1,
    "prisma": 1.1,
    "graphql": 1.15,
    "websocket": 1.1,
    "celery": 1.1,
    "redis": 1.05,
    "grpc": 1.2,
    "kafka": 1.25,
    "terraform": 1.2,
}

_NON_SOURCE = re.compile(r"\.(md|txt|json|yaml|yml|toml|lock|sum|png|jpg|svg|ico|woff|ttf|min\.js)$", re.IGNORECASE)


@dataclass
class CostBreakdown:
    category: str
    loc: int
    hours: float
    notes: str

    def as_dict(self) -> dict:
        return {"category": self.category, "loc": self.loc, "hours": round(self.hours, 1), "notes": self.notes}


@dataclass
class CostEstimate:
    total_loc: int
    effective_hours: float
    complexity_multiplier: float
    junior_usd: int
    senior_usd: int
    agency_usd: int
    duration_weeks_solo: float       # solo senior dev estimate
    duration_weeks_team: float       # 3-dev team estimate
    breakdown: list[CostBreakdown] = field(default_factory=list)
    complexity_notes: list[str] = field(default_factory=list)
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "total_loc": self.total_loc,
            "effective_hours": round(self.effective_hours, 1),
            "complexity_multiplier": self.complexity_multiplier,
            "junior_usd": self.junior_usd,
            "senior_usd": self.senior_usd,
            "agency_usd": self.agency_usd,
            "duration_weeks_solo": round(self.duration_weeks_solo, 1),
            "duration_weeks_team": round(self.duration_weeks_team, 1),
            "complexity_notes": self.complexity_notes,
            "summary": self.summary,
            "breakdown": [b.as_dict() for b in self.breakdown],
        }


def estimate_cost(repo: RepoData) -> CostEstimate:
    """Estimate rebuild cost from LOC, file types, and architecture signals."""
    loc_by_ext: dict[str, int] = {}
    total_loc = 0
    base_hours = 0.0
    complexity_multiplier = 1.0
    complexity_notes: list[str] = []

    all_paths = " ".join(f.path.lower() for f in repo.files)

    for repo_file in repo.files:
        if _NON_SOURCE.search(repo_file.path):
            continue
        _, _, ext = repo_file.path.rpartition(".")
        ext_key = f".{ext.lower()}"
        lines = len([l for l in repo_file.content.splitlines() if l.strip()])  # non-blank lines
        loc_by_ext[ext_key] = loc_by_ext.get(ext_key, 0) + lines
        total_loc += lines
        mult = _COMPLEXITY.get(ext_key, 0.008)
        base_hours += lines * mult

    # Architecture complexity bonuses
    for signal, mult in _ARCH_SIGNALS.items():
        if signal in all_paths or signal in (repo.readme or "").lower():
            complexity_multiplier *= mult
            complexity_notes.append(f"{signal.title()} detected (+{round((mult-1)*100)}% complexity)")

    # Size complexity
    if total_loc > 10_000:
        complexity_multiplier *= 1.2
        complexity_notes.append("Large codebase (>10K LOC): +20% for system integration complexity")
    elif total_loc > 5_000:
        complexity_multiplier *= 1.1
        complexity_notes.append("Medium-large codebase (>5K LOC): +10% integration complexity")

    # Cap multiplier
    complexity_multiplier = min(complexity_multiplier, 2.5)

    effective_hours = base_hours * complexity_multiplier

    # Minimum 8 hours (even tiny projects)
    effective_hours = max(effective_hours, 8)

    junior_usd = round(effective_hours * RATE_JUNIOR / 100) * 100
    senior_usd = round(effective_hours * RATE_SENIOR / 100) * 100
    agency_usd = round(effective_hours * RATE_AGENCY / 100) * 100

    # Duration: 6 productive hours/day, 5 days/week
    hours_per_week = 30
    duration_weeks_solo = effective_hours / hours_per_week
    duration_weeks_team = duration_weeks_solo / 2.5  # 3-dev team, ~2.5x speedup (coordination overhead)

    # Build breakdown by language group
    breakdown: list[CostBreakdown] = []
    groups = {
        "Backend": {".py", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".cs"},
        "Frontend": {".js", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".html", ".css", ".scss"},
        "Mobile": {".swift", ".kt"},
        "Systems": {".c", ".cpp"},
        "Data/Config": {".sql", ".graphql", ".prisma", ".yaml", ".yml", ".toml", ".json"},
        "Scripts": {".sh"},
    }
    for group_name, exts in groups.items():
        group_loc = sum(loc_by_ext.get(e, 0) for e in exts)
        if group_loc == 0:
            continue
        group_hours = sum(loc_by_ext.get(e, 0) * _COMPLEXITY.get(e, 0.008) for e in exts) * complexity_multiplier
        top_exts = [e for e in exts if loc_by_ext.get(e, 0) > 0]
        breakdown.append(CostBreakdown(
            category=group_name,
            loc=group_loc,
            hours=group_hours,
            notes=", ".join(sorted(top_exts)),
        ))
    breakdown.sort(key=lambda x: -x.loc)

    summary = (
        f"{total_loc:,} effective LOC → {round(effective_hours)} hours estimated. "
        f"Rebuild cost: ${junior_usd:,} (junior) / ${senior_usd:,} (senior) / ${agency_usd:,} (agency). "
        f"Solo senior timeline: ~{duration_weeks_solo:.1f} weeks."
    )

    return CostEstimate(
        total_loc=total_loc,
        effective_hours=effective_hours,
        complexity_multiplier=round(complexity_multiplier, 2),
        junior_usd=junior_usd,
        senior_usd=senior_usd,
        agency_usd=agency_usd,
        duration_weeks_solo=duration_weeks_solo,
        duration_weeks_team=duration_weeks_team,
        breakdown=breakdown,
        complexity_notes=complexity_notes,
        summary=summary,
    )
