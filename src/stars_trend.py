"""
Stars Trend — GitHub API, no AI tokens.
Fetches star history and computes growth metrics.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class StarDataPoint:
    date: str      # YYYY-MM-DD
    stars: int     # cumulative

    def as_dict(self) -> dict:
        return {"date": self.date, "stars": self.stars}


@dataclass
class StarsTrend:
    total_stars: int
    data_points: list[StarDataPoint] = field(default_factory=list)
    growth_30d: int = 0        # stars gained in last 30 days (approx)
    growth_rate_pct: float = 0  # month-over-month %
    momentum: str = ""         # "accelerating" | "steady" | "slowing" | "stalled"
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "total_stars": self.total_stars,
            "growth_30d": self.growth_30d,
            "growth_rate_pct": round(self.growth_rate_pct, 1),
            "momentum": self.momentum,
            "summary": self.summary,
            "data_points": [dp.as_dict() for dp in self.data_points],
        }


def fetch_stars_trend(
    owner: str,
    repo: str,
    token: Optional[str] = None,
    max_pages: int = 10,
) -> StarsTrend:
    """
    Fetch up to max_pages × 100 stargazer timestamps from GitHub API.
    Requires Accept: application/vnd.github.star+json header.
    """
    all_timestamps: list[str] = []
    page = 1

    while page <= max_pages:
        url = f"https://api.github.com/repos/{owner}/{repo}/stargazers?per_page=100&page={page}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.star+json")
        req.add_header("User-Agent", "repo-xray/1.0")
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                if not data:
                    break
                for item in data:
                    starred_at = item.get("starred_at", "")
                    if starred_at:
                        all_timestamps.append(starred_at[:10])  # YYYY-MM-DD
                page += 1
        except urllib.error.HTTPError as e:
            if e.code == 422:
                # GitHub returns 422 when star list is too large and not authenticated
                break
            raise RuntimeError(f"GitHub API error {e.code}") from e
        except Exception:
            break

    if not all_timestamps:
        return StarsTrend(
            total_stars=0,
            summary="Star history unavailable (private repo, or too many stars without auth token).",
        )

    # Bucket into weekly data points
    from collections import Counter
    weekly: Counter = Counter()
    for ts in all_timestamps:
        # Round to start of week (Monday)
        dt = datetime.strptime(ts, "%Y-%m-%d")
        week_start = dt - __import__('datetime').timedelta(days=dt.weekday())
        weekly[week_start.strftime("%Y-%m-%d")] += 1

    sorted_weeks = sorted(weekly.keys())
    cumulative = 0
    data_points: list[StarDataPoint] = []
    for week in sorted_weeks:
        cumulative += weekly[week]
        data_points.append(StarDataPoint(date=week, stars=cumulative))

    # Growth metrics using last 2 windows
    total = cumulative
    n = len(data_points)

    if n >= 2:
        half = n // 2
        first_half = data_points[half - 1].stars if half > 0 else 0
        second_half = data_points[-1].stars - first_half
        growth_rate = (second_half - first_half) / max(first_half, 1) * 100
    else:
        growth_rate = 0.0
        second_half = 0

    # Last ~4 weeks growth
    if n >= 4:
        growth_30d = data_points[-1].stars - data_points[-4].stars
    elif n >= 1:
        growth_30d = data_points[-1].stars - (data_points[0].stars if n > 1 else 0)
    else:
        growth_30d = 0

    if growth_rate > 20:
        momentum = "accelerating"
    elif growth_rate > 5:
        momentum = "steady"
    elif growth_rate > -5:
        momentum = "stable"
    elif growth_rate > -20:
        momentum = "slowing"
    else:
        momentum = "stalled"

    summary = (
        f"{total:,} stars tracked (sampled from first {len(all_timestamps)} stargazers). "
        f"Recent momentum: {momentum}. ~{growth_30d:+,} stars in last ~30 days."
    )

    return StarsTrend(
        total_stars=total,
        data_points=data_points,
        growth_30d=growth_30d,
        growth_rate_pct=growth_rate,
        momentum=momentum,
        summary=summary,
    )
