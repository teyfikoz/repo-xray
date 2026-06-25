"""
Tech Debt Scorer — static analysis, zero AI tokens.
Measures code health indicators and returns a 0-100 score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from .fetcher import RepoData

_TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX|WORKAROUND|NOSONAR)\b", re.IGNORECASE)
_COMMENT_RE = re.compile(r"^\s*(?:#|//|/\*|\*)", re.MULTILINE)
_CONSOLE_LOG_RE = re.compile(r"\bconsole\.log\s*\(", re.IGNORECASE)
_PRINT_DEBUG_RE = re.compile(r"\bprint\s*\(.*debug", re.IGNORECASE)
_MAGIC_NUMBER_RE = re.compile(r"(?<!['\"\w])(?<!\.)\b(?!0\b|1\b)\d{2,}\b(?!['\"])")
_LONG_FUNC_RE = re.compile(
    r"(?:def |function |const \w+ =.*=>|async function )\s*\w+\s*\(", re.IGNORECASE
)
_DEAD_CODE_RE = re.compile(r"^\s*(?:#|//)\s*(?:def |function |class |import |from )", re.IGNORECASE)
_DEPRECATED_RE = re.compile(
    r"\b(?:@deprecated|\.deprecated\b|TODO.*deprecat|FIXME.*deprecat)", re.IGNORECASE
)

_TEST_PATHS = re.compile(r"(?:test|spec|__tests__|fixtures)", re.IGNORECASE)
_SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".cs"}


@dataclass
class DebtItem:
    category: str
    value: str        # human-readable finding
    penalty: int      # points deducted from score
    file: Optional[str] = None

    def as_dict(self) -> dict:
        return {"category": self.category, "value": self.value, "penalty": self.penalty, "file": self.file}


from typing import Optional


@dataclass
class TechDebtReport:
    score: int                              # 0 (worst) – 100 (clean)
    grade: str                              # A / B / C / D / F
    items: list[DebtItem] = field(default_factory=list)
    summary: str = ""
    todo_count: int = 0
    test_ratio_pct: int = 0
    avg_file_lines: int = 0
    total_loc: int = 0
    debt_highlights: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary,
            "todo_count": self.todo_count,
            "test_ratio_pct": self.test_ratio_pct,
            "avg_file_lines": self.avg_file_lines,
            "total_loc": self.total_loc,
            "debt_highlights": self.debt_highlights,
            "items": [i.as_dict() for i in self.items],
        }


def _ext(path: str) -> str:
    _, _, e = path.rpartition(".")
    return f".{e}"


def score_tech_debt(repo: RepoData) -> TechDebtReport:
    """Static tech-debt analysis. Returns score 0-100 (higher = less debt)."""
    items: list[DebtItem] = []
    penalties = 0

    source_files = [f for f in repo.files if _ext(f.path) in _SOURCE_EXTS]
    test_files = [f for f in source_files if _TEST_PATHS.search(f.path)]
    non_test = [f for f in source_files if not _TEST_PATHS.search(f.path)]

    if not source_files:
        return TechDebtReport(score=50, grade="C", summary="Insufficient source files for analysis.")

    # ── 1. TODO/FIXME density ─────────────────────────────────────────────────
    total_todos = 0
    todo_by_file: dict[str, int] = {}
    for f in non_test:
        count = len(_TODO_RE.findall(f.content))
        if count:
            todo_by_file[f.path] = count
            total_todos += count
    total_loc = sum(len(f.content.splitlines()) for f in non_test)
    todo_density = total_todos / max(total_loc, 1) * 1000  # per 1K lines

    if todo_density > 20:
        p = min(20, int(todo_density))
        items.append(DebtItem("TODO Density", f"{total_todos} TODO/FIXME in {total_loc} lines ({todo_density:.1f}/1K)", p))
        penalties += p
    elif todo_density > 10:
        p = 8
        items.append(DebtItem("TODO Density", f"{total_todos} TODO/FIXME ({todo_density:.1f}/1K lines)", p))
        penalties += p
    elif total_todos > 0:
        p = 3
        items.append(DebtItem("TODO Density", f"{total_todos} TODO/FIXME ({todo_density:.1f}/1K lines)", p))
        penalties += p

    # ── 2. Test coverage signal ───────────────────────────────────────────────
    test_ratio = len(test_files) / max(len(source_files), 1)
    if test_ratio < 0.05:
        p = 25
        items.append(DebtItem("Test Coverage", f"Only {len(test_files)}/{len(source_files)} files are tests — likely no tests", p))
        penalties += p
    elif test_ratio < 0.15:
        p = 12
        items.append(DebtItem("Test Coverage", f"{len(test_files)}/{len(source_files)} test files ({test_ratio*100:.0f}%)", p))
        penalties += p
    elif test_ratio < 0.25:
        p = 5
        items.append(DebtItem("Test Coverage", f"Test coverage could improve ({test_ratio*100:.0f}% test files)", p))
        penalties += p

    # ── 3. File length / God files ────────────────────────────────────────────
    long_files = [(f.path, len(f.content.splitlines())) for f in non_test if len(f.content.splitlines()) > 400]
    long_files.sort(key=lambda x: -x[1])
    if long_files:
        worst_len = long_files[0][1]
        p = min(15, len(long_files) * 3)
        items.append(DebtItem(
            "God Files",
            f"{len(long_files)} file(s) over 400 lines (worst: {long_files[0][0]} @ {worst_len} lines)",
            p,
            file=long_files[0][0],
        ))
        penalties += p

    # ── 4. Console.log left in production code ────────────────────────────────
    console_log_files: list[str] = []
    for f in non_test:
        if _CONSOLE_LOG_RE.search(f.content):
            console_log_files.append(f.path)
    if len(console_log_files) > 3:
        p = 8
        items.append(DebtItem("Debug Statements", f"console.log() in {len(console_log_files)} non-test files", p))
        penalties += p
    elif console_log_files:
        p = 3
        items.append(DebtItem("Debug Statements", f"console.log() found in {len(console_log_files)} file(s)", p))
        penalties += p

    # ── 5. Deprecated patterns ────────────────────────────────────────────────
    dep_hits = sum(1 for f in non_test if _DEPRECATED_RE.search(f.content))
    if dep_hits:
        p = min(10, dep_hits * 3)
        items.append(DebtItem("Deprecated Code", f"{dep_hits} file(s) with @deprecated markers", p))
        penalties += p

    # ── 6. Commented-out code blocks (dead code) ──────────────────────────────
    dead_code_files: list[str] = []
    for f in non_test:
        matches = _DEAD_CODE_RE.findall(f.content)
        if len(matches) >= 3:
            dead_code_files.append(f.path)
    if dead_code_files:
        p = min(10, len(dead_code_files) * 2)
        items.append(DebtItem("Dead Code", f"Commented-out code blocks in {len(dead_code_files)} file(s)", p))
        penalties += p

    # ── 7. Magic numbers ──────────────────────────────────────────────────────
    magic_total = sum(len(_MAGIC_NUMBER_RE.findall(f.content)) for f in non_test)
    if magic_total > 50:
        p = 6
        items.append(DebtItem("Magic Numbers", f"{magic_total} magic numbers (unnamed constants) — use named constants", p))
        penalties += p

    # ── 8. Single large file (monolith signal) ────────────────────────────────
    if len(non_test) <= 3 and total_loc > 500:
        p = 8
        items.append(DebtItem("Monolith Signal", f"Only {len(non_test)} source files with {total_loc} LOC — likely monolithic structure", p))
        penalties += p

    # ── Score ─────────────────────────────────────────────────────────────────
    score = max(0, 100 - penalties)
    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    avg_lines = total_loc // max(len(non_test), 1)
    test_ratio_pct = round(test_ratio * 100)

    highlights = []
    if items:
        highlights = [f"[{i.category}] {i.value}" for i in sorted(items, key=lambda x: -x.penalty)[:3]]

    if score >= 85:
        summary = f"Low tech debt — codebase is well-maintained (score {score}/100, Grade {grade})."
    elif score >= 60:
        summary = f"Moderate tech debt detected (score {score}/100, Grade {grade}). {len(items)} area(s) need attention."
    else:
        summary = f"High tech debt (score {score}/100, Grade {grade}). Significant refactoring recommended."

    return TechDebtReport(
        score=score,
        grade=grade,
        items=items,
        summary=summary,
        todo_count=total_todos,
        test_ratio_pct=test_ratio_pct,
        avg_file_lines=avg_lines,
        total_loc=total_loc,
        debt_highlights=highlights,
    )
