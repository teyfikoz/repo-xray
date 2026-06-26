"""
Code Quality Analyzer — static, no AI tokens.
Detects: complexity signals, duplication, doc coverage, test coverage, code smells.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections import Counter
from .fetcher import RepoData


@dataclass
class CodeQualityReport:
    score: int             # 0–100
    grade: str             # A–F
    total_lines: int
    source_files: int
    test_files: int
    test_ratio: float      # test_files / source_files
    doc_coverage: float    # 0.0–1.0 fraction of functions that have docstrings/comments above
    long_functions: int    # functions >50 lines
    large_files: int       # files >500 lines
    duplicate_blocks: int  # approximate — same 5-line chunks
    todo_count: int
    fixme_count: int
    magic_numbers: int
    deep_nesting: int      # lines with indentation > 5 levels
    avg_file_size: int     # average lines per source file
    smells: list[str]
    signals: list[str]
    summary: str

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "total_lines": self.total_lines,
            "source_files": self.source_files,
            "test_files": self.test_files,
            "test_ratio": round(self.test_ratio, 2),
            "doc_coverage": round(self.doc_coverage, 2),
            "long_functions": self.long_functions,
            "large_files": self.large_files,
            "duplicate_blocks": self.duplicate_blocks,
            "todo_count": self.todo_count,
            "fixme_count": self.fixme_count,
            "magic_numbers": self.magic_numbers,
            "deep_nesting": self.deep_nesting,
            "avg_file_size": self.avg_file_size,
            "smells": self.smells,
            "signals": self.signals,
            "summary": self.summary,
        }


SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java",
               ".kt", ".swift", ".c", ".cpp", ".cs", ".rb", ".php"}

TEST_PATTERNS = re.compile(
    r"(^|/)(test_|_test\.|spec\.|\.test\.|\.spec\.|tests/|__tests__/|test/)",
    re.IGNORECASE
)

FUNC_DEF = re.compile(
    r"^\s*(def |function |async function |func |fn |public |private |protected |static )"
    r"(?!\s*$)",
    re.MULTILINE
)

MAGIC_NUM = re.compile(r"(?<![a-zA-Z_])\b(\d{2,})\b(?!\s*[)\],]|\s*\*\s*\d)")

DEEP_INDENT = re.compile(r"^( {20,}|\t{5,})", re.MULTILINE)

DOC_ABOVE = re.compile(
    r'("""|\'\'\'|/\*\*|//[!/]|#\s)',
)


def _score_to_grade(score: int) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _detect_duplicates(files: list) -> int:
    """Approximate duplicate block detection — count repeated 5-line windows."""
    chunk_counts: Counter = Counter()
    for f in files:
        lines = [l.strip() for l in f.content.splitlines() if l.strip() and not l.strip().startswith(("#", "//", "*", "/*"))]
        for i in range(len(lines) - 4):
            chunk = "\n".join(lines[i:i + 5])
            if len(chunk) > 50:  # skip trivial chunks
                chunk_counts[chunk] += 1
    return sum(1 for c in chunk_counts.values() if c > 1)


def score_code_quality(repo: RepoData) -> CodeQualityReport:
    """Analyse source files for code quality signals."""
    smells: list[str] = []
    signals: list[str] = []

    source_files = [f for f in repo.files if any(f.path.endswith(e) for e in SOURCE_EXTS)]
    test_files = [f for f in source_files if TEST_PATTERNS.search(f.path)]
    non_test_files = [f for f in source_files if f not in test_files]

    if not source_files:
        return CodeQualityReport(
            score=50, grade="C", total_lines=0, source_files=0, test_files=0,
            test_ratio=0.0, doc_coverage=0.0, long_functions=0, large_files=0,
            duplicate_blocks=0, todo_count=0, fixme_count=0, magic_numbers=0,
            deep_nesting=0, avg_file_size=0, smells=[], signals=["No source files found"],
            summary="No source files detected in the fetched content.",
        )

    total_lines = sum(len(f.content.splitlines()) for f in source_files)
    avg_file_size = total_lines // max(len(source_files), 1)
    test_ratio = len(test_files) / max(len(non_test_files), 1)

    # Long functions (rough: count def/function and measure until next def or EOF)
    long_functions = 0
    for f in non_test_files:
        lines = f.content.splitlines()
        func_starts = [i for i, l in enumerate(lines) if FUNC_DEF.match(l)]
        for idx, start in enumerate(func_starts):
            end = func_starts[idx + 1] if idx + 1 < len(func_starts) else len(lines)
            if end - start > 50:
                long_functions += 1

    # Large files
    large_files = sum(1 for f in source_files if len(f.content.splitlines()) > 500)

    # TODO / FIXME
    all_content = "\n".join(f.content for f in source_files)
    todo_count = len(re.findall(r"\bTODO\b", all_content, re.IGNORECASE))
    fixme_count = len(re.findall(r"\bFIXME\b", all_content, re.IGNORECASE))

    # Magic numbers (exclude 0, 1, 2 — too common)
    magic_numbers = sum(
        1 for m in MAGIC_NUM.finditer(all_content)
        if m.group(1) not in ("0", "1", "2", "10", "100")
    )

    # Deep nesting
    deep_nesting = sum(len(DEEP_INDENT.findall(f.content)) for f in source_files)

    # Doc coverage (rough: fraction of function defs preceded by docstring/comment within 3 lines)
    documented = 0
    total_funcs = 0
    for f in non_test_files:
        lines = f.content.splitlines()
        for i, line in enumerate(lines):
            if FUNC_DEF.match(line):
                total_funcs += 1
                # Check the 3 lines above for docstring/comment
                above = "\n".join(lines[max(0, i - 3):i])
                if DOC_ABOVE.search(above):
                    documented += 1
    doc_coverage = documented / max(total_funcs, 1)

    # Duplicate blocks
    duplicate_blocks = _detect_duplicates(non_test_files[:20])  # cap for performance

    # ---- Scoring ----
    score = 100

    # Tests
    if test_ratio == 0:
        score -= 20
        smells.append("No test files found")
    elif test_ratio < 0.2:
        score -= 10
        smells.append(f"Low test coverage ratio ({test_ratio:.0%})")
    else:
        signals.append(f"Test ratio: {test_ratio:.0%} ({len(test_files)} test files)")

    # Long functions
    if long_functions > 10:
        score -= 15
        smells.append(f"{long_functions} long functions (>50 lines) — split into smaller units")
    elif long_functions > 3:
        score -= 7
        smells.append(f"{long_functions} long functions detected")

    # Large files
    if large_files > 5:
        score -= 10
        smells.append(f"{large_files} large files (>500 lines) — consider splitting modules")
    elif large_files > 0:
        score -= 4
        signals.append(f"{large_files} file(s) over 500 lines")

    # Duplicates
    if duplicate_blocks > 20:
        score -= 10
        smells.append(f"High duplication: ~{duplicate_blocks} repeated code blocks")
    elif duplicate_blocks > 5:
        score -= 5
        signals.append(f"Possible duplication: ~{duplicate_blocks} repeated blocks")

    # TODOs
    if todo_count + fixme_count > 20:
        score -= 8
        smells.append(f"{todo_count} TODOs + {fixme_count} FIXMEs — significant technical debt markers")
    elif todo_count + fixme_count > 5:
        score -= 3
        signals.append(f"{todo_count} TODOs / {fixme_count} FIXMEs in codebase")

    # Magic numbers
    if magic_numbers > 30:
        score -= 5
        smells.append("Many magic numbers — use named constants")

    # Deep nesting
    if deep_nesting > 20:
        score -= 5
        smells.append("Excessive nesting depth — refactor with early returns")

    # Doc coverage
    if doc_coverage < 0.1 and total_funcs > 10:
        score -= 5
        smells.append(f"Very low doc coverage ({doc_coverage:.0%}) — add docstrings")
    elif doc_coverage > 0.5:
        signals.append(f"Good doc coverage ({doc_coverage:.0%})")

    signals.append(f"{len(source_files)} source files, {total_lines:,} total lines")
    if avg_file_size:
        signals.append(f"Average file size: {avg_file_size} lines")

    score = max(0, min(100, score))
    grade = _score_to_grade(score)

    if score >= 85:
        summary = f"High code quality (Score {score}/100, Grade {grade}). Clean, well-tested codebase."
    elif score >= 70:
        summary = f"Decent code quality (Score {score}/100, Grade {grade}). Minor issues: {smells[0] if smells else 'none'}."
    elif score >= 40:
        summary = f"Moderate quality concerns (Score {score}/100, Grade {grade}). Key issues: {'; '.join(smells[:2])}."
    else:
        summary = f"Low code quality (Score {score}/100, Grade {grade}). Multiple issues: {'; '.join(smells[:3])}."

    return CodeQualityReport(
        score=score,
        grade=grade,
        total_lines=total_lines,
        source_files=len(source_files),
        test_files=len(test_files),
        test_ratio=test_ratio,
        doc_coverage=doc_coverage,
        long_functions=long_functions,
        large_files=large_files,
        duplicate_blocks=duplicate_blocks,
        todo_count=todo_count,
        fixme_count=fixme_count,
        magic_numbers=magic_numbers,
        deep_nesting=deep_nesting,
        avg_file_size=avg_file_size,
        smells=smells,
        signals=signals,
        summary=summary,
    )
