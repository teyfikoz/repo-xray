"""
README Quality Analyzer — static, no AI tokens.
Scores the README on completeness, structure, and developer-friendliness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from .fetcher import RepoData


@dataclass
class ReadmeQualityReport:
    score: int             # 0–100
    grade: str             # A / B / C / D / F
    word_count: int
    has_badges: bool
    has_installation: bool
    has_usage: bool
    has_examples: bool
    has_api_docs: bool
    has_contributing: bool
    has_license_section: bool
    has_screenshots: bool
    has_demo_link: bool
    has_toc: bool
    sections_found: list[str]
    missing_sections: list[str]
    signals: list[str]
    summary: str

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "word_count": self.word_count,
            "has_badges": self.has_badges,
            "has_installation": self.has_installation,
            "has_usage": self.has_usage,
            "has_examples": self.has_examples,
            "has_api_docs": self.has_api_docs,
            "has_contributing": self.has_contributing,
            "has_license_section": self.has_license_section,
            "has_screenshots": self.has_screenshots,
            "has_demo_link": self.has_demo_link,
            "has_toc": self.has_toc,
            "sections_found": self.sections_found,
            "missing_sections": self.missing_sections,
            "signals": self.signals,
            "summary": self.summary,
        }


# (section_name, patterns, points, required)
SECTION_CHECKS = [
    ("Installation",  [r"##\s*instal", r"##\s*getting.started", r"##\s*setup", r"##\s*quick.start"], 15, True),
    ("Usage",         [r"##\s*usage", r"##\s*how.to.use", r"##\s*getting.started"],                   15, True),
    ("Examples",      [r"##\s*example", r"```", r"###\s*example"],                                    10, True),
    ("API / Docs",    [r"##\s*api", r"##\s*documentation", r"##\s*reference"],                        10, False),
    ("Contributing",  [r"##\s*contribut", r"contributing\.md"],                                        8, False),
    ("License",       [r"##\s*licen", r"licensed under", r"mit license", r"apache license"],           7, True),
    ("Screenshots",   [r"!\[.*\]\(.*\.(png|jpg|gif|svg|webp)", r"demo", r"screenshot"],               8, False),
    ("Demo / Link",   [r"https?://[^\s]+\.(com|io|app|dev|net|org)", r"live.demo", r"try.it"],        5, False),
    ("Table of Contents", [r"##\s*table.of.content", r"##\s*contents", r"- \[.*\]\(#"],              5, False),
]


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


def analyse_readme(repo: RepoData) -> ReadmeQualityReport:
    """Score the README quality."""
    signals: list[str] = []
    sections_found: list[str] = []
    missing_sections: list[str] = []

    readme = repo.readme or ""

    # No README at all
    if not readme.strip():
        # Check if there's a README file in the file tree
        for f in repo.files:
            if re.match(r"readme(?:\.[a-z]+)?$", f.path.split("/")[-1].lower()):
                readme = f.content
                break

    if not readme.strip():
        return ReadmeQualityReport(
            score=0, grade="F", word_count=0,
            has_badges=False, has_installation=False, has_usage=False,
            has_examples=False, has_api_docs=False, has_contributing=False,
            has_license_section=False, has_screenshots=False, has_demo_link=False,
            has_toc=False, sections_found=[], missing_sections=["README file"],
            signals=["No README found — critical gap for any open-source project"],
            summary="No README file detected. This repository has zero documentation.",
        )

    t = readme.lower()
    word_count = len(readme.split())
    score = 0

    # Base score for having a README at all
    score += 5
    if word_count >= 100:
        score += 5
    if word_count >= 300:
        score += 5
    if word_count >= 800:
        score += 5
    signals.append(f"README word count: {word_count:,}")

    # Badges (shields.io, codecov, etc.)
    has_badges = bool(re.search(r"!\[.*\]\(https?://(img\.shields\.io|badg|codecov|github\.com/.*badge|travis)", t))
    if has_badges:
        score += 5
        signals.append("Has status badges (build, coverage, etc.)")

    # Section checks
    section_map: dict[str, bool] = {}
    for name, patterns, pts, required in SECTION_CHECKS:
        found = any(re.search(p, t) for p in patterns)
        section_map[name] = found
        if found:
            score += pts
            sections_found.append(name)
        elif required:
            missing_sections.append(name)
            signals.append(f"Missing '{name}' section")

    has_installation = section_map.get("Installation", False)
    has_usage = section_map.get("Usage", False)
    has_examples = section_map.get("Examples", False)
    has_api_docs = section_map.get("API / Docs", False)
    has_contributing = section_map.get("Contributing", False)
    has_license_section = section_map.get("License", False)
    has_screenshots = section_map.get("Screenshots", False)
    has_demo_link = section_map.get("Demo / Link", False)
    has_toc = section_map.get("Table of Contents", False)

    # Code blocks — practical examples
    code_block_count = len(re.findall(r"```", readme))
    if code_block_count >= 2:
        signals.append(f"Contains {code_block_count // 2} code block(s)")
    elif code_block_count == 0:
        signals.append("No code blocks — add examples to improve usability")

    # Heading structure
    heading_count = len(re.findall(r"^#{1,3}\s", readme, re.MULTILINE))
    if heading_count >= 5:
        signals.append(f"Well-structured with {heading_count} headings")
    elif heading_count == 0:
        signals.append("No markdown headings — wall of text, hard to scan")
        score -= 5

    score = max(0, min(100, score))
    grade = _score_to_grade(score)

    if score >= 85:
        summary = f"Excellent README (Score {score}/100, Grade {grade}). Well-documented with {word_count:,} words and {len(sections_found)} sections."
    elif score >= 70:
        summary = f"Good README (Score {score}/100, Grade {grade}). Covers the basics but missing: {', '.join(missing_sections) or 'nothing critical'}."
    elif score >= 40:
        summary = f"Minimal README (Score {score}/100, Grade {grade}). Missing key sections: {', '.join(missing_sections)}."
    else:
        summary = f"Poor README (Score {score}/100, Grade {grade}). Needs significant improvement — missing: {', '.join(missing_sections or ['most sections'])}."

    return ReadmeQualityReport(
        score=score,
        grade=grade,
        word_count=word_count,
        has_badges=has_badges,
        has_installation=has_installation,
        has_usage=has_usage,
        has_examples=has_examples,
        has_api_docs=has_api_docs,
        has_contributing=has_contributing,
        has_license_section=has_license_section,
        has_screenshots=has_screenshots,
        has_demo_link=has_demo_link,
        has_toc=has_toc,
        sections_found=sections_found,
        missing_sections=missing_sections,
        signals=signals,
        summary=summary,
    )
