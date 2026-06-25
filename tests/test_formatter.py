"""Tests for output formatters."""

import json
from src.fetcher import RepoData, RepoFile
from src.formatter import to_json, to_markdown, to_plain


SAMPLE_REPO = RepoData(
    owner="testuser",
    name="testrepo",
    description="A test repo",
    stars=1234,
    forks=56,
    language="Python",
    topics=["ai", "cli"],
    files=[RepoFile(path="main.py", content="print('hello')", size=14)],
    readme="# TestRepo\nA simple test.",
)

SAMPLE_ANALYSIS = {
    "summary": "A test project for unit testing.",
    "tech_stack": ["Python", "pytest"],
    "architecture": "Single-module script.",
    "key_files": [{"path": "main.py", "role": "Entry point"}],
    "difficulty": "beginner",
    "learning_insights": ["Insight one.", "Insight two."],
    "ai_rebuild_prompt": "Build a Python CLI tool...",
    "quick_start_guide": "1. Clone\n2. Run python main.py",
    "similar_projects": ["click", "typer"],
    "fun_fact": "Python was named after Monty Python.",
}


def test_to_json_valid():
    result = to_json(SAMPLE_ANALYSIS)
    parsed = json.loads(result)
    assert parsed["difficulty"] == "beginner"
    assert "Python" in parsed["tech_stack"]


def test_to_markdown_contains_name():
    result = to_markdown(SAMPLE_REPO, SAMPLE_ANALYSIS)
    assert "testuser/testrepo" in result
    assert "1,234" in result  # stars formatted
    assert "beginner" in result.lower()


def test_to_markdown_has_sections():
    result = to_markdown(SAMPLE_REPO, SAMPLE_ANALYSIS)
    for section in ["## What is this?", "## Tech Stack", "## Architecture", "## Key Files",
                    "## Learning Insights", "## AI Rebuild Prompt", "## Quick Start Guide"]:
        assert section in result


def test_to_plain_contains_summary():
    result = to_plain(SAMPLE_REPO, SAMPLE_ANALYSIS)
    assert "REPO-XRAY REPORT" in result
    assert "A test project for unit testing." in result
    assert "BEGINNER" in result
