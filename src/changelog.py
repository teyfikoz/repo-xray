"""
Changelog Analyzer — GitHub API + AI.
Compares two refs (tags/commits/branches) and generates a human-readable changelog.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CommitEntry:
    sha: str
    message: str       # first line only
    author: str
    date: str

    def as_dict(self) -> dict:
        return {"sha": self.sha[:8], "message": self.message, "author": self.author, "date": self.date}


@dataclass
class ChangelogReport:
    base_ref: str
    head_ref: str
    commits: list[CommitEntry] = field(default_factory=list)
    files_changed: int = 0
    additions: int = 0
    deletions: int = 0
    ai_summary: str = ""
    summary: str = ""

    def as_dict(self) -> dict:
        return {
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "commits_count": len(self.commits),
            "files_changed": self.files_changed,
            "additions": self.additions,
            "deletions": self.deletions,
            "ai_summary": self.ai_summary,
            "summary": self.summary,
            "commits": [c.as_dict() for c in self.commits[:50]],
        }


def _gh_get(path: str, token: Optional[str] = None):
    req = urllib.request.Request(f"https://api.github.com{path}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "repo-xray/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def analyse_changelog(
    owner: str,
    repo: str,
    base: str,
    head: str,
    token: Optional[str] = None,
    groq_api_key: Optional[str] = None,
    hf_api_key: Optional[str] = None,
) -> ChangelogReport:
    """Compare base..head and generate a changelog narrative."""
    import os

    # GitHub compare API
    try:
        compare = _gh_get(f"/repos/{owner}/{repo}/compare/{base}...{head}", token)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"GitHub compare API error {e.code}: cannot compare {base}...{head}") from e

    commits: list[CommitEntry] = []
    for c in compare.get("commits", []):
        msg = (c.get("commit", {}).get("message") or "").split("\n")[0]
        author = c.get("commit", {}).get("author", {}).get("name", "unknown")
        date = c.get("commit", {}).get("author", {}).get("date", "")[:10]
        commits.append(CommitEntry(sha=c.get("sha", ""), message=msg, author=author, date=date))

    files_changed = compare.get("total_commits", 0)
    additions = sum(f.get("additions", 0) for f in compare.get("files", []))
    deletions = sum(f.get("deletions", 0) for f in compare.get("files", []))
    files_changed = len(compare.get("files", []))

    # AI summary
    ai_summary = ""
    groq_key = groq_api_key or os.environ.get("GROQ_API_KEY", "")
    hf_key = hf_api_key or os.environ.get("HF_API_TOKEN", "")

    if commits and (groq_key or hf_key):
        commit_list = "\n".join(f"- {c.message} ({c.author}, {c.date})" for c in commits[:30])
        file_list = ", ".join(f.get("filename", "") for f in compare.get("files", [])[:20])

        prompt = (
            f"Summarise the following git changes between {base} and {head} in {owner}/{repo}.\n"
            f"Write 3-4 sentences covering: what changed, why it matters, and any breaking changes.\n"
            f"Be specific and technical. Plain text only.\n\n"
            f"COMMITS:\n{commit_list}\n\n"
            f"FILES CHANGED: {file_list}\n"
            f"Stats: +{additions} / -{deletions} lines across {files_changed} files."
        )

        try:
            payload = {
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 300,
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
                    ai_summary = result["choices"][0]["message"]["content"] or ""
        except Exception:
            ai_summary = ""

    summary = (
        f"{len(commits)} commits between {base} → {head}. "
        f"{files_changed} files changed, +{additions}/{-deletions} lines."
    )

    return ChangelogReport(
        base_ref=base,
        head_ref=head,
        commits=commits,
        files_changed=files_changed,
        additions=additions,
        deletions=deletions,
        ai_summary=ai_summary,
        summary=summary,
    )
