"""
GitHub repository fetcher.
Pulls file tree + content via GitHub REST API (no auth required for public repos).
"""

import re
import urllib.request
import urllib.error
import json
from dataclasses import dataclass, field
from typing import Optional

# File extensions considered "source code" (skip binaries, assets, lock files)
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt",
    ".swift", ".c", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".vue",
    ".svelte", ".html", ".css", ".scss", ".sql", ".sh", ".yaml", ".yml",
    ".toml", ".json", ".env.example", ".md", ".mdx", ".graphql", ".prisma",
}

# Skip these directories
SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "__pycache__", ".next",
    ".nuxt", "vendor", "venv", ".venv", "env", "coverage", ".cache",
    "tmp", "temp", "logs", ".idea", ".vscode",
}

# Cap how many files / chars we fetch (to stay within LLM context)
MAX_FILES = 60
MAX_CHARS_PER_FILE = 4_000
MAX_TOTAL_CHARS = 80_000


@dataclass
class RepoFile:
    path: str
    content: str
    size: int


@dataclass
class RepoData:
    owner: str
    name: str
    description: str
    stars: int
    forks: int
    language: str
    topics: list[str]
    files: list[RepoFile] = field(default_factory=list)
    readme: str = ""
    default_branch: str = "main"

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL or 'owner/repo' string."""
    url = url.strip().rstrip("/")

    # Handle 'owner/repo' shorthand
    if "/" in url and not url.startswith("http"):
        parts = url.split("/")
        return parts[0], parts[1]

    # Handle full GitHub URLs
    pattern = r"github\.com[:/]([^/]+)/([^/.\s]+)"
    match = re.search(pattern, url)
    if not match:
        raise ValueError(f"Cannot parse GitHub URL: {url}")
    return match.group(1), match.group(2).replace(".git", "")


def _gh_api(path: str, token: Optional[str] = None) -> dict | list:
    """Make a GitHub API request. Optionally authenticated."""
    url = f"https://api.github.com{path}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "repo-xray/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"GitHub API error {e.code}: {body[:200]}") from e


def _get_file_content(owner: str, repo: str, path: str, branch: str, token: Optional[str] = None) -> str:
    """Fetch raw file content from GitHub."""
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    req = urllib.request.Request(raw_url)
    req.add_header("User-Agent", "repo-xray/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _should_include(path: str, size: int) -> bool:
    """Decide whether to include a file based on extension and path."""
    if size > 100_000:  # skip files > 100KB
        return False
    parts = path.split("/")
    # Skip blacklisted directories
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False
    # Accept files with known extensions or specific names
    lower = path.lower()
    name = parts[-1].lower()
    if name in {"readme.md", "makefile", "dockerfile", ".env.example", "docker-compose.yml"}:
        return True
    _, _, ext = name.rpartition(".")
    return f".{ext}" in SOURCE_EXTENSIONS


def fetch_repo(url: str, token: Optional[str] = None, verbose: bool = False) -> RepoData:
    """Fetch repository metadata and source files."""
    owner, repo_name = parse_github_url(url)

    if verbose:
        print(f"  Fetching metadata for {owner}/{repo_name}...")

    # Metadata
    meta = _gh_api(f"/repos/{owner}/{repo_name}", token)
    data = RepoData(
        owner=owner,
        name=repo_name,
        description=meta.get("description") or "",
        stars=meta.get("stargazers_count", 0),
        forks=meta.get("forks_count", 0),
        language=meta.get("language") or "Unknown",
        topics=meta.get("topics", []),
        default_branch=meta.get("default_branch", "main"),
    )

    # README
    try:
        readme_meta = _gh_api(f"/repos/{owner}/{repo_name}/readme", token)
        import base64
        content_b64 = readme_meta.get("content", "").replace("\n", "")
        data.readme = base64.b64decode(content_b64).decode("utf-8", errors="replace")[:3000]
    except Exception:
        data.readme = ""

    # File tree
    if verbose:
        print("  Fetching file tree...")
    try:
        tree_data = _gh_api(
            f"/repos/{owner}/{repo_name}/git/trees/{data.default_branch}?recursive=1",
            token
        )
        tree = tree_data.get("tree", [])
    except Exception:
        tree = []

    # Filter and sort files (prioritise root-level + smaller files first)
    candidates = [
        item for item in tree
        if item.get("type") == "blob" and _should_include(item["path"], item.get("size", 0))
    ]
    # Sort: root files first, then by depth, then by size
    candidates.sort(key=lambda x: (x["path"].count("/"), x.get("size", 0)))

    total_chars = 0
    for item in candidates[:MAX_FILES * 2]:  # over-fetch, stop when limits hit
        if len(data.files) >= MAX_FILES or total_chars >= MAX_TOTAL_CHARS:
            break
        if verbose:
            print(f"  Reading {item['path']}...")
        content = _get_file_content(owner, repo_name, item["path"], data.default_branch, token)
        if not content:
            continue
        trimmed = content[:MAX_CHARS_PER_FILE]
        if len(content) > MAX_CHARS_PER_FILE:
            trimmed += f"\n... [truncated {len(content) - MAX_CHARS_PER_FILE} chars]"
        data.files.append(RepoFile(path=item["path"], content=trimmed, size=item.get("size", 0)))
        total_chars += len(trimmed)

    return data
