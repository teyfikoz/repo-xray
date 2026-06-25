"""
Dependency Risk Analyzer — static analysis, zero AI tokens.
Parses package manifests and scores dependency health.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from .fetcher import RepoData

RISK_CRITICAL = "critical"
RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"
RISK_OK = "ok"

# ── Known problematic packages (static list — expand regularly) ───────────────
# Format: package_name_lower → (risk_level, reason)
_KNOWN_RISKY: dict[str, tuple[str, str]] = {
    # Abandoned / unmaintained
    "request": (RISK_HIGH, "Deprecated since 2020, no longer maintained — use axios/fetch/httpx"),
    "moment": (RISK_MEDIUM, "Deprecated — use dayjs or date-fns"),
    "node-uuid": (RISK_HIGH, "Deprecated — use uuid package"),
    "jade": (RISK_MEDIUM, "Renamed to pug"),
    "bower": (RISK_HIGH, "Deprecated package manager"),
    "grunt": (RISK_LOW, "Legacy task runner — consider Vite/esbuild"),
    "event-stream": (RISK_CRITICAL, "Was compromised in supply chain attack (2018)"),
    "left-pad": (RISK_MEDIUM, "Historically caused npm outage — ensure pinned"),
    "is-thirteen": (RISK_LOW, "Joke package — remove if in production"),
    "colors": (RISK_HIGH, "v1.4.44-44 was sabotaged by author — pin to v1.4.0"),
    "faker": (RISK_HIGH, "v6.6.6 was sabotaged — use @faker-js/faker"),
    # Python
    "pycrypto": (RISK_CRITICAL, "Unmaintained with known CVEs — use pycryptodome"),
    "py-bcrypt": (RISK_HIGH, "Unmaintained — use bcrypt"),
    "pysftp": (RISK_HIGH, "Unmaintained, last release 2016"),
    "pickle": (RISK_MEDIUM, "Python stdlib but insecure deserialization — never unpickle untrusted data"),
    "urllib2": (RISK_LOW, "Python 2 module — indicates Python 2 codebase"),
    "django-axes": (RISK_LOW, "Check version — older versions had bypass vulnerabilities"),
    # Security-sensitive
    "eval": (RISK_HIGH, "Direct eval package — dangerous"),
    "serialize-javascript": (RISK_MEDIUM, "Older versions had XSS vuln — ensure v3.1+"),
    "lodash": (RISK_MEDIUM, "Prototype pollution in older versions — ensure v4.17.21+"),
    "minimist": (RISK_MEDIUM, "Prototype pollution — ensure v1.2.6+"),
    "qs": (RISK_MEDIUM, "Prototype pollution in older versions — ensure v6.7.3+"),
    "set-value": (RISK_HIGH, "Prototype pollution — update or replace"),
    "merge": (RISK_MEDIUM, "Prototype pollution — use safer alternative"),
    "deep-extend": (RISK_HIGH, "Prototype pollution — unmaintained"),
    "handlebars": (RISK_MEDIUM, "Prototype pollution in older versions — ensure v4.7.7+"),
    "xmldom": (RISK_HIGH, "Multiple CVEs — ensure latest version"),
    "node-forge": (RISK_MEDIUM, "Older versions have vulnerabilities — update to v1.3+"),
}

# ── License risk ──────────────────────────────────────────────────────────────
_HIGH_RISK_LICENSES = {"AGPL-3.0", "GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "SSPL"}
_COPYLEFT_NOTE = "Copyleft license — may force-open your source code"


@dataclass
class DepFinding:
    name: str
    version: Optional[str]
    risk_level: str
    reason: str
    ecosystem: str   # npm | pypi | go | cargo | etc.

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "ecosystem": self.ecosystem,
        }


@dataclass
class DepRiskReport:
    risk_score: int                          # 0 (worst) – 100 (clean)
    grade: str
    findings: list[DepFinding] = field(default_factory=list)
    total_deps: int = 0
    ecosystems: list[str] = field(default_factory=list)
    lock_files_present: bool = False
    summary: str = ""
    highlights: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "grade": self.grade,
            "summary": self.summary,
            "total_deps": self.total_deps,
            "ecosystems": self.ecosystems,
            "lock_files_present": self.lock_files_present,
            "highlights": self.highlights,
            "findings": [f.as_dict() for f in self.findings],
        }


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> list[tuple[str, Optional[str]]]:
    """Parse requirements.txt / constraints.txt"""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        # Remove extras like [security]
        line = re.sub(r'\[.*?\]', '', line)
        # Split on version specifiers
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*(?:[><=!~^]{1,2}\s*([^\s;]+))?', line)
        if m:
            name, version = m.group(1), m.group(2)
            deps.append((name.lower(), version))
    return deps


def _parse_package_json(content: str) -> list[tuple[str, Optional[str]]]:
    """Parse npm package.json"""
    deps = []
    try:
        data = json.loads(content)
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in data.get(key, {}).items():
                deps.append((name.lower(), str(version)))
    except Exception:
        pass
    return deps


def _parse_go_mod(content: str) -> list[tuple[str, Optional[str]]]:
    """Parse go.mod"""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r'^\s*([a-zA-Z0-9._/\-]+)\s+v([^\s]+)', line)
        if m:
            name = m.group(1).split("/")[-1].lower()
            deps.append((name, m.group(2)))
    return deps


def _parse_cargo_toml(content: str) -> list[tuple[str, Optional[str]]]:
    """Parse Cargo.toml"""
    deps = []
    in_deps = False
    for line in content.splitlines():
        if line.strip().startswith("[dependencies") or line.strip().startswith("[dev-dependencies"):
            in_deps = True
            continue
        if line.strip().startswith("[") and in_deps:
            in_deps = False
        if in_deps:
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*(?:["\']([^"\']+)["\']|.*version\s*=\s*["\']([^"\']+)["\'])', line)
            if m:
                name = m.group(1).lower()
                version = m.group(2) or m.group(3)
                deps.append((name, version))
    return deps


def _parse_gemfile(content: str) -> list[tuple[str, Optional[str]]]:
    """Parse Gemfile"""
    deps = []
    for line in content.splitlines():
        m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:.*['\"]([^'\"]+)['\"])?", line)
        if m:
            deps.append((m.group(1).lower(), m.group(2)))
    return deps


_MANIFEST_PARSERS = {
    "requirements.txt": ("pypi", _parse_requirements_txt),
    "requirements-dev.txt": ("pypi", _parse_requirements_txt),
    "requirements_dev.txt": ("pypi", _parse_requirements_txt),
    "package.json": ("npm", _parse_package_json),
    "go.mod": ("go", _parse_go_mod),
    "cargo.toml": ("cargo", _parse_cargo_toml),
    "gemfile": ("gem", _parse_gemfile),
}

_LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
               "pipfile.lock", "go.sum", "cargo.lock", "gemfile.lock", "bun.lockb"}


def analyse_dependencies(repo: RepoData) -> DepRiskReport:
    """Parse all package manifests and identify risky dependencies."""
    all_deps: list[tuple[str, Optional[str], str]] = []  # (name, version, ecosystem)
    findings: list[DepFinding] = []
    ecosystems: set[str] = set()
    lock_present = False
    penalties = 0

    for repo_file in repo.files:
        fname = repo_file.path.split("/")[-1].lower()

        if fname in _LOCK_FILES:
            lock_present = True
            continue

        if fname in _MANIFEST_PARSERS:
            ecosystem, parser = _MANIFEST_PARSERS[fname]
            parsed = parser(repo_file.content)
            for name, version in parsed:
                all_deps.append((name, version, ecosystem))
                ecosystems.add(ecosystem)

    # Check each dep
    seen_names: set[str] = set()
    risk_rank = {RISK_CRITICAL: 4, RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1, RISK_OK: 0}

    for name, version, ecosystem in all_deps:
        if name in seen_names:
            continue
        seen_names.add(name)

        if name in _KNOWN_RISKY:
            risk_level, reason = _KNOWN_RISKY[name]
            findings.append(DepFinding(name, version, risk_level, reason, ecosystem))

    # Lock file penalty
    has_manifest = bool(ecosystems)
    if has_manifest and not lock_present:
        penalties += 15

    # Score from findings
    for f in findings:
        if f.risk_level == RISK_CRITICAL:
            penalties += 30
        elif f.risk_level == RISK_HIGH:
            penalties += 15
        elif f.risk_level == RISK_MEDIUM:
            penalties += 7
        elif f.risk_level == RISK_LOW:
            penalties += 2

    findings.sort(key=lambda x: -risk_rank[x.risk_level])

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

    if not all_deps:
        summary = "No package manifests found — unable to analyse dependencies."
    elif not findings:
        summary = f"No known risky dependencies in {len(seen_names)} packages across {len(ecosystems)} ecosystem(s)."
        if not lock_present and has_manifest:
            summary += " Warning: no lock file detected (reproducibility risk)."
    else:
        critical = sum(1 for f in findings if f.risk_level == RISK_CRITICAL)
        high = sum(1 for f in findings if f.risk_level == RISK_HIGH)
        summary = (
            f"{len(findings)}/{len(seen_names)} packages flagged "
            f"({critical} critical, {high} high). "
            f"Risk score: {score}/100 (Grade {grade})."
        )
        if not lock_present:
            summary += " No lock file detected."

    highlights = [f"[{f.risk_level.upper()}] {f.name}: {f.reason}" for f in findings[:3]]

    return DepRiskReport(
        risk_score=score,
        grade=grade,
        findings=findings,
        total_deps=len(seen_names),
        ecosystems=sorted(ecosystems),
        lock_files_present=lock_present,
        summary=summary,
        highlights=highlights,
    )
