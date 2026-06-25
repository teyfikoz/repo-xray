"""
Security Audit — static analysis, zero AI tokens.
Scans fetched source files for common vulnerability patterns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from .fetcher import RepoData

# ── Severity levels ──────────────────────────────────────────────────────────
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"


@dataclass
class SecurityFinding:
    severity: str          # critical | high | medium | low | info
    category: str          # Secrets | Injection | Crypto | etc.
    file: str
    line: int
    description: str
    snippet: str           # the offending line (truncated)

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "snippet": self.snippet,
        }


@dataclass
class SecurityReport:
    score: int                              # 0 (worst) – 100 (clean)
    grade: str                              # A / B / C / D / F
    findings: list[SecurityFinding] = field(default_factory=list)
    summary: str = ""
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "summary": self.summary,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "findings": [f.as_dict() for f in self.findings],
        }


# ── Pattern registry ─────────────────────────────────────────────────────────
# Each rule: (severity, category, description, compiled_regex)
_RULES: list[tuple[str, str, str, re.Pattern]] = [
    # ── Secrets ──────────────────────────────────────────────────────────────
    (CRITICAL, "Secrets", "AWS Access Key ID detected",
     re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)),
    (CRITICAL, "Secrets", "AWS Secret Access Key pattern",
     re.compile(r"aws.{0,20}secret.{0,10}['\"][A-Za-z0-9/+]{40}['\"]", re.IGNORECASE)),
    (CRITICAL, "Secrets", "GitHub Personal Access Token",
     re.compile(r"ghp_[A-Za-z0-9]{36}", re.IGNORECASE)),
    (CRITICAL, "Secrets", "GitHub OAuth token",
     re.compile(r"gho_[A-Za-z0-9]{36}", re.IGNORECASE)),
    (CRITICAL, "Secrets", "Private key block found",
     re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY", re.IGNORECASE)),
    (CRITICAL, "Secrets", "Anthropic/OpenAI API key pattern",
     re.compile(r"sk-[A-Za-z0-9]{32,}", re.IGNORECASE)),
    (CRITICAL, "Secrets", "Stripe live secret key",
     re.compile(r"sk_live_[A-Za-z0-9]{24,}", re.IGNORECASE)),
    (HIGH, "Secrets", "Hardcoded password assignment",
     re.compile(r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE)),
    (HIGH, "Secrets", "Hardcoded API key assignment",
     re.compile(r"(?:api_key|apikey|api-key)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE)),
    (HIGH, "Secrets", "Hardcoded secret/token assignment",
     re.compile(r"(?:secret|token)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE)),
    (HIGH, "Secrets", "Bearer token hardcoded",
     re.compile(r"[Bb]earer\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE)),

    # ── SQL Injection ─────────────────────────────────────────────────────────
    (HIGH, "SQL Injection", "SQL query built with f-string (injection risk)",
     re.compile(r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{', re.IGNORECASE)),
    (HIGH, "SQL Injection", "SQL query built with string concatenation",
     re.compile(r'["\'].*(SELECT|INSERT|UPDATE|DELETE)\s.*["\']\s*\+', re.IGNORECASE)),
    (MEDIUM, "SQL Injection", "SQL format() interpolation (unsafe if user input)",
     re.compile(r'\.format\(.*\).*(?:SELECT|WHERE|INSERT)', re.IGNORECASE)),

    # ── Command Injection ─────────────────────────────────────────────────────
    (CRITICAL, "Command Injection", "os.system() with f-string (command injection)",
     re.compile(r'os\.system\s*\(\s*f["\']', re.IGNORECASE)),
    (HIGH, "Command Injection", "subprocess with shell=True (injection risk)",
     re.compile(r'subprocess\.(?:run|call|Popen|check_output).*shell\s*=\s*True', re.IGNORECASE)),
    (HIGH, "Command Injection", "exec() with dynamic content",
     re.compile(r'\bexec\s*\(\s*f["\']', re.IGNORECASE)),
    (HIGH, "Command Injection", "eval() usage (dangerous with user input)",
     re.compile(r'\beval\s*\(', re.IGNORECASE)),

    # ── Cryptography ──────────────────────────────────────────────────────────
    (HIGH, "Weak Crypto", "MD5 used (broken for security purposes)",
     re.compile(r'\b(?:hashlib\.md5|MD5\s*\(|createHash\(["\']md5["\'])', re.IGNORECASE)),
    (MEDIUM, "Weak Crypto", "SHA1 used (weak, avoid for signing/hashing secrets)",
     re.compile(r'\b(?:hashlib\.sha1|SHA1\s*\(|createHash\(["\']sha1["\'])', re.IGNORECASE)),
    (HIGH, "Weak Crypto", "Math.random() used for security (not cryptographically secure)",
     re.compile(r'Math\.random\s*\(\s*\)', re.IGNORECASE)),

    # ── XSS ──────────────────────────────────────────────────────────────────
    (HIGH, "XSS", "innerHTML assignment (potential XSS)",
     re.compile(r'\.innerHTML\s*=', re.IGNORECASE)),
    (HIGH, "XSS", "dangerouslySetInnerHTML (React XSS risk)",
     re.compile(r'dangerouslySetInnerHTML', re.IGNORECASE)),
    (MEDIUM, "XSS", "document.write() usage (XSS risk)",
     re.compile(r'document\.write\s*\(', re.IGNORECASE)),

    # ── Insecure Config ───────────────────────────────────────────────────────
    (HIGH, "Insecure Config", "SSL verification disabled (verify=False)",
     re.compile(r'verify\s*=\s*False', re.IGNORECASE)),
    (MEDIUM, "Insecure Config", "DEBUG=True in non-test file",
     re.compile(r'\bDEBUG\s*=\s*True\b')),
    (MEDIUM, "Insecure Config", "CORS allow-all origin (*)",
     re.compile(r'["\']Access-Control-Allow-Origin["\'].*["\']\*["\']', re.IGNORECASE)),
    (LOW, "Insecure Config", "TODO/FIXME security comment",
     re.compile(r'#.*(TODO|FIXME).*(auth|security|password|token|injection|xss|csrf)', re.IGNORECASE)),

    # ── Path Traversal ────────────────────────────────────────────────────────
    (HIGH, "Path Traversal", "open() with potential user-controlled path",
     re.compile(r'open\s*\(\s*(?:request|req|params|query|body)', re.IGNORECASE)),
    (MEDIUM, "Path Traversal", "Potential directory traversal pattern",
     re.compile(r'["\']\.\./', re.IGNORECASE)),

    # ── Sensitive Data Exposure ───────────────────────────────────────────────
    (MEDIUM, "Data Exposure", "print()/console.log of potential sensitive data",
     re.compile(r'(?:print|console\.log)\s*\(.*(?:password|secret|token|key)', re.IGNORECASE)),
    (LOW, "Data Exposure", "Hardcoded IP address",
     re.compile(r'\b(?:192\.168|10\.\d+\.\d+|172\.\d+\.\d+)\.\d+\b')),
]

# File extensions to skip (binaries, assets, lock files)
_SKIP_EXTS = {".lock", ".sum", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf", ".min.js"}
# Skip test files for some checks (they intentionally test dangerous patterns)
_TEST_PATH_PATTERNS = re.compile(r"(?:test|spec|__tests__|fixtures)", re.IGNORECASE)


def _is_test_file(path: str) -> bool:
    return bool(_TEST_PATH_PATTERNS.search(path))


def _snippet(line: str, max_len: int = 120) -> str:
    s = line.strip()
    return s[:max_len] + "…" if len(s) > max_len else s


def audit_security(repo: RepoData) -> SecurityReport:
    """Run static security analysis on all fetched source files."""
    findings: list[SecurityFinding] = []

    skip_in_tests = {CRITICAL, HIGH}  # still report these even in test files but note it

    for repo_file in repo.files:
        _, _, ext = repo_file.path.rpartition(".")
        if f".{ext}" in _SKIP_EXTS:
            continue

        is_test = _is_test_file(repo_file.path)
        lines = repo_file.content.splitlines()

        for line_no, line in enumerate(lines, 1):
            for severity, category, description, pattern in _RULES:
                # For test files, skip LOW/INFO/MEDIUM to reduce noise
                if is_test and severity not in skip_in_tests:
                    continue
                if pattern.search(line):
                    desc = description
                    if is_test:
                        desc += " (in test file — verify intentional)"
                    findings.append(SecurityFinding(
                        severity=severity,
                        category=category,
                        file=repo_file.path,
                        line=line_no,
                        description=desc,
                        snippet=_snippet(line),
                    ))

    # De-duplicate: same file+line+category → keep highest severity
    seen: dict[tuple, SecurityFinding] = {}
    severity_rank = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}
    for f in findings:
        key = (f.file, f.line, f.category)
        if key not in seen or severity_rank[f.severity] > severity_rank[seen[key].severity]:
            seen[key] = f
    findings = sorted(seen.values(), key=lambda x: (-severity_rank[x.severity], x.file, x.line))

    critical = sum(1 for f in findings if f.severity == CRITICAL)
    high = sum(1 for f in findings if f.severity == HIGH)
    medium = sum(1 for f in findings if f.severity == MEDIUM)
    low = sum(1 for f in findings if f.severity == LOW)

    # Score: start at 100, deduct by severity
    score = max(0, 100 - critical * 25 - high * 10 - medium * 4 - low * 1)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    if not findings:
        summary = "No obvious security issues detected in the analysed source files."
    else:
        summary = (
            f"{len(findings)} issue(s) found: "
            f"{critical} critical, {high} high, {medium} medium, {low} low. "
            f"Security score: {score}/100 (Grade {grade})."
        )

    return SecurityReport(
        score=score,
        grade=grade,
        findings=findings,
        summary=summary,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
    )
