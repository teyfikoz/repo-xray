"""
CI/CD & Container Analyzer — static, no AI tokens.
Inspects Dockerfiles, GitHub Actions workflows, and other CI configs for
best practices, security issues, and missing automation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from .fetcher import RepoData


@dataclass
class CIReport:
    score: int               # 0–100
    grade: str
    has_ci: bool
    ci_providers: list[str]  # github-actions, travis, circleci, gitlab-ci, etc.
    has_dockerfile: bool
    has_docker_compose: bool
    has_tests_in_ci: bool
    has_lint_in_ci: bool
    has_security_scan: bool  # trivy, snyk, codeql, dependabot
    has_release_automation: bool
    has_caching: bool
    dockerfile_issues: list[str]
    workflow_issues: list[str]
    signals: list[str]
    summary: str

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "has_ci": self.has_ci,
            "ci_providers": self.ci_providers,
            "has_dockerfile": self.has_dockerfile,
            "has_docker_compose": self.has_docker_compose,
            "has_tests_in_ci": self.has_tests_in_ci,
            "has_lint_in_ci": self.has_lint_in_ci,
            "has_security_scan": self.has_security_scan,
            "has_release_automation": self.has_release_automation,
            "has_caching": self.has_caching,
            "dockerfile_issues": self.dockerfile_issues,
            "workflow_issues": self.workflow_issues,
            "signals": self.signals,
            "summary": self.summary,
        }


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


def _analyse_dockerfile(content: str) -> list[str]:
    """Return list of Dockerfile best-practice violations."""
    issues = []
    lines = content.splitlines()
    t = content.lower()

    # Running as root
    has_user = any(l.strip().upper().startswith("USER ") for l in lines)
    if not has_user:
        issues.append("No USER instruction — container runs as root (security risk)")

    # Latest tag
    if re.search(r"FROM\s+\S+:latest", content, re.IGNORECASE):
        issues.append("FROM uses :latest tag — pin to specific version for reproducibility")

    # apt-get without --no-install-recommends
    if "apt-get install" in t and "--no-install-recommends" not in t:
        issues.append("apt-get install without --no-install-recommends — increases image size")

    # Multiple RUN commands that could be chained
    run_count = sum(1 for l in lines if l.strip().upper().startswith("RUN "))
    if run_count > 5:
        issues.append(f"{run_count} separate RUN layers — chain with && to reduce image layers")

    # COPY . . before dependency install
    lines_upper = [l.strip().upper() for l in lines]
    copy_all_idx = next((i for i, l in enumerate(lines_upper) if l.startswith("COPY . .") or l.startswith("COPY . /APP")), None)
    if copy_all_idx is not None and copy_all_idx < 5:
        issues.append("COPY . . before dependency install — defeats build cache")

    # No HEALTHCHECK
    if "healthcheck" not in t:
        issues.append("No HEALTHCHECK instruction — add for container orchestration readiness")

    # Secrets in ENV
    for line in lines:
        if re.search(r"ENV\s+(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)\s*=", line, re.IGNORECASE):
            issues.append(f"Secret in ENV instruction: {line.strip()[:60]} — use secrets manager instead")

    # curl | bash pattern (risky installs)
    if re.search(r"curl\s+.*\|\s*(sudo\s+)?bash", t):
        issues.append("curl | bash pattern detected — risky, prefer verified package installs")

    return issues


def _analyse_workflow(content: str, filename: str) -> list[str]:
    """Return list of GitHub Actions issues."""
    issues = []
    t = content.lower()

    # Pinned action versions
    unpinned = re.findall(r"uses:\s*[^\s@]+@(main|master|latest|HEAD)", content)
    if unpinned:
        issues.append(f"Unpinned action refs (uses @{unpinned[0]} etc.) — pin to commit SHA for security")

    # Secrets in workflow logs
    if re.search(r"echo\s+\$\{\{?\s*secrets\.", content):
        issues.append("Possible secret echo in workflow — never print secrets to logs")

    # pull_request_target with untrusted code
    if "pull_request_target" in t and "checkout" in t:
        issues.append("pull_request_target + checkout may execute untrusted PR code (security risk)")

    # Missing permissions block
    if "permissions:" not in t:
        issues.append("No explicit `permissions:` block — add least-privilege permissions")

    # timeout-minutes missing
    if "timeout-minutes:" not in t:
        issues.append("No `timeout-minutes` set — runaway jobs will consume billed minutes")

    # Third-party actions without security review
    third_party = re.findall(r"uses:\s*([^/\s]+/[^/\s@]+)@", content)
    known_safe = {"actions", "github", "aws-actions", "azure", "google-github-actions", "docker"}
    risky = [a for a in third_party if a.split("/")[0].lower() not in known_safe]
    if risky:
        issues.append(f"Third-party actions: {', '.join(set(risky[:3]))} — review before trusting")

    return issues


def analyse_ci(repo: RepoData) -> CIReport:
    """Inspect CI/CD configuration files."""
    signals: list[str] = []
    dockerfile_issues: list[str] = []
    workflow_issues: list[str] = []
    ci_providers: list[str] = []

    has_dockerfile = False
    has_docker_compose = False
    has_tests_in_ci = False
    has_lint_in_ci = False
    has_security_scan = False
    has_release_automation = False
    has_caching = False
    has_ci = False

    all_workflow_content = ""

    for f in repo.files:
        fname = f.path.split("/")[-1].lower()
        fpath = f.path.lower()

        # Dockerfile
        if fname in ("dockerfile", "dockerfile.prod", "dockerfile.dev") or re.match(r"dockerfile\.", fname):
            has_dockerfile = True
            issues = _analyse_dockerfile(f.content)
            dockerfile_issues.extend(issues)

        # Docker Compose
        if fname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            has_docker_compose = True
            signals.append("Docker Compose configuration found")

        # GitHub Actions
        if ".github/workflows/" in fpath and (fname.endswith(".yml") or fname.endswith(".yaml")):
            has_ci = True
            if "github-actions" not in ci_providers:
                ci_providers.append("github-actions")
            all_workflow_content += f.content + "\n"
            wf_issues = _analyse_workflow(f.content, fname)
            workflow_issues.extend(wf_issues)

            t = f.content.lower()
            if re.search(r"(pytest|jest|cargo test|go test|npm test|yarn test|rspec|mocha)", t):
                has_tests_in_ci = True
            if re.search(r"(lint|eslint|pylint|flake8|ruff|prettier|golangci|rubocop|ktlint)", t):
                has_lint_in_ci = True
            if re.search(r"(trivy|snyk|codeql|dependabot|ossf|security|bandit|semgrep)", t):
                has_security_scan = True
            if re.search(r"(release|publish|deploy|push.*registry|npm publish|cargo publish)", t):
                has_release_automation = True
            if "cache" in t:
                has_caching = True

        # Other CI providers
        if fname in (".travis.yml", ".travis.yaml"):
            has_ci = True
            ci_providers.append("travis-ci")
        if fname in (".circleci/config.yml", "circle.yml") or ".circleci/" in fpath:
            has_ci = True
            if "circleci" not in ci_providers:
                ci_providers.append("circleci")
        if fname in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
            has_ci = True
            ci_providers.append("gitlab-ci")
        if fname in ("jenkinsfile",) or fname.startswith("jenkinsfile"):
            has_ci = True
            ci_providers.append("jenkins")
        if fname in ("bitbucket-pipelines.yml",):
            has_ci = True
            ci_providers.append("bitbucket-pipelines")
        if ".github/dependabot.yml" in fpath or ".github/dependabot.yaml" in fpath:
            has_security_scan = True
            signals.append("Dependabot configured for automated dependency updates")

    # ---- Scoring ----
    score = 0

    if has_ci:
        score += 25
        signals.append(f"CI via: {', '.join(ci_providers)}")
    else:
        signals.append("No CI/CD configuration found")

    if has_tests_in_ci:
        score += 20
        signals.append("Tests run in CI")
    else:
        signals.append("Tests NOT found in CI pipeline")

    if has_lint_in_ci:
        score += 10
        signals.append("Linting/formatting in CI")

    if has_dockerfile:
        score += 10
        signals.append("Dockerfile present")
    if has_docker_compose:
        score += 5

    if has_security_scan:
        score += 15
        signals.append("Security scanning configured (Dependabot, CodeQL, Snyk, etc.)")
    else:
        signals.append("No security scanning configured")

    if has_release_automation:
        score += 10
        signals.append("Release automation in CI")

    if has_caching:
        score += 5
        signals.append("Build caching configured")

    # Deduct for issues
    score -= min(20, len(dockerfile_issues) * 3)
    score -= min(20, len(workflow_issues) * 4)

    score = max(0, min(100, score))
    grade = _score_to_grade(score)

    issues_total = len(dockerfile_issues) + len(workflow_issues)
    if score >= 85:
        summary = f"Excellent CI/CD setup (Score {score}/100, Grade {grade}). Automated testing, linting, and security scanning in place."
    elif score >= 55:
        summary = f"Decent CI/CD (Score {score}/100, Grade {grade}). {issues_total} issues found. {'Missing security scanning. ' if not has_security_scan else ''}{'Missing test automation. ' if not has_tests_in_ci else ''}"
    elif has_ci:
        summary = f"CI exists but needs work (Score {score}/100, Grade {grade}). {issues_total} issues detected."
    else:
        summary = f"No CI/CD found (Score {score}/100, Grade {grade}). Add GitHub Actions for automated testing and deployment."

    return CIReport(
        score=score,
        grade=grade,
        has_ci=has_ci,
        ci_providers=ci_providers,
        has_dockerfile=has_dockerfile,
        has_docker_compose=has_docker_compose,
        has_tests_in_ci=has_tests_in_ci,
        has_lint_in_ci=has_lint_in_ci,
        has_security_scan=has_security_scan,
        has_release_automation=has_release_automation,
        has_caching=has_caching,
        dockerfile_issues=dockerfile_issues,
        workflow_issues=workflow_issues,
        signals=signals,
        summary=summary,
    )
