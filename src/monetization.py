"""
Monetization Potential Analyzer — static, no AI tokens.
Scores a repo's commercial viability and suggests monetization strategies.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from .fetcher import RepoData


@dataclass
class MonetizationReport:
    score: int          # 0–100
    grade: str
    category: str       # tool / library / saas-ready / data / infra / game / content
    monetization_models: list[str]   # ordered by fit
    has_pricing_hints: bool
    has_auth: bool
    has_payment_hints: bool
    has_api: bool
    has_dashboard_ui: bool
    has_cli: bool
    is_library: bool
    saas_readiness: int   # 0–10
    open_core_potential: bool
    signals: list[str]
    recommendations: list[str]
    summary: str

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "category": self.category,
            "monetization_models": self.monetization_models,
            "has_pricing_hints": self.has_pricing_hints,
            "has_auth": self.has_auth,
            "has_payment_hints": self.has_payment_hints,
            "has_api": self.has_api,
            "has_dashboard_ui": self.has_dashboard_ui,
            "has_cli": self.has_cli,
            "is_library": self.is_library,
            "saas_readiness": self.saas_readiness,
            "open_core_potential": self.open_core_potential,
            "signals": self.signals,
            "recommendations": self.recommendations,
            "summary": self.summary,
        }


def _score_to_grade(score: int) -> str:
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def _detect_category(repo: RepoData, all_content: str) -> str:
    """Infer primary project category."""
    t = all_content.lower()
    fname_set = {f.path.split("/")[-1].lower() for f in repo.files}

    if repo.language in ("Jupyter Notebook",) or ".ipynb" in str(fname_set):
        return "data"
    if re.search(r"(setup\.py|pyproject\.toml|package\.json.*\"main\")", t) and "def " in t:
        return "library"
    if re.search(r"(pygame|unity|godot|phaser|three\.js)", t):
        return "game"
    if re.search(r"(flask|fastapi|express|nextjs|nuxt|rails|django|router\.get|@app\.route)", t):
        return "saas-ready"
    if re.search(r"(click|argparse|typer|commander|clap\b|cobra\b)", t):
        return "tool"
    if re.search(r"(docker|kubernetes|terraform|ansible|helm|k8s)", t):
        return "infra"
    if re.search(r"(blog|cms|hugo|jekyll|gatsby|contentful|mdx)", t):
        return "content"
    return "tool"


def analyse_monetization(repo: RepoData) -> MonetizationReport:
    """Assess monetization potential based on static signals."""
    signals: list[str] = []
    recommendations: list[str] = []

    all_content = "\n".join(f.content for f in repo.files)
    t = all_content.lower()
    readme_t = (repo.readme or "").lower()
    combined = t + readme_t

    # ---- Feature detection ----
    has_auth = bool(re.search(
        r"(jwt|bearer token|oauth|passport\.js|auth\.py|login_required|useauth|supabase\.auth"
        r"|nextauth|keycloak|clerk\.|firebase.*auth|magic.link|session.*secret)",
        combined
    ))

    has_payment_hints = bool(re.search(
        r"(stripe|paddle|lemonsqueezy|paypal|braintree|chargebee|recurly"
        r"|billing|subscription|checkout|invoice|proration|plan.*price)",
        combined
    ))

    has_pricing_hints = bool(re.search(
        r"(pricing|price|tier|free.plan|pro.plan|premium|enterprise|per.month|per.seat"
        r"|\$\d+|€\d+|£\d+|usd|monthly|annually)",
        readme_t
    ))

    has_api = bool(re.search(
        r"(router\.(get|post|put|delete|patch)|@app\.route|@router\.|rest.api"
        r"|graphql|openapi|swagger|api_key|rate.limit)",
        combined
    ))

    has_dashboard_ui = bool(re.search(
        r"(dashboard|admin.panel|analytics|chart|graph|visualization|recharts"
        r"|tremor|shadcn|tailwind.*ui|material.ui|antd|chakra)",
        combined
    ))

    has_cli = bool(re.search(
        r"(argparse|click\b|typer\b|commander\.js|yargs|clap\b|cobra\b|bin.*script|#!/)",
        combined
    ))

    # Library detection: has setup.py/pyproject/package.json with main entry + no web server
    is_library = bool(re.search(
        r"(\"main\":\s*\"[^\"]+\"|setup\(|setuptools|from setuptools|exports\.)",
        combined
    )) and not has_api

    open_core_potential = bool(re.search(
        r"(plugin|extension|hook|middleware|provider|adapter|connector|integration)",
        combined
    ))

    # ---- SaaS readiness score (0-10) ----
    saas_score = 0
    if has_auth:
        saas_score += 3
        signals.append("Authentication system detected")
    if has_payment_hints:
        saas_score += 3
        signals.append("Payment/billing integration hints")
    if has_api:
        saas_score += 2
        signals.append("REST/GraphQL API detected")
    if has_dashboard_ui:
        saas_score += 1
        signals.append("Dashboard UI components detected")
    if repo.stars > 100:
        saas_score += 1
        signals.append(f"Market validation: {repo.stars:,} GitHub stars")

    category = _detect_category(repo, combined)
    signals.append(f"Project category: {category}")

    # ---- Monetization models ranking ----
    models: list[tuple[int, str]] = []

    if category == "library":
        models += [
            (90, "Open Source + Paid Support/Consulting"),
            (80, "Open Core (free OSS + paid enterprise features)"),
            (60, "Hosted managed version (SaaS wrapper)"),
            (50, "Sponsorware / GitHub Sponsors"),
        ]
        recommendations.append("Create a hosted SaaS version with a free tier — many successful libraries have done this (e.g. Sentry, PostHog)")
        recommendations.append("Add enterprise features (SSO, audit logs, SLA) gated behind a commercial license")

    elif category == "saas-ready":
        models += [
            (95, "SaaS subscription (monthly/annual tiers)"),
            (85, "Freemium (free tier + paid features)"),
            (70, "API access tiers (rate limits + usage billing)"),
            (60, "White-label / OEM licensing"),
        ]
        recommendations.append("Add Stripe/Paddle for subscriptions — the backend is already web-server ready")
        if not has_auth:
            recommendations.append("Implement user authentication first — required for subscription gating")
        if not has_payment_hints:
            recommendations.append("Integrate a payment processor (Stripe/Paddle) to unlock SaaS revenue")

    elif category == "tool":
        models += [
            (80, "CLI tool → paid Pro version with advanced features"),
            (75, "Hosted web version of the CLI tool"),
            (60, "One-time purchase (Gumroad/Lemon Squeezy)"),
            (50, "SaaS API wrapper"),
        ]
        recommendations.append("Build a web UI around the CLI — many devs pay for convenience")
        recommendations.append("One-time paid binary/plugin via Gumroad or Lemon Squeezy — low friction")

    elif category == "data":
        models += [
            (85, "Data-as-a-Service (API with usage billing)"),
            (80, "Premium dataset access (subscription)"),
            (60, "Consulting / custom analysis service"),
            (50, "Jupyter-based course or tutorial product"),
        ]
        recommendations.append("Wrap the analysis in a REST API and offer usage-based pricing")

    elif category == "infra":
        models += [
            (85, "Managed hosted version (remove DevOps pain)"),
            (75, "Support contracts + SLA"),
            (65, "Enterprise license for advanced features"),
        ]
        recommendations.append("Offer a hosted/managed tier — engineers pay to avoid running infra")

    else:
        models += [
            (70, "SaaS subscription"),
            (60, "Freemium"),
            (50, "One-time purchase"),
        ]

    if open_core_potential:
        models.append((72, "Open core (commercial plugin/extension marketplace)"))
        signals.append("Plugin/extension architecture detected — open core model viable")

    if has_pricing_hints:
        signals.append("Pricing/tier hints already in README")
        recommendations.insert(0, "Pricing concept exists — implement payment gating next")

    models.sort(key=lambda x: x[0], reverse=True)
    monetization_models = [m[1] for m in models]

    # ---- Overall score ----
    score = 20  # base
    score += saas_score * 5       # 0–50
    if has_payment_hints:
        score += 10
    if has_pricing_hints:
        score += 5
    if repo.stars > 50:
        score += 5
    if repo.stars > 500:
        score += 5
    if open_core_potential:
        score += 5

    score = max(0, min(100, score))
    grade = _score_to_grade(score)

    if score >= 80:
        summary = (f"High monetization potential (Score {score}/100, Grade {grade}). "
                   f"Category: {category}. Recommended model: {monetization_models[0]}.")
    elif score >= 50:
        summary = (f"Moderate monetization potential (Score {score}/100, Grade {grade}). "
                   f"With {len(recommendations)} improvements, this could be a revenue-generating product.")
    else:
        summary = (f"Early-stage monetization potential (Score {score}/100, Grade {grade}). "
                   f"Needs auth, payments, and UI before it can charge users.")

    return MonetizationReport(
        score=score,
        grade=grade,
        category=category,
        monetization_models=monetization_models,
        has_pricing_hints=has_pricing_hints,
        has_auth=has_auth,
        has_payment_hints=has_payment_hints,
        has_api=has_api,
        has_dashboard_ui=has_dashboard_ui,
        has_cli=has_cli,
        is_library=is_library,
        saas_readiness=saas_score,
        open_core_potential=open_core_potential,
        signals=signals,
        recommendations=recommendations,
        summary=summary,
    )
