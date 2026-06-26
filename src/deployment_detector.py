"""
Deployment Detector — static, no AI tokens.
Detects which deployment platforms the repo is configured for and
gives readiness scores + setup advice.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from .fetcher import RepoData


@dataclass
class DeploymentReport:
    platforms: list[str]           # detected platforms
    primary_platform: str          # best match
    container_ready: bool
    serverless_ready: bool
    edge_ready: bool
    self_hosted_ready: bool
    platform_details: dict         # platform → {score, config_file, notes}
    missing_configs: list[str]     # recommended but absent
    signals: list[str]
    summary: str

    def as_dict(self) -> dict:
        return {
            "platforms": self.platforms,
            "primary_platform": self.primary_platform,
            "container_ready": self.container_ready,
            "serverless_ready": self.serverless_ready,
            "edge_ready": self.edge_ready,
            "self_hosted_ready": self.self_hosted_ready,
            "platform_details": self.platform_details,
            "missing_configs": self.missing_configs,
            "signals": self.signals,
            "summary": self.summary,
        }


# (platform_name, config_file_patterns, content_patterns, category)
PLATFORM_SIGNATURES: list[tuple[str, list[str], list[str], str]] = [
    ("Vercel",
     ["vercel.json", ".vercelignore"],
     [r"\"builds\":", r"vercel\b", r"@vercel/"],
     "serverless"),

    ("Netlify",
     ["netlify.toml", "_redirects", "_headers"],
     [r"netlify\b", r"\[build\]\s*command", r"netlify-cli"],
     "serverless"),

    ("Railway",
     ["railway.toml", "railway.json", "Procfile"],
     [r"railway\b", r"railway\.app"],
     "paas"),

    ("Fly.io",
     ["fly.toml"],
     [r"fly\.io", r"\[fly\b"],
     "paas"),

    ("Render",
     ["render.yaml", "render.yml"],
     [r"render\b", r"render\.com"],
     "paas"),

    ("Heroku",
     ["Procfile", "app.json"],
     [r"heroku\b", r"process\.env\.PORT"],
     "paas"),

    ("AWS",
     ["serverless.yml", "serverless.yaml", "template.yaml", "template.json",
      "cdk.json", "amplify.yml", ".elasticbeanstalk/config.yml"],
     [r"aws-cdk|aws-lambda|amazonaws|serverless framework|amplify", r"CloudFormation"],
     "cloud"),

    ("GCP",
     ["app.yaml", "cloudbuild.yaml", "cloudbuild.yml"],
     [r"google.*cloud|cloud.run|app.engine|gcloud\b"],
     "cloud"),

    ("Azure",
     ["azure-pipelines.yml", ".azure/", "azure-deploy.json"],
     [r"azure\b|microsoft.*azure"],
     "cloud"),

    ("Docker / Self-hosted",
     ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml"],
     [r"FROM\s+\w", r"services:\n"],
     "container"),

    ("Kubernetes",
     ["k8s/", "kubernetes/", "helm/", "Chart.yaml"],
     [r"apiVersion:\s*v\d", r"kind:\s*(Deployment|Service|Ingress|Pod)"],
     "container"),

    ("GitHub Pages",
     [".github/workflows/pages.yml", ".github/workflows/gh-pages.yml", "docs/"],
     [r"github.*pages|gh-pages|pages-build-deployment"],
     "static"),

    ("Cloudflare Workers",
     ["wrangler.toml", "wrangler.json"],
     [r"cloudflare.*workers|wrangler\b"],
     "edge"),

    ("Deno Deploy",
     ["deno.json", "deno.jsonc"],
     [r"deno\.land|deno deploy"],
     "edge"),

    ("Supabase",
     ["supabase/config.toml"],
     [r"supabase\b"],
     "baas"),
]


def detect_deployment(repo: RepoData) -> DeploymentReport:
    """Detect deployment platform configurations."""
    signals: list[str] = []
    platform_details: dict = {}
    platforms: list[str] = []

    all_content = "\n".join(f.content for f in repo.files)
    fname_set = {f.path.lower() for f in repo.files}
    fname_basename_set = {f.path.split("/")[-1].lower() for f in repo.files}

    for platform, file_patterns, content_patterns, category in PLATFORM_SIGNATURES:
        score = 0
        config_files = []
        notes = []

        # File match
        for fp in file_patterns:
            fp_lower = fp.lower()
            if any(fp_lower in fn for fn in fname_set) or fp_lower in fname_basename_set:
                score += 40
                config_files.append(fp)

        # Content match
        for pattern in content_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                score += 20

        if score >= 40:
            platforms.append(platform)
            platform_details[platform] = {
                "confidence": min(100, score),
                "config_files": config_files,
                "category": category,
                "notes": notes,
            }

    # ---- Category flags ----
    categories_found = {d["category"] for d in platform_details.values()}
    container_ready = "container" in categories_found or any(
        p in platforms for p in ("Docker / Self-hosted", "Kubernetes")
    )
    serverless_ready = "serverless" in categories_found or any(
        p in platforms for p in ("Vercel", "Netlify", "AWS")
    )
    edge_ready = "edge" in categories_found
    self_hosted_ready = container_ready

    # Primary platform (highest confidence)
    primary_platform = "Unknown"
    if platform_details:
        primary_platform = max(platform_details, key=lambda p: platform_details[p]["confidence"])
        signals.append(f"Primary deployment: {primary_platform}")

    for p in platforms:
        cfs = platform_details[p].get("config_files", [])
        signals.append(f"{p}: config={', '.join(cfs) if cfs else 'detected via content'}")

    # ---- Missing configs recommendation ----
    missing_configs: list[str] = []
    if not container_ready:
        missing_configs.append("Add Dockerfile for container portability")
    if not serverless_ready and platforms:
        missing_configs.append("Add vercel.json or netlify.toml for one-click cloud deployment")
    if not any(".github/workflows" in fn for fn in fname_set):
        missing_configs.append("Add GitHub Actions workflow for CI/CD automation")

    if not platforms:
        signals.append("No deployment configuration detected")
        summary = "No deployment platform detected. Add a Dockerfile + GitHub Actions workflow to get started."
    elif len(platforms) == 1:
        summary = f"Configured for {platforms[0]}. {len(missing_configs)} additional deployment options available."
    else:
        summary = f"Multi-platform deployment: {', '.join(platforms[:3])}{'...' if len(platforms) > 3 else ''}. Primary: {primary_platform}."

    return DeploymentReport(
        platforms=platforms,
        primary_platform=primary_platform,
        container_ready=container_ready,
        serverless_ready=serverless_ready,
        edge_ready=edge_ready,
        self_hosted_ready=self_hosted_ready,
        platform_details=platform_details,
        missing_configs=missing_configs,
        signals=signals,
        summary=summary,
    )
