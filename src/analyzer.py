"""
AI analysis engine.
Groq (llama-3.3-70b-versatile) primary — HuggingFace router fallback.

Modes:
  ai       — AI-only analysis (original behaviour)
  full     — AI + all static modules combined into one report
"""

import json
import os
import urllib.request
import urllib.error
from typing import Optional
from .fetcher import RepoData

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
HF_API_URL = "https://router.huggingface.co/v1/chat/completions"

GROQ_MODEL = "llama-3.3-70b-versatile"
HF_MODEL = "meta-llama/Llama-3.3-70B-Instruct"


def _build_context(repo: RepoData) -> str:
    """Assemble the repo content into a single context string."""
    lines = [
        f"# Repository: {repo.full_name}",
        f"Description: {repo.description}",
        f"Primary language: {repo.language}",
        f"Stars: {repo.stars:,} | Forks: {repo.forks:,}",
        f"Topics: {', '.join(repo.topics) if repo.topics else 'none'}",
        "",
    ]
    if repo.readme:
        lines.append("## README (excerpt)")
        lines.append(repo.readme[:1500])
        lines.append("")

    lines.append(f"## Source Files ({len(repo.files)} files)")
    for f in repo.files:
        lines.append(f"\n### {f.path}")
        lines.append("```")
        lines.append(f.content)
        lines.append("```")

    return "\n".join(lines)


SYSTEM_PROMPT = """You are an expert software architect and technical educator.
Your job is to analyse GitHub repositories and produce clear, insightful reports
that help developers understand and learn from any codebase quickly.

Be concise, precise, and use plain English. Avoid filler phrases."""

ANALYSIS_PROMPT = """Analyse the following GitHub repository and return a JSON object with these exact keys:

{
  "summary": "2-3 sentence plain-English description of what this project does and who it is for",
  "tech_stack": ["list", "of", "technologies", "frameworks", "libraries"],
  "architecture": "2-3 sentences describing the overall architecture pattern (MVC, microservices, monolith, etc.)",
  "key_files": [
    {"path": "relative/path", "role": "what this file does in one sentence"}
  ],
  "difficulty": "beginner | intermediate | advanced",
  "learning_insights": [
    "Insight 1: something interesting or non-obvious about this codebase",
    "Insight 2: a pattern or technique worth learning from",
    "Insight 3: a design decision that stands out"
  ],
  "ai_rebuild_prompt": "A detailed prompt you would give an AI coding agent to recreate this project from scratch. Include stack, architecture, key features, and data models.",
  "quick_start_guide": "Step-by-step instructions to clone, set up, and run this project locally (5-8 steps)",
  "similar_projects": ["project or library name developers coming from this repo might also explore"],
  "fun_fact": "One surprising, delightful, or counterintuitive fact about this codebase or the tech it uses"
}

Return ONLY valid JSON. No markdown fences, no extra text.

REPOSITORY CONTENT:
"""


def _call_api(url: str, headers: dict, payload: dict) -> str:
    """Make an OpenAI-compatible chat completion API call."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    req.add_header("User-Agent", "OpenAI/Python 1.0.0")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            return result["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"API error {e.code}: {body[:300]}") from e


def analyse(
    repo: RepoData,
    groq_api_key: Optional[str] = None,
    hf_api_key: Optional[str] = None,
    verbose: bool = False,
) -> dict:
    """Run AI analysis on repo data. Returns parsed JSON dict."""
    groq_key = groq_api_key or os.environ.get("GROQ_API_KEY", "")
    hf_key = hf_api_key or os.environ.get("HF_API_TOKEN", "")

    context = _build_context(repo)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": ANALYSIS_PROMPT + context},
    ]
    payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 4096,
        "response_format": {"type": "json_object"},
    }

    raw_content = ""

    # Try Groq first
    if groq_key:
        if verbose:
            print("  Calling Groq API...")
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {groq_key}",
            }
            raw_content = _call_api(GROQ_API_URL, headers, payload)
        except Exception as e:
            if verbose:
                print(f"  Groq failed: {e} — trying HuggingFace fallback...")

    # HuggingFace fallback
    if not raw_content and hf_key:
        if verbose:
            print("  Calling HuggingFace API...")
        try:
            hf_payload = dict(payload)
            hf_payload["model"] = HF_MODEL
            hf_payload.pop("response_format", None)  # HF doesn't support json_object mode
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {hf_key}",
            }
            raw_content = _call_api(HF_API_URL, headers, hf_payload)
        except Exception as e:
            raise RuntimeError(f"Both Groq and HuggingFace failed. Last error: {e}") from e

    if not raw_content:
        raise RuntimeError(
            "No API key provided. Set GROQ_API_KEY or HF_API_TOKEN environment variable."
        )

    # Parse JSON (strip possible markdown fences)
    content = raw_content.strip()
    if content.startswith("```"):
        content = content.split("```", 2)[1]
        if content.startswith("json"):
            content = content[4:]
        content = content.rsplit("```", 1)[0]

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse AI response as JSON: {e}\nRaw:\n{content[:500]}") from e


def analyse_full(
    repo: RepoData,
    groq_api_key: Optional[str] = None,
    hf_api_key: Optional[str] = None,
    verbose: bool = False,
) -> dict:
    """
    Full analysis: runs all static modules + AI analysis in one pass.
    Returns merged dict with keys from all modules.
    """
    from .security_audit import audit_security
    from .tech_debt import score_tech_debt
    from .api_surface import extract_api_surface
    from .dep_risk import analyse_dependencies
    from .cost_estimator import estimate_cost
    from .license_risk import analyse_license
    from .readme_quality import analyse_readme
    from .code_quality import score_code_quality
    from .ci_analyzer import analyse_ci
    from .monetization import analyse_monetization
    from .deployment_detector import detect_deployment
    from .migration_advisor import detect_migration_needs

    if verbose:
        print("  [static] Security audit...")
    security = audit_security(repo)

    if verbose:
        print("  [static] Tech debt scoring...")
    tech_debt = score_tech_debt(repo)

    if verbose:
        print("  [static] API surface extraction...")
    api_surface = extract_api_surface(repo)

    if verbose:
        print("  [static] Dependency risk analysis...")
    dep_risk = analyse_dependencies(repo)

    if verbose:
        print("  [static] Cost estimation...")
    cost = estimate_cost(repo)

    if verbose:
        print("  [static] License risk analysis...")
    license_risk = analyse_license(repo)

    if verbose:
        print("  [static] README quality scoring...")
    readme_quality = analyse_readme(repo)

    if verbose:
        print("  [static] Code quality analysis...")
    code_quality = score_code_quality(repo)

    if verbose:
        print("  [static] CI/CD analysis...")
    ci = analyse_ci(repo)

    if verbose:
        print("  [static] Monetization potential...")
    monetization = analyse_monetization(repo)

    if verbose:
        print("  [static] Deployment detection...")
    deployment = detect_deployment(repo)

    if verbose:
        print("  [static] Migration advisor...")
    migration = detect_migration_needs(repo)

    if verbose:
        print("  [AI] Running AI analysis...")
    ai = analyse(repo, groq_api_key=groq_api_key, hf_api_key=hf_api_key, verbose=verbose)

    return {
        **ai,
        "security": security.as_dict(),
        "tech_debt": tech_debt.as_dict(),
        "api_surface": api_surface.as_dict(),
        "dep_risk": dep_risk.as_dict(),
        "cost": cost.as_dict(),
        "license_risk": license_risk.as_dict(),
        "readme_quality": readme_quality.as_dict(),
        "code_quality": code_quality.as_dict(),
        "ci": ci.as_dict(),
        "monetization": monetization.as_dict(),
        "deployment": deployment.as_dict(),
        "migration": migration.as_dict(),
    }
