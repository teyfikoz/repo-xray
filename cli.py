#!/usr/bin/env python3
"""
repo-xray CLI
Reverse-engineer any public GitHub repository into an AI prompt + learning guide.

Usage:
    python cli.py https://github.com/owner/repo
    python cli.py owner/repo --format markdown --output report.md
    python cli.py owner/repo --mode security
    python cli.py owner/repo --mode full
    python cli.py owner/repo1 owner/repo2 --compare
    python cli.py owner/repo --changelog v1.0 v2.0
"""

import argparse
import json
import os
import sys

from src.fetcher import fetch_repo
from src.analyzer import analyse, analyse_full
from src.formatter import to_json, to_markdown, to_plain


def _print_security(result: dict) -> None:
    from src.security_audit import audit_security
    sec = result.get("security") or {}
    print(f"\n{'='*60}")
    print(f"SECURITY AUDIT — Score: {sec.get('score', '?')}/100 (Grade {sec.get('grade', '?')})")
    print(f"{'='*60}")
    print(sec.get("summary", ""))
    findings = sec.get("findings", [])
    if findings:
        print()
        for f in findings[:20]:
            print(f"  [{f['severity'].upper():8}] {f['file']}:{f['line']}")
            print(f"            {f['description']}")
            print(f"            → {f['snippet'][:100]}")
    print()


def _print_tech_debt(result: dict) -> None:
    td = result.get("tech_debt") or {}
    print(f"\n{'='*60}")
    print(f"TECH DEBT — Score: {td.get('score', '?')}/100 (Grade {td.get('grade', '?')})")
    print(f"{'='*60}")
    print(td.get("summary", ""))
    print(f"  LOC: {td.get('total_loc', 0):,} | Test ratio: {td.get('test_ratio_pct', 0)}% | Avg file: {td.get('avg_file_lines', 0)} lines | TODOs: {td.get('todo_count', 0)}")
    for item in td.get("items", []):
        print(f"  [{item['category']}] -{item['penalty']}pts  {item['value']}")
    print()


def _print_api_surface(result: dict) -> None:
    api = result.get("api_surface") or {}
    print(f"\n{'='*60}")
    print(f"API SURFACE — {api.get('count', 0)} endpoint(s)")
    print(f"{'='*60}")
    print(api.get("summary", ""))
    for ep in api.get("endpoints", []):
        print(f"  [{ep['method']:7}] {ep['path']:40} ({ep['framework']}, {ep['file']}:{ep['line']})")
    print()


def _print_dep_risk(result: dict) -> None:
    dep = result.get("dep_risk") or {}
    print(f"\n{'='*60}")
    print(f"DEPENDENCY RISK — Score: {dep.get('risk_score', '?')}/100 (Grade {dep.get('grade', '?')})")
    print(f"{'='*60}")
    print(dep.get("summary", ""))
    for f in dep.get("findings", []):
        print(f"  [{f['risk_level'].upper():8}] {f['name']} {f.get('version') or ''}: {f['reason']}")
    print()


def _print_cost(result: dict) -> None:
    cost = result.get("cost") or {}
    print(f"\n{'='*60}")
    print(f"COST ESTIMATE")
    print(f"{'='*60}")
    print(cost.get("summary", ""))
    print(f"\n  {'Category':<15} {'LOC':>8}  {'Hours':>8}  {'@ $25/hr':>10}  {'@ $90/hr':>10}  {'@ $200/hr':>10}")
    for b in cost.get("breakdown", []):
        print(f"  {b['category']:<15} {b['loc']:>8,}  {b['hours']:>8.0f}h")
    print(f"\n  TOTAL: {cost.get('total_loc', 0):,} LOC → {cost.get('effective_hours', 0):.0f} hrs")
    print(f"  Junior: ${cost.get('junior_usd', 0):,}  |  Senior: ${cost.get('senior_usd', 0):,}  |  Agency: ${cost.get('agency_usd', 0):,}")
    print(f"  Solo timeline: ~{cost.get('duration_weeks_solo', 0):.1f} weeks  |  Team (3 devs): ~{cost.get('duration_weeks_team', 0):.1f} weeks")
    print()


def _print_license(result: dict) -> None:
    lic = result.get("license_risk") or {}
    print(f"\n{'='*60}")
    print(f"LICENSE RISK — {lic.get('detected_license', 'Unknown')} (Grade {lic.get('grade', '?')})")
    print(f"{'='*60}")
    print(lic.get("summary", ""))
    print(f"\n  {lic.get('advice', '')}")
    for sig in lic.get("signals", []):
        print(f"  • {sig}")
    if lic.get("source_file"):
        print(f"\n  Detected from: {lic['source_file']}")
    print()


def _print_readme(result: dict) -> None:
    r = result.get("readme_quality") or {}
    print(f"\n{'='*60}")
    print(f"README QUALITY — Score: {r.get('score', '?')}/100 (Grade {r.get('grade', '?')})")
    print(f"{'='*60}")
    print(r.get("summary", ""))
    print(f"\n  Word count: {r.get('word_count', 0):,}")
    found = r.get("sections_found", [])
    missing = r.get("missing_sections", [])
    if found:
        print(f"  Sections found: {', '.join(found)}")
    if missing:
        print(f"  Missing sections: {', '.join(missing)}")
    for sig in r.get("signals", [])[:5]:
        print(f"  • {sig}")
    print()


def _print_code_quality(result: dict) -> None:
    cq = result.get("code_quality") or {}
    print(f"\n{'='*60}")
    print(f"CODE QUALITY — Score: {cq.get('score', '?')}/100 (Grade {cq.get('grade', '?')})")
    print(f"{'='*60}")
    print(cq.get("summary", ""))
    print(f"\n  Files: {cq.get('source_files', 0)} source / {cq.get('test_files', 0)} test")
    print(f"  Lines: {cq.get('total_lines', 0):,} total, avg {cq.get('avg_file_size', 0)} lines/file")
    print(f"  Test ratio: {cq.get('test_ratio', 0):.0%} | Doc coverage: {cq.get('doc_coverage', 0):.0%}")
    print(f"  Long functions: {cq.get('long_functions', 0)} | Large files: {cq.get('large_files', 0)} | TODOs: {cq.get('todo_count', 0)}")
    for smell in cq.get("smells", []):
        print(f"  ⚠  {smell}")
    print()


def _print_ci(result: dict) -> None:
    ci = result.get("ci") or {}
    print(f"\n{'='*60}")
    print(f"CI/CD ANALYSIS — Score: {ci.get('score', '?')}/100 (Grade {ci.get('grade', '?')})")
    print(f"{'='*60}")
    print(ci.get("summary", ""))
    providers = ci.get("ci_providers", [])
    if providers:
        print(f"\n  CI providers: {', '.join(providers)}")
    features = []
    if ci.get("has_tests_in_ci"):
        features.append("tests")
    if ci.get("has_lint_in_ci"):
        features.append("lint")
    if ci.get("has_security_scan"):
        features.append("security scan")
    if ci.get("has_caching"):
        features.append("caching")
    if features:
        print(f"  CI features: {', '.join(features)}")
    for issue in ci.get("dockerfile_issues", [])[:5]:
        print(f"  [Dockerfile] {issue}")
    for issue in ci.get("workflow_issues", [])[:5]:
        print(f"  [Workflow]   {issue}")
    print()


def _print_monetization(result: dict) -> None:
    m = result.get("monetization") or {}
    print(f"\n{'='*60}")
    print(f"MONETIZATION POTENTIAL — Score: {m.get('score', '?')}/100 (Grade {m.get('grade', '?')})")
    print(f"{'='*60}")
    print(m.get("summary", ""))
    print(f"\n  Category: {m.get('category', 'unknown')} | SaaS readiness: {m.get('saas_readiness', 0)}/10")
    models = m.get("monetization_models", [])
    if models:
        print(f"\n  Recommended models:")
        for i, model in enumerate(models[:4], 1):
            print(f"    {i}. {model}")
    recs = m.get("recommendations", [])
    if recs:
        print(f"\n  Action items:")
        for rec in recs[:3]:
            print(f"  → {rec}")
    print()


def _print_deployment(result: dict) -> None:
    d = result.get("deployment") or {}
    print(f"\n{'='*60}")
    print(f"DEPLOYMENT DETECTION")
    print(f"{'='*60}")
    print(d.get("summary", ""))
    platforms = d.get("platforms", [])
    if platforms:
        print(f"\n  Detected: {', '.join(platforms)}")
    flags = []
    if d.get("container_ready"):
        flags.append("container-ready")
    if d.get("serverless_ready"):
        flags.append("serverless-ready")
    if d.get("edge_ready"):
        flags.append("edge-ready")
    if flags:
        print(f"  Capabilities: {', '.join(flags)}")
    for missing in d.get("missing_configs", []):
        print(f"  • Missing: {missing}")
    print()


def _print_migration(result: dict) -> None:
    mg = result.get("migration") or {}
    print(f"\n{'='*60}")
    print(f"MIGRATION ADVISOR")
    print(f"{'='*60}")
    print(mg.get("summary", ""))
    stack = mg.get("current_stack", {})
    if stack:
        print(f"\n  Detected stack:")
        for layer, tech in stack.items():
            print(f"    {layer}: {tech}")
    warnings = mg.get("upgrade_warnings", [])
    if warnings:
        print(f"\n  Upgrade warnings:")
        for w in warnings:
            print(f"  ⚠  {w}")
    options = mg.get("migration_options", [])
    if options:
        print(f"\n  Migration opportunities:")
        for opt in options[:5]:
            print(f"  [{opt['priority'].upper():8}] {opt['from']} → {opt['to']} (effort: {opt['effort']})")
            print(f"              {opt['reason']}")
    print()


def _run_static_only(args, repo) -> dict:
    """Run only static analysis modules (no AI)."""
    from src.security_audit import audit_security
    from src.tech_debt import score_tech_debt
    from src.api_surface import extract_api_surface
    from src.dep_risk import analyse_dependencies
    from src.cost_estimator import estimate_cost
    from src.license_risk import analyse_license
    from src.readme_quality import analyse_readme
    from src.code_quality import score_code_quality
    from src.ci_analyzer import analyse_ci
    from src.monetization import analyse_monetization
    from src.deployment_detector import detect_deployment
    from src.migration_advisor import detect_migration_needs

    result: dict = {"mode": args.mode}

    if args.mode in ("security", "full"):
        if args.verbose:
            print("  Running security audit...")
        result["security"] = audit_security(repo).as_dict()

    if args.mode in ("tech-debt", "full"):
        if args.verbose:
            print("  Scoring tech debt...")
        result["tech_debt"] = score_tech_debt(repo).as_dict()

    if args.mode in ("api-surface", "full"):
        if args.verbose:
            print("  Extracting API surface...")
        result["api_surface"] = extract_api_surface(repo).as_dict()

    if args.mode in ("deps", "full"):
        if args.verbose:
            print("  Analysing dependencies...")
        result["dep_risk"] = analyse_dependencies(repo).as_dict()

    if args.mode in ("cost", "full"):
        if args.verbose:
            print("  Estimating cost...")
        result["cost"] = estimate_cost(repo).as_dict()

    if args.mode in ("license", "full"):
        if args.verbose:
            print("  Analysing license risk...")
        result["license_risk"] = analyse_license(repo).as_dict()

    if args.mode in ("readme", "full"):
        if args.verbose:
            print("  Scoring README quality...")
        result["readme_quality"] = analyse_readme(repo).as_dict()

    if args.mode in ("code-quality", "full"):
        if args.verbose:
            print("  Analysing code quality...")
        result["code_quality"] = score_code_quality(repo).as_dict()

    if args.mode in ("ci", "full"):
        if args.verbose:
            print("  Analysing CI/CD configuration...")
        result["ci"] = analyse_ci(repo).as_dict()

    if args.mode in ("monetization", "full"):
        if args.verbose:
            print("  Assessing monetization potential...")
        result["monetization"] = analyse_monetization(repo).as_dict()

    if args.mode in ("deployment", "full"):
        if args.verbose:
            print("  Detecting deployment configuration...")
        result["deployment"] = detect_deployment(repo).as_dict()

    if args.mode in ("migration", "full"):
        if args.verbose:
            print("  Running migration advisor...")
        result["migration"] = detect_migration_needs(repo).as_dict()

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="repo-xray",
        description="Reverse-engineer any GitHub repo into an AI prompt + learning guide.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py fastapi/fastapi
  python cli.py vercel/next.js --format markdown --output nextjs-report.md
  python cli.py supabase/supabase --format json
  python cli.py django/django --mode security
  python cli.py django/django --mode full --output full-report.json --format json
  python cli.py fastapi/fastapi flask/flask --compare
  python cli.py owner/repo --changelog v1.0.0 v2.0.0
  python cli.py owner/repo --stars-trend

Modes:
  ai           Default — AI analysis only (summary, tech stack, rebuild prompt, etc.)
  security     Static security audit (secrets, injection, XSS, weak crypto, etc.)
  tech-debt    Static tech debt scorer (TODOs, test ratio, god files, dead code)
  api-surface  Static API endpoint extractor (FastAPI, Express, Django, Flask, etc.)
  deps         Static dependency risk analysis (abandoned, vulnerable packages)
  cost         Static rebuild cost estimator (LOC-based, market rates)
  license      Static license risk (MIT/Apache/GPL/AGPL/Proprietary detection)
  readme       Static README quality scorer (sections, examples, word count)
  code-quality Static code quality (long functions, duplication, test ratio, smells)
  ci           Static CI/CD analyzer (Dockerfile best practices, Actions security)
  monetization Static monetization potential (SaaS readiness, model recommendations)
  deployment   Static deployment detector (Vercel/Netlify/Railway/Fly/K8s/Docker)
  migration    Static migration advisor (EOL tech, upgrade paths, effort estimates)
  full         All of the above combined

API Keys (via env vars):
  GROQ_API_KEY    — Groq primary (fast, free tier)
  HF_API_TOKEN    — HuggingFace fallback
  GITHUB_TOKEN    — Optional: higher rate limits
        """,
    )
    parser.add_argument("repos", nargs="+", help="GitHub URL(s) or 'owner/repo' (1-5 for --compare)")
    parser.add_argument(
        "--format", "-f",
        choices=["markdown", "json", "plain"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show progress messages",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=[
            "ai", "security", "tech-debt", "api-surface", "deps", "cost",
            "license", "readme", "code-quality", "ci", "monetization",
            "deployment", "migration", "full",
        ],
        default="ai",
        help="Analysis mode (default: ai)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare 2-5 repos side by side",
    )
    parser.add_argument(
        "--changelog",
        nargs=2,
        metavar=("BASE", "HEAD"),
        help="Compare two git refs and generate changelog (e.g. --changelog v1.0 v2.0)",
    )
    parser.add_argument(
        "--stars-trend",
        action="store_true",
        dest="stars_trend",
        help="Fetch and display star growth history",
    )
    parser.add_argument(
        "--groq-key",
        metavar="KEY",
        help="Groq API key (overrides GROQ_API_KEY env var)",
    )
    parser.add_argument(
        "--hf-key",
        metavar="KEY",
        help="HuggingFace API key (overrides HF_API_TOKEN env var)",
    )
    parser.add_argument(
        "--github-token",
        metavar="TOKEN",
        help="GitHub personal access token for higher rate limits",
    )

    args = parser.parse_args()

    groq_key = args.groq_key or os.environ.get("GROQ_API_KEY", "")
    hf_key = args.hf_key or os.environ.get("HF_API_TOKEN", "")
    gh_token = args.github_token or os.environ.get("GITHUB_TOKEN", "")

    # Static-only modes don't need an AI key
    static_only_modes = {
        "security", "tech-debt", "api-surface", "deps", "cost",
        "license", "readme", "code-quality", "ci", "monetization",
        "deployment", "migration",
    }
    needs_ai = args.mode not in static_only_modes or args.compare or args.changelog

    if needs_ai and not groq_key and not hf_key:
        print(
            "Error: No API key found.\n"
            "Set GROQ_API_KEY (recommended) or HF_API_TOKEN environment variable.\n"
            "Get a free Groq key at https://console.groq.com\n"
            f"Note: --mode {args.mode} requires an AI key.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        repo_url = args.repos[0]

        # ── Changelog mode ────────────────────────────────────────────────────
        if args.changelog:
            from src.fetcher import parse_github_url
            from src.changelog import analyse_changelog
            owner, repo_name = parse_github_url(repo_url)
            base, head = args.changelog
            if args.verbose:
                print(f"Comparing {base}..{head} in {owner}/{repo_name}...")
            report = analyse_changelog(owner, repo_name, base, head, gh_token or None, groq_key, hf_key)
            output = json.dumps(report.as_dict(), indent=2, ensure_ascii=False)
            _write_output(output, args)
            return

        # ── Stars trend mode ──────────────────────────────────────────────────
        if args.stars_trend:
            from src.fetcher import parse_github_url
            from src.stars_trend import fetch_stars_trend
            owner, repo_name = parse_github_url(repo_url)
            if args.verbose:
                print(f"Fetching star history for {owner}/{repo_name}...")
            trend = fetch_stars_trend(owner, repo_name, gh_token or None)
            output = json.dumps(trend.as_dict(), indent=2, ensure_ascii=False)
            _write_output(output, args)
            return

        # ── Compare mode ──────────────────────────────────────────────────────
        if args.compare:
            if len(args.repos) < 2:
                print("Error: --compare requires at least 2 repo arguments.", file=sys.stderr)
                sys.exit(1)
            from src.comparison import compare_repos
            if args.verbose:
                print(f"Comparing {len(args.repos)} repos...")
            report = compare_repos(
                args.repos,
                github_token=gh_token or None,
                groq_api_key=groq_key,
                hf_api_key=hf_key,
                verbose=args.verbose,
            )
            output = json.dumps(report.as_dict(), indent=2, ensure_ascii=False)
            _write_output(output, args)
            return

        # ── Standard single-repo modes ────────────────────────────────────────
        if args.verbose:
            print(f"[1/{3 if args.mode == 'ai' else 2}] Fetching repository: {repo_url}")

        repo = fetch_repo(repo_url, token=gh_token or None, verbose=args.verbose)

        if args.verbose:
            print(f"      {len(repo.files)} source files fetched ({repo.stars:,} stars)")

        if args.mode in static_only_modes:
            # Static analysis only — no AI call
            result = _run_static_only(args, repo)
            output = json.dumps(result, indent=2, ensure_ascii=False)

            # Pretty-print to stdout for non-JSON formats
            if args.format != "json" and not args.output:
                if "security" in result:
                    _print_security(result)
                if "tech_debt" in result:
                    _print_tech_debt(result)
                if "api_surface" in result:
                    _print_api_surface(result)
                if "dep_risk" in result:
                    _print_dep_risk(result)
                if "cost" in result:
                    _print_cost(result)
                if "license_risk" in result:
                    _print_license(result)
                if "readme_quality" in result:
                    _print_readme(result)
                if "code_quality" in result:
                    _print_code_quality(result)
                if "ci" in result:
                    _print_ci(result)
                if "monetization" in result:
                    _print_monetization(result)
                if "deployment" in result:
                    _print_deployment(result)
                if "migration" in result:
                    _print_migration(result)
                return

        elif args.mode == "full":
            if args.verbose:
                print("[2/2] Running full analysis (static + AI)...")
            result = analyse_full(repo, groq_api_key=groq_key, hf_api_key=hf_key, verbose=args.verbose)
        else:
            # ai mode (default)
            if args.verbose:
                print("[2/3] Running AI analysis...")
            result = analyse(repo, groq_api_key=groq_key, hf_api_key=hf_key, verbose=args.verbose)

        # Format output
        if args.verbose:
            print("[3/3] Formatting output...")
        if args.format == "json":
            output = to_json(result)
        elif args.format == "plain":
            output = to_plain(repo, result)
        else:
            output = to_markdown(repo, result)

        _write_output(output, args)

    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _write_output(output: str, args) -> None:
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        if args.verbose:
            print(f"Done! Report saved to: {args.output}")
        else:
            print(f"Report saved to: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
