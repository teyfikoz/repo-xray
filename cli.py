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


def _run_static_only(args, repo) -> dict:
    """Run only static analysis modules (no AI)."""
    from src.security_audit import audit_security
    from src.tech_debt import score_tech_debt
    from src.api_surface import extract_api_surface
    from src.dep_risk import analyse_dependencies
    from src.cost_estimator import estimate_cost

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
        choices=["ai", "security", "tech-debt", "api-surface", "deps", "cost", "full"],
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
    static_only_modes = {"security", "tech-debt", "api-surface", "deps", "cost"}
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
