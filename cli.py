#!/usr/bin/env python3
"""
repo-xray CLI
Reverse-engineer any public GitHub repository into an AI prompt + learning guide.

Usage:
    python cli.py https://github.com/owner/repo
    python cli.py owner/repo --format markdown --output report.md
    python cli.py owner/repo --format json
    python cli.py owner/repo --verbose
"""

import argparse
import os
import sys

from src.fetcher import fetch_repo
from src.analyzer import analyse
from src.formatter import to_json, to_markdown, to_plain


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="repo-xray",
        description="Reverse-engineer any GitHub repo into an AI prompt + learning guide.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py https://github.com/fastapi/fastapi
  python cli.py vercel/next.js --format markdown --output nextjs-report.md
  python cli.py supabase/supabase --format json
  python cli.py django/django --verbose

API Keys (via env vars):
  GROQ_API_KEY    — Groq primary (fast, free tier)
  HF_API_TOKEN    — HuggingFace fallback
  GITHUB_TOKEN    — Optional: higher rate limits for private-ish repos
        """,
    )
    parser.add_argument("repo", help="GitHub URL or 'owner/repo'")
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

    if not groq_key and not hf_key:
        print(
            "Error: No API key found.\n"
            "Set GROQ_API_KEY (recommended) or HF_API_TOKEN environment variable.\n"
            "Get a free Groq key at https://console.groq.com",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        # Step 1: Fetch
        if args.verbose:
            print(f"[1/3] Fetching repository: {args.repo}")
        repo = fetch_repo(args.repo, token=gh_token or None, verbose=args.verbose)

        if args.verbose:
            print(f"      {len(repo.files)} source files fetched ({repo.stars:,} stars)")

        # Step 2: Analyse
        if args.verbose:
            print("[2/3] Running AI analysis...")
        analysis = analyse(repo, groq_api_key=groq_key, hf_api_key=hf_key, verbose=args.verbose)

        # Step 3: Format
        if args.verbose:
            print("[3/3] Formatting output...")
        if args.format == "json":
            output = to_json(analysis)
        elif args.format == "plain":
            output = to_plain(repo, analysis)
        else:
            output = to_markdown(repo, analysis)

        # Output
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
            if args.verbose:
                print(f"Done! Report saved to: {args.output}")
            else:
                print(f"Report saved to: {args.output}")
        else:
            print(output)

    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
