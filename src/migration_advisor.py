"""
Migration Advisor — static detection + optional AI deep-dive.
Detects the current tech stack and suggests migration paths with effort estimates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from .fetcher import RepoData


@dataclass
class MigrationAdvisorReport:
    current_stack: dict          # {layer: technology}
    migration_options: list[dict]  # [{from, to, reason, effort, priority}]
    upgrade_warnings: list[str]  # deprecated/EOL versions found
    compatibility_risks: list[str]
    signals: list[str]
    summary: str

    def as_dict(self) -> dict:
        return {
            "current_stack": self.current_stack,
            "migration_options": self.migration_options,
            "upgrade_warnings": self.upgrade_warnings,
            "compatibility_risks": self.compatibility_risks,
            "signals": self.signals,
            "summary": self.summary,
        }


# ---- Stack detection patterns ----
STACK_PATTERNS = {
    "language": [
        ("Python 2",    r"print\s+['\"]|from __future__ import print|python_requires.*['\"]2\.",  "deprecated"),
        ("Python 3",    r"python_requires.*['\"]3\.|#!/usr/bin/env python3|from typing import",   "current"),
        ("TypeScript",  r"\.tsx?$|tsconfig\.json|\"typescript\":",                                 "current"),
        ("JavaScript",  r"\.js$|\.jsx$",                                                           "current"),
        ("Go",          r"go\.mod|package main|func main\(\)",                                     "current"),
        ("Rust",        r"Cargo\.toml|fn main\(\)|use std::",                                      "current"),
        ("Java",        r"pom\.xml|build\.gradle|public static void main",                          "current"),
        ("Ruby",        r"Gemfile|\.rb$|def initialize",                                            "current"),
        ("PHP",         r"composer\.json|<\?php|\$_GET|\$_POST",                                   "aging"),
    ],
    "framework": [
        ("Next.js",     r"next\.config\.(js|mjs|ts)|from 'next/|\"next\":",        "current"),
        ("React",       r"from 'react'|import React|jsx|tsx",                       "current"),
        ("Vue 3",       r"vue@3|\"vue\":\s*\"3|createApp\(|<script setup",          "current"),
        ("Vue 2",       r"vue@2|\"vue\":\s*\"2|new Vue\(",                           "aging"),
        ("Angular",     r"@angular/core|ng serve|angular\.json",                    "current"),
        ("Svelte",      r"svelte|\.svelte$",                                         "current"),
        ("Express",     r"express\(\)|app\.use\(|app\.get\(",                       "aging"),
        ("Fastify",     r"fastify\b|fastify\(\)",                                   "current"),
        ("FastAPI",     r"from fastapi|FastAPI\(\)|@app\.(get|post)",               "current"),
        ("Flask",       r"from flask|Flask\(__name__\)|@app\.route",                "aging"),
        ("Django",      r"from django|INSTALLED_APPS|urls\.py",                     "current"),
        ("Rails",       r"Rails\.application|ActiveRecord|config\.routes",          "aging"),
        ("NestJS",      r"@nestjs/|@Module\(|@Injectable\(",                        "current"),
    ],
    "database": [
        ("PostgreSQL",  r"psycopg2|pg\b|postgres|@prisma.*postgresql|asyncpg",    "current"),
        ("MySQL",       r"mysql2?|pymysql|\"mysql\":",                              "aging"),
        ("MongoDB",     r"mongoose|pymongo|mongodb\+srv|MongoClient",               "current"),
        ("SQLite",      r"sqlite3|\.db$|SQLite",                                    "development"),
        ("Redis",       r"redis\b|ioredis|redis-py|celery",                        "current"),
        ("Prisma",      r"prisma\b|schema\.prisma|@prisma/client",                 "current"),
        ("Drizzle",     r"drizzle-orm|drizzle\b",                                  "current"),
        ("Supabase",    r"supabase\b|createClient.*supabase",                      "current"),
        ("Firebase",    r"firebase\b|firestore|initializeApp",                     "current"),
    ],
    "css": [
        ("Tailwind CSS",     r"tailwindcss|tailwind\.config|class.*\"[a-z]+-\d|className.*\"flex", "current"),
        ("CSS Modules",      r"\.module\.css|styles\[|styles\.",                                    "current"),
        ("Styled Components",r"styled-components|styled\.\w+`|createGlobalStyle",                  "aging"),
        ("Sass/SCSS",        r"\.scss$|\.sass$|@import\s+'",                                       "aging"),
        ("Bootstrap",        r"bootstrap\b|btn-primary|col-md-",                                   "aging"),
    ],
    "build_tool": [
        ("Vite",        r"vite\b|vite\.config\.(js|ts)|\"vite\":",          "current"),
        ("Webpack",     r"webpack\.config|\"webpack\":|new webpack\.",       "aging"),
        ("Turbo",       r"turbo\.json|turbopack|\"turbo\":",                 "current"),
        ("esbuild",     r"esbuild\b",                                        "current"),
        ("Rollup",      r"rollup\.config|\"rollup\":",                       "aging"),
        ("Parcel",      r"\"parcel\":",                                       "aging"),
        ("Create React App", r"react-scripts|create-react-app",             "deprecated"),
    ],
    "runtime": [
        ("Node.js",     r"node\b|\.nvmrc|\.node-version|\bprocess\.env",    "current"),
        ("Bun",         r"bun\b|bun\.lockb",                                 "current"),
        ("Deno",        r"deno\b|deno\.json",                                "current"),
    ],
    "package_manager": [
        ("pnpm",        r"pnpm-lock\.yaml|\"packageManager\".*pnpm",        "current"),
        ("yarn",        r"yarn\.lock|\"packageManager\".*yarn",              "current"),
        ("npm",         r"package-lock\.json",                               "current"),
        ("bun",         r"bun\.lockb",                                       "current"),
        ("pip",         r"requirements\.txt|pip install",                    "current"),
        ("poetry",      r"pyproject\.toml.*poetry|poetry\.lock",            "current"),
        ("uv",          r"uv\.lock|\"uv\":",                                 "current"),
    ],
}

# Migration suggestions: (from_pattern, to, reason, effort)
MIGRATION_RULES = [
    ("Create React App", "Vite",        "CRA is deprecated and unmaintained. Vite is 10-100x faster.", "low",    "critical"),
    ("Webpack",          "Vite",        "Vite cold starts ~10x faster for most SPAs.",                 "medium", "high"),
    ("Styled Components","Tailwind CSS","Tailwind eliminates runtime CSS-in-JS overhead.",              "high",   "medium"),
    ("Bootstrap",        "Tailwind CSS","Tailwind offers better customization with less bloat.",        "high",   "low"),
    ("Sass/SCSS",        "Tailwind CSS","Modern utility-first CSS — lower maintenance burden.",         "medium", "low"),
    ("Flask",            "FastAPI",     "FastAPI is async, typed, and 2-3x faster under load.",        "medium", "high"),
    ("Express",          "Fastify",     "Fastify is 2x faster and has native TypeScript support.",     "medium", "medium"),
    ("Vue 2",            "Vue 3",       "Vue 2 reached EOL Jan 2024 — security risk.",                 "medium", "critical"),
    ("Python 2",         "Python 3",    "Python 2 is EOL since 2020 — serious security risk.",         "high",   "critical"),
    ("MySQL",            "PostgreSQL",  "PostgreSQL has better JSON support, window functions, and extensions.", "high", "medium"),
    ("SQLite",           "PostgreSQL",  "SQLite is great for dev but lacks concurrency for production.", "medium", "high"),
    ("npm",              "pnpm",        "pnpm is 2-3x faster and uses less disk space with symlinks.", "low",    "low"),
    ("Rollup",           "Vite",        "Vite wraps Rollup with a faster dev server experience.",       "low",    "medium"),
]

EOL_WARNINGS = [
    ("Python 2",         "Python 2 reached end-of-life in January 2020"),
    ("Vue 2",            "Vue 2 reached end-of-life in December 2023"),
    ("Create React App", "Create React App is deprecated (no active maintenance since 2023)"),
    ("Angular 1",        "AngularJS reached end-of-life in December 2021"),
    ("Bootstrap",        "Bootstrap 3/4 has no security patches — upgrade to Bootstrap 5 or migrate to Tailwind"),
    ("Webpack",          "Webpack 4 is EOL — if using v4, upgrade to v5 or migrate to Vite"),
]


def detect_migration_needs(repo: RepoData) -> MigrationAdvisorReport:
    """Detect current stack and recommend migrations."""
    signals: list[str] = []
    upgrade_warnings: list[str] = []
    compatibility_risks: list[str] = []
    migration_options: list[dict] = []
    current_stack: dict = {}

    all_content = "\n".join(f.content for f in repo.files)
    readme_t = (repo.readme or "").lower()
    combined = all_content + "\n" + readme_t

    # ---- Detect current stack ----
    for layer, technologies in STACK_PATTERNS.items():
        for tech_name, pattern, status in technologies:
            if re.search(pattern, combined, re.IGNORECASE | re.MULTILINE):
                if layer not in current_stack:
                    current_stack[layer] = tech_name
                signals.append(f"{layer}: {tech_name} ({status})")

                # EOL warning
                for eol_tech, warning in EOL_WARNINGS:
                    if eol_tech.lower() == tech_name.lower():
                        upgrade_warnings.append(warning)
                break  # first match wins per layer

    # ---- Build migration options ----
    detected_techs = set(current_stack.values())

    for from_tech, to_tech, reason, effort, priority in MIGRATION_RULES:
        if from_tech in detected_techs:
            migration_options.append({
                "from": from_tech,
                "to": to_tech,
                "reason": reason,
                "effort": effort,       # low / medium / high
                "priority": priority,   # low / medium / high / critical
            })

    # Sort: critical first, then high
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    migration_options.sort(key=lambda x: priority_order.get(x["priority"], 4))

    # ---- Compatibility risks ----
    if "Python 3" in detected_techs and "Python 2" in detected_techs:
        compatibility_risks.append("Mixed Python 2/3 syntax detected — ensure 3.x only")

    if "Vue 2" in detected_techs and "Vue 3" in detected_techs:
        compatibility_risks.append("Vue 2 and Vue 3 patterns both detected — mixed migration state")

    if "Webpack" in detected_techs and "Vite" in detected_techs:
        compatibility_risks.append("Both Webpack and Vite detected — check which is actually used")

    # Node version compatibility
    node_version_match = re.search(r"node.*(\d+)\.", combined, re.IGNORECASE)
    if node_version_match:
        v = int(node_version_match.group(1))
        if v < 18:
            compatibility_risks.append(f"Node.js v{v} detected — upgrade to v20 LTS (v16 is EOL)")

    # Python version
    py_match = re.search(r"python_requires.*['\"]>=?\s*3\.(\d+)", combined)
    if py_match:
        minor = int(py_match.group(1))
        if minor < 9:
            compatibility_risks.append(f"Python 3.{minor} target — consider 3.11+ for performance improvements")

    stack_summary = ", ".join(f"{k}: {v}" for k, v in list(current_stack.items())[:5])
    critical_count = sum(1 for m in migration_options if m["priority"] == "critical")

    if critical_count > 0:
        summary = (f"Stack: {stack_summary}. CRITICAL: {critical_count} end-of-life technology/ies requiring immediate migration. "
                   f"{len(migration_options)} total migration opportunities.")
    elif migration_options:
        summary = (f"Stack: {stack_summary}. {len(migration_options)} migration opportunities identified. "
                   f"Top recommendation: migrate from {migration_options[0]['from']} → {migration_options[0]['to']}.")
    else:
        summary = f"Modern stack detected: {stack_summary}. No critical migrations needed."

    return MigrationAdvisorReport(
        current_stack=current_stack,
        migration_options=migration_options,
        upgrade_warnings=upgrade_warnings,
        compatibility_risks=compatibility_risks,
        signals=signals,
        summary=summary,
    )
