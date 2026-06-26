"""
License Risk Analyzer — static, no AI tokens.
Detects repository license and assesses commercial/legal risk.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from .fetcher import RepoData


# Risk levels: safe / notice / caution / restricted / unknown
LICENSE_DB: dict[str, dict] = {
    # Permissive — safe for commercial use
    "mit":          {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "MIT",          "label": "MIT"},
    "apache-2.0":   {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "Apache-2.0",   "label": "Apache 2.0"},
    "apache 2.0":   {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "Apache-2.0",   "label": "Apache 2.0"},
    "bsd-2":        {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "BSD-2-Clause", "label": "BSD 2-Clause"},
    "bsd-3":        {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "BSD-3-Clause", "label": "BSD 3-Clause"},
    "isc":          {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "ISC",          "label": "ISC"},
    "unlicense":    {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "Unlicense",    "label": "Unlicense (Public Domain)"},
    "cc0":          {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "CC0-1.0",      "label": "CC0 1.0 (Public Domain)"},
    "wtfpl":        {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "WTFPL",        "label": "WTFPL"},
    "zlib":         {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "Zlib",         "label": "zlib"},
    "boost":        {"risk": "safe",       "grade": "A", "commercial": True,  "copyleft": False, "spdx": "BSL-1.0",      "label": "Boost Software License 1.0"},
    "mpl-2.0":      {"risk": "notice",     "grade": "B", "commercial": True,  "copyleft": True,  "spdx": "MPL-2.0",      "label": "Mozilla Public License 2.0"},
    "mpl 2.0":      {"risk": "notice",     "grade": "B", "commercial": True,  "copyleft": True,  "spdx": "MPL-2.0",      "label": "Mozilla Public License 2.0"},
    "eupl":         {"risk": "notice",     "grade": "B", "commercial": True,  "copyleft": True,  "spdx": "EUPL-1.2",     "label": "European Union Public License"},
    # Weak copyleft — notice required
    "lgpl-2.1":     {"risk": "notice",     "grade": "B", "commercial": True,  "copyleft": True,  "spdx": "LGPL-2.1",     "label": "GNU LGPL 2.1"},
    "lgpl-3.0":     {"risk": "notice",     "grade": "B", "commercial": True,  "copyleft": True,  "spdx": "LGPL-3.0",     "label": "GNU LGPL 3.0"},
    "lgpl":         {"risk": "notice",     "grade": "B", "commercial": True,  "copyleft": True,  "spdx": "LGPL-3.0",     "label": "GNU LGPL"},
    # Strong copyleft — caution for commercial
    "gpl-2.0":      {"risk": "caution",    "grade": "C", "commercial": False, "copyleft": True,  "spdx": "GPL-2.0",      "label": "GNU GPL 2.0"},
    "gpl-3.0":      {"risk": "caution",    "grade": "C", "commercial": False, "copyleft": True,  "spdx": "GPL-3.0",      "label": "GNU GPL 3.0"},
    "gpl":          {"risk": "caution",    "grade": "C", "commercial": False, "copyleft": True,  "spdx": "GPL-3.0",      "label": "GNU GPL"},
    # Network copyleft — restricted for SaaS
    "agpl-3.0":     {"risk": "restricted", "grade": "D", "commercial": False, "copyleft": True,  "spdx": "AGPL-3.0",     "label": "GNU AGPL 3.0"},
    "agpl":         {"risk": "restricted", "grade": "D", "commercial": False, "copyleft": True,  "spdx": "AGPL-3.0",     "label": "GNU AGPL"},
    "sspl":         {"risk": "restricted", "grade": "D", "commercial": False, "copyleft": True,  "spdx": "SSPL-1.0",     "label": "Server Side Public License (MongoDB)"},
    "commons clause": {"risk": "restricted", "grade": "D", "commercial": False, "copyleft": False, "spdx": "Commons-Clause", "label": "Commons Clause"},
    "busl":         {"risk": "caution",    "grade": "C", "commercial": False, "copyleft": False, "spdx": "BUSL-1.1",     "label": "Business Source License (HashiCorp)"},
    "elastic":      {"risk": "caution",    "grade": "C", "commercial": False, "copyleft": False, "spdx": "Elastic-2.0",  "label": "Elastic License 2.0"},
    "proprietary":  {"risk": "restricted", "grade": "F", "commercial": False, "copyleft": False, "spdx": "Proprietary",  "label": "Proprietary / All Rights Reserved"},
    "all rights reserved": {"risk": "restricted", "grade": "F", "commercial": False, "copyleft": False, "spdx": "Proprietary", "label": "All Rights Reserved"},
    "cc-by-nc":     {"risk": "restricted", "grade": "D", "commercial": False, "copyleft": False, "spdx": "CC-BY-NC",     "label": "Creative Commons BY-NC (Non-Commercial)"},
    "cc by-nc":     {"risk": "restricted", "grade": "D", "commercial": False, "copyleft": False, "spdx": "CC-BY-NC",     "label": "Creative Commons BY-NC (Non-Commercial)"},
}

RISK_ADVICE: dict[str, str] = {
    "safe":       "✅ Permissive license — free to use in commercial products with minimal obligations.",
    "notice":     "📋 Weak copyleft — commercial use OK, but modifications to this library must stay open source.",
    "caution":    "⚠️  Strong copyleft — distributing this code requires your product to also be open source (GPL).",
    "restricted": "🚫 Restricted — SaaS/commercial use prohibited or requires separate commercial license.",
    "unknown":    "❓ License not detected — treat as proprietary or contact the author before commercial use.",
}


@dataclass
class LicenseRiskReport:
    detected_license: str = "Unknown"
    spdx: str = ""
    risk: str = "unknown"      # safe / notice / caution / restricted / unknown
    grade: str = "?"
    commercial_ok: bool = False
    copyleft: bool = False
    summary: str = ""
    advice: str = ""
    signals: list[str] = field(default_factory=list)
    source_file: str = ""      # which file the license was found in

    def as_dict(self) -> dict:
        return {
            "detected_license": self.detected_license,
            "spdx": self.spdx,
            "risk": self.risk,
            "grade": self.grade,
            "commercial_ok": self.commercial_ok,
            "copyleft": self.copyleft,
            "summary": self.summary,
            "advice": self.advice,
            "signals": self.signals,
            "source_file": self.source_file,
        }


def _detect_from_text(text: str) -> Optional[dict]:
    """Match license text content against known fingerprints."""
    t = text.lower()

    # SPDX identifier line (most reliable)
    spdx_match = re.search(r"spdx-license-identifier:\s*([\w\-.+]+)", t)
    if spdx_match:
        spdx_id = spdx_match.group(1).lower().strip()
        for key, info in LICENSE_DB.items():
            if key in spdx_id or spdx_id in key:
                return info

    # Fingerprint phrases
    patterns = [
        ("agpl-3.0",  r"gnu affero general public license.*version 3"),
        ("agpl",      r"affero general public"),
        ("gpl-3.0",   r"gnu general public license.*version 3"),
        ("gpl-2.0",   r"gnu general public license.*version 2"),
        ("lgpl-3.0",  r"gnu lesser general public license.*version 3"),
        ("lgpl-2.1",  r"gnu lesser general public license.*version 2\.1"),
        ("mpl-2.0",   r"mozilla public license.*2\.0"),
        ("apache-2.0",r"apache license.*2\.0|licensed under the apache"),
        ("mit",       r"permission is hereby granted.*free of charge|mit license"),
        ("bsd-3",     r"redistributions of source code must retain.*neither the name"),
        ("bsd-2",     r"redistributions of source code must retain"),
        ("isc",       r"isc license"),
        ("unlicense", r"this is free and unencumbered software released into the public domain"),
        ("cc0",       r"creative commons.*cc0|no copyright"),
        ("sspl",      r"server side public license"),
        ("busl",      r"business source license"),
        ("elastic",   r"elastic license"),
        ("commons clause", r"commons clause"),
        ("all rights reserved", r"all rights reserved"),
        ("proprietary", r"proprietary|confidential.*do not distribute"),
        ("cc-by-nc",  r"creative commons.*noncommercial|cc by-nc"),
    ]

    for key, pattern in patterns:
        if re.search(pattern, t):
            return LICENSE_DB.get(key)

    return None


def _detect_from_filename(filename: str) -> Optional[str]:
    """Extract license name from package.json or pyproject.toml."""
    return None  # handled by caller


def analyse_license(repo: RepoData) -> LicenseRiskReport:
    """Detect and assess the repository license."""
    signals: list[str] = []
    info: Optional[dict] = None
    source_file = ""

    # 1. Look for LICENSE / COPYING files
    license_files = [
        f for f in repo.files
        if re.match(r"(?:license|licence|copying|copyright)(?:\.[a-z]+)?$",
                    f.path.split("/")[-1].lower())
    ]
    for lf in license_files:
        result = _detect_from_text(lf.content)
        if result:
            info = result
            source_file = lf.path
            break

    # 2. Check package.json "license" field
    if not info:
        for f in repo.files:
            if f.path.split("/")[-1].lower() == "package.json":
                try:
                    import json
                    pkg = json.loads(f.content)
                    lic = str(pkg.get("license", "")).lower().strip()
                    if lic:
                        for key, data in LICENSE_DB.items():
                            if key in lic or lic in key:
                                info = data
                                source_file = f.path
                                break
                except Exception:
                    pass
                break

    # 3. Check pyproject.toml / setup.py
    if not info:
        for f in repo.files:
            fname = f.path.split("/")[-1].lower()
            if fname in ("pyproject.toml", "setup.cfg", "setup.py"):
                m = re.search(r'license\s*=\s*["\']?([^"\'\\n,\]]+)', f.content, re.IGNORECASE)
                if m:
                    lic = m.group(1).strip().lower()
                    for key, data in LICENSE_DB.items():
                        if key in lic or lic in key:
                            info = data
                            source_file = fname
                            break
                if info:
                    break

    # 4. Search in README
    if not info and repo.readme:
        result = _detect_from_text(repo.readme)
        if result:
            info = result
            source_file = "README"

    # 5. Search all files for SPDX headers
    if not info:
        for f in repo.files:
            result = _detect_from_text(f.content[:500])
            if result:
                info = result
                source_file = f.path
                signals.append(f"License detected from SPDX header in {f.path}")
                break

    # Build report
    if not info:
        if not license_files:
            signals.append("No LICENSE file found — likely proprietary or unlicensed")
        else:
            signals.append(f"LICENSE file found ({license_files[0].path}) but content not recognized")
        return LicenseRiskReport(
            detected_license="Unknown",
            spdx="",
            risk="unknown",
            grade="?",
            commercial_ok=False,
            copyleft=False,
            summary="License could not be detected. Treat as proprietary before commercial use.",
            advice=RISK_ADVICE["unknown"],
            signals=signals,
            source_file=source_file or (license_files[0].path if license_files else ""),
        )

    label = info["label"]
    risk = info["risk"]
    grade = info["grade"]

    if info["copyleft"]:
        signals.append(f"Copyleft license ({label}) — modifications must remain open source")
    if not info["commercial"]:
        signals.append(f"Commercial use restricted — review terms or obtain commercial license")
    if risk == "safe":
        signals.append("Permissive — safe to use in proprietary/commercial products")
    if info["spdx"] == "AGPL-3.0":
        signals.append("AGPL: Even SaaS use (network distribution) triggers open-source obligation")

    summary = (
        f"{label} license ({risk.upper()} risk, Grade {grade}). "
        f"Commercial use: {'✅ OK' if info['commercial'] else '🚫 Restricted'}. "
        f"Copyleft: {'Yes' if info['copyleft'] else 'No'}."
    )

    return LicenseRiskReport(
        detected_license=label,
        spdx=info["spdx"],
        risk=risk,
        grade=grade,
        commercial_ok=info["commercial"],
        copyleft=info["copyleft"],
        summary=summary,
        advice=RISK_ADVICE[risk],
        signals=signals,
        source_file=source_file,
    )
