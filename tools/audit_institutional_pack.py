#!/usr/bin/env python3
"""Audit the institutional distribution layer of a CodeProbe checkout.

The audit is deliberately lightweight and standard-library only. It verifies the
presence of teaching, review, deployment and release-control artefacts that are
needed when the kit is distributed as part of a course.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "00-kit-index.md",
    "README.md",
    "educator/07-course-integration.md",
    "educator/09-project-kit-notice.md",
    "educator/03-student-disclosure-template.md",
    "docs/10-provenance.md",
    "docs/11-design-decisions.md",
    "release/release-manifest.json",
    "docs/00-file-catalogue.md",
    "docs/01-naming-policy.md",
    "docs/02-architecture.md",
    "docs/04-browser-security.md",
    "docs/05-offline-deployment.md",
    "docs/06-calibration-guide.md",
    "docs/history/11-documentation-resources.md",
    "educator/02-student-announcement.docx",
    "docs/08-release-process.md",
    "docs/09-release-integrity.md",
    "docs/03-report-schema.md",
    "docs/07-ui-extension-guide.md",
    "docs/13-signed-release-workflow.md",
    "docs/12-release-hash-sheet.md",
    "docs/history/08-dynamic-ui-and-review.md",
    "docs/history/09-release-integrity.md",
    "docs/history/10-naming-governance.md",
    "educator/01-student-quick-start.md",
    "educator/04-instructor-checklist.md",
    "educator/08-deployment-one-page.md",
    "educator/05-review-protocol.md",
    "educator/06-evidence-rubric.md",
    "educator/02-student-announcement.md",
    "app/index.html",
    "app/project.html",
    "app/runtime-config.json",
    "app/resource-integrity.json",
    "release/file-rename-map.csv",
    "docs/15-final-release-audit.md",
    "docs/history/13-final-audit.md",
    "tools/check_file_references.py",
    "release/final-audit-summary.md",
    "release/final-audit-report.json",
    "tools/final_audit.py",
    "tools/check_naming.py",
]

POLICY_FILES = [
    "README.md",
    "educator/07-course-integration.md",
    "educator/09-project-kit-notice.md",
    "educator/01-student-quick-start.md",
    "educator/04-instructor-checklist.md",
    "educator/05-review-protocol.md",
]

REQUIRED_POLICY_MARKERS = [
    "review signal",
    "not proof of misconduct",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _missing_files(root: Path) -> List[str]:
    return [relative for relative in REQUIRED_FILES if not (root / relative).is_file()]


def _policy_errors(root: Path) -> List[str]:
    errors: List[str] = []
    for relative in POLICY_FILES:
        text = _read(root / relative).lower()
        for marker in REQUIRED_POLICY_MARKERS:
            if marker not in text:
                errors.append(f"{relative} lacks policy marker: {marker}")
    return errors


def _html_errors(root: Path) -> List[str]:
    errors: List[str] = []
    for relative in ["app/index.html", "app/project.html"]:
        text = _read(root / relative)
        if "Content-Security-Policy" not in text:
            errors.append(f"{relative} lacks a Content-Security-Policy meta tag")
        if "unsafe-inline" in text:
            errors.append(f"{relative} permits unsafe-inline")
        if re.search(r"<script(?!(?:[^>]*\bsrc=))[^>]*>\s*\S", text, re.I | re.S):
            errors.append(f"{relative} contains an inline script body")
        if re.search(r"<style\b", text, re.I):
            errors.append(f"{relative} contains an inline style block")
    return errors


def _json_errors(root: Path) -> List[str]:
    errors: List[str] = []
    for relative in ["release/release-manifest.json", "app/runtime-config.json", "app/resource-integrity.json"]:
        try:
            json.loads(_read(root / relative))
        except Exception as exc:
            errors.append(f"{relative} is not valid JSON: {exc}")
    return errors


def run_audit(root: Path = ROOT) -> List[str]:
    """Return a list of institutional-distribution audit errors."""
    root = root.resolve()
    errors: List[str] = []
    errors.extend(f"missing required institutional file: {relative}" for relative in _missing_files(root))
    if not errors:
        errors.extend(_policy_errors(root))
        errors.extend(_html_errors(root))
        errors.extend(_json_errors(root))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit CodeProbe institutional distribution artefacts.")
    parser.add_argument("--root", default=str(ROOT), help="Source checkout root. Defaults to this package root.")
    parser.add_argument("--json-out", help="Optional path for machine-readable audit output.")
    args = parser.parse_args(argv)

    root = Path(args.root)
    errors = run_audit(root)
    payload = {"ok": not errors, "errors": errors}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("[PASS] institutional distribution artefacts verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
