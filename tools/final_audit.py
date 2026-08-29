#!/usr/bin/env python3
"""Generate deterministic final package audit artefacts for CodeProbe."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for path in (SRC, TOOLS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import audit_institutional_pack  # noqa: E402
import check_file_references  # noqa: E402
import check_naming  # noqa: E402
import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine.release import atomic_write_text, iter_release_files  # noqa: E402

REQUIRED_FINAL_PATHS = [
    "00-kit-index.md",
    "README.md",
    "app/index.html",
    "app/project.html",
    "app/codeprobe-ui.js",
    "app/project-ui.js",
    "app/pyodide-loader.js",
    "app/resource-integrity.json",
    "src/codeprobe_runtime.py",
    "tools/check_release.py",
    "tools/build_release.py",
    "tools/check_file_references.py",
    "tools/check_naming.py",
    "tools/final_audit.py",
    "release/file-rename-map.csv",
    "release/release-manifest.json",
    "docs/00-file-catalogue.md",
    "docs/01-naming-policy.md",
    "docs/15-final-release-audit.md",
    "docs/history/13-final-audit.md",
]

FORBIDDEN_ACTIVE_PATHS = [
    "KIT_INDEX.md",
    "RELEASE_MANIFEST.json",
    "release/rename-map.csv",
    "tools/check_references.py",
    "src/index.html",
    "src/project_index.html",
    "src/index.js",
    "src/project_index.js",
    "src/engine.py",
    "src/analyze_project.py",
    "src/release_check.py",
]


def build_audit(root: Path = ROOT) -> dict:
    root = root.resolve()
    files = sorted(path.relative_to(root).as_posix() for path in iter_release_files(root))
    by_area = Counter(path.split("/", 1)[0] if "/" in path else "root" for path in files)
    missing_required = [path for path in REQUIRED_FINAL_PATHS if not (root / path).is_file()]
    forbidden_present = [path for path in FORBIDDEN_ACTIVE_PATHS if (root / path).exists()]
    reference_errors = check_file_references.run_reference_audit(root)
    naming_errors = check_naming.run_checks(root)
    institutional_errors = audit_institutional_pack.run_audit(root)
    return {
        "schema": "codeprobe-final-package-audit/v1",
        "app_version": engine.APP_VERSION,
        "generated_at_utc": "not embedded; final ZIP hash is recorded in the external sidecar",
        "file_count": len(files),
        "files_by_area": dict(sorted(by_area.items())),
        "required_final_paths": REQUIRED_FINAL_PATHS,
        "missing_required_paths": missing_required,
        "forbidden_active_paths": FORBIDDEN_ACTIVE_PATHS,
        "forbidden_paths_present": forbidden_present,
        "reference_integrity_ok": not reference_errors,
        "reference_errors": reference_errors,
        "naming_policy_ok": not naming_errors,
        "naming_errors": naming_errors,
        "institutional_package_ok": not institutional_errors,
        "institutional_errors": institutional_errors,
        "status": "pass" if not missing_required and not forbidden_present and not reference_errors and not naming_errors and not institutional_errors else "fail",
    }


def render_report(report: dict) -> str:
    """Render the canonical machine-readable audit artefact."""
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def render_summary(report: dict) -> str:
    """Render the human-readable companion for an audit report."""
    lines = [
        "# Final audit summary",
        "",
        f"Version: CodeProbe v{report['app_version']}",
        f"Status: {report['status'].upper()}",
        f"Release-set files counted: {report['file_count']}",
        "",
        "## Area counts",
        "",
    ]
    for area, count in report["files_by_area"].items():
        lines.append(f"- `{area}`: {count}")
    lines.extend([
        "",
        "## Checks",
        "",
        f"- Required final paths present: {'yes' if not report['missing_required_paths'] else 'no'}",
        f"- Forbidden active legacy paths absent: {'yes' if not report['forbidden_paths_present'] else 'no'}",
        f"- Reference integrity: {'pass' if report['reference_integrity_ok'] else 'fail'}",
        f"- Naming policy: {'pass' if report['naming_policy_ok'] else 'fail'}",
        f"- Institutional package audit: {'pass' if report['institutional_package_ok'] else 'fail'}",
        "",
        "The JSON companion file provides the machine-readable audit detail.",
    ])
    return "\n".join(lines) + "\n"


def verify_reports(root: Path = ROOT, report: dict | None = None) -> list[str]:
    """Compare committed audit artefacts with a freshly computed report."""
    root = root.resolve()
    report = report or build_audit(root)
    expected = {
        root / "release" / "final-audit-report.json": render_report(report),
        root / "release" / "final-audit-summary.md": render_summary(report),
    }
    errors: list[str] = []
    for path, content in expected.items():
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            errors.append(f"missing audit artefact: {relative}")
            continue
        try:
            actual = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"invalid or unreadable audit artefact: {relative}")
            continue
        if actual != content:
            errors.append(f"stale audit artefact: {relative}")
    return errors


def write_reports(
    root: Path = ROOT,
    report: dict | None = None,
    output_dir: Path | None = None,
) -> dict:
    """Persist a successful audit using atomic replacement for each file."""
    root = root.resolve()
    report = report or build_audit(root)
    if report.get("status") != "pass":
        raise ValueError("refusing to replace release evidence with a failed audit")
    release_dir = output_dir.resolve() if output_dir is not None else root / "release"
    report_text = render_report(report)
    summary_text = render_summary(report)
    atomic_write_text(release_dir / "final-audit-report.json", report_text)
    atomic_write_text(release_dir / "final-audit-summary.md", summary_text)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the CodeProbe final package audit boundary.")
    parser.add_argument("--root", default=str(ROOT), help="CodeProbe checkout root.")
    args = parser.parse_args(argv)
    root = Path(args.root)
    report = build_audit(root)
    artefact_errors = verify_reports(root, report)
    status = "pass" if report["status"] == "pass" and not artefact_errors else "fail"
    for error in artefact_errors:
        print(f"[FAIL] {error}")
    print(f"final-audit: {status} ({report['file_count']} files)")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
