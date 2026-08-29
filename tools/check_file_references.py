#!/usr/bin/env python3
"""Check high-confidence internal file references in a CodeProbe checkout.

This script validates path references that are safe to interpret mechanically:
Markdown links, HTML local src/href attributes, browser resource-integrity entries,
the canonical file-rename map, and containment of retired active paths.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

ROOT = Path(__file__).resolve().parents[1]
RENAME_MAP = Path("release/file-rename-map.csv")
TEXT_SUFFIXES = {".md", ".html", ".htm"}
IGNORED_PARTS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"}
IGNORED_REFERENCE_PREFIXES = ("http://", "https://", "mailto:", "#", "data:", "javascript:")

LEGACY_REFERENCE_TOKENS = (
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
    "src/runtime_config.json",
    "src/RESOURCE_INTEGRITY_MANIFEST.json",
    "educator_resources/",
    "COURSE_INTEGRATION.md",
    "PROJECT_KIT_NOTICE.md",
    "STUDENT_DISCLOSURE_TEMPLATE.md",
    "AI_ASSISTANCE_AND_PROVENANCE.md",
    "DESIGN_DECISIONS.md",
)

CONTROLLED_LEGACY_REFERENCE_FILES = {
    "CHANGELOG.md",
    "docs/00-file-catalogue.md",
    "release/file-rename-map.csv",
    "release/final-audit-report.json",
    "tests/test_app_runtime_tools_paths.py",
    "tests/test_documentation_resources.py",
    "tests/test_final_naming_release.py",
    "tests/test_final_naming_stability.py",
    "tests/test_final_package_audit.py",
    "tests/test_final_release_audit.py",
    "tools/check_file_references.py",
    "tools/check_naming.py",
    "tools/final_audit.py",
    "release/final-audit-summary.md",
}

LEGACY_SCAN_SUFFIXES = {".md", ".html", ".js", ".py", ".json", ".csv", ".txt"}


@dataclass(frozen=True)
class ReferenceProblem:
    source: str
    reference: str
    message: str

    def as_text(self) -> str:
        return f"{self.source}: {self.reference!r} — {self.message}"


def _normalise_reference(raw: str) -> str | None:
    ref = raw.strip().strip('"\'')
    if not ref or ref.startswith(IGNORED_REFERENCE_PREFIXES):
        return None
    ref = ref.split("#", 1)[0].split("?", 1)[0]
    if not ref or ref.startswith(IGNORED_REFERENCE_PREFIXES):
        return None
    if any(ch in ref for ch in "*{}<>"):
        return None
    if ref.startswith("/"):
        ref = ref.lstrip("/")
    return ref


def _resolve(root: Path, source: Path, ref: str) -> Path:
    if ref.startswith(("./", "../")):
        return (source.parent / ref).resolve()
    first = ref.split("/", 1)[0]
    if (root / first).exists():
        return (root / ref).resolve()
    return (source.parent / ref).resolve()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def markdown_and_html_references(path: Path) -> Iterable[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in re.finditer(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text):
        yield match.group(1)
    for match in re.finditer(r"\b(?:src|href)\s*=\s*[\"']([^\"']+)[\"']", text, re.I):
        yield match.group(1)


def check_document_links(root: Path) -> List[ReferenceProblem]:
    problems: List[ReferenceProblem] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative_path = path.relative_to(root)
        if set(relative_path.parts) & IGNORED_PARTS:
            continue
        relative_source = relative_path.as_posix()
        for raw_ref in markdown_and_html_references(path):
            ref = _normalise_reference(raw_ref)
            if not ref:
                continue
            resolved = _resolve(root, path, ref)
            if not _inside(resolved, root):
                problems.append(ReferenceProblem(relative_source, raw_ref, "reference resolves outside package root"))
                continue
            if ref.endswith("/"):
                if not resolved.is_dir():
                    problems.append(ReferenceProblem(relative_source, raw_ref, "target directory does not exist"))
            elif not resolved.exists():
                problems.append(ReferenceProblem(relative_source, raw_ref, "target file or directory does not exist"))
    return problems


def check_resource_integrity_manifest(root: Path) -> List[ReferenceProblem]:
    manifest = root / "app" / "resource-integrity.json"
    if not manifest.exists():
        return [ReferenceProblem("app/resource-integrity.json", "", "manifest is missing")]
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        return [ReferenceProblem("app/resource-integrity.json", "", f"invalid JSON: {exc}")]
    problems: List[ReferenceProblem] = []
    for item in data.get("assets", []):
        ref = item.get("path")
        if not isinstance(ref, str) or not ref:
            problems.append(ReferenceProblem("app/resource-integrity.json", str(ref), "asset lacks a usable path"))
            continue
        if not (root / "app" / ref).is_file():
            problems.append(ReferenceProblem("app/resource-integrity.json", ref, "asset file does not exist relative to app/"))
    return problems


def load_rename_rows(root: Path) -> list[dict[str, str]]:
    path = root / RENAME_MAP
    if not path.is_file():
        raise FileNotFoundError(f"{RENAME_MAP.as_posix()} is missing")
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def check_rename_map(root: Path) -> List[ReferenceProblem]:
    problems: List[ReferenceProblem] = []
    try:
        rows = load_rename_rows(root)
    except Exception as exc:
        return [ReferenceProblem(RENAME_MAP.as_posix(), "", str(exc))]
    required = {"current_path", "proposed_final_path", "role", "action", "phase", "area", "risk_level", "rationale"}
    if rows:
        missing_columns = required - set(rows[0])
        if missing_columns:
            problems.append(ReferenceProblem(RENAME_MAP.as_posix(), ",".join(sorted(missing_columns)), "required column(s) missing"))
    current_paths: set[str] = set()
    proposed_paths: set[str] = set()
    duplicates: set[str] = set()
    duplicate_proposed: set[str] = set()
    for row in rows:
        current = (row.get("current_path") or "").strip()
        proposed = (row.get("proposed_final_path") or "").strip()
        if not current:
            problems.append(ReferenceProblem(RENAME_MAP.as_posix(), str(row), "row lacks current_path"))
            continue
        if current in current_paths:
            duplicates.add(current)
        current_paths.add(current)
        if not (root / current).is_file():
            problems.append(ReferenceProblem(RENAME_MAP.as_posix(), current, "current_path is not a file in this release"))
        if not proposed:
            problems.append(ReferenceProblem(RENAME_MAP.as_posix(), current, "row lacks proposed_final_path"))
        else:
            if proposed in proposed_paths:
                duplicate_proposed.add(proposed)
            proposed_paths.add(proposed)
    for duplicate in sorted(duplicates):
        problems.append(ReferenceProblem(RENAME_MAP.as_posix(), duplicate, "duplicate current_path"))
    for duplicate in sorted(duplicate_proposed):
        problems.append(ReferenceProblem(RENAME_MAP.as_posix(), duplicate, "duplicate proposed_final_path"))
    ignored_suffixes = {".pyc", ".pyo"}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(root)
        rel = rel_path.as_posix()
        if set(rel_path.parts) & IGNORED_PARTS or path.suffix.lower() in ignored_suffixes:
            continue
        if rel not in current_paths:
            problems.append(ReferenceProblem(RENAME_MAP.as_posix(), rel, "file is missing from rename map"))
    return problems


def check_uncontrolled_legacy_references(root: Path) -> List[ReferenceProblem]:
    problems: List[ReferenceProblem] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in LEGACY_SCAN_SUFFIXES:
            continue
        rel_path = path.relative_to(root)
        rel = rel_path.as_posix()
        if set(rel_path.parts) & IGNORED_PARTS:
            continue
        if rel in CONTROLLED_LEGACY_REFERENCE_FILES or rel.startswith("docs/history/"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in LEGACY_REFERENCE_TOKENS:
            if token in text:
                problems.append(ReferenceProblem(rel, token, "legacy migration path appears outside controlled history/audit files"))
    return problems


def run_checks(root: Path = ROOT) -> List[str]:
    root = root.resolve()
    problems: List[ReferenceProblem] = []
    problems.extend(check_document_links(root))
    problems.extend(check_resource_integrity_manifest(root))
    problems.extend(check_rename_map(root))
    problems.extend(check_uncontrolled_legacy_references(root))
    return [problem.as_text() for problem in problems]


def run_reference_audit(root: Path = ROOT) -> List[str]:
    return run_checks(root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check high-confidence CodeProbe path references and rename-map coverage.")
    parser.add_argument("--root", default=str(ROOT), help="CodeProbe checkout root. Defaults to this package root.")
    parser.add_argument("--json-out", help="Optional path for machine-readable audit results.")
    args = parser.parse_args(argv)
    root = Path(args.root)
    errors = run_checks(root)
    payload = {"ok": not errors, "errors": errors}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("[PASS] high-confidence references and rename map verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
