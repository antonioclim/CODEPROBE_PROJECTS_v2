#!/usr/bin/env python3
"""Validate final CodeProbe file names and retired-path containment.

This checker is deliberately conservative. It does not try to enforce a style
on standard project files such as README.md or LICENSE, but it does verify that
public package paths are short, representative and located in the expected
areas after the final naming migration.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]

STANDARD_ROOT_FILES = {
    ".codeprobeignore.example",
    ".gitignore",
    "00-kit-index.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
}
EXPECTED_DIRS = {"app", "src", "tools", "docs", "educator", "calibration", "release", "tests"}
IGNORED_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"}
RETIRED_FILES = {
    "KIT_INDEX.md",
    "RELEASE_MANIFEST.json",
    "AI_ASSISTANCE_AND_PROVENANCE.md",
    "DESIGN_DECISIONS.md",
    "COURSE_INTEGRATION.md",
    "PROJECT_KIT_NOTICE.md",
    "STUDENT_DISCLOSURE_TEMPLATE.md",
    "release/rename-map.csv",
    "tools/check_references.py",
    "src/engine.py",
    "src/index.html",
    "src/project_index.html",
    "src/index.js",
    "src/project_index.js",
    "src/pyodide_loader.js",
    "src/runtime_config.json",
    "src/RESOURCE_INTEGRITY_MANIFEST.json",
    "src/run_local_server.py",
    "src/analyze_project.py",
    "src/release_check.py",
}
Kebab = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+)?$")
SnakePy = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*\.py$")
NumberedMd = re.compile(r"^[0-9]{2}-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
NumberedTemplate = re.compile(r"^[0-9]{2}-[a-z0-9]+(?:-[a-z0-9]+)*(?:\.template)?\.(?:md|json|csv)$")


def iter_release_paths(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if set(rel.parts) & IGNORED_DIRS:
            continue
        if path.suffix.lower() in {".pyc", ".pyo"}:
            continue
        yield path


def check_root_layout(root: Path) -> list[str]:
    errors: list[str] = []
    actual_root_files = {p.name for p in root.iterdir() if p.is_file()}
    for required in STANDARD_ROOT_FILES:
        if required not in actual_root_files:
            errors.append(f"missing standard root file: {required}")
    for retired in RETIRED_FILES:
        if (root / retired).exists():
            errors.append(f"retired path still exists: {retired}")
    for path in root.iterdir():
        if path.is_dir() and path.name not in EXPECTED_DIRS and path.name not in IGNORED_DIRS:
            errors.append(f"unexpected top-level directory: {path.name}")
    return errors


def check_file_names(root: Path) -> list[str]:
    errors: list[str] = []
    for path in iter_release_paths(root):
        rel = path.relative_to(root).as_posix()
        parts = path.relative_to(root).parts
        name = path.name
        if len(name) > 80:
            errors.append(f"file name too long: {rel}")
        if any(ch.isspace() for ch in name):
            errors.append(f"file name contains whitespace: {rel}")
        if parts[0] == "docs" and len(parts) == 2 and name.endswith(".md") and not NumberedMd.match(name):
            errors.append(f"docs markdown file should be numbered kebab-case: {rel}")
        if parts[0] == "docs" and len(parts) >= 3 and parts[1] == "history" and name.endswith(".md") and not NumberedMd.match(name):
            errors.append(f"history markdown file should be numbered kebab-case: {rel}")
        if parts[0] == "educator" and name.endswith(".md") and not NumberedMd.match(name):
            errors.append(f"educator markdown file should be numbered kebab-case: {rel}")
        if parts[0] == "calibration" and len(parts) == 2 and name not in {"README.md"}:
            if name.startswith("0") and not NumberedTemplate.match(name):
                errors.append(f"calibration ordered template name is malformed: {rel}")
        if parts[0] == "app" and name not in {"README.md", "runtime-config.example.json"}:
            if path.suffix.lower() in {".html", ".js", ".css", ".json"}:
                if name.endswith(".example.json"):
                    stem = name[:-len(".example.json")]
                    ok = Kebab.match(stem) is not None
                else:
                    ok = Kebab.match(name) is not None
                if not ok:
                    errors.append(f"app asset should use kebab-case: {rel}")
        if parts[0] == "tools" and path.suffix == ".py" and not SnakePy.match(name):
            errors.append(f"tool script should use snake_case.py: {rel}")
        if parts[0] == "tests" and path.suffix == ".py":
            if not name.startswith("test_") or not SnakePy.match(name):
                errors.append(f"test file should use test_snake_case.py: {rel}")
    return errors


def run_checks(root: Path = ROOT) -> list[str]:
    root = root.resolve()
    return check_root_layout(root) + check_file_names(root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check final CodeProbe naming conventions and retired paths.")
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args(argv)
    errors = run_checks(Path(args.root))
    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1
    print("[PASS] final naming policy verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
