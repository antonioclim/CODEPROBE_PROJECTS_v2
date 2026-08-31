#!/usr/bin/env python3
"""Local CLI for CodeProbe project/ZIP analysis.

The browser remains the preferred single-file interface. This CLI is intended
for instructors and students who need an auditable multi-file project report
with .codeprobeignore support before submission. The maintainer support package shares folder/ZIP
input handling with the calibration tools to reduce duplicate maintenance paths.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site
):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for _path in (SRC, TOOLS):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import codeprobe_runtime as engine
from codeprobe_engine.project_io import read_folder_files, stderr_warning


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "project_name": args.project_name,
        "profile": args.profile,
        "include_documentation": args.include_documentation,
        "max_files": args.max_files,
        "max_file_bytes": args.max_file_bytes,
    }
    if args.zip:
        archive = Path(args.zip)
        payload["project_name"] = args.project_name or archive.stem
        payload["zip_base64"] = base64.b64encode(archive.read_bytes()).decode("ascii")
    else:
        root = Path(args.folder or ".").resolve()
        payload["project_name"] = args.project_name or root.name or "project"
        payload["files"] = read_folder_files(root, include_binary_placeholders=True, warning_sink=stderr_warning)
    if args.ignore_file:
        payload["ignore_text"] = Path(args.ignore_file).read_text(encoding="utf-8")
    if args.config:
        payload["config_override"] = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.calibration_profile:
        payload["calibration_profile"] = json.loads(Path(args.calibration_profile).read_text(encoding="utf-8"))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse a CodeProbe project folder or ZIP archive.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--folder", help="Project folder to walk recursively.")
    source.add_argument("--zip", help="Project ZIP archive to analyse.")
    parser.add_argument("--project-name", default="", help="Project name used in the report header.")
    parser.add_argument("--profile", default="default", choices=sorted(engine.SCORING_PROFILES), help="Scoring profile.")
    parser.add_argument("--include-documentation", action="store_true", help="Include Markdown/documentation as documentation-only context.")
    parser.add_argument("--ignore-file", help="Additional .codeprobeignore-style file to apply.")
    parser.add_argument("--config", help="JSON metric override file.")
    parser.add_argument("--calibration-profile", help="Course-local calibration profile JSON produced by calibrate_profile.py.")
    parser.add_argument("--max-files", type=int, default=engine.PROJECT_MAX_FILES_DEFAULT, help="Maximum number of analysable source files.")
    parser.add_argument("--max-file-bytes", type=int, default=engine.PROJECT_MAX_FILE_BYTES_DEFAULT, help="Maximum bytes per source file.")
    parser.add_argument("--json-out", help="Write JSON report to this path.")
    parser.add_argument("--text-out", help="Write text report to this path.")
    args = parser.parse_args(argv)

    try:
        payload = build_payload(args)
        result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
    except Exception as exc:
        print(f"CodeProbe project analysis failed: {exc}", file=sys.stderr)
        return 2

    text = result.get("text", "")
    project_report = result.get("project_report", {})
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(project_report, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.text_out:
        Path(args.text_out).write_text(text, encoding="utf-8")
    if not args.text_out:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
