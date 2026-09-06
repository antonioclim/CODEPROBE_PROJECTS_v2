#!/usr/bin/env python3
"""Bounded local CLI for CodeProbe project and ZIP analysis."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit("this command requires isolated, site-free Python; rerun it with -I -S -B")

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for _path in (SRC, TOOLS):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import codeprobe_runtime as engine
from codeprobe_engine.project_io import (
    DEFAULT_MAX_ARCHIVE_BYTES,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_TOTAL_BYTES,
    project_payload_from_path,
    read_bounded_regular_file,
)


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    source = Path(args.zip or args.folder)
    payload = project_payload_from_path(
        source,
        include_binary_placeholders=True,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_entries=args.max_entries,
        max_files=args.max_files,
        max_archive_bytes=args.max_archive_bytes,
        max_ignore_bytes=args.max_ignore_bytes,
        max_ignore_rules=args.max_ignore_rules,
    )
    payload.update({
        "project_name": args.project_name or payload["project_name"],
        "profile": args.profile,
        "include_documentation": args.include_documentation,
        "max_compression_ratio": args.max_compression_ratio,
        "max_ignore_bytes": args.max_ignore_bytes,
        "max_ignore_rules": args.max_ignore_rules,
    })
    if args.ignore_file:
        ignore_path = Path(args.ignore_file).absolute()
        data = read_bounded_regular_file(
            ignore_path,
            root=ignore_path.parent,
            max_bytes=args.max_ignore_bytes,
        )
        try:
            payload["ignore_text"] = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("explicit ignore file must be UTF-8 text") from exc
    if args.config:
        payload["config_override"] = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.calibration_profile:
        payload["calibration_profile"] = json.loads(Path(args.calibration_profile).read_text(encoding="utf-8"))
    return payload


def report_destinations(args: argparse.Namespace) -> dict[str, Path]:
    """Preflight all output names against input identities before any write.

    Reports belong outside the project tree. Existing multiply linked files are
    refused, including aliases outside that tree. Parent aliases are resolved
    once to accommodate host paths such as macOS /tmp; leaf redirects are not.
    This is not a lock against another writer controlling the parent directory.
    """
    source = Path(args.zip or args.folder).resolve()
    protected = [source, *(Path(value).resolve() for value in
                 (args.config, args.calibration_profile, args.ignore_file) if value)]
    key = lambda path: os.path.normcase(os.fspath(path)).casefold()
    protected_keys = {key(path) for path in protected}
    outputs: dict[str, Path] = {}
    seen: set[str] = set()
    identities: set[tuple[int, int]] = set()
    for name, value in (("json", args.json_out), ("text", args.text_out)):
        if not value:
            continue
        lexical = Path(os.path.abspath(value))
        try:
            metadata = lexical.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))):
                raise ValueError("report destination must be a regular file, not a link or reparse point")
            if metadata.st_nlink != 1:
                raise ValueError("report destination must not be hard-linked")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in identities:
                raise ValueError("report destinations alias one another")
            identities.add(identity)
        destination = lexical.resolve()
        identity_key = key(destination)
        if identity_key in seen:
            raise ValueError("report destinations collide")
        seen.add(identity_key)
        if identity_key in protected_keys:
            raise ValueError("report destination must not overwrite an input")
        if args.folder and (identity_key == key(source) or identity_key.startswith(key(source).rstrip(os.sep) + os.sep)):
            raise ValueError("report destination must be outside the input project tree")
        if not destination.parent.is_dir():
            raise ValueError("report destination parent must be an existing directory")
        outputs[name] = destination
    return outputs


def write_reports(args: argparse.Namespace, outputs: dict[str, Path], contents: dict[str, str]) -> None:
    """Prepare both complete reports, then replace only revalidated destinations.

    Each replacement is atomic; the two names are not a filesystem transaction.
    An I/O error after the first replacement can leave just that report updated.
    """
    staged: dict[str, Path] = {}
    try:
        if report_destinations(args) != outputs:
            raise ValueError("report destinations changed since input validation")
        for name, destination in outputs.items():
            descriptor, temporary = tempfile.mkstemp(prefix=".codeprobe-report-", dir=destination.parent)
            staged[name] = Path(temporary)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(contents[name].encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
        for name, destination in outputs.items():
            if report_destinations(args) != outputs:
                raise ValueError("report destinations changed before replacement")
            os.replace(staged[name], destination)
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse a CodeProbe project folder or ZIP archive safely.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--folder", help="Project folder to walk without following links.")
    source.add_argument("--zip", help="Project ZIP archive to analyse.")
    parser.add_argument("--project-name", default="", help="Project name used in the report header.")
    parser.add_argument("--profile", default=None, choices=sorted(engine.SCORING_PROFILES), help="Scoring profile.")
    parser.add_argument("--include-documentation", action="store_true", help="Include documentation as context.")
    parser.add_argument("--ignore-file", help="Additional bounded .codeprobeignore-style file.")
    parser.add_argument("--config", help="JSON metric override file.")
    parser.add_argument("--calibration-profile", help="Course-local calibration profile JSON.")
    parser.add_argument("--max-files", type=int, default=engine.PROJECT_MAX_FILES_DEFAULT)
    parser.add_argument("--max-file-bytes", type=int, default=engine.PROJECT_MAX_FILE_BYTES_DEFAULT)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-archive-bytes", type=int, default=DEFAULT_MAX_ARCHIVE_BYTES)
    parser.add_argument("--max-compression-ratio", type=float, default=100.0)
    parser.add_argument("--max-ignore-bytes", type=int, default=131072)
    parser.add_argument("--max-ignore-rules", type=int, default=1000)
    parser.add_argument("--json-out", help="Write JSON report to this path.")
    parser.add_argument("--text-out", help="Write text report to this path.")
    args = parser.parse_args(argv)
    try:
        outputs = report_destinations(args)
        payload = build_payload(args)
        result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload, allow_nan=False)))
        text = result.get("text", "")
        contents = {
            "json": json.dumps(result.get("project_report", {}), indent=2, ensure_ascii=False, allow_nan=False) + "\n",
            "text": text + ("" if text.endswith("\n") else "\n"),
        }
        write_reports(args, outputs, contents)
    except Exception as exc:
        print(f"CodeProbe project analysis failed: {exc}", file=sys.stderr)
        return 2
    if not args.text_out:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
