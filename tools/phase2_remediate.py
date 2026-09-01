#!/usr/bin/env python3
"""Apply the audited project-input and calibration remediation transaction.

This temporary maintainer script is executed only by the companion GitHub
Actions workflow.  It removes itself and both temporary workflows before the
release evidence is regenerated and the final commit is created.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(relative: str, content: str) -> None:
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{relative}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")


def replace_between(relative: str, start: str, end: str, replacement: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    left = text.find(start)
    if left < 0:
        raise RuntimeError(f"{relative}: start marker not found: {start!r}")
    right = text.find(end, left + len(start))
    if right < 0:
        raise RuntimeError(f"{relative}: end marker not found: {end!r}")
    path.write_text(text[:left] + replacement + text[right:], encoding="utf-8", newline="\n")


PROJECT_IO = '''"""Shared, bounded project-input helpers for CodeProbe command-line tools."""

from __future__ import annotations

import base64
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import codeprobe_runtime as engine

WarningSink = Optional[Callable[[str], None]]
DEFAULT_MAX_TOTAL_BYTES = 20_000_000
DEFAULT_MAX_ARCHIVE_BYTES = 8_000_000
DEFAULT_MAX_ENTRIES = 2_000
DEFAULT_MAX_IGNORE_BYTES = 131_072
READ_CHUNK_BYTES = 65_536


class ProjectInputError(ValueError):
    """Raised when a project source crosses a declared safety boundary."""


def stderr_warning(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _safe_text(value: object) -> str:
    return ascii(os.fspath(value) if isinstance(value, os.PathLike) else str(value))


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & marker)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    change_time = 0 if os.name == "nt" else int(metadata.st_ctime_ns)
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        change_time,
    )


def _relative_parts(path: Path, root: Path) -> tuple[str, ...]:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ProjectInputError(f"project path escapes its root: {_safe_text(path)}") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ProjectInputError(f"project path is not canonical below its root: {_safe_text(path)}")
    return relative.parts


def _inspect_no_redirects(path: Path, root: Path, *, final_directory: bool = False) -> os.stat_result:
    root = _absolute(root)
    path = _absolute(path)
    parts = _relative_parts(path, root)
    current = root
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise ProjectInputError(f"cannot inspect project root: {_safe_text(exc)}") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or _is_reparse_point(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ProjectInputError("project root must be a real directory, not a link or reparse point")
    for index, part in enumerate(parts):
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ProjectInputError(f"cannot inspect project path {_safe_text(current)}: {_safe_text(exc)}") from exc
        is_final = index == len(parts) - 1
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ProjectInputError(f"links and reparse points are forbidden in project input: {_safe_text(current)}")
        if not is_final and not stat.S_ISDIR(metadata.st_mode):
            raise ProjectInputError(f"non-directory project ancestor: {_safe_text(current)}")
        if is_final:
            expected = stat.S_ISDIR(metadata.st_mode) if final_directory else stat.S_ISREG(metadata.st_mode)
            if not expected:
                kind = "directory" if final_directory else "regular file"
                raise ProjectInputError(f"project entry is not a {kind}: {_safe_text(current)}")
    return metadata


def _open_regular(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)


def read_bounded_regular_file(path: Path, *, root: Path, max_bytes: int) -> bytes:
    """Read one stable regular file without following links and with a hard cap."""
    if isinstance(max_bytes, bool) or int(max_bytes) < 0:
        raise ProjectInputError("max_bytes must be a non-negative integer")
    max_bytes = int(max_bytes)
    root = _absolute(root)
    path = _absolute(path)
    before_path = _inspect_no_redirects(path, root)
    if before_path.st_size > max_bytes:
        raise ProjectInputError(f"file exceeds the {max_bytes}-byte input limit: {_safe_text(path)}")
    try:
        descriptor = _open_regular(path)
    except OSError as exc:
        raise ProjectInputError(f"cannot open project file safely: {_safe_text(path)}: {_safe_text(exc)}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProjectInputError(f"project entry is not a regular file: {_safe_text(path)}")
        if _identity(before) != _identity(before_path):
            raise ProjectInputError(f"project file changed before read: {_safe_text(path)}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ProjectInputError(f"file exceeded the {max_bytes}-byte limit while being read: {_safe_text(path)}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        after_path = _inspect_no_redirects(path, root)
        try:
            verification = _open_regular(path)
        except OSError as exc:
            raise ProjectInputError(f"project file changed during read: {_safe_text(path)}: {_safe_text(exc)}") from exc
        try:
            same_file = os.path.sameopenfile(descriptor, verification)
        finally:
            os.close(verification)
    except ProjectInputError:
        raise
    except OSError as exc:
        raise ProjectInputError(f"I/O failure while reading project file {_safe_text(path)}: {_safe_text(exc)}") from exc
    finally:
        os.close(descriptor)
    if _identity(before) != _identity(after) or _identity(before_path) != _identity(after_path) or not same_file:
        raise ProjectInputError(f"project file changed during read: {_safe_text(path)}")
    return b"".join(chunks)


def _directory_is_builtin_ignored(relative: str, rules: list[engine.IgnoreRule]) -> bool:
    probe = relative.rstrip("/") + "/__codeprobe_inventory_probe__.py"
    return engine.project_path_is_ignored(probe, rules)


def _walk_metadata(root: Path, *, max_entries: int) -> list[tuple[Path, os.stat_result]]:
    root = _absolute(root)
    root_metadata = root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or _is_reparse_point(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ProjectInputError("project root must be a real directory")
    built_in = engine.parse_ignore_patterns(engine.default_project_ignore_text())
    pending = [root]
    captured: list[tuple[Path, os.stat_result]] = []
    while pending:
        directory = pending.pop()
        _inspect_no_redirects(directory, root, final_directory=True) if directory != root else None
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise ProjectInputError(f"cannot enumerate project directory {_safe_text(directory)}: {_safe_text(exc)}") from exc
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ProjectInputError(f"cannot inspect project entry {_safe_text(relative)}: {_safe_text(exc)}") from exc
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                raise ProjectInputError(f"links and reparse points are forbidden in project input: {_safe_text(relative)}")
            if stat.S_ISDIR(metadata.st_mode):
                if not _directory_is_builtin_ignored(relative, built_in):
                    child_directories.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ProjectInputError(f"special filesystem entry is forbidden in project input: {_safe_text(relative)}")
            captured.append((path, metadata))
            if len(captured) > max_entries:
                raise ProjectInputError(f"project inventory exceeds the {max_entries}-entry limit")
        pending.extend(reversed(child_directories))
    return sorted(captured, key=lambda item: item[0].relative_to(root).as_posix().casefold())


def read_folder_files(
    root: Path,
    *,
    include_binary_placeholders: bool = True,
    warning_sink: WarningSink = None,
    max_file_bytes: int = engine.PROJECT_MAX_FILE_BYTES_DEFAULT,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_files: int = engine.PROJECT_MAX_FILES_DEFAULT,
    max_ignore_bytes: int = DEFAULT_MAX_IGNORE_BYTES,
) -> List[Dict[str, Any]]:
    """Return a bounded payload for a folder without following redirects."""
    root = _absolute(root)
    metadata_entries = _walk_metadata(root, max_entries=int(max_entries))
    built_in_text = engine.default_project_ignore_text()
    embedded_text = ""
    ignore_entry = next(
        ((path, metadata) for path, metadata in metadata_entries if path.relative_to(root).as_posix() == ".codeprobeignore"),
        None,
    )
    if ignore_entry is not None:
        ignore_path, ignore_metadata = ignore_entry
        if ignore_metadata.st_size > max_ignore_bytes:
            raise ProjectInputError(f".codeprobeignore exceeds the {max_ignore_bytes}-byte limit")
        embedded_bytes = read_bounded_regular_file(ignore_path, root=root, max_bytes=max_ignore_bytes)
        embedded_text, warning = engine.decode_text_bytes(embedded_bytes)
        if embedded_text is None:
            raise ProjectInputError(f".codeprobeignore is not readable text: {warning}")
    rules = engine.parse_ignore_patterns(built_in_text + ("\n" + embedded_text if embedded_text else ""))

    files: List[Dict[str, Any]] = []
    total_read = 0
    analysable_seen = 0
    for path, metadata in metadata_entries:
        relative = path.relative_to(root).as_posix()
        if relative == ".codeprobeignore":
            files.append({"path": relative, "content": embedded_text, "size_bytes": metadata.st_size})
            continue
        ignored = engine.project_path_is_ignored(relative, rules)
        extension = engine.project_extension(relative)
        supported = extension in engine.PROJECT_TEXT_EXTENSIONS
        oversized = metadata.st_size > max_file_bytes
        if ignored or not supported or oversized or analysable_seen >= max_files:
            if include_binary_placeholders:
                files.append({"path": relative, "content": "", "size_bytes": metadata.st_size})
            continue
        if total_read + metadata.st_size > max_total_bytes:
            if include_binary_placeholders:
                files.append({"path": relative, "content": "", "size_bytes": metadata.st_size})
            if warning_sink:
                warning_sink(f"{relative}: skipped because the folder read budget is {max_total_bytes} bytes")
            continue
        data = read_bounded_regular_file(path, root=root, max_bytes=max_file_bytes)
        total_read += len(data)
        analysable_seen += 1
        text, warning = engine.decode_text_bytes(data)
        if text is None:
            if warning_sink:
                warning_sink(f"{relative}: {warning}")
            if include_binary_placeholders:
                files.append({"path": relative, "content": "", "size_bytes": len(data)})
            continue
        if warning and warning_sink:
            warning_sink(f"{relative}: {warning}")
        files.append({"path": relative, "content": text, "size_bytes": len(data)})
    return files


def project_payload_from_path(
    path: Path,
    *,
    include_binary_placeholders: bool = True,
    max_file_bytes: int = engine.PROJECT_MAX_FILE_BYTES_DEFAULT,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_files: int = engine.PROJECT_MAX_FILES_DEFAULT,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
) -> Dict[str, Any]:
    """Build a bounded engine payload from a folder or ZIP archive."""
    path = _absolute(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProjectInputError(f"project sample is unavailable: {_safe_text(path)}: {_safe_text(exc)}") from exc
    common = {
        "max_file_bytes": int(max_file_bytes),
        "max_total_bytes": int(max_total_bytes),
        "max_zip_entries": int(max_entries),
        "max_files": int(max_files),
        "max_zip_bytes": int(max_archive_bytes),
    }
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ProjectInputError("project sample must not be a link or reparse point")
    if stat.S_ISDIR(metadata.st_mode):
        return {
            "project_name": path.name,
            "files": read_folder_files(
                path,
                include_binary_placeholders=include_binary_placeholders,
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                max_entries=max_entries,
                max_files=max_files,
            ),
            **common,
        }
    if stat.S_ISREG(metadata.st_mode) and path.suffix.lower() == ".zip":
        archive = read_bounded_regular_file(path, root=path.parent, max_bytes=max_archive_bytes)
        return {
            "project_name": path.stem,
            "zip_base64": base64.b64encode(archive).decode("ascii"),
            **common,
        }
    raise ProjectInputError(f"project sample must be a directory or ZIP archive: {_safe_text(path)}")
'''


ANALYSE_PROJECT = '''#!/usr/bin/env python3
"""Bounded local CLI for CodeProbe project and ZIP analysis."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit("this command requires isolated, site-free Python; rerun it with -I -S -B")

import argparse
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
from codeprobe_engine.project_io import (
    DEFAULT_MAX_ARCHIVE_BYTES,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_TOTAL_BYTES,
    project_payload_from_path,
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
        ignore_path = Path(args.ignore_file)
        data = ignore_path.read_bytes()
        if len(data) > args.max_ignore_bytes:
            raise ValueError(f"explicit ignore file exceeds {args.max_ignore_bytes} bytes")
        payload["ignore_text"] = data.decode("utf-8")
    if args.config:
        payload["config_override"] = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.calibration_profile:
        payload["calibration_profile"] = json.loads(Path(args.calibration_profile).read_text(encoding="utf-8"))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse a CodeProbe project folder or ZIP archive safely.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--folder", help="Project folder to walk without following links.")
    source.add_argument("--zip", help="Project ZIP archive to analyse.")
    parser.add_argument("--project-name", default="", help="Project name used in the report header.")
    parser.add_argument("--profile", default="default", choices=sorted(engine.SCORING_PROFILES), help="Scoring profile.")
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
        payload = build_payload(args)
        result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
    except Exception as exc:
        print(f"CodeProbe project analysis failed: {exc}", file=sys.stderr)
        return 2
    text = result.get("text", "")
    project_report = result.get("project_report", {})
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(project_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.text_out:
        Path(args.text_out).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


CALIBRATE_PROFILE = '''#!/usr/bin/env python3
"""Build a scoped CodeProbe profile with independent holdout evaluation."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit("this command requires isolated, site-free Python; rerun it with -I -S -B")

import argparse
import csv
import hashlib
import json
import os
import stat
import statistics
import time
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
    ProjectInputError,
    project_payload_from_path,
    read_bounded_regular_file,
)

NEGATIVE_LABELS = {"human", "known_human", "declared_human", "pre_llm", "student_human", "no_ai"}
POSITIVE_LABELS = {"ai", "llm", "generated", "ai_generated", "llm_generated", "heavy_ai", "synthetic_ai"}
HYBRID_LABELS = {"hybrid", "assisted", "ai_assisted", "light_ai", "mixed", "revised_ai"}
SUPPORTED_LABELS = NEGATIVE_LABELS | POSITIVE_LABELS | HYBRID_LABELS
FIT_SPLITS = {"fit", "train", "training", "selection"}
EVALUATION_SPLITS = {"evaluation", "evaluate", "eval", "test", "holdout", "validation"}


@dataclass
class SampleResult:
    path: str
    label: str
    kind: str
    language: str
    score: Optional[float]
    applicable: bool
    sloc: int
    verdict_class: str
    warning: str = ""
    sample_id: str = ""
    split: str = ""
    group_id: str = ""


def load_manifest(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.DictReader(handle))
        return {"profile_id": path.stem, "label": path.stem, "samples": rows}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("samples"), list):
        raise ValueError("JSON manifest must be an object containing a samples list.")
    return data


def resolve_sample_path(base_dir: Path, sample_path: str) -> Path:
    base = Path(os.path.abspath(os.fspath(base_dir)))
    candidate = Path(sample_path)
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = Path(os.path.abspath(os.fspath(candidate)))
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError("calibration samples must remain below the declared corpus root") from exc
    return candidate


def sample_kind(path: Path, record: Dict[str, Any]) -> str:
    explicit = str(record.get("kind") or record.get("mode") or "").strip().lower()
    if explicit in {"file", "project"}:
        return explicit
    if path.suffix.lower() == ".zip":
        return "project"
    try:
        metadata = path.lstat()
    except OSError:
        return "file"
    return "project" if stat.S_ISDIR(metadata.st_mode) else "file"


def _normalise_label(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _normalise_split(value: object) -> str:
    raw = str(value or "").strip().lower().replace("-", "_")
    if not raw:
        return ""
    if raw in FIT_SPLITS:
        return "fit"
    if raw in EVALUATION_SPLITS:
        return "evaluation"
    raise ValueError(f"unsupported calibration split: {raw!r}")


def _stratum(label: str) -> str:
    return "human" if label in NEGATIVE_LABELS else "positive"


def _safe_relative_identifier(base_dir: Path, path: Path, raw_path: str, index: int) -> str:
    try:
        relative = path.relative_to(base_dir).as_posix()
    except ValueError:
        relative = ""
    candidate = relative or str(raw_path or "").replace("\\", "/")
    pure = PurePosixPath(candidate)
    if (
        not candidate
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
    ):
        suffix = path.suffix.lower()[:12]
        digest = hashlib.sha256(f"{index}|{raw_path}".encode("utf-8", errors="backslashreplace")).hexdigest()[:16]
        return f"sample-{digest}{suffix}"
    return pure.as_posix()


def _safe_output_identifier(value: str, index: int) -> str:
    raw = str(value or "").replace("\\", "/")
    pure = PurePosixPath(raw)
    if raw and not pure.is_absolute() and not any(part in {"", ".", ".."} for part in pure.parts):
        return pure.as_posix()
    suffix = Path(raw).suffix.lower()[:12]
    digest = hashlib.sha256(f"{index}|{raw}".encode("utf-8", errors="backslashreplace")).hexdigest()[:16]
    return f"sample-{digest}{suffix}"


def _group_token(value: object, fallback: str) -> str:
    raw = str(value or fallback)
    return "group-" + hashlib.sha256(raw.encode("utf-8", errors="backslashreplace")).hexdigest()[:16]


def _read_text_file(path: Path, root: Path) -> str:
    data = read_bounded_regular_file(path, root=root, max_bytes=engine.PROJECT_MAX_FILE_BYTES_DEFAULT)
    text, warning = engine.decode_text_bytes(data)
    if text is None:
        raise ValueError(warning or "file is not readable text")
    return text


def analyse_sample(
    path: Path,
    record: Dict[str, Any],
    profile: str,
    *,
    base_dir: Path | None = None,
    sample_id: str = "",
    split: str = "",
    group_id: str = "",
) -> SampleResult:
    label = _normalise_label(record.get("label") or record.get("class"))
    if label not in SUPPORTED_LABELS:
        raise ValueError(f"unsupported or missing label for {sample_id or path.name}: {label!r}")
    kind = sample_kind(path, record)
    language_hint = record.get("language_hint") or record.get("language") or None
    safe_id = sample_id or _safe_output_identifier(str(path), 0)
    safe_group = group_id or _group_token(record.get("group") or record.get("group_id"), safe_id)
    root = base_dir or path.parent
    try:
        if kind == "project":
            payload = project_payload_from_path(
                path,
                include_binary_placeholders=False,
                max_archive_bytes=DEFAULT_MAX_ARCHIVE_BYTES,
                max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
                max_entries=DEFAULT_MAX_ENTRIES,
            )
            payload["profile"] = profile
            result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
            report = result["project_report"]
        else:
            payload = {
                "code": _read_text_file(path, root),
                "filename": path.name,
                "profile": profile,
                "language_hint": None if language_hint == "auto" else language_hint,
            }
            report = json.loads(engine.codeprobe_analyze(json.dumps(payload)))["report"]
        applicable = bool(report.get("overall_applicable"))
        score = float(report.get("overall_score", 0.0)) if applicable else None
        return SampleResult(
            path=safe_id,
            sample_id=safe_id,
            group_id=safe_group,
            split=_normalise_split(split),
            label=label,
            kind=kind,
            language=str(report.get("language") or ("project" if kind == "project" else "unknown")),
            score=score,
            applicable=applicable,
            sloc=int(report.get("sloc") or report.get("total_sloc") or 0),
            verdict_class=str(report.get("verdict_class") or "insufficient"),
        )
    except Exception as exc:
        return SampleResult(
            path=safe_id,
            sample_id=safe_id,
            group_id=safe_group,
            split=_normalise_split(split),
            label=label,
            kind=kind,
            language="unknown",
            score=None,
            applicable=False,
            sloc=0,
            verdict_class="error",
            warning=f"{type(exc).__name__}: {exc}",
        )


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    q = max(0.0, min(1.0, q))
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    fraction = position - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def describe_scores(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "mean": round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "stdev": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
        "min": round(min(values), 4),
        "p10": round(percentile(values, 0.10), 4),
        "p25": round(percentile(values, 0.25), 4),
        "p75": round(percentile(values, 0.75), 4),
        "p90": round(percentile(values, 0.90), 4),
        "max": round(max(values), 4),
    }


def threshold_rates(human_scores: Sequence[float], ai_scores: Sequence[float], hybrid_scores: Sequence[float], threshold: float) -> Dict[str, float]:
    positive_scores = list(ai_scores) + list(hybrid_scores)
    return {
        "threshold": round(threshold, 4),
        "false_positive_rate": round(sum(score >= threshold for score in human_scores) / len(human_scores), 4) if human_scores else 0.0,
        "ai_generated_review_rate": round(sum(score >= threshold for score in ai_scores) / len(ai_scores), 4) if ai_scores else 0.0,
        "hybrid_review_rate": round(sum(score >= threshold for score in hybrid_scores) / len(hybrid_scores), 4) if hybrid_scores else 0.0,
        "true_positive_rate": round(sum(score >= threshold for score in positive_scores) / len(positive_scores), 4) if positive_scores else 0.0,
    }


def choose_review_trigger(human_scores: Sequence[float], ai_scores: Sequence[float], hybrid_scores: Sequence[float], target_fpr: float) -> Tuple[float, List[Dict[str, float]], str]:
    positive_scores = list(ai_scores) + list(hybrid_scores)
    grid = [round(x / 100.0, 2) for x in range(10, 91)]
    rows = [threshold_rates(human_scores, ai_scores, hybrid_scores, threshold) for threshold in grid]
    if human_scores and positive_scores:
        eligible = [row for row in rows if row["false_positive_rate"] <= target_fpr]
        if eligible:
            best = max(eligible, key=lambda row: (row["true_positive_rate"], -row["threshold"]))
            return best["threshold"], rows, "selected_on_fit_partition_at_target_fpr"
    if human_scores:
        trigger = min(0.90, max(0.40, percentile(human_scores, 1.0 - target_fpr)))
        return round(trigger, 2), rows, "fit_human_percentile_fallback"
    raise ValueError("fit partition has no applicable known-human samples")


def bands_from_trigger(trigger: float) -> Dict[str, float]:
    low = min(0.35, max(0.18, trigger * 0.55))
    moderate = min(0.55, max(low + 0.10, trigger * 0.80))
    elevated = min(0.85, max(moderate + 0.10, trigger + 0.10))
    return {"low_max": round(low, 4), "moderate_max": round(moderate, 4), "elevated_max": round(elevated, 4), "review_trigger": round(trigger, 4)}


def label_groups(results: Sequence[SampleResult]) -> Tuple[List[float], List[float], List[float]]:
    applicable = [item for item in results if item.applicable and item.score is not None]
    return (
        [float(item.score) for item in applicable if item.label in NEGATIVE_LABELS],
        [float(item.score) for item in applicable if item.label in POSITIVE_LABELS],
        [float(item.score) for item in applicable if item.label in HYBRID_LABELS],
    )


def _normalise_results(results: Sequence[SampleResult]) -> list[SampleResult]:
    normalised: list[SampleResult] = []
    for index, item in enumerate(results):
        identifier = _safe_output_identifier(item.sample_id or item.path, index)
        split = _normalise_split(item.split)
        group = item.group_id if str(item.group_id).startswith("group-") else _group_token(item.group_id, identifier)
        normalised.append(replace(item, path=identifier, sample_id=identifier, group_id=group, split=split))
    return normalised


def _assign_splits(results: Sequence[SampleResult], manifest: Dict[str, Any]) -> tuple[list[SampleResult], str]:
    values = [item.split for item in results]
    if any(values):
        if not all(values):
            raise ValueError("explicit calibration splits must be supplied for every sample")
        assigned = list(results)
        strategy = "explicit_group_holdout"
    else:
        fraction = float(manifest.get("evaluation_fraction", 0.25))
        if not 0.10 <= fraction <= 0.50:
            raise ValueError("evaluation_fraction must be between 0.10 and 0.50")
        seed = str(manifest.get("split_seed") or "codeprobe-calibration-v1")
        groups_by_stratum: dict[str, set[str]] = {"human": set(), "positive": set()}
        group_strata: dict[str, str] = {}
        for item in results:
            stratum = _stratum(item.label)
            previous = group_strata.setdefault(item.group_id, stratum)
            if previous != stratum:
                raise ValueError("one calibration group cannot mix known-human and positive labels")
            groups_by_stratum[stratum].add(item.group_id)
        evaluation_groups: set[str] = set()
        for stratum, groups in groups_by_stratum.items():
            if len(groups) < 2:
                raise ValueError(f"independent evaluation requires at least two {stratum} groups")
            ordered = sorted(groups, key=lambda value: hashlib.sha256(f"{seed}|{stratum}|{value}".encode()).hexdigest())
            count = max(1, min(len(ordered) - 1, round(len(ordered) * fraction)))
            evaluation_groups.update(ordered[:count])
        assigned = [replace(item, split="evaluation" if item.group_id in evaluation_groups else "fit") for item in results]
        strategy = "deterministic_stratified_group_holdout"
    group_splits: dict[str, str] = {}
    for item in assigned:
        previous = group_splits.setdefault(item.group_id, item.split)
        if previous != item.split:
            raise ValueError("all samples from one calibration group must remain in one partition")
    return assigned, strategy


def _require_partition_balance(results: Sequence[SampleResult], label: str) -> None:
    human, ai, hybrid = label_groups(results)
    if not human:
        raise ValueError(f"{label} partition has no applicable known-human sample")
    if not (ai or hybrid):
        raise ValueError(f"{label} partition has no applicable AI-generated or hybrid sample")


def _profile_domain(results: Sequence[SampleResult]) -> tuple[str, str]:
    applicable = [item for item in results if item.applicable and item.score is not None]
    kinds = {item.kind for item in applicable}
    if len(kinds) != 1:
        raise ValueError("one calibration profile cannot mix file and project report kinds")
    kind = next(iter(kinds))
    languages = {item.language for item in applicable}
    if len(languages) != 1:
        raise ValueError("one calibration profile cannot mix languages; generate one profile per language")
    language = next(iter(languages))
    if kind == "project" and language != "project":
        raise ValueError("project calibration samples must yield project reports")
    return kind, language


def build_profile(manifest: Dict[str, Any], results: Sequence[SampleResult], target_fpr: float) -> Dict[str, Any]:
    normalised = _normalise_results(results)
    failures = [item for item in normalised if item.verdict_class in {"error", "missing"}]
    if failures:
        detail = "; ".join(f"{item.sample_id}: {item.warning or item.verdict_class}" for item in failures[:5])
        raise ValueError(f"calibration aborted because sample analysis failed: {detail}")
    assigned, strategy = _assign_splits(normalised, manifest)
    kind, language = _profile_domain(assigned)
    fit = [item for item in assigned if item.split == "fit"]
    evaluation = [item for item in assigned if item.split == "evaluation"]
    _require_partition_balance(fit, "fit")
    _require_partition_balance(evaluation, "evaluation")
    fit_human, fit_ai, fit_hybrid = label_groups(fit)
    eval_human, eval_ai, eval_hybrid = label_groups(evaluation)
    all_human, all_ai, all_hybrid = label_groups(assigned)
    trigger, sensitivity, trigger_source = choose_review_trigger(fit_human, fit_ai, fit_hybrid, target_fpr)
    bands = bands_from_trigger(trigger)
    profile_id = str(manifest.get("profile_id") or manifest.get("name") or "course-local-profile")
    label = str(manifest.get("label") or manifest.get("title") or profile_id)
    validation = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_version": engine.APP_VERSION,
        "target_false_positive_rate": target_fpr,
        "trigger_source": trigger_source,
        "sample_count": len(assigned),
        "applicable_sample_count": len([item for item in assigned if item.applicable]),
        "evaluation_design": {
            "strategy": strategy,
            "independent_holdout": True,
            "selection_partition": "fit",
            "performance_partition": "evaluation",
            "group_exclusive": True,
            "fit_sample_count": len(fit),
            "evaluation_sample_count": len(evaluation),
            "fit_group_count": len({item.group_id for item in fit}),
            "evaluation_group_count": len({item.group_id for item in evaluation}),
        },
        "score_distributions": {
            "human": describe_scores(all_human),
            "ai_generated": describe_scores(all_ai),
            "hybrid": describe_scores(all_hybrid),
        },
        "fit_score_distributions": {
            "human": describe_scores(fit_human),
            "ai_generated": describe_scores(fit_ai),
            "hybrid": describe_scores(fit_hybrid),
        },
        "evaluation_score_distributions": {
            "human": describe_scores(eval_human),
            "ai_generated": describe_scores(eval_ai),
            "hybrid": describe_scores(eval_hybrid),
        },
        "fit_at_selected_trigger": threshold_rates(fit_human, fit_ai, fit_hybrid, trigger),
        "evaluation_at_selected_trigger": threshold_rates(eval_human, eval_ai, eval_hybrid, trigger),
        "sensitivity_partition": "fit",
        "sensitivity": sensitivity,
        "sample_results": [item.__dict__ for item in assigned],
    }
    notes = [
        "Generated from a group-exclusive fit/evaluation design.",
        "The trigger was selected only on the fit partition; reported performance comes from the untouched evaluation partition.",
        "Sample paths and group identifiers are corpus-relative or pseudonymised; absolute local paths are not exported.",
        "The trigger is a review threshold, not a probability boundary and not evidence of misconduct.",
    ]
    if len(fit_human) < 20 or len(fit_ai) + len(fit_hybrid) < 20 or len(eval_human) < 10 or len(eval_ai) + len(eval_hybrid) < 10:
        notes.append("Calibration partitions are small; treat this profile as a draft and expand the corpus before high-stakes use.")
    return {
        "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
        "profile_id": profile_id,
        "label": label,
        "course": manifest.get("course", ""),
        "assignment": manifest.get("assignment", ""),
        "profile_version": manifest.get("profile_version", ""),
        "scope": {"report_kinds": [kind], "languages": [language], "mixed_domains_permitted": False},
        "review_policy": {kind: bands},
        "metric_overrides": manifest.get("metric_overrides", {}),
        "validation": validation,
        "notes": notes,
    }


def write_summary(path: Path, profile: Dict[str, Any]) -> None:
    validation = profile.get("validation", {})
    design = validation.get("evaluation_design", {})
    evaluation = validation.get("evaluation_at_selected_trigger", {})
    distributions = validation.get("evaluation_score_distributions", {})
    sensitivity = validation.get("sensitivity", [])
    scope = profile.get("scope", {})
    kind = (scope.get("report_kinds") or ["file"])[0]
    trigger = float(profile.get("review_policy", {}).get(kind, {}).get("review_trigger", 0.60))
    lines = [
        f"# CodeProbe calibration summary — {profile.get('label', profile.get('profile_id', 'course-local'))}",
        "",
        f"Generated with CodeProbe {engine.APP_VERSION}.",
        f"Calibrated scope: `{kind}` / `{', '.join(scope.get('languages') or [])}`.",
        f"Suggested local review trigger: **{trigger * 100:.1f}%**.",
        f"Selection source: `{validation.get('trigger_source', 'unknown')}` using only the fit partition.",
        f"Evaluation design: `{design.get('strategy', 'unknown')}`; group-exclusive independent holdout: `{design.get('independent_holdout', False)}`.",
        f"Fit/evaluation samples: {design.get('fit_sample_count', 0)}/{design.get('evaluation_sample_count', 0)}.",
        "",
        "## Independent evaluation at the selected trigger",
        "",
        f"- Known-human false-positive review rate: {float(evaluation.get('false_positive_rate', 0.0)):.3f}",
        f"- AI-generated review rate: {float(evaluation.get('ai_generated_review_rate', 0.0)):.3f}",
        f"- Hybrid review rate: {float(evaluation.get('hybrid_review_rate', 0.0)):.3f}",
        f"- Combined positive review rate: {float(evaluation.get('true_positive_rate', 0.0)):.3f}",
        "",
        "## Evaluation score distributions",
        "",
        "| Label group | n | mean | median | p90 | max |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for group in ("human", "ai_generated", "hybrid"):
        stats = distributions.get(group, {"count": 0})
        lines.append(f"| {group} | {stats.get('count', 0)} | {stats.get('mean', 'n/a')} | {stats.get('median', 'n/a')} | {stats.get('p90', 'n/a')} | {stats.get('max', 'n/a')} |")
    lines.extend(["", "## Fit-partition sensitivity grid", "", "| threshold | fit human FPR | fit AI review rate | fit hybrid review rate | fit combined positive rate |", "|---:|---:|---:|---:|---:|"])
    for row in sensitivity:
        if int(float(row["threshold"]) * 100) % 5 == 0:
            lines.append(f"| {row['threshold']:.2f} | {row['false_positive_rate']:.3f} | {row.get('ai_generated_review_rate', 0.0):.3f} | {row.get('hybrid_review_rate', 0.0):.3f} | {row['true_positive_rate']:.3f} |")
    lines.extend(["", "## Caveats", ""])
    lines.extend(f"- {note}" for note in profile.get("notes", []))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_observations_csv(path: Path, results: Sequence[SampleResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["sample_id", "group_id", "split", "path", "label", "kind", "language", "applicable", "score", "score_percent", "sloc", "verdict_class", "warning"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index, item in enumerate(_normalise_results(results)):
            writer.writerow({
                "sample_id": item.sample_id,
                "group_id": item.group_id,
                "split": item.split,
                "path": item.sample_id,
                "label": item.label,
                "kind": item.kind,
                "language": item.language,
                "applicable": item.applicable,
                "score": "" if item.score is None else f"{item.score:.6f}",
                "score_percent": "" if item.score is None else f"{item.score * 100:.2f}",
                "sloc": item.sloc,
                "verdict_class": item.verdict_class,
                "warning": item.warning,
            })


def write_sensitivity_csv(path: Path, profile: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["threshold", "false_positive_rate", "ai_generated_review_rate", "hybrid_review_rate", "true_positive_rate"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in profile.get("validation", {}).get("sensitivity", []):
            writer.writerow({field: row.get(field, "") for field in fields})


def _manifest_records(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    samples = manifest.get("samples") or manifest.get("records") or []
    if not isinstance(samples, list):
        raise ValueError("calibration manifest must contain a samples/records list")
    return [item for item in samples if isinstance(item, dict)]


def run_calibration(args: Any) -> Dict[str, Any]:
    manifest_path = Path(args.manifest).absolute()
    manifest = load_manifest(manifest_path)
    if getattr(args, "profile_id", None):
        manifest["profile_id"] = args.profile_id
    if getattr(args, "label", None):
        manifest["label"] = args.label
    if getattr(args, "profile_version", None):
        manifest["profile_version"] = args.profile_version
    if getattr(args, "config", None):
        manifest["metric_overrides"] = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if getattr(args, "evaluation_fraction", None) is not None:
        manifest["evaluation_fraction"] = float(args.evaluation_fraction)
    if getattr(args, "split_seed", None):
        manifest["split_seed"] = str(args.split_seed)

    base_dir = Path(getattr(args, "root", "") or manifest_path.parent).absolute()
    target_fpr = float(getattr(args, "target_fpr", 0.10))
    target_fpr = target_fpr / 100.0 if target_fpr > 1.0 else target_fpr
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("target_fpr must be between 0 and 1, or between 0 and 100 as a percentage")
    profile_name = getattr(args, "profile", "default") or "default"
    results: List[SampleResult] = []
    records = _manifest_records(manifest)
    if not records:
        raise ValueError("calibration manifest contains no sample records")
    explicit_split_presence = [bool(str(record.get("split") or record.get("partition") or "").strip()) for record in records]
    if any(explicit_split_presence) and not all(explicit_split_presence):
        raise ValueError("explicit split/partition must be supplied for every calibration sample")
    for index, record in enumerate(records):
        raw_path = record.get("path") or record.get("file") or record.get("folder") or record.get("zip")
        label = _normalise_label(record.get("label") or record.get("class"))
        if not raw_path:
            results.append(SampleResult(f"sample-{index}", label, "file", "unknown", None, False, 0, "missing", "sample path missing", f"sample-{index}", _normalise_split(record.get("split") or record.get("partition")), _group_token(record.get("group"), f"sample-{index}")))
            continue
        path = resolve_sample_path(base_dir, str(raw_path))
        sample_id = _safe_relative_identifier(base_dir, path, str(raw_path), index)
        group_id = _group_token(record.get("group") or record.get("group_id") or record.get("student_id") or record.get("submission_id"), sample_id)
        split = _normalise_split(record.get("split") or record.get("partition"))
        try:
            path.lstat()
        except OSError:
            results.append(SampleResult(sample_id, label, sample_kind(path, record), "unknown", None, False, 0, "missing", "path does not exist", sample_id, split, group_id))
            continue
        results.append(analyse_sample(path, record, profile_name, base_dir=base_dir, sample_id=sample_id, split=split, group_id=group_id))
    failures = [item for item in results if item.verdict_class in {"error", "missing"}]
    if failures:
        detail = "; ".join(f"{item.sample_id}: {item.warning}" for item in failures[:5])
        raise ValueError(f"calibration aborted because sample analysis failed: {detail}")
    profile = build_profile(manifest, results, target_fpr)
    assigned = [SampleResult(**item) for item in profile["validation"]["sample_results"]]
    out_dir = Path(getattr(args, "out_dir", "") or manifest_path.with_suffix(""))
    out_dir.mkdir(parents=True, exist_ok=True)
    profile_path = out_dir / "calibration_profile.json"
    observations_path = out_dir / "calibration_observations.csv"
    sensitivity_path = out_dir / "threshold_sensitivity.csv"
    summary_path = out_dir / "validation_summary.md"
    profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_observations_csv(observations_path, assigned)
    write_sensitivity_csv(sensitivity_path, profile)
    write_summary(summary_path, profile)
    return {"profile": profile, "results": [item.__dict__ for item in assigned], "profile_path": str(profile_path), "observations_path": str(observations_path), "sensitivity_path": str(sensitivity_path), "summary_path": str(summary_path)}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a scoped CodeProbe calibration profile with independent evaluation.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", default="")
    parser.add_argument("--profile", default="default", choices=sorted(engine.SCORING_PROFILES))
    parser.add_argument("--profile-id", default="")
    parser.add_argument("--label", default="")
    parser.add_argument("--profile-version", default="")
    parser.add_argument("--target-fpr", type=float, default=0.10)
    parser.add_argument("--evaluation-fraction", type=float, default=None)
    parser.add_argument("--split-seed", default="")
    parser.add_argument("--min-per-class-for-language", type=int, default=10)
    parser.add_argument("--config")
    parser.add_argument("--out-dir")
    parser.add_argument("--profile-out")
    parser.add_argument("--summary-out")
    parser.add_argument("--json-out")
    parser.add_argument("--md-out")
    parser.add_argument("--csv-out")
    parser.add_argument("--sensitivity-out")
    args = parser.parse_args(argv)
    profile_out = args.profile_out or args.json_out
    summary_out = args.summary_out or args.md_out
    if not args.out_dir and not profile_out:
        parser.error("provide --out-dir or --profile-out/--json-out")
    result = run_calibration(args)
    profile = result["profile"]
    written_profile = result["profile_path"]
    written_summary = result["summary_path"]
    written_observations = result["observations_path"]
    written_sensitivity = result["sensitivity_path"]
    if profile_out:
        path = Path(profile_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written_profile = str(path)
    if summary_out:
        path = Path(summary_out)
        write_summary(path, profile)
        written_summary = str(path)
    assigned = [SampleResult(**item) for item in result.get("results", [])]
    if args.csv_out:
        path = Path(args.csv_out)
        write_observations_csv(path, assigned)
        written_observations = str(path)
    if args.sensitivity_out:
        path = Path(args.sensitivity_out)
        write_sensitivity_csv(path, profile)
        written_sensitivity = str(path)
    print(f"Wrote calibration profile: {written_profile}")
    print(f"Wrote validation summary: {written_summary}")
    print(f"Wrote observations CSV: {written_observations}")
    print(f"Wrote threshold sensitivity CSV: {written_sensitivity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


PROJECT_TESTS = '''from __future__ import annotations

import base64
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine import project_io  # noqa: E402


def zip_payload(entries, *, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for path, content in entries:
            archive.writestr(path, content)
    return base64.b64encode(buffer.getvalue()).decode("ascii"), buffer.getvalue()


class PhaseThreeProjectModeTests(unittest.TestCase):
    def test_codeprobeignore_excludes_generated_and_documentation_files(self) -> None:
        payload = {"project_name": "student-project", "files": [{"path": ".codeprobeignore", "content": "generated/\n*.min.js\n"}, {"path": "src/main.py", "content": "def add(left, right):\n    return left + right\n\nprint(add(1, 2))\n"}, {"path": "generated/client.py", "content": "def generated():\n    return 42\n"}, {"path": "web/app.min.js", "content": "function x(){return 1}\n"}, {"path": "docs/README.md", "content": "# Notes\n"}], "profile": "default"}
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})
        self.assertEqual(report["schema_version"], "2.2.0-project")

    def test_zip_project_payload_is_supported_and_rejects_unsafe_paths(self) -> None:
        encoded, _ = zip_payload([("src/app.py", "def main():\n    return 0\n\nmain()\n"), ("../escape.py", "print('bad')\n"), ("assets/logo.png", b"\x00\x01\x02")])
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "zip-project", "zip_base64": encoded})))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/app.py"})
        reasons = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(reasons.get("../escape.py"), "unsafe_path")

    def test_project_score_uses_sloc_weighting_and_cap(self) -> None:
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "weighted", "files": [{"path": "a.py", "content": "def a():\n    return 1\n"}, {"path": "b.js", "content": "function b() { return 2; }\n"}]})))["project_report"]
        self.assertEqual(report["included_file_count"], 2)
        self.assertEqual(report["aggregation"]["per_file_sloc_cap"], engine.PROJECT_WEIGHT_CAP_SLOC)

    def test_markdown_is_excluded_from_project_aggregate_by_default(self) -> None:
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "docs", "files": [{"path": "README.md", "content": "# Project\n"}]})))["project_report"]
        self.assertEqual(report["included_file_count"], 0)
        self.assertFalse(report["overall_applicable"])

    def test_negated_codeprobeignore_rule_can_reinclude_authored_source(self) -> None:
        payload = {"project_name": "negation", "files": [{"path": ".codeprobeignore", "content": "src/generated/\n!src/generated/handwritten.py\n"}, {"path": "src/generated/client.py", "content": "def generated():\n    return 1\n"}, {"path": "src/generated/handwritten.py", "content": "def handwritten():\n    return 2\n"}]}
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/generated/handwritten.py"})

    def test_unsafe_embedded_ignore_file_is_not_loaded(self) -> None:
        encoded, _ = zip_payload([("../.codeprobeignore", "src/\n"), ("src/app.py", "def main():\n    return 0\n")])
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "unsafe-ignore", "zip_base64": encoded})))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/app.py"})

    def test_project_text_report_lists_included_and_excluded_files(self) -> None:
        result = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "text-report", "files": [{"path": "src/app.py", "content": "def main():\n    return 0\n"}, {"path": "README.md", "content": "# Documentation\n"}]})))
        self.assertIn("Analysed files:", result["text"])
        self.assertIn("Excluded files:", result["text"])


class HostileProjectInputTests(unittest.TestCase):
    def _report(self, payload):
        return json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]

    def test_forged_file_size_metadata_is_not_trusted(self):
        report = self._report({"project_name": "forged", "max_file_bytes": 16, "files": [{"path": "main.py", "content": "x = '" + "a" * 100 + "'\n", "size_bytes": 1}]})
        self.assertEqual(report["excluded_files"][0]["reason"], "file_too_large")

    def test_invalid_file_limit_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "max_file_bytes"):
            engine.analyse_project_payload({"files": [], "max_file_bytes": 0})

    def test_invalid_total_limit_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "max_total_bytes"):
            engine.analyse_project_payload({"files": [], "max_total_bytes": -1})

    def test_zip_compressed_size_limit_is_checked_before_decode(self):
        encoded, raw = zip_payload([("main.py", "print('x')\n")])
        with self.assertRaisesRegex(ValueError, "compressed ZIP limit"):
            engine.analyse_project_payload({"zip_base64": encoded, "max_zip_bytes": len(raw) - 1})

    def test_zip_entry_count_limit_is_checked_from_eocd(self):
        encoded, _ = zip_payload([(f"f{i}.py", "print(1)\n") for i in range(3)])
        with self.assertRaisesRegex(ValueError, "entry limit"):
            engine.analyse_project_payload({"zip_base64": encoded, "max_zip_entries": 2})

    def test_zip_compression_ratio_bomb_is_not_decompressed(self):
        encoded, _ = zip_payload([("bomb.py", "#" + "0" * 200000)])
        report = self._report({"zip_base64": encoded, "max_file_bytes": 300000, "max_compression_ratio": 5})
        self.assertEqual(report["excluded_files"][0]["reason"], "compression_ratio_exceeded")

    def test_zip_member_size_limit_prevents_read(self):
        encoded, _ = zip_payload([("large.py", "x" * 1000)])
        report = self._report({"zip_base64": encoded, "max_file_bytes": 100})
        self.assertEqual(report["excluded_files"][0]["reason"], "file_too_large")

    def test_zip_total_budget_excludes_later_members(self):
        encoded, _ = zip_payload([("a.py", "a = 1\n" * 5), ("b.py", "b = 2\n" * 5)])
        report = self._report({"zip_base64": encoded, "max_total_bytes": 45})
        self.assertIn("project_total_byte_limit", {item["reason"] for item in report["excluded_files"]})

    def test_zip_unsupported_compression_is_not_opened(self):
        if not hasattr(zipfile, "ZIP_BZIP2"):
            self.skipTest("BZIP2 not available")
        encoded, _ = zip_payload([("main.py", "print(1)\n")], compression=zipfile.ZIP_BZIP2)
        report = self._report({"zip_base64": encoded})
        self.assertEqual(report["excluded_files"][0]["reason"], "unsupported_compression_method")

    def test_zip_encrypted_flag_is_rejected_before_member_read(self):
        encoded, raw = zip_payload([("main.py", "print(1)\n")])
        altered = bytearray(raw)
        local = altered.find(b"PK\x03\x04")
        central = altered.find(b"PK\x01\x02")
        altered[local + 6:local + 8] = (1).to_bytes(2, "little")
        altered[central + 8:central + 10] = (1).to_bytes(2, "little")
        report = self._report({"zip_base64": base64.b64encode(altered).decode("ascii")})
        self.assertEqual(report["excluded_files"][0]["reason"], "encrypted_zip_entry")

    def test_portable_duplicate_paths_are_excluded(self):
        encoded, _ = zip_payload([("A.py", "print(1)\n"), ("a.py", "print(2)\n")])
        report = self._report({"zip_base64": encoded})
        self.assertIn("duplicate_path", {item["reason"] for item in report["excluded_files"]})

    def test_ignore_file_below_ignored_directory_cannot_control_project(self):
        payload = {"files": [{"path": "node_modules/.codeprobeignore", "content": "src/\n"}, {"path": "src/main.py", "content": "print(1)\n"}]}
        report = self._report(payload)
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})

    def test_explicit_ignore_text_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "ignore_text"):
            engine.analyse_project_payload({"files": [], "ignore_text": "x" * 20, "max_ignore_bytes": 10})

    def test_explicit_ignore_rule_count_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "ignore rule"):
            engine.analyse_project_payload({"files": [], "ignore_text": "a\nb\nc\n", "max_ignore_rules": 2})

    def test_common_export_root_is_stripped_before_root_ignore(self):
        encoded, _ = zip_payload([("repo-main/.codeprobeignore", "generated/\n"), ("repo-main/generated/a.py", "print(1)\n"), ("repo-main/src/main.py", "print(2)\n")])
        report = self._report({"zip_base64": encoded})
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})

    def test_zip64_marker_is_rejected(self):
        encoded, raw = zip_payload([("main.py", "print(1)\n")])
        altered = bytearray(raw)
        eocd = altered.rfind(b"PK\x05\x06")
        altered[eocd + 10:eocd + 12] = (0xFFFF).to_bytes(2, "little")
        with self.assertRaisesRegex(ValueError, "ZIP64"):
            engine.analyse_project_payload({"zip_base64": base64.b64encode(altered).decode("ascii")})

    def test_multidisk_marker_is_rejected(self):
        encoded, raw = zip_payload([("main.py", "print(1)\n")])
        altered = bytearray(raw)
        eocd = altered.rfind(b"PK\x05\x06")
        altered[eocd + 4:eocd + 6] = (1).to_bytes(2, "little")
        with self.assertRaisesRegex(ValueError, "multi-disk"):
            engine.analyse_project_payload({"zip_base64": base64.b64encode(altered).decode("ascii")})

    def test_folder_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"; root.mkdir()
            outside = Path(tmp) / "outside.py"; outside.write_text("print('secret')\n")
            try:
                (root / "link.py").symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(project_io.ProjectInputError, "links"):
                project_io.read_folder_files(root)

    @unittest.skipIf(os.name == "nt", "POSIX special-file test")
    def test_folder_special_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(project_io.ProjectInputError, "special"):
                project_io.read_folder_files(root)

    @unittest.skipIf(os.name == "nt", "permission semantics differ")
    def test_ignored_unreadable_directory_is_not_traversed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); ignored = root / "node_modules"; ignored.mkdir(); (ignored / "large.py").write_text("x" * 10000)
            ignored.chmod(0)
            try:
                (root / "main.py").write_text("print(1)\n")
                files = project_io.read_folder_files(root)
                self.assertEqual({item["path"] for item in files}, {"main.py"})
            finally:
                ignored.chmod(stat.S_IRWXU)

    def test_folder_total_budget_avoids_second_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "a.py").write_text("a = 1\n" * 5); (root / "b.py").write_text("b = 2\n" * 5)
            files = project_io.read_folder_files(root, max_total_bytes=40)
            self.assertEqual(len([item for item in files if item["content"]]), 1)

    def test_folder_inventory_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(3): (root / f"{index}.py").write_text("print(1)\n")
            with self.assertRaisesRegex(project_io.ProjectInputError, "inventory"):
                project_io.read_folder_files(root, max_entries=2)


if __name__ == "__main__":
    unittest.main()
'''


RUNTIME_HELPERS = r'''
PROJECT_MAX_TOTAL_BYTES_DEFAULT = 20_000_000
PROJECT_MAX_ZIP_BYTES_DEFAULT = 8_000_000
PROJECT_MAX_ZIP_ENTRIES_DEFAULT = 2_000
PROJECT_MAX_COMPRESSION_RATIO_DEFAULT = 100.0
PROJECT_MAX_IGNORE_BYTES_DEFAULT = 131_072
PROJECT_MAX_IGNORE_RULES_DEFAULT = 1_000
PROJECT_READ_CHUNK_BYTES = 65_536


def _project_limit(payload: Dict[str, Any], key: str, default: int | float, *, minimum: int | float, maximum: int | float, integer: bool = True) -> int | float:
    raw = payload.get(key, default)
    if isinstance(raw, bool):
        raise ValueError(f"{key} must be a bounded {'integer' if integer else 'number'}")
    try:
        value = int(raw) if integer else float(raw)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{key} must be a bounded {'integer' if integer else 'number'}") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def _base64_decoded_upper_bound(text: str) -> int:
    return (len(text) // 4) * 3 + 3


def _zip_eocd_entry_count(data: bytes, max_entries: int) -> int:
    minimum = max(0, len(data) - 65_557)
    offset = data.rfind(b"PK\x05\x06", minimum)
    if offset < 0 or offset + 22 > len(data):
        raise ValueError("The uploaded archive lacks a valid ZIP end-of-central-directory record.")
    disk = int.from_bytes(data[offset + 4:offset + 6], "little")
    central_disk = int.from_bytes(data[offset + 6:offset + 8], "little")
    disk_entries = int.from_bytes(data[offset + 8:offset + 10], "little")
    entries = int.from_bytes(data[offset + 10:offset + 12], "little")
    central_size = int.from_bytes(data[offset + 12:offset + 16], "little")
    central_offset = int.from_bytes(data[offset + 16:offset + 20], "little")
    comment_length = int.from_bytes(data[offset + 20:offset + 22], "little")
    if offset + 22 + comment_length != len(data):
        raise ValueError("The uploaded archive has trailing or inconsistent ZIP data.")
    if 0xFFFF in {disk_entries, entries} or 0xFFFFFFFF in {central_size, central_offset}:
        raise ValueError("ZIP64 project archives are not accepted by the bounded browser runtime.")
    if disk != 0 or central_disk != 0 or disk_entries != entries:
        raise ValueError("Multi-disk ZIP project archives are not accepted.")
    if entries > max_entries:
        raise ValueError(f"ZIP entry limit exceeded: {entries} entries exceeds {max_entries}.")
    if central_offset + central_size > offset:
        raise ValueError("ZIP central-directory metadata is inconsistent.")
    return entries


def _zip_unix_entry_type(info: zipfile.ZipInfo) -> int:
    return (int(info.external_attr) >> 16) & 0o170000


def _candidate_reason_for_metadata(path: str, *, size_bytes: int, compressed_size: int, limits: Dict[str, Any], include_documentation: bool) -> Tuple[str, str]:
    if project_path_is_unsafe(path):
        return "unsafe_path", "Path is absolute, empty or contains parent-directory traversal."
    extension = project_extension(path)
    basename = normalise_project_path(path).rsplit("/", 1)[-1]
    if basename == ".codeprobeignore":
        if size_bytes > limits["max_ignore_bytes"]:
            return "ignore_file_too_large", f".codeprobeignore exceeds {limits['max_ignore_bytes']} bytes."
        return "", ""
    if size_bytes > limits["max_file_bytes"]:
        return "file_too_large", f"{size_bytes} bytes exceeds limit {limits['max_file_bytes']}."
    if extension in PROJECT_BINARY_EXTENSIONS:
        return "binary_or_non_source_extension", "Binary or non-source extension excluded before decompression."
    if extension in PROJECT_DOCUMENTATION_EXTENSIONS and not include_documentation:
        return "documentation_excluded_by_default", "Documentation excluded before decompression."
    if extension not in PROJECT_CODE_EXTENSIONS and not (include_documentation and extension in PROJECT_DOCUMENTATION_EXTENSIONS):
        return "unsupported_extension", "Unsupported extension excluded before decompression."
    ratio = size_bytes / max(compressed_size, 1)
    if size_bytes and ratio > limits["max_compression_ratio"]:
        return "compression_ratio_exceeded", f"Declared expansion ratio {ratio:.1f}:1 exceeds {limits['max_compression_ratio']:.1f}:1."
    return "", ""


def _read_zip_member_bounded(archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum: int) -> bytes:
    chunks: List[bytes] = []
    total = 0
    with archive.open(info, "r") as handle:
        while True:
            chunk = handle.read(min(PROJECT_READ_CHUNK_BYTES, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError(f"ZIP member exceeded the {maximum}-byte limit while being read: {info.filename}")
            chunks.append(chunk)
    data = b"".join(chunks)
    if len(data) != int(info.file_size):
        raise ValueError(f"ZIP member size disagrees with central-directory metadata: {info.filename}")
    return data


def _calibration_object(raw: Any) -> Dict[str, Any] | None:
    if raw in (None, ""):
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except Exception:
            return None
        return value if isinstance(value, dict) else None
    return None


def calibration_scope_decision(raw: Any, report_kind: str, language: str | None = None) -> Tuple[bool, str]:
    profile = _calibration_object(raw)
    if not profile or not isinstance(profile.get("scope"), dict):
        return True, ""
    scope = profile["scope"]
    kinds = scope.get("report_kinds") or scope.get("kinds") or []
    languages = scope.get("languages") or []
    if not isinstance(kinds, list) or not all(isinstance(item, str) for item in kinds):
        return False, "Calibration profile scope has an invalid report_kinds field."
    if not isinstance(languages, list) or not all(isinstance(item, str) for item in languages):
        return False, "Calibration profile scope has an invalid languages field."
    if kinds and report_kind not in kinds:
        return False, f"Calibration profile is scoped to {', '.join(kinds)}, not {report_kind}."
    if language and languages and language not in languages:
        return False, f"Calibration profile is scoped to {', '.join(languages)}, not {language}."
    return True, ""

'''


COLLECT_FUNCTION = r'''def collect_project_files(
    payload: Dict[str, Any],
    warnings: List[str],
    limits: Dict[str, Any],
    *,
    include_documentation: bool,
) -> Tuple[List[ProjectCandidateFile], str]:
    """Collect bounded project candidates without decompressing excluded members."""
    files: List[ProjectCandidateFile] = []
    source = "file-list"
    explicit_ignore = str(payload.get("ignore_text") or "")
    if len(explicit_ignore.encode("utf-8")) > limits["max_ignore_bytes"]:
        raise ValueError(f"ignore_text exceeds the {limits['max_ignore_bytes']}-byte limit")

    if payload.get("zip_base64"):
        source = "zip"
        encoded = str(payload.get("zip_base64") or "")
        if _base64_decoded_upper_bound(encoded) > limits["max_zip_bytes"] + 3:
            raise ValueError(f"compressed ZIP limit exceeded before Base64 decoding ({limits['max_zip_bytes']} bytes)")
        try:
            archive_bytes = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError(f"zip_base64 is not valid base64: {exc}") from exc
        if len(archive_bytes) > limits["max_zip_bytes"]:
            raise ValueError(f"compressed ZIP limit exceeded: {len(archive_bytes)} bytes exceeds {limits['max_zip_bytes']}")
        declared_entries = _zip_eocd_entry_count(archive_bytes, limits["max_zip_entries"])
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                infos = archive.infolist()
                if len(infos) != declared_entries or len(infos) > limits["max_zip_entries"]:
                    raise ValueError("ZIP entry inventory disagrees with the bounded EOCD preflight")
                dummy = [ProjectCandidateFile(str(info.filename or ""), "", int(info.file_size)) for info in infos if not info.is_dir()]
                common_root, _ = infer_common_project_root(dummy)
                prefix = common_root.rstrip("/") + "/" if common_root else ""
                def evaluation_path(raw: str) -> str:
                    if project_path_is_unsafe(raw):
                        return raw
                    normalised = normalise_project_path(raw)
                    return normalised[len(prefix):] if prefix and normalised.startswith(prefix) else normalised

                root_ignore_text = ""
                for info in infos:
                    raw = str(info.filename or "")
                    if info.is_dir() or project_path_is_unsafe(raw):
                        continue
                    path = evaluation_path(raw)
                    if path != ".codeprobeignore":
                        continue
                    reason, detail = _candidate_reason_for_metadata(path, size_bytes=int(info.file_size), compressed_size=int(info.compress_size), limits=limits, include_documentation=include_documentation)
                    if reason:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), reason, detail))
                        continue
                    if info.flag_bits & 0x1:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "encrypted_zip_entry", "Encrypted ZIP entries are not accepted."))
                        continue
                    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "unsupported_compression_method", "Only stored and deflated ZIP members are accepted."))
                        continue
                    data = _read_zip_member_bounded(archive, info, limits["max_ignore_bytes"])
                    root_ignore_text, warning = decode_text_bytes(data)
                    if root_ignore_text is None:
                        raise ValueError(f".codeprobeignore is not readable text: {warning}")
                    break
                active_rules = parse_ignore_patterns(default_project_ignore_text() + ("\n" + root_ignore_text if root_ignore_text else "") + ("\n" + explicit_ignore if explicit_ignore else ""))
                if len(active_rules) > limits["max_ignore_rules"]:
                    raise ValueError(f"active ignore rule count exceeds {limits['max_ignore_rules']}")
                seen_portable: Set[str] = set()
                total_read = 0
                analysed_candidates = 0
                for info in infos:
                    if info.is_dir():
                        raw_dir = str(info.filename or "").rstrip("/")
                        if project_path_is_unsafe(raw_dir):
                            raise ValueError(f"unsafe ZIP directory path: {raw_dir}")
                        continue
                    raw = str(info.filename or "")
                    path = evaluation_path(raw)
                    if raw == "" or project_path_is_unsafe(raw):
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "unsafe_path", "Path is absolute, empty or contains parent-directory traversal."))
                        continue
                    portable = path.casefold()
                    if portable in seen_portable:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "duplicate_path", "A previous ZIP member collides on a case-insensitive filesystem."))
                        continue
                    seen_portable.add(portable)
                    entry_type = _zip_unix_entry_type(info)
                    if entry_type not in {0, 0o100000}:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "special_zip_entry", "Links and special ZIP entries are forbidden."))
                        continue
                    if info.flag_bits & 0x1:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "encrypted_zip_entry", "Encrypted ZIP entries are not accepted."))
                        continue
                    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "unsupported_compression_method", "Only stored and deflated ZIP members are accepted."))
                        continue
                    if path == ".codeprobeignore":
                        files.append(ProjectCandidateFile(raw, root_ignore_text, int(info.file_size)))
                        continue
                    if path.rsplit("/", 1)[-1] == ".codeprobeignore":
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), "nested_ignore_file", "Only a project-root .codeprobeignore may control the project."))
                        continue
                    reason, detail = _candidate_reason_for_metadata(path, size_bytes=int(info.file_size), compressed_size=int(info.compress_size), limits=limits, include_documentation=include_documentation)
                    if not reason and project_path_is_ignored(path, active_rules):
                        reason, detail = "ignored_by_codeprobeignore", "Matched built-in or project ignore rules before decompression."
                    if not reason and analysed_candidates >= limits["max_files"]:
                        reason, detail = "project_file_limit", f"Maximum analysed file count is {limits['max_files']}."
                    if not reason and total_read + int(info.file_size) > limits["max_total_bytes"]:
                        reason, detail = "project_total_byte_limit", f"Reading this member would exceed the {limits['max_total_bytes']}-byte project budget."
                    if reason:
                        files.append(ProjectCandidateFile(raw, "", int(info.file_size), reason, detail))
                        continue
                    data = _read_zip_member_bounded(archive, info, limits["max_file_bytes"])
                    total_read += len(data)
                    analysed_candidates += 1
                    text, warning = decode_text_bytes(data)
                    if text is None:
                        files.append(ProjectCandidateFile(raw, "", len(data), "undecodable_text", warning))
                    else:
                        if warning:
                            warnings.append(f"{raw}: {warning}.")
                        files.append(ProjectCandidateFile(raw, text, len(data)))
        except zipfile.BadZipFile as exc:
            raise ValueError("The uploaded archive is not a readable ZIP file.") from exc
    else:
        raw_items = payload.get("files") or []
        if not isinstance(raw_items, list):
            raise ValueError("files must be an array")
        if len(raw_items) > limits["max_zip_entries"]:
            raise ValueError(f"project entry limit exceeded: {len(raw_items)} exceeds {limits['max_zip_entries']}")
        dummy = [ProjectCandidateFile(str(item.get("path") or item.get("name") or ""), "", 0) for item in raw_items if isinstance(item, dict)]
        common_root, _ = infer_common_project_root(dummy)
        prefix = common_root.rstrip("/") + "/" if common_root else ""
        root_ignore_text = ""
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            raw = str(item.get("path") or item.get("name") or "")
            if project_path_is_unsafe(raw):
                continue
            path = normalise_project_path(raw)
            if prefix and path.startswith(prefix):
                path = path[len(prefix):]
            if path == ".codeprobeignore":
                root_ignore_text = str(item.get("content") if item.get("content") is not None else item.get("text") or "")
                if len(root_ignore_text.encode("utf-8")) > limits["max_ignore_bytes"]:
                    raise ValueError(f".codeprobeignore exceeds the {limits['max_ignore_bytes']}-byte limit")
                break
        active_rules = parse_ignore_patterns(default_project_ignore_text() + ("\n" + root_ignore_text if root_ignore_text else "") + ("\n" + explicit_ignore if explicit_ignore else ""))
        if len(active_rules) > limits["max_ignore_rules"]:
            raise ValueError(f"active ignore rule count exceeds {limits['max_ignore_rules']}")
        total_read = 0
        analysed_candidates = 0
        seen_portable: Set[str] = set()
        for item in raw_items:
            if not isinstance(item, dict):
                raise ValueError("each files entry must be an object")
            raw = str(item.get("path") or item.get("name") or "")
            text = str(item.get("content") if item.get("content") is not None else item.get("text") or "")
            actual_size = len(text.encode("utf-8"))
            path = raw if project_path_is_unsafe(raw) else normalise_project_path(raw)
            if prefix and not project_path_is_unsafe(raw) and path.startswith(prefix):
                path = path[len(prefix):]
            reason = detail = ""
            if project_path_is_unsafe(raw):
                reason, detail = "unsafe_path", "Path is absolute, empty or contains parent-directory traversal."
            elif path.casefold() in seen_portable:
                reason, detail = "duplicate_path", "A previous file collides on a case-insensitive filesystem."
            else:
                seen_portable.add(path.casefold())
            if not reason and path.rsplit("/", 1)[-1] == ".codeprobeignore" and path != ".codeprobeignore":
                reason, detail = "nested_ignore_file", "Only a project-root .codeprobeignore may control the project."
            if not reason:
                metadata_reason, metadata_detail = _candidate_reason_for_metadata(path, size_bytes=actual_size, compressed_size=actual_size, limits=limits, include_documentation=include_documentation)
                reason, detail = metadata_reason, metadata_detail
            if not reason and path != ".codeprobeignore" and project_path_is_ignored(path, active_rules):
                reason, detail = "ignored_by_codeprobeignore", "Matched built-in or project ignore rules."
            if not reason and path != ".codeprobeignore" and analysed_candidates >= limits["max_files"]:
                reason, detail = "project_file_limit", f"Maximum analysed file count is {limits['max_files']}."
            if not reason and path != ".codeprobeignore" and total_read + actual_size > limits["max_total_bytes"]:
                reason, detail = "project_total_byte_limit", f"Reading this file would exceed the {limits['max_total_bytes']}-byte project budget."
            if not reason and path != ".codeprobeignore":
                analysed_candidates += 1
                total_read += actual_size
            declared = item.get("size_bytes")
            if declared is not None:
                try:
                    declared_size = int(declared)
                except (TypeError, ValueError, OverflowError):
                    warnings.append(f"{raw}: invalid declared size ignored.")
                else:
                    if declared_size != actual_size:
                        warnings.append(f"{raw}: declared size {declared_size} replaced by actual UTF-8 size {actual_size}.")
            files.append(ProjectCandidateFile(raw, text if not reason else "", actual_size, reason, detail))
    return files, source

'''


BUILD_IGNORE = r'''def build_project_ignore_rules(
    files: Sequence[ProjectCandidateFile],
    payload: Dict[str, Any],
    *,
    max_ignore_bytes: int = PROJECT_MAX_IGNORE_BYTES_DEFAULT,
    max_ignore_rules: int = PROJECT_MAX_IGNORE_RULES_DEFAULT,
) -> Tuple[List[IgnoreRule], List[str]]:
    """Combine bounded built-in, root-project and explicit ignore rules."""
    notes: List[str] = []
    ignore_text = default_project_ignore_text()
    notes.append("Built-in ignore patterns for dependencies, build output, generated artefacts and binary assets were applied.")
    embedded = [item for item in files if not item.pre_exclusion_reason and not project_path_is_unsafe(item.path) and normalise_project_path(item.path) == ".codeprobeignore"]
    if len(embedded) > 1:
        raise ValueError("project contains more than one root .codeprobeignore")
    if embedded:
        encoded = embedded[0].text.encode("utf-8")
        if len(encoded) > max_ignore_bytes:
            raise ValueError(f".codeprobeignore exceeds the {max_ignore_bytes}-byte limit")
        ignore_text += "\n" + embedded[0].text
        notes.append("Loaded the project-root .codeprobeignore.")
    explicit = str(payload.get("ignore_text") or "")
    if len(explicit.encode("utf-8")) > max_ignore_bytes:
        raise ValueError(f"ignore_text exceeds the {max_ignore_bytes}-byte limit")
    if explicit:
        ignore_text += "\n" + explicit
        notes.append("Applied additional bounded ignore patterns supplied by the caller.")
    rules = parse_ignore_patterns(ignore_text)
    if len(rules) > max_ignore_rules:
        raise ValueError(f"active ignore rule count exceeds {max_ignore_rules}")
    notes.append(f"Active ignore rules: {len(rules)}.")
    return rules, notes

'''


def patch_runtime() -> None:
    replace_once("src/codeprobe_runtime.py", "import statistics\nimport time\nimport tokenize", "import statistics\nimport time\nimport tokenize\nimport unicodedata")
    replace_once(
        "src/codeprobe_runtime.py",
        "PROJECT_MAX_FILE_BYTES_DEFAULT = 1_000_000\nPROJECT_SLOC_WEIGHT_CAP = 500",
        "PROJECT_MAX_FILE_BYTES_DEFAULT = 1_000_000\n" + RUNTIME_HELPERS.split("\n\ndef _project_limit", 1)[0].split("\n", 1)[1] + "\n\ndef _project_limit" + RUNTIME_HELPERS.split("\n\ndef _project_limit", 1)[1] + "PROJECT_SLOC_WEIGHT_CAP = 500",
    )
    replace_once(
        "src/codeprobe_runtime.py",
        '''@dataclass\nclass ProjectCandidateFile:\n    """A text file candidate received from a browser file list or ZIP archive."""\n\n    path: str\n    text: str\n    size_bytes: int = 0\n''',
        '''@dataclass\nclass ProjectCandidateFile:\n    """A bounded text candidate or a metadata-only pre-exclusion record."""\n\n    path: str\n    text: str\n    size_bytes: int = 0\n    pre_exclusion_reason: str = ""\n    pre_exclusion_detail: str = ""\n''',
    )
    replace_once(
        "src/codeprobe_runtime.py",
        "ProjectCandidateFile(path=new_path, text=item.text, size_bytes=item.size_bytes)",
        "ProjectCandidateFile(path=new_path, text=item.text, size_bytes=item.size_bytes, pre_exclusion_reason=item.pre_exclusion_reason, pre_exclusion_detail=item.pre_exclusion_detail)",
    )
    replace_between("src/codeprobe_runtime.py", "def collect_project_files(", "def build_project_ignore_rules(", COLLECT_FUNCTION)
    replace_between("src/codeprobe_runtime.py", "def build_project_ignore_rules(", "def aggregate_project_reports(", BUILD_IGNORE)

    old_start = '''def analyse_project_payload(payload: Dict[str, Any]) -> Dict[str, Any]:\n    """Analyse a multi-file project with .codeprobeignore-aware inclusion."""\n    profile = payload.get("profile") or DEFAULT_PROFILE\n    override = payload.get("config_override")\n    calibration_raw = payload.get("calibration_profile") if payload.get("calibration_profile") is not None else payload.get("calibration_profile_json")\n    calibration_profile = normalise_calibration_profile(calibration_raw)\n    review_policy = calibration_profile.get("review_policy")\n    config = merged_metric_config(profile, override, calibration_profile)\n    project_fingerprint = effective_engine_fingerprint(payload.get("engine_fingerprint") or payload.get("engine_integrity"))\n    engine = AnalysisEngine(config, calibration_profile=calibration_profile, engine_fingerprint=project_fingerprint)\n    warnings: List[str] = list(calibration_profile.get("warnings", []))\n    start = time.perf_counter()\n\n    candidates, source = collect_project_files(payload, warnings)\n    input_packaging = project_packaging_profile(candidates, source)\n'''
    new_start = '''def analyse_project_payload(payload: Dict[str, Any]) -> Dict[str, Any]:\n    """Analyse a bounded multi-file project with auditable exclusion decisions."""\n    profile = payload.get("profile") or DEFAULT_PROFILE\n    override = payload.get("config_override")\n    include_documentation = bool(payload.get("include_documentation", False))\n    limits = {\n        "max_files": _project_limit(payload, "max_files", PROJECT_MAX_FILES_DEFAULT, minimum=1, maximum=10_000),\n        "max_file_bytes": _project_limit(payload, "max_file_bytes", PROJECT_MAX_FILE_BYTES_DEFAULT, minimum=1, maximum=16_000_000),\n        "max_total_bytes": _project_limit(payload, "max_total_bytes", PROJECT_MAX_TOTAL_BYTES_DEFAULT, minimum=1, maximum=256_000_000),\n        "max_zip_bytes": _project_limit(payload, "max_zip_bytes", PROJECT_MAX_ZIP_BYTES_DEFAULT, minimum=1, maximum=64_000_000),\n        "max_zip_entries": _project_limit(payload, "max_zip_entries", PROJECT_MAX_ZIP_ENTRIES_DEFAULT, minimum=1, maximum=20_000),\n        "max_compression_ratio": _project_limit(payload, "max_compression_ratio", PROJECT_MAX_COMPRESSION_RATIO_DEFAULT, minimum=1.0, maximum=1_000.0, integer=False),\n        "max_ignore_bytes": _project_limit(payload, "max_ignore_bytes", PROJECT_MAX_IGNORE_BYTES_DEFAULT, minimum=1, maximum=1_000_000),\n        "max_ignore_rules": _project_limit(payload, "max_ignore_rules", PROJECT_MAX_IGNORE_RULES_DEFAULT, minimum=1, maximum=10_000),\n    }\n    calibration_raw = payload.get("calibration_profile") if payload.get("calibration_profile") is not None else payload.get("calibration_profile_json")\n    scope_allowed, scope_warning = calibration_scope_decision(calibration_raw, "project", "project")\n    effective_calibration_raw = calibration_raw if scope_allowed else None\n    calibration_profile = normalise_calibration_profile(effective_calibration_raw)\n    review_policy = calibration_profile.get("review_policy")\n    config = merged_metric_config(profile, override, calibration_profile)\n    project_fingerprint = effective_engine_fingerprint(payload.get("engine_fingerprint") or payload.get("engine_integrity"))\n    engine = AnalysisEngine(config, calibration_profile={}, engine_fingerprint=project_fingerprint)\n    warnings: List[str] = list(calibration_profile.get("warnings", []))\n    if scope_warning:\n        warnings.append(scope_warning + " The generic project policy was used instead.")\n    start = time.perf_counter()\n\n    candidates, source = collect_project_files(payload, warnings, limits, include_documentation=include_documentation)\n    input_packaging = project_packaging_profile(candidates, source)\n    input_packaging["limits"] = dict(limits)\n'''
    replace_once("src/codeprobe_runtime.py", old_start, new_start)
    replace_once(
        "src/codeprobe_runtime.py",
        '''    max_files = int(payload.get("max_files") or PROJECT_MAX_FILES_DEFAULT)\n    max_file_bytes = int(payload.get("max_file_bytes") or PROJECT_MAX_FILE_BYTES_DEFAULT)\n    include_documentation = bool(payload.get("include_documentation", False))\n    language_hint = payload.get("language_hint")\n''',
        '''    max_files = int(limits["max_files"])\n    max_file_bytes = int(limits["max_file_bytes"])\n    language_hint = payload.get("language_hint")\n''',
    )
    replace_once(
        "src/codeprobe_runtime.py",
        "    ignore_rules, ignore_notes = build_project_ignore_rules(candidates, payload)\n",
        "    ignore_rules, ignore_notes = build_project_ignore_rules(candidates, payload, max_ignore_bytes=int(limits['max_ignore_bytes']), max_ignore_rules=int(limits['max_ignore_rules']))\n",
    )
    replace_once(
        "src/codeprobe_runtime.py",
        '''        path = normalise_project_path(raw_path)\n        if path in seen:\n''',
        '''        path = normalise_project_path(raw_path)\n        if candidate.pre_exclusion_reason:\n            excluded.append(ProjectExcludedFile(path if not project_path_is_unsafe(raw_path) else raw_path, candidate.pre_exclusion_reason, candidate.pre_exclusion_detail))\n            continue\n        if path in seen:\n''',
    )
    replace_once(
        "src/codeprobe_runtime.py",
        '''        "calibration_profile": calibration_profile_public(calibration_profile),\n        "review_policy": review_policy,\n''',
        '''        "calibration_profile": calibration_profile_public(calibration_profile),\n        "calibration_scope": (_calibration_object(effective_calibration_raw) or {}).get("scope", {}),\n        "review_policy": review_policy,\n''',
    )

    old_analyse = '''def codeprobe_analyze(payload_json: str) -> str:\n    payload = json.loads(payload_json)\n    profile = payload.get("profile") or "default"\n    override = payload.get("config_override")\n    calibration_raw = payload.get("calibration_profile") if payload.get("calibration_profile") is not None else payload.get("calibration_profile_json")\n    calibration_profile = normalise_calibration_profile(calibration_raw)\n    config = merged_metric_config(profile, override, calibration_profile)\n    fingerprint = effective_engine_fingerprint(payload.get("engine_fingerprint") or payload.get("engine_integrity"))\n    engine = AnalysisEngine(config, calibration_profile=calibration_profile, engine_fingerprint=fingerprint)\n    language_hint = payload.get("language_hint")\n    if language_hint == "auto":\n        language_hint = None\n    report = engine.analyse(\n        payload.get("code", ""),\n        payload.get("filename", "fragment.py"),\n        language_hint=language_hint,\n        profile=profile,\n    )\n    return json.dumps(\n        {\n            "report": report_to_dict(report),\n            "text": format_report_text(report),\n        },\n        ensure_ascii=False,\n    )\n\n\n'''
    new_analyse = '''def codeprobe_analyze(payload_json: str) -> str:\n    payload = json.loads(payload_json)\n    profile = payload.get("profile") or "default"\n    override = payload.get("config_override")\n    code = payload.get("code", "")\n    filename = payload.get("filename", "fragment.py")\n    language_hint = payload.get("language_hint")\n    if language_hint == "auto":\n        language_hint = None\n    detected = detect_language(filename, code, language_hint)\n    calibration_raw = payload.get("calibration_profile") if payload.get("calibration_profile") is not None else payload.get("calibration_profile_json")\n    scope_allowed, scope_warning = calibration_scope_decision(calibration_raw, "file", detected)\n    effective_raw = calibration_raw if scope_allowed else None\n    calibration_profile = normalise_calibration_profile(effective_raw)\n    config = merged_metric_config(profile, override, calibration_profile)\n    fingerprint = effective_engine_fingerprint(payload.get("engine_fingerprint") or payload.get("engine_integrity"))\n    engine = AnalysisEngine(config, calibration_profile=calibration_profile, engine_fingerprint=fingerprint)\n    report = engine.analyse(code, filename, language_hint=language_hint, profile=profile)\n    if scope_warning:\n        report.warnings.append(scope_warning + " The generic file policy was used instead.")\n        report.notes.append("The supplied calibration profile was outside its declared report-kind or language scope and was not applied.")\n    payload_report = report_to_dict(report)\n    payload_report["calibration_scope"] = (_calibration_object(effective_raw) or {}).get("scope", {})\n    return json.dumps({"report": payload_report, "text": format_report_text(report)}, ensure_ascii=False)\n\n\n'''
    replace_once("src/codeprobe_runtime.py", old_analyse, new_analyse)


def patch_javascript() -> None:
    for relative in ("app/codeprobe-ui.js", "app/project-ui.js"):
        replace_once(relative, "const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;", "const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;\n    const MAX_BROWSER_PROJECT_ZIP_BYTES = 8000000;\n    const MAX_BROWSER_PROJECT_TOTAL_BYTES = 20000000;\n    const MAX_BROWSER_PROJECT_ENTRIES = 2000;")
    replace_once(
        "app/codeprobe-ui.js",
        '''    async function handleProjectZip(file) {\n      if (!file) return;\n      const zipBase64 = arrayBufferToBase64(await file.arrayBuffer());\n''',
        '''    async function handleProjectZip(file) {\n      if (!file) return;\n      if ((file.size || 0) > MAX_BROWSER_PROJECT_ZIP_BYTES) {\n        throw new Error(`Project ZIP exceeds the ${MAX_BROWSER_PROJECT_ZIP_BYTES} byte browser limit.`);\n      }\n      const zipBase64 = arrayBufferToBase64(await file.arrayBuffer());\n''',
    )
    replace_once(
        "app/codeprobe-ui.js",
        '''        zip_filename: file.name || "archive.zip",\n        zip_base64: zipBase64\n''',
        '''        zip_filename: file.name || "archive.zip",\n        zip_base64: zipBase64,\n        max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES,\n        max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES,\n        max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES,\n        max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES\n''',
    )
    replace_once(
        "app/codeprobe-ui.js",
        '''      const payloadFiles = [];\n      const warnings = [];\n      for (const file of files) {\n''',
        '''      if (files.length > MAX_BROWSER_PROJECT_ENTRIES) {\n        throw new Error(`Project selection exceeds the ${MAX_BROWSER_PROJECT_ENTRIES} entry browser limit.`);\n      }\n      const payloadFiles = [];\n      const warnings = [];\n      let acceptedBytes = 0;\n      for (const file of files) {\n''',
    )
    replace_once(
        "app/codeprobe-ui.js",
        '''        try {\n          const decoded = await decodeFile(file);\n          payloadFiles.push({ path, content: decoded.text, size_bytes: file.size || decoded.text.length });\n''',
        '''        if (acceptedBytes + (file.size || 0) > MAX_BROWSER_PROJECT_TOTAL_BYTES) {\n          payloadFiles.push({ path, content: "", size_bytes: file.size || 0 });\n          warnings.push(`${path}: skipped because the browser project budget is ${MAX_BROWSER_PROJECT_TOTAL_BYTES} bytes`);\n          continue;\n        }\n        try {\n          const decoded = await decodeFile(file);\n          acceptedBytes += file.size || new TextEncoder().encode(decoded.text).length;\n          payloadFiles.push({ path, content: decoded.text, size_bytes: file.size || new TextEncoder().encode(decoded.text).length });\n''',
    )
    replace_once(
        "app/codeprobe-ui.js",
        '''        project_name: projectName,\n        files: payloadFiles\n''',
        '''        project_name: projectName,\n        files: payloadFiles,\n        max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES,\n        max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES,\n        max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES,\n        max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES\n''',
    )
    replace_once(
        "app/project-ui.js",
        '''    async function loadZip(file) {\n      const buffer = await file.arrayBuffer();\n''',
        '''    async function loadZip(file) {\n      if ((file.size || 0) > MAX_BROWSER_PROJECT_ZIP_BYTES) { els.status.textContent = `ZIP exceeds the ${MAX_BROWSER_PROJECT_ZIP_BYTES} byte browser limit.`; return; }\n      const buffer = await file.arrayBuffer();\n''',
    )
    replace_once(
        "app/project-ui.js",
        '''      state.payload = { project_name: state.projectName, zip_base64: bytesToBase64(new Uint8Array(buffer)) };\n''',
        '''      state.payload = { project_name: state.projectName, zip_base64: bytesToBase64(new Uint8Array(buffer)), max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES };\n''',
    )
    replace_once(
        "app/project-ui.js",
        '''      if (selected.length > 1500) {\n        els.status.textContent = "Folder selection contains too many files for the browser UI; use tools/analyze_project.py for this project.";\n''',
        '''      if (selected.length > MAX_BROWSER_PROJECT_ENTRIES) {\n        els.status.textContent = "Folder selection contains too many files for the browser UI; use tools/analyze_project.py for this project.";\n''',
    )
    replace_once(
        "app/project-ui.js",
        '''      const files = []; const warnings = [];\n      for (const file of selected) {\n''',
        '''      const files = []; const warnings = []; let acceptedBytes = 0;\n      for (const file of selected) {\n''',
    )
    replace_once(
        "app/project-ui.js",
        '''        if ((file.size || 0) > MAX_BROWSER_PROJECT_TEXT_BYTES) { warnings.push(`${path}: skipped in browser because it exceeds 1 MB`); continue; }\n        try { files.push(await decodeTextFile(file)); } catch (error) { warnings.push(`${path}: ${error.message}`); }\n''',
        '''        if ((file.size || 0) > MAX_BROWSER_PROJECT_TEXT_BYTES) { warnings.push(`${path}: skipped in browser because it exceeds 1 MB`); continue; }\n        if (acceptedBytes + (file.size || 0) > MAX_BROWSER_PROJECT_TOTAL_BYTES) { warnings.push(`${path}: skipped because the browser project budget is ${MAX_BROWSER_PROJECT_TOTAL_BYTES} bytes`); continue; }\n        try { files.push(await decodeTextFile(file)); acceptedBytes += file.size || 0; } catch (error) { warnings.push(`${path}: ${error.message}`); }\n''',
    )
    replace_once(
        "app/project-ui.js",
        '''      state.payload = { project_name: state.projectName, files };\n''',
        '''      state.payload = { project_name: state.projectName, files, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES, max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES };\n''',
    )


def patch_calibration_tests() -> None:
    relative = "tests/test_calibration_profiles.py"
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if "class IndependentCalibrationBoundaryTests" in text:
        return
    if "from pathlib import Path" not in text:
        raise RuntimeError("calibration test import marker missing")
    addition = r'''

class IndependentCalibrationBoundaryTests(unittest.TestCase):
    def _result(self, name, label, score, *, split="", language="python", kind="file", group=""):
        return calibrate_profile.SampleResult(name, label, kind, "project" if kind == "project" else language, score, True, 20, "low", "", name, split, group or f"group-{name}")

    def _balanced(self):
        return [
            self._result("h-fit.py", "human", 0.20, split="fit"),
            self._result("a-fit.py", "ai_generated", 0.80, split="fit"),
            self._result("h-eval.py", "human", 0.25, split="evaluation"),
            self._result("a-eval.py", "ai_generated", 0.75, split="evaluation"),
        ]

    def test_profile_records_independent_holdout(self):
        profile = calibrate_profile.build_profile({"profile_id": "p"}, self._balanced(), 0.10)
        self.assertTrue(profile["validation"]["evaluation_design"]["independent_holdout"])

    def test_trigger_is_selected_from_fit_partition(self):
        first = calibrate_profile.build_profile({"profile_id": "p"}, self._balanced(), 0.10)
        changed = self._balanced(); changed[2].score = 0.99; changed[3].score = 0.01
        second = calibrate_profile.build_profile({"profile_id": "p"}, changed, 0.10)
        self.assertEqual(first["review_policy"], second["review_policy"])

    def test_absolute_paths_are_pseudonymised(self):
        rows = self._balanced(); rows[0].path = "/home/alice/private/h.py"; rows[0].sample_id = ""
        profile = calibrate_profile.build_profile({"profile_id": "p"}, rows, 0.10)
        serialised = json.dumps(profile)
        self.assertNotIn("/home/alice", serialised)

    def test_mixed_file_languages_are_rejected(self):
        rows = self._balanced(); rows[-1].language = "javascript"
        with self.assertRaisesRegex(ValueError, "mix languages"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, 0.10)

    def test_mixed_report_kinds_are_rejected(self):
        rows = self._balanced(); rows[-1].kind = "project"; rows[-1].language = "project"
        with self.assertRaisesRegex(ValueError, "mix file and project"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, 0.10)

    def test_project_profile_is_scoped_to_project_only(self):
        rows = [self._result("hf", "human", .2, split="fit", kind="project"), self._result("af", "ai_generated", .8, split="fit", kind="project"), self._result("he", "human", .2, split="evaluation", kind="project"), self._result("ae", "ai_generated", .8, split="evaluation", kind="project")]
        profile = calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)
        self.assertEqual(profile["scope"]["report_kinds"], ["project"])
        self.assertNotIn("file", profile["review_policy"])

    def test_file_profile_records_language_scope(self):
        profile = calibrate_profile.build_profile({"profile_id": "p"}, self._balanced(), .1)
        self.assertEqual(profile["scope"]["languages"], ["python"])

    def test_failed_sample_aborts_profile(self):
        rows = self._balanced(); rows[0].verdict_class = "error"; rows[0].warning = "read failed"
        with self.assertRaisesRegex(ValueError, "sample analysis failed"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_partial_explicit_splits_are_rejected(self):
        rows = self._balanced(); rows[-1].split = ""
        with self.assertRaisesRegex(ValueError, "every sample"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_automatic_split_is_reproducible(self):
        rows = [self._result(f"h{i}", "human", .2 + i/100) for i in range(4)] + [self._result(f"a{i}", "ai_generated", .7 + i/100) for i in range(4)]
        left = calibrate_profile.build_profile({"profile_id": "p", "split_seed": "s"}, rows, .1)
        right = calibrate_profile.build_profile({"profile_id": "p", "split_seed": "s"}, rows, .1)
        self.assertEqual([item["split"] for item in left["validation"]["sample_results"]], [item["split"] for item in right["validation"]["sample_results"]])

    def test_groups_do_not_cross_partitions(self):
        rows = [self._result("h1a", "human", .2, group="g-h1"), self._result("h1b", "human", .21, group="g-h1"), self._result("h2", "human", .22, group="g-h2"), self._result("a1", "ai_generated", .8, group="g-a1"), self._result("a2", "ai_generated", .82, group="g-a2")]
        profile = calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)
        observed = {}
        for item in profile["validation"]["sample_results"]:
            observed.setdefault(item["group_id"], set()).add(item["split"])
        self.assertTrue(all(len(value) == 1 for value in observed.values()))

    def test_insufficient_groups_fail_closed(self):
        rows = [self._result("h1", "human", .2, group="same-h"), self._result("h2", "human", .22, group="same-h"), self._result("a1", "ai_generated", .8, group="same-a"), self._result("a2", "ai_generated", .82, group="same-a")]
        with self.assertRaisesRegex(ValueError, "at least two"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_observation_csv_has_no_absolute_path(self):
        import tempfile
        rows = self._balanced(); rows[0].path = "C:/Users/Alice/private.py"; rows[0].sample_id = ""
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "observations.csv"
            calibrate_profile.write_observations_csv(output, rows)
            self.assertNotIn("Users/Alice", output.read_text())

    def test_runtime_scope_rejects_language_mismatch(self):
        profile = {"scope": {"report_kinds": ["file"], "languages": ["python"]}}
        allowed, message = engine.calibration_scope_decision(profile, "file", "javascript")
        self.assertFalse(allowed)
        self.assertIn("javascript", message)
'''
    marker = '\n\nif __name__ == "__main__":\n'
    if marker not in text:
        raise RuntimeError("calibration test main marker missing")
    path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8", newline="\n")


def patch_browser_tests() -> None:
    relative = "tests/test_dynamic_ui_review.py"
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if "class BrowserInputBudgetTests" in text:
        return
    addition = r'''

class BrowserInputBudgetTests(unittest.TestCase):
    def test_main_zip_limit_precedes_array_buffer(self):
        script = (ROOT / "app" / "codeprobe-ui.js").read_text(encoding="utf-8")
        start = script.index("async function handleProjectZip")
        section = script[start:script.index("function projectTextCandidate", start)]
        self.assertLess(section.index("MAX_BROWSER_PROJECT_ZIP_BYTES"), section.index("file.arrayBuffer"))

    def test_project_zip_limit_precedes_array_buffer(self):
        script = (ROOT / "app" / "project-ui.js").read_text(encoding="utf-8")
        start = script.index("async function loadZip")
        section = script[start:script.index("async function loadFolder", start)]
        self.assertLess(section.index("MAX_BROWSER_PROJECT_ZIP_BYTES"), section.index("file.arrayBuffer"))

    def test_browser_folder_budget_is_present_in_both_interfaces(self):
        for name in ("codeprobe-ui.js", "project-ui.js"):
            self.assertIn("MAX_BROWSER_PROJECT_TOTAL_BYTES", (ROOT / "app" / name).read_text(encoding="utf-8"))

    def test_browser_payload_forwards_engine_limits(self):
        for name in ("codeprobe-ui.js", "project-ui.js"):
            script = (ROOT / "app" / name).read_text(encoding="utf-8")
            for token in ("max_zip_bytes", "max_zip_entries", "max_file_bytes", "max_total_bytes"):
                self.assertIn(token, script)
'''
    marker = '\n\nif __name__ == "__main__":\n'
    if marker not in text:
        raise RuntimeError("dynamic UI test main marker missing")
    path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8", newline="\n")


def patch_docs() -> None:
    replace_once(
        "README.md",
        "The browser interface accepts direct drag-and-drop: a single source file opens single-file analysis; a folder, multiple files or a GitHub ZIP export opens project mode.",
        "The browser interface accepts bounded direct drag-and-drop: a single source file opens single-file analysis; a folder, multiple files or a GitHub ZIP export opens project mode. Folder traversal does not follow links or special filesystem entries, while ZIP intake applies compressed-size, entry-count, member-size, aggregate-size and expansion-ratio limits before member content is read.",
    )
    replace_once(
        "README.md",
        "A local calibration profile is only as reliable as its labelled samples.",
        "A local calibration profile is only as reliable as its labelled samples and its group-exclusive fit/evaluation design; CodeProbe selects a trigger on the fit partition and reports performance only on the untouched evaluation partition.",
    )
    replace_once(
        "CHANGELOG.md",
        "### Added\n\n- Add least-privilege GitHub Actions validation",
        "### Added\n\n- Add bounded project-folder and ZIP intake with pre-read exclusion, stable regular-file reads, symlink/special-entry rejection, compressed and expanded byte budgets, entry limits and compression-ratio controls.\n- Add group-exclusive calibration fit/evaluation partitions, explicit report-kind and language scope, fail-closed sample handling and pseudonymised sample identifiers.\n- Add hostile regressions for forged metadata, ZIP bombs, encrypted or special members, unsafe filesystem entries, nested ignore control and calibration leakage.\n- Add least-privilege GitHub Actions validation",
    )
    for relative, heading, body in (
        ("docs/03-report-schema.md", "## Bounded project-input metadata", "Project reports now record the effective hard limits under `input_packaging.limits`. Metadata-only exclusions such as `compression_ratio_exceeded`, `project_total_byte_limit`, `encrypted_zip_entry`, `special_zip_entry` and `nested_ignore_file` are decided before excluded ZIP members are decompressed. The `calibration_scope` field records the report-kind and language domain of the profile that was actually applied."),
        ("docs/06-calibration-guide.md", "## Independent evaluation and profile scope", "A generated profile must use group-exclusive fit and evaluation partitions. The review trigger is selected only on the fit partition. False-positive and positive review rates reported as performance are calculated only on the untouched evaluation partition. A profile is scoped to one report kind and one language; mixed file/project or mixed-language corpora must be split into separate profiles. Sample paths are corpus-relative or pseudonymised and failed sample reads abort generation before any profile is written."),
        ("calibration/README.md", "## Required fit/evaluation boundary", "Use either an explicit `split` column/value (`fit` or `evaluation`) for every sample or allow the tool to create a deterministic stratified group holdout. Supply `group`, `student_id` or `submission_id` whenever several files come from one author or submission so related samples cannot cross partitions. At least two known-human groups and two positive groups are required. Generated observations never export absolute local paths."),
    ):
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        if heading not in text:
            path.write_text(text.rstrip() + f"\n\n{heading}\n\n{body}\n", encoding="utf-8", newline="\n")


def refresh_browser_integrity() -> None:
    app = ROOT / "app"
    manifest_path = app / "resource-integrity.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sri: dict[str, str] = {}
    for item in manifest["assets"]:
        path = (app / item["path"]).resolve()
        content = path.read_bytes()
        digest = hashlib.sha256(content)
        item["size_bytes"] = len(content)
        item["sha256_hex"] = digest.hexdigest()
        item["sri_sha256"] = "sha256-" + base64.b64encode(digest.digest()).decode("ascii")
        sri[item["path"]] = item["sri_sha256"]
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    for html_name, script_name in (("index.html", "codeprobe-ui.js"), ("project.html", "project-ui.js")):
        path = app / html_name
        text = path.read_text(encoding="utf-8")
        pattern = rf'(<script\s+src="{re.escape(script_name)}"\s+defer\s+integrity=")[^"]+("[^>]*></script>)'
        updated, count = re.subn(pattern, rf'\g<1>{sri[script_name]}\g<2>', text)
        if count != 1:
            raise RuntimeError(f"{html_name}: could not refresh SRI for {script_name}")
        path.write_text(updated, encoding="utf-8", newline="\n")


def main() -> int:
    write("src/codeprobe_engine/project_io.py", PROJECT_IO)
    write("tools/analyze_project.py", ANALYSE_PROJECT)
    write("tools/calibrate_profile.py", CALIBRATE_PROFILE)
    write("tests/test_project_mode.py", PROJECT_TESTS)
    patch_runtime()
    patch_javascript()
    patch_calibration_tests()
    patch_browser_tests()
    patch_docs()
    for relative in (
        ".github/workflows/audit-snapshot-export.yml",
        ".github/workflows/phase2-remediation.yml",
        "tools/phase2_remediate.py",
    ):
        path = ROOT / relative
        if path.exists():
            path.unlink()
    refresh_browser_integrity()
    print("Phase 2 source transaction applied; temporary automation removed from the working tree.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
