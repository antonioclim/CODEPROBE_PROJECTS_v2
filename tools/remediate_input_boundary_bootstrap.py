#!/usr/bin/env python3
"""Apply the audited project-input boundary remediation to a checkout.

This bootstrap utility lives only on the isolated automation branch. It edits a
checkout of ``audit/codeprobe-hostile-remediation`` and is not copied into the
resulting audit-branch commit.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def write_if_changed(path: Path, text: str) -> None:
    if not text.endswith("\n"):
        text += "\n"
    current = path.read_text(encoding="utf-8")
    if current != text:
        path.write_text(text, encoding="utf-8", newline="\n")


RUNTIME_COLLECTION_CODE = r'''def project_input_limits(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate project-ingestion limits, allowing callers to lower safe defaults."""

    integer_limits = {
        "max_files": (PROJECT_MAX_FILES_DEFAULT, PROJECT_MAX_FILES_HARD),
        "max_file_bytes": (PROJECT_MAX_FILE_BYTES_DEFAULT, PROJECT_MAX_FILE_BYTES_HARD),
        "max_total_bytes": (PROJECT_MAX_TOTAL_BYTES_DEFAULT, PROJECT_MAX_TOTAL_BYTES_HARD),
        "max_archive_bytes": (PROJECT_MAX_ARCHIVE_BYTES_DEFAULT, PROJECT_MAX_ARCHIVE_BYTES_HARD),
        "max_input_entries": (PROJECT_MAX_INPUT_ENTRIES_DEFAULT, PROJECT_MAX_INPUT_ENTRIES_HARD),
    }
    limits: Dict[str, Any] = {}
    for key, (default, hard_maximum) in integer_limits.items():
        raw = payload.get(key, default)
        if type(raw) is not int or raw <= 0:
            raise ValueError(f"{key} must be a positive integer.")
        if raw > hard_maximum:
            raise ValueError(f"{key} exceeds the hard safety ceiling {hard_maximum}.")
        limits[key] = raw

    raw_ratio = payload.get("max_compression_ratio", PROJECT_MAX_COMPRESSION_RATIO_DEFAULT)
    if isinstance(raw_ratio, bool) or not isinstance(raw_ratio, (int, float)):
        raise ValueError("max_compression_ratio must be numeric.")
    ratio = float(raw_ratio)
    if not math.isfinite(ratio) or ratio < 1.0:
        raise ValueError("max_compression_ratio must be finite and at least 1.0.")
    if ratio > PROJECT_MAX_COMPRESSION_RATIO_HARD:
        raise ValueError(
            f"max_compression_ratio exceeds the hard safety ceiling {PROJECT_MAX_COMPRESSION_RATIO_HARD}."
        )
    limits["max_compression_ratio"] = ratio
    return limits


def project_pre_read_exclusion_reason(path: str, include_documentation: bool = False) -> Optional[str]:
    """Return exclusions decidable from a path before opening its content."""

    norm = normalise_project_path(path)
    ext = project_extension(norm)
    basename = norm.rsplit("/", 1)[-1].lower()
    if basename == ".codeprobeignore":
        return None
    if ext in PROJECT_BINARY_EXTENSIONS:
        return "binary_or_non_source_extension"
    if ext in PROJECT_DOCUMENTATION_EXTENSIONS and not include_documentation:
        return "documentation_excluded_by_default"
    if ext not in PROJECT_CODE_EXTENSIONS and not (
        include_documentation and ext in PROJECT_DOCUMENTATION_EXTENSIONS
    ):
        return "unsupported_extension"
    if basename.endswith((".min.js", ".min.css", ".bundle.js")):
        return "minified_or_bundled_asset"
    return None


def _base64_decoded_upper_bound(encoded: str) -> int:
    if not encoded:
        return 0
    padding = 2 if encoded.endswith("==") else (1 if encoded.endswith("=") else 0)
    return (len(encoded) // 4) * 3 - padding


def _zip_eocd_record(data: bytes) -> Dict[str, int]:
    """Read the classic ZIP end record before ZipFile allocates its member list."""

    signature = b"PK\x05\x06"
    lower = max(0, len(data) - (65_535 + 22))
    cursor = len(data)
    while True:
        offset = data.rfind(signature, lower, cursor)
        if offset < 0:
            raise ValueError("ZIP end-of-central-directory record is missing or malformed.")
        if offset + 22 <= len(data):
            comment_length = int.from_bytes(data[offset + 20 : offset + 22], "little")
            if offset + 22 + comment_length == len(data):
                break
        cursor = offset

    disk_number = int.from_bytes(data[offset + 4 : offset + 6], "little")
    central_disk = int.from_bytes(data[offset + 6 : offset + 8], "little")
    entries_on_disk = int.from_bytes(data[offset + 8 : offset + 10], "little")
    total_entries = int.from_bytes(data[offset + 10 : offset + 12], "little")
    central_size = int.from_bytes(data[offset + 12 : offset + 16], "little")
    central_offset = int.from_bytes(data[offset + 16 : offset + 20], "little")
    if disk_number or central_disk or entries_on_disk != total_entries:
        raise ValueError("Multi-disk ZIP archives are not supported.")
    if total_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise ValueError("ZIP64 project archives are not accepted by this bounded browser workflow.")
    if central_offset + central_size > offset:
        raise ValueError("ZIP central-directory bounds are inconsistent with the archive container.")
    return {
        "total_entries": total_entries,
        "central_size": central_size,
        "central_offset": central_offset,
    }


def _zip_member_rejection(info: zipfile.ZipInfo) -> Tuple[str, str]:
    if info.flag_bits & 0x1:
        return "encrypted_zip_member", "Encrypted ZIP members are not analysed."
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        return "unsupported_zip_compression", "Only stored and DEFLATE ZIP members are accepted."
    if info.create_system == 3:
        unix_mode = (int(info.external_attr) >> 16) & 0xFFFF
        file_type = unix_mode & 0o170000
        if file_type not in {0, 0o040000, 0o100000}:
            return "zip_non_regular_entry", "The ZIP member represents a symbolic link or special filesystem entry."
    return "", ""


def _read_zip_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    maximum_bytes: int,
) -> bytes:
    """Decompress one member incrementally and stop at a strict output ceiling."""

    chunks: List[bytes] = []
    total = 0
    try:
        with archive.open(info, "r") as handle:
            while True:
                remaining = maximum_bytes - total
                if remaining < 0:
                    raise ValueError(f"ZIP member {info.filename!r} exceeds its bounded read ceiling.")
                chunk = handle.read(min(PROJECT_ZIP_READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise ValueError(f"ZIP member {info.filename!r} exceeds its bounded read ceiling.")
                chunks.append(chunk)
    except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
        raise ValueError(f"Could not read ZIP member {info.filename!r}: {exc}") from exc
    content = b"".join(chunks)
    if len(content) != int(info.file_size):
        raise ValueError(f"ZIP member {info.filename!r} size differs from its central-directory record.")
    return content


def _effective_archive_path(raw_path: str, common_root: str) -> str:
    if project_path_is_unsafe(raw_path):
        return raw_path.replace("\\", "/").strip()
    norm = normalise_project_path(raw_path)
    prefix = common_root.rstrip("/") + "/" if common_root else ""
    if prefix and norm.startswith(prefix):
        return norm[len(prefix) :] or norm
    return norm


def _preexcluded_candidate(path: str, size: int, reason: str, detail: str) -> ProjectCandidateFile:
    return ProjectCandidateFile(
        path=path,
        text="",
        size_bytes=max(0, int(size)),
        excluded_reason=reason,
        excluded_detail=detail,
    )


def _project_ignore_rules_for_collection(
    embedded_ignore_texts: Sequence[str],
    payload: Dict[str, Any],
) -> List[IgnoreRule]:
    ignore_text = default_project_ignore_text()
    if embedded_ignore_texts:
        ignore_text += "\n" + "\n".join(embedded_ignore_texts)
    if payload.get("ignore_text"):
        ignore_text += "\n" + str(payload.get("ignore_text"))
    return parse_ignore_patterns(ignore_text)


def _collect_file_list_project(
    payload: Dict[str, Any],
    limits: Dict[str, Any],
) -> List[ProjectCandidateFile]:
    raw_items = payload.get("files") or []
    if not isinstance(raw_items, list):
        raise ValueError("files must be an array of project-file objects.")
    if len(raw_items) > limits["max_input_entries"]:
        raise ValueError(
            f"Project input contains {len(raw_items)} entries; limit is {limits['max_input_entries']}."
        )

    candidates: List[ProjectCandidateFile] = []
    total_bytes = 0
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            raise ValueError(f"files[{index}] must be an object.")
        path = str(item.get("path") or item.get("name") or "fragment.txt")
        text = str(item.get("content") if item.get("content") is not None else item.get("text") or "")
        actual_size = len(text.encode("utf-8", errors="strict"))
        declared = item.get("size_bytes")
        if declared is None:
            declared_size = actual_size
        elif type(declared) is not int or declared < 0:
            raise ValueError(f"files[{index}].size_bytes must be a non-negative integer.")
        else:
            declared_size = declared
        effective_size = max(actual_size, declared_size)
        total_bytes += effective_size
        if total_bytes > limits["max_total_bytes"]:
            raise ValueError(
                f"Project file-list payload exceeds total byte limit {limits['max_total_bytes']}."
            )
        candidates.append(
            ProjectCandidateFile(
                path=path,
                text=text,
                size_bytes=effective_size,
                excluded_reason=str(item.get("preexcluded_reason") or "")[:80],
                excluded_detail=str(item.get("preexcluded_detail") or "")[:500],
            )
        )

    common_root, _reason = infer_common_project_root(candidates)
    embedded_ignore_texts = [
        item.text
        for item in candidates
        if not project_path_is_unsafe(item.path)
        and _effective_archive_path(item.path, common_root).rsplit("/", 1)[-1] == ".codeprobeignore"
        and item.size_bytes <= limits["max_file_bytes"]
        and not item.excluded_reason
    ]
    rules = _project_ignore_rules_for_collection(embedded_ignore_texts, payload)
    include_documentation = bool(payload.get("include_documentation", False))
    selected = 0
    seen_portable: Set[str] = set()
    output: List[ProjectCandidateFile] = []
    for item in candidates:
        raw_path = str(item.path or "")
        if project_path_is_unsafe(raw_path):
            output.append(item)
            continue
        effective = _effective_archive_path(raw_path, common_root)
        portable = normalise_project_path(effective).casefold()
        if portable in seen_portable:
            output.append(_preexcluded_candidate(raw_path, item.size_bytes, "duplicate_path", "A case-insensitive path collision was detected."))
            continue
        seen_portable.add(portable)
        if item.excluded_reason:
            output.append(item)
            continue
        if effective.rsplit("/", 1)[-1] == ".codeprobeignore":
            output.append(item)
            continue
        if project_path_is_ignored(effective, rules):
            output.append(_preexcluded_candidate(raw_path, item.size_bytes, "ignored_by_codeprobeignore", "Excluded before analysis by built-in or project ignore rules."))
            continue
        reason = project_pre_read_exclusion_reason(effective, include_documentation)
        if reason:
            output.append(_preexcluded_candidate(raw_path, item.size_bytes, reason, "Excluded from the source-analysis boundary before metric execution."))
            continue
        if item.size_bytes > limits["max_file_bytes"]:
            output.append(_preexcluded_candidate(raw_path, item.size_bytes, "file_too_large", f"{item.size_bytes} bytes exceeds limit {limits['max_file_bytes']}."))
            continue
        if selected >= limits["max_files"]:
            output.append(_preexcluded_candidate(raw_path, item.size_bytes, "project_file_limit", f"Maximum analysed file count is {limits['max_files']}."))
            continue
        if looks_like_minified_asset(effective, item.text):
            output.append(_preexcluded_candidate(raw_path, item.size_bytes, "minified_or_bundled_asset", "Detected as minified or bundled content."))
            continue
        selected += 1
        output.append(item)
    return output


def _collect_zip_project(
    payload: Dict[str, Any],
    warnings: List[str],
    limits: Dict[str, Any],
) -> List[ProjectCandidateFile]:
    encoded = payload.get("zip_base64")
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("zip_base64 must be a non-empty base64 string.")
    if len(encoded) % 4 != 0 or _base64_decoded_upper_bound(encoded) > limits["max_archive_bytes"]:
        raise ValueError(f"Compressed project archive exceeds limit {limits['max_archive_bytes']} bytes.")
    try:
        archive_bytes = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError(f"zip_base64 is not valid base64: {exc}") from exc
    if len(archive_bytes) > limits["max_archive_bytes"]:
        raise ValueError(f"Compressed project archive exceeds limit {limits['max_archive_bytes']} bytes.")

    eocd = _zip_eocd_record(archive_bytes)
    if eocd["total_entries"] > limits["max_input_entries"]:
        raise ValueError(
            f"ZIP contains {eocd['total_entries']} entries; limit is {limits['max_input_entries']}."
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded archive is not a readable ZIP file.") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) != eocd["total_entries"]:
            raise ValueError("ZIP entry count differs from the end-of-central-directory record.")
        metadata: List[Dict[str, Any]] = []
        total_uncompressed = 0
        for info in infos:
            if info.is_dir():
                continue
            path = str(info.filename or "")
            size = int(info.file_size)
            compressed = int(info.compress_size)
            if size < 0 or compressed < 0:
                raise ValueError("ZIP member sizes must be non-negative.")
            total_uncompressed += size
            if total_uncompressed > limits["max_total_bytes"]:
                raise ValueError(
                    f"ZIP uncompressed size exceeds total byte limit {limits['max_total_bytes']}."
                )
            ratio = size / max(compressed, 1)
            if ratio > limits["max_compression_ratio"]:
                raise ValueError(
                    f"ZIP member {path!r} compression ratio {ratio:.1f} exceeds limit {limits['max_compression_ratio']:.1f}."
                )
            rejection, detail = _zip_member_rejection(info)
            metadata.append(
                {
                    "path": path,
                    "info": info,
                    "size": size,
                    "rejection": rejection,
                    "detail": detail,
                }
            )

        metadata_candidates = [
            ProjectCandidateFile(path=item["path"], text="", size_bytes=item["size"])
            for item in metadata
        ]
        common_root, _root_reason = infer_common_project_root(metadata_candidates)
        for item in metadata:
            item["effective_path"] = _effective_archive_path(item["path"], common_root)

        embedded_ignore_texts: List[str] = []
        ignore_cache: Dict[int, Tuple[str, str]] = {}
        for index, item in enumerate(metadata):
            path = item["effective_path"]
            if (
                item["rejection"]
                or project_path_is_unsafe(item["path"])
                or path.rsplit("/", 1)[-1] != ".codeprobeignore"
                or item["size"] > limits["max_file_bytes"]
            ):
                continue
            data = _read_zip_member_bounded(archive, item["info"], limits["max_file_bytes"])
            text, warning = decode_text_bytes(data)
            if text is None:
                ignore_cache[index] = ("", warning or "unreadable ignore file")
                continue
            ignore_cache[index] = (text, warning)
            embedded_ignore_texts.append(text)
            if warning:
                warnings.append(f"{path}: {warning}.")

        rules = _project_ignore_rules_for_collection(embedded_ignore_texts, payload)
        include_documentation = bool(payload.get("include_documentation", False))
        selected = 0
        seen_portable: Set[str] = set()
        output: List[ProjectCandidateFile] = []
        for index, item in enumerate(metadata):
            raw_path = item["path"]
            path = item["effective_path"]
            size = item["size"]
            if project_path_is_unsafe(raw_path):
                output.append(_preexcluded_candidate(raw_path, size, "unsafe_path", "Path is absolute, empty or contains parent-directory traversal."))
                continue
            portable = normalise_project_path(path).casefold()
            if portable in seen_portable:
                output.append(_preexcluded_candidate(raw_path, size, "duplicate_path", "A case-insensitive path collision was detected."))
                continue
            seen_portable.add(portable)
            if item["rejection"]:
                output.append(_preexcluded_candidate(raw_path, size, item["rejection"], item["detail"]))
                continue
            if path.rsplit("/", 1)[-1] == ".codeprobeignore":
                cached_text, cached_warning = ignore_cache.get(index, ("", "ignore file was not read"))
                if not cached_text and cached_warning:
                    output.append(_preexcluded_candidate(raw_path, size, "unreadable_ignore_file", cached_warning))
                else:
                    output.append(ProjectCandidateFile(raw_path, cached_text, size))
                continue
            if project_path_is_ignored(path, rules):
                output.append(_preexcluded_candidate(raw_path, size, "ignored_by_codeprobeignore", "Excluded before decompression by built-in or project ignore rules."))
                continue
            reason = project_pre_read_exclusion_reason(path, include_documentation)
            if reason:
                output.append(_preexcluded_candidate(raw_path, size, reason, "Excluded before decompression from the source-analysis boundary."))
                continue
            if size > limits["max_file_bytes"]:
                output.append(_preexcluded_candidate(raw_path, size, "file_too_large", f"{size} bytes exceeds limit {limits['max_file_bytes']}."))
                continue
            if selected >= limits["max_files"]:
                output.append(_preexcluded_candidate(raw_path, size, "project_file_limit", f"Maximum analysed file count is {limits['max_files']}."))
                continue
            data = _read_zip_member_bounded(archive, item["info"], limits["max_file_bytes"])
            text, warning = decode_text_bytes(data)
            if text is None:
                output.append(_preexcluded_candidate(raw_path, size, "binary_content", warning or "Content is not readable source text."))
                continue
            if warning:
                warnings.append(f"{path}: {warning}.")
            if looks_like_minified_asset(path, text):
                output.append(_preexcluded_candidate(raw_path, size, "minified_or_bundled_asset", "Detected as minified or bundled content after bounded decoding."))
                continue
            selected += 1
            output.append(ProjectCandidateFile(raw_path, text, len(data)))
        return output


def collect_project_files(payload: Dict[str, Any], warnings: List[str]) -> Tuple[List[ProjectCandidateFile], str]:
    """Collect a bounded project file list without pre-limit ZIP decompression."""

    limits = project_input_limits(payload)
    if payload.get("zip_base64"):
        return _collect_zip_project(payload, warnings, limits), "zip"
    return _collect_file_list_project(payload, limits), "file-list"
'''


PROJECT_IO_CODE = r'''"""Bounded and non-following project-input helpers for CodeProbe CLIs."""

from __future__ import annotations

import base64
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import codeprobe_runtime as engine

WarningSink = Optional[Callable[[str], None]]
_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class FolderEntry:
    path: Path
    relative: str
    size_bytes: int
    kind: str
    detail: str = ""


def stderr_warning(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)


def _safe_text(value: object) -> str:
    return ascii(os.fspath(value) if isinstance(value, os.PathLike) else str(value))[1:-1]


def _record_placeholder(entry: FolderEntry, reason: str, detail: str) -> Dict[str, Any]:
    return {
        "path": entry.relative,
        "content": "",
        "size_bytes": max(0, entry.size_bytes),
        "preexcluded_reason": reason,
        "preexcluded_detail": detail,
    }


def _validate_root(root: Path) -> Path:
    supplied = Path(root)
    try:
        metadata = supplied.lstat()
    except OSError as exc:
        raise ValueError(f"project root is unavailable: {_safe_text(exc)}") from exc
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        raise ValueError("project root must not be a symbolic link or reparse point")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("project root is not a directory")
    return supplied.resolve()


def _inventory_folder(
    root: Path,
    *,
    max_entries: int,
    warning_sink: WarningSink,
) -> List[FolderEntry]:
    root = _validate_root(root)
    default_rules = engine.parse_ignore_patterns(engine.default_project_ignore_text())
    pending = [root]
    entries_seen = 0
    files: List[FolderEntry] = []
    while pending:
        directory = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ValueError(f"cannot enumerate project directory {_safe_text(directory)}: {_safe_text(exc)}") from exc
        child_directories: List[Path] = []
        for child in children:
            entries_seen += 1
            if entries_seen > max_entries:
                raise ValueError(f"project folder exceeds input-entry limit {max_entries}")
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                files.append(FolderEntry(path, relative, 0, "unreadable", str(exc)))
                continue
            if child.is_symlink() or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                files.append(FolderEntry(path, relative, int(metadata.st_size), "redirect", "symbolic link, junction or reparse point"))
                continue
            if stat.S_ISDIR(metadata.st_mode):
                probe = f"{relative}/.codeprobe-directory-probe"
                if engine.project_path_is_ignored(probe, default_rules):
                    continue
                child_directories.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                files.append(FolderEntry(path, relative, int(metadata.st_size), "regular"))
            else:
                files.append(FolderEntry(path, relative, int(metadata.st_size), "special", "non-regular filesystem entry"))
        pending.extend(reversed(child_directories))
    return sorted(files, key=lambda item: item.relative)


def _open_beneath(root: Path, relative: str) -> int:
    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe project path: {relative!r}")
    file_flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        file_flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW

    can_walk_descriptors = (
        hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
    )
    if not can_walk_descriptors:
        current = root
        for part in parts[:-1]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(f"unsafe project path ancestor: {current}")
        return os.open(root.joinpath(*parts), file_flags)

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    directory_descriptor = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        stat.S_IMODE(metadata.st_mode),
    )


def _read_regular_file_bounded(root: Path, entry: FolderEntry, maximum_bytes: int) -> bytes:
    before_path = entry.path.lstat()
    if stat.S_ISLNK(before_path.st_mode) or _is_reparse(before_path) or not stat.S_ISREG(before_path.st_mode):
        raise ValueError(f"project file is no longer a stable regular file: {entry.relative}")
    if int(before_path.st_size) > maximum_bytes:
        raise ValueError(f"project file exceeds bounded read limit: {entry.relative}")
    try:
        descriptor = _open_beneath(root, entry.relative)
    except OSError as exc:
        raise ValueError(f"unsafe or unreadable project file {entry.relative}: {_safe_text(exc)}") from exc
    chunks: List[bytes] = []
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not os.path.samestat(before_path, before):
            raise ValueError(f"project file changed before read: {entry.relative}")
        while True:
            remaining = maximum_bytes - total
            chunk = os.read(descriptor, min(64 * 1024, remaining + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError(f"project file exceeded bounded read limit: {entry.relative}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = entry.path.lstat()
    if (
        _stable_identity(before) != _stable_identity(after)
        or _stable_identity(before_path) != _stable_identity(after_path)
        or not os.path.samestat(before, after_path)
    ):
        raise ValueError(f"project file changed during read: {entry.relative}")
    return b"".join(chunks)


def read_bounded_control_text(path: Path, maximum_bytes: int) -> str:
    """Read one explicitly selected control JSON/text file with a hard ceiling."""
    path = Path(path)
    parent = _validate_root(path.parent)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"control file is not a regular file: {path}")
    entry = FolderEntry(path.resolve(), path.name, int(metadata.st_size), "regular")
    data = _read_regular_file_bounded(parent, entry, maximum_bytes)
    return data.decode("utf-8")


def iter_safe_regular_paths(
    root: Path,
    *,
    max_entries: int = engine.PROJECT_MAX_INPUT_ENTRIES_DEFAULT,
) -> Sequence[Path]:
    """Return regular paths below a root and fail closed on redirects/special files."""
    resolved = _validate_root(root)
    entries = _inventory_folder(resolved, max_entries=max_entries, warning_sink=None)
    unsafe = [entry for entry in entries if entry.kind != "regular"]
    if unsafe:
        first = unsafe[0]
        raise ValueError(f"unsafe calibration corpus entry {first.relative}: {first.detail or first.kind}")
    return tuple(entry.path for entry in entries)


def read_folder_files(
    root: Path,
    *,
    include_binary_placeholders: bool = True,
    warning_sink: WarningSink = None,
    include_documentation: bool = False,
    ignore_text: str = "",
    max_files: int = engine.PROJECT_MAX_FILES_DEFAULT,
    max_file_bytes: int = engine.PROJECT_MAX_FILE_BYTES_DEFAULT,
    max_total_bytes: int = engine.PROJECT_MAX_TOTAL_BYTES_DEFAULT,
    max_input_entries: int = engine.PROJECT_MAX_INPUT_ENTRIES_DEFAULT,
) -> List[Dict[str, Any]]:
    """Build a bounded folder payload without following redirects or special files."""
    limits = engine.project_input_limits({
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "max_total_bytes": max_total_bytes,
        "max_input_entries": max_input_entries,
    })
    resolved = _validate_root(root)
    entries = _inventory_folder(resolved, max_entries=limits["max_input_entries"], warning_sink=warning_sink)

    embedded_texts: List[str] = []
    ignore_content: Dict[str, str] = {}
    for entry in entries:
        if entry.kind != "regular" or entry.path.name != ".codeprobeignore":
            continue
        if entry.size_bytes > limits["max_file_bytes"]:
            continue
        try:
            data = _read_regular_file_bounded(resolved, entry, limits["max_file_bytes"])
            text, warning = engine.decode_text_bytes(data)
        except Exception as exc:
            if warning_sink:
                warning_sink(f"{entry.relative}: {exc}")
            continue
        if text is not None:
            embedded_texts.append(text)
            ignore_content[entry.relative] = text
            if warning and warning_sink:
                warning_sink(f"{entry.relative}: {warning}")

    combined_ignore = engine.default_project_ignore_text()
    if embedded_texts:
        combined_ignore += "\n" + "\n".join(embedded_texts)
    if ignore_text:
        combined_ignore += "\n" + ignore_text
    rules = engine.parse_ignore_patterns(combined_ignore)

    files: List[Dict[str, Any]] = []
    selected = 0
    total_read_budget = 0
    for entry in entries:
        if entry.kind == "redirect":
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "symbolic_link_or_reparse", entry.detail))
            continue
        if entry.kind != "regular":
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "special_file", entry.detail or entry.kind))
            continue
        if entry.path.name == ".codeprobeignore":
            text = ignore_content.get(entry.relative)
            if text is not None:
                files.append({"path": entry.relative, "content": text, "size_bytes": entry.size_bytes})
            elif include_binary_placeholders:
                files.append(_record_placeholder(entry, "unreadable_ignore_file", "The ignore file could not be read safely."))
            continue
        if engine.project_path_is_ignored(entry.relative, rules):
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "ignored_by_codeprobeignore", "Excluded before opening by built-in or project ignore rules."))
            continue
        reason = engine.project_pre_read_exclusion_reason(entry.relative, include_documentation)
        if reason:
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, reason, "Excluded before opening from the source-analysis boundary."))
            continue
        if entry.size_bytes > limits["max_file_bytes"]:
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "file_too_large", f"{entry.size_bytes} bytes exceeds limit {limits['max_file_bytes']}."))
            continue
        if selected >= limits["max_files"]:
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "project_file_limit", f"Maximum analysed file count is {limits['max_files']}."))
            continue
        if total_read_budget + entry.size_bytes > limits["max_total_bytes"]:
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "project_total_byte_limit", f"Reading this file would exceed total byte limit {limits['max_total_bytes']}."))
            continue
        try:
            data = _read_regular_file_bounded(resolved, entry, limits["max_file_bytes"])
        except Exception as exc:
            if warning_sink:
                warning_sink(f"{entry.relative}: {exc}")
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "unstable_or_unreadable_file", str(exc)))
            continue
        total_read_budget += len(data)
        text, warning = engine.decode_text_bytes(data)
        if text is None:
            if warning_sink:
                warning_sink(f"{entry.relative}: {warning}")
            if include_binary_placeholders:
                files.append(_record_placeholder(entry, "binary_content", warning or "Content is not readable source text."))
            continue
        if warning and warning_sink:
            warning_sink(f"{entry.relative}: {warning}")
        selected += 1
        files.append({"path": entry.relative, "content": text, "size_bytes": len(data)})
    return files


def project_payload_from_path(
    path: Path,
    *,
    include_binary_placeholders: bool = True,
    include_documentation: bool = False,
    ignore_text: str = "",
    max_files: int = engine.PROJECT_MAX_FILES_DEFAULT,
    max_file_bytes: int = engine.PROJECT_MAX_FILE_BYTES_DEFAULT,
    max_total_bytes: int = engine.PROJECT_MAX_TOTAL_BYTES_DEFAULT,
    max_archive_bytes: int = engine.PROJECT_MAX_ARCHIVE_BYTES_DEFAULT,
    max_input_entries: int = engine.PROJECT_MAX_INPUT_ENTRIES_DEFAULT,
    max_compression_ratio: float = engine.PROJECT_MAX_COMPRESSION_RATIO_DEFAULT,
) -> Dict[str, Any]:
    """Build an engine payload from a bounded folder or regular ZIP file."""
    limits = engine.project_input_limits({
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "max_total_bytes": max_total_bytes,
        "max_archive_bytes": max_archive_bytes,
        "max_input_entries": max_input_entries,
        "max_compression_ratio": max_compression_ratio,
    })
    path = Path(path)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        raise ValueError(f"project input must not be a symbolic link or reparse point: {path}")
    base_payload = dict(limits)
    base_payload["include_documentation"] = include_documentation
    if ignore_text:
        base_payload["ignore_text"] = ignore_text
    if stat.S_ISDIR(metadata.st_mode):
        resolved = _validate_root(path)
        base_payload.update({
            "project_name": resolved.name,
            "files": read_folder_files(
                resolved,
                include_binary_placeholders=include_binary_placeholders,
                include_documentation=include_documentation,
                ignore_text=ignore_text,
                max_files=limits["max_files"],
                max_file_bytes=limits["max_file_bytes"],
                max_total_bytes=limits["max_total_bytes"],
                max_input_entries=limits["max_input_entries"],
            ),
        })
        return base_payload
    if stat.S_ISREG(metadata.st_mode) and path.suffix.lower() == ".zip":
        if int(metadata.st_size) > limits["max_archive_bytes"]:
            raise ValueError(f"compressed project archive exceeds limit {limits['max_archive_bytes']} bytes")
        parent = _validate_root(path.parent)
        entry = FolderEntry(path.resolve(), path.name, int(metadata.st_size), "regular")
        content = _read_regular_file_bounded(parent, entry, limits["max_archive_bytes"])
        base_payload.update({
            "project_name": path.stem,
            "zip_base64": base64.b64encode(content).decode("ascii"),
        })
        return base_payload
    raise ValueError(f"project sample must be a directory or ZIP archive: {path}")
'''


ANALYZE_BUILD_PAYLOAD = r'''def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    ignore_text = ""
    if args.ignore_file:
        ignore_text = read_bounded_control_text(Path(args.ignore_file), args.max_file_bytes)
    source_path = Path(args.zip or args.folder)
    payload = project_payload_from_path(
        source_path,
        include_binary_placeholders=True,
        include_documentation=args.include_documentation,
        ignore_text=ignore_text,
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_archive_bytes=args.max_archive_bytes,
        max_input_entries=args.max_input_entries,
        max_compression_ratio=args.max_compression_ratio,
    )
    payload["project_name"] = args.project_name or payload.get("project_name") or "project"
    payload["profile"] = args.profile
    if args.config:
        payload["config_override"] = json.loads(Path(args.config).read_text(encoding="utf-8"))
    if args.calibration_profile:
        payload["calibration_profile"] = json.loads(Path(args.calibration_profile).read_text(encoding="utf-8"))
    return payload
'''


TEST_METHODS = r'''
    def test_file_list_uses_actual_utf8_size_instead_of_trusted_metadata(self) -> None:
        payload = {
            "project_name": "forged-size",
            "max_file_bytes": 32,
            "files": [{"path": "large.py", "content": "x = '" + ("a" * 80) + "'\n", "size_bytes": 1}],
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        excluded = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(excluded.get("large.py"), "file_too_large")

    def test_invalid_project_limits_fail_closed(self) -> None:
        for payload in (
            {"files": [], "max_file_bytes": True},
            {"files": [], "max_total_bytes": 0},
            {"files": [], "max_compression_ratio": float("inf")},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    engine.collect_project_files(payload, [])

    def test_zip_entry_limit_is_checked_before_zipfile_construction(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.py", "a = 1\n")
            archive.writestr("b.py", "b = 2\n")
            archive.writestr("c.py", "c = 3\n")
        payload = {
            "zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii"),
            "max_input_entries": 2,
        }
        with mock.patch.object(engine.zipfile, "ZipFile", side_effect=AssertionError("ZipFile must not be constructed")):
            with self.assertRaisesRegex(ValueError, "entries"):
                engine.collect_project_files(payload, [])

    def test_zip_ratio_is_rejected_before_member_open(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bomb.py", b"0" * 200_000)
        payload = {
            "zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii"),
            "max_compression_ratio": 5.0,
        }
        with mock.patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("member must not be opened")):
            with self.assertRaisesRegex(ValueError, "compression ratio"):
                engine.collect_project_files(payload, [])

    def test_zip_ignored_member_is_not_decompressed(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(".codeprobeignore", "ignored.py\n")
            archive.writestr("ignored.py", "print('ignored')\n")
            archive.writestr("main.py", "def main():\n    return 1\n\nprint(main())\n")
        payload = {"zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii")}
        opened = []
        original_open = zipfile.ZipFile.open

        def tracked_open(instance, name, *args, **kwargs):
            opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else str(name))
            return original_open(instance, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "open", tracked_open):
            report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertNotIn("ignored.py", opened)
        self.assertIn("main.py", opened)
        excluded = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(excluded.get("ignored.py"), "ignored_by_codeprobeignore")

    def test_zip_symlink_member_is_excluded_without_opening(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("link.py")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "outside.py")
            archive.writestr("main.py", "def main():\n    return 1\n\nprint(main())\n")
        payload = {"zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii")}
        opened = []
        original_open = zipfile.ZipFile.open

        def tracked_open(instance, name, *args, **kwargs):
            opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else str(name))
            return original_open(instance, name, *args, **kwargs)

        with mock.patch.object(zipfile.ZipFile, "open", tracked_open):
            report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertNotIn("link.py", opened)
        excluded = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(excluded.get("link.py"), "zip_non_regular_entry")

    def test_folder_reader_does_not_follow_external_symlink(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            (root / "main.py").write_text("print('safe')\n", encoding="utf-8")
            secret = base / "secret.py"
            secret.write_text("TOP_SECRET = True\n", encoding="utf-8")
            try:
                os.symlink(secret, root / "linked.py")
            except OSError as exc:
                self.skipTest(f"symbolic-link creation unavailable: {exc}")
            records = project_io.read_folder_files(root)
        by_path = {item["path"]: item for item in records}
        self.assertEqual(by_path["linked.py"].get("preexcluded_reason"), "symbolic_link_or_reparse")
        self.assertEqual(by_path["linked.py"]["content"], "")
        self.assertNotIn("TOP_SECRET", json.dumps(records))

    def test_folder_reader_does_not_open_ignored_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".codeprobeignore").write_text("ignored.py\n", encoding="utf-8")
            (root / "ignored.py").write_text("print('ignored')\n", encoding="utf-8")
            (root / "main.py").write_text("print('safe')\n", encoding="utf-8")
            original = project_io._read_regular_file_bounded

            def guarded_read(project_root, entry, maximum_bytes):
                if entry.relative == "ignored.py":
                    raise AssertionError("ignored file was opened")
                return original(project_root, entry, maximum_bytes)

            with mock.patch.object(project_io, "_read_regular_file_bounded", guarded_read):
                records = project_io.read_folder_files(root)
        by_path = {item["path"]: item for item in records}
        self.assertEqual(by_path["ignored.py"].get("preexcluded_reason"), "ignored_by_codeprobeignore")
        self.assertIn("main.py", by_path)

    def test_folder_reader_records_fifo_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fifo = root / "input.pipe"
            os.mkfifo(fifo)
            records = project_io.read_folder_files(root)
        by_path = {item["path"]: item for item in records}
        self.assertEqual(by_path["input.pipe"].get("preexcluded_reason"), "special_file")
'''


BROWSER_TEST_METHOD = r'''
    def test_project_archive_size_guards_precede_array_buffer_reads(self):
        main_ui = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        project_ui = (APP / "project-ui.js").read_text(encoding="utf-8")
        main_start = main_ui.index("async function handleProjectZip")
        main_read = main_ui.index("await file.arrayBuffer()", main_start)
        self.assertLess(main_ui.index("MAX_BROWSER_PROJECT_ARCHIVE_BYTES", main_start), main_read)
        project_start = project_ui.index("async function loadZip")
        project_read = project_ui.index("await file.arrayBuffer()", project_start)
        self.assertLess(project_ui.index("MAX_BROWSER_PROJECT_ARCHIVE_BYTES", project_start), project_read)
        self.assertIn("MAX_BROWSER_PROJECT_TOTAL_BYTES", main_ui)
        self.assertIn("MAX_BROWSER_PROJECT_TOTAL_BYTES", project_ui)
'''


def patch_runtime(root: Path) -> None:
    path = root / "src" / "codeprobe_runtime.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "PROJECT_MAX_FILES_DEFAULT = 300\nPROJECT_MAX_FILE_BYTES_DEFAULT = 1_000_000\nPROJECT_SLOC_WEIGHT_CAP = 500",
        "PROJECT_MAX_FILES_DEFAULT = 300\nPROJECT_MAX_FILE_BYTES_DEFAULT = 1_000_000\nPROJECT_MAX_TOTAL_BYTES_DEFAULT = 25_000_000\nPROJECT_MAX_ARCHIVE_BYTES_DEFAULT = 25_000_000\nPROJECT_MAX_INPUT_ENTRIES_DEFAULT = 2_000\nPROJECT_MAX_COMPRESSION_RATIO_DEFAULT = 100.0\nPROJECT_MAX_FILES_HARD = 5_000\nPROJECT_MAX_FILE_BYTES_HARD = 16_000_000\nPROJECT_MAX_TOTAL_BYTES_HARD = 128_000_000\nPROJECT_MAX_ARCHIVE_BYTES_HARD = 64_000_000\nPROJECT_MAX_INPUT_ENTRIES_HARD = 10_000\nPROJECT_MAX_COMPRESSION_RATIO_HARD = 200.0\nPROJECT_ZIP_READ_CHUNK_BYTES = 64 * 1024\nPROJECT_SLOC_WEIGHT_CAP = 500",
        "runtime constants",
    )
    text = replace_once(
        text,
        '''@dataclass\nclass ProjectCandidateFile:\n    """A text file candidate received from a browser file list or ZIP archive."""\n\n    path: str\n    text: str\n    size_bytes: int = 0\n''',
        '''@dataclass\nclass ProjectCandidateFile:\n    """A bounded project candidate or a metadata-only exclusion record."""\n\n    path: str\n    text: str\n    size_bytes: int = 0\n    excluded_reason: str = ""\n    excluded_detail: str = ""\n''',
        "candidate dataclass",
    )
    text = replace_once(
        text,
        "ProjectCandidateFile(path=new_path, text=item.text, size_bytes=item.size_bytes)",
        "ProjectCandidateFile(path=new_path, text=item.text, size_bytes=item.size_bytes, excluded_reason=item.excluded_reason, excluded_detail=item.excluded_detail)",
        "common-root field preservation",
    )
    start = text.index("def collect_project_files(")
    end = text.index("\ndef build_project_ignore_rules", start)
    text = text[:start] + RUNTIME_COLLECTION_CODE + text[end:]
    text = replace_once(
        text,
        '''    candidates, source = collect_project_files(payload, warnings)\n    input_packaging = project_packaging_profile(candidates, source)\n''',
        '''    limits = project_input_limits(payload)\n    max_files = limits["max_files"]\n    max_file_bytes = limits["max_file_bytes"]\n    candidates, source = collect_project_files(payload, warnings)\n    input_packaging = project_packaging_profile(candidates, source)\n    input_packaging["limits"] = dict(limits)\n''',
        "project limit ordering",
    )
    text = replace_once(
        text,
        '''    max_files = int(payload.get("max_files") or PROJECT_MAX_FILES_DEFAULT)\n    max_file_bytes = int(payload.get("max_file_bytes") or PROJECT_MAX_FILE_BYTES_DEFAULT)\n''',
        "",
        "remove late limits",
    )
    text = replace_once(
        text,
        '''        seen.add(path)\n\n        if len(included_reports) >= max_files:\n''',
        '''        seen.add(path)\n\n        if candidate.excluded_reason:\n            excluded.append(ProjectExcludedFile(path, candidate.excluded_reason, candidate.excluded_detail))\n            continue\n        if len(included_reports) >= max_files:\n''',
        "preexcluded candidate handling",
    )
    write_if_changed(path, text)


def patch_project_io(root: Path) -> None:
    write_if_changed(root / "src" / "codeprobe_engine" / "project_io.py", PROJECT_IO_CODE)


def patch_analyse_cli(root: Path) -> None:
    path = root / "tools" / "analyze_project.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "import base64\n",
        "",
        "remove raw base64 import",
    )
    text = replace_once(
        text,
        "from codeprobe_engine.project_io import read_folder_files, stderr_warning",
        "from codeprobe_engine.project_io import project_payload_from_path, read_bounded_control_text, stderr_warning",
        "project io imports",
    )
    start = text.index("def build_payload(")
    end = text.index("\ndef main", start)
    text = text[:start] + ANALYZE_BUILD_PAYLOAD + text[end:]
    text = replace_once(
        text,
        '''    parser.add_argument("--max-files", type=int, default=engine.PROJECT_MAX_FILES_DEFAULT, help="Maximum number of analysable source files.")\n    parser.add_argument("--max-file-bytes", type=int, default=engine.PROJECT_MAX_FILE_BYTES_DEFAULT, help="Maximum bytes per source file.")\n''',
        '''    parser.add_argument("--max-files", type=int, default=engine.PROJECT_MAX_FILES_DEFAULT, help="Maximum number of analysable source files.")\n    parser.add_argument("--max-file-bytes", type=int, default=engine.PROJECT_MAX_FILE_BYTES_DEFAULT, help="Maximum bytes per source file.")\n    parser.add_argument("--max-total-bytes", type=int, default=engine.PROJECT_MAX_TOTAL_BYTES_DEFAULT, help="Maximum aggregate project bytes admitted to the bounded input layer.")\n    parser.add_argument("--max-archive-bytes", type=int, default=engine.PROJECT_MAX_ARCHIVE_BYTES_DEFAULT, help="Maximum compressed ZIP container bytes.")\n    parser.add_argument("--max-input-entries", type=int, default=engine.PROJECT_MAX_INPUT_ENTRIES_DEFAULT, help="Maximum folder or ZIP inventory entries.")\n    parser.add_argument("--max-compression-ratio", type=float, default=engine.PROJECT_MAX_COMPRESSION_RATIO_DEFAULT, help="Maximum allowed uncompressed/compressed ratio for one ZIP member.")\n''',
        "CLI limit arguments",
    )
    write_if_changed(path, text)


def patch_calibration(root: Path) -> None:
    path = root / "tools" / "calibrate_corpus.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "import codeprobe_runtime as engine\n",
        "import codeprobe_runtime as engine\nfrom codeprobe_engine.project_io import iter_safe_regular_paths\n",
        "calibration safe iterator import",
    )
    text = replace_once(
        text,
        '''        for path in sorted(folder.rglob("*")):\n            if not path.is_file():\n                continue\n''',
        '''        for path in iter_safe_regular_paths(folder):\n''',
        "calibration traversal",
    )
    write_if_changed(path, text)


def patch_main_ui(root: Path) -> None:
    path = root / "app" / "codeprobe-ui.js"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    const MAX_BROWSER_DROP_FILES = 2000;\n    const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;\n''',
        '''    const MAX_BROWSER_DROP_FILES = 2000;\n    const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;\n    const MAX_BROWSER_PROJECT_TOTAL_BYTES = 25000000;\n    const MAX_BROWSER_PROJECT_ARCHIVE_BYTES = 25000000;\n''',
        "main browser limits",
    )
    text = replace_once(
        text,
        '''    async function handleProjectZip(file) {\n      if (!file) return;\n      const zipBase64 = arrayBufferToBase64(await file.arrayBuffer());\n''',
        '''    async function handleProjectZip(file) {\n      if (!file) return;\n      if ((file.size || 0) > MAX_BROWSER_PROJECT_ARCHIVE_BYTES) {\n        els.statusText.textContent = `Project ZIP exceeds the ${MAX_BROWSER_PROJECT_ARCHIVE_BYTES.toLocaleString()} byte browser limit.`;\n        return;\n      }\n      const zipBase64 = arrayBufferToBase64(await file.arrayBuffer());\n''',
        "main ZIP preflight",
    )
    text = replace_once(
        text,
        '''        zip_filename: file.name || "archive.zip",\n        zip_base64: zipBase64\n''',
        '''        zip_filename: file.name || "archive.zip",\n        zip_base64: zipBase64,\n        max_archive_bytes: MAX_BROWSER_PROJECT_ARCHIVE_BYTES,\n        max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES,\n        max_input_entries: MAX_BROWSER_DROP_FILES\n''',
        "main ZIP limits payload",
    )
    text = replace_once(
        text,
        '''      const payloadFiles = [];\n      const warnings = [];\n      for (const file of files) {\n        const path = file._codeprobeRelativePath || file.webkitRelativePath || file.name || "file";\n        if (!projectTextCandidate(path) || file.size > MAX_BROWSER_PROJECT_TEXT_BYTES) {\n          payloadFiles.push({ path, content: "", size_bytes: file.size || 0 });\n          continue;\n        }\n        try {\n''',
        '''      const payloadFiles = [];\n      const warnings = [];\n      let admittedBytes = 0;\n      for (const file of files) {\n        const path = file._codeprobeRelativePath || file.webkitRelativePath || file.name || "file";\n        const fileBytes = Number(file.size || 0);\n        if (!projectTextCandidate(path)) {\n          payloadFiles.push({ path, content: "", size_bytes: fileBytes, preexcluded_reason: "unsupported_extension", preexcluded_detail: "Excluded before browser file reading." });\n          continue;\n        }\n        if (fileBytes > MAX_BROWSER_PROJECT_TEXT_BYTES) {\n          payloadFiles.push({ path, content: "", size_bytes: fileBytes, preexcluded_reason: "file_too_large", preexcluded_detail: "Excluded before browser file reading." });\n          continue;\n        }\n        if (admittedBytes + fileBytes > MAX_BROWSER_PROJECT_TOTAL_BYTES) {\n          payloadFiles.push({ path, content: "", size_bytes: fileBytes, preexcluded_reason: "project_total_byte_limit", preexcluded_detail: "Excluded before browser file reading." });\n          continue;\n        }\n        admittedBytes += fileBytes;\n        try {\n''',
        "main folder preflight",
    )
    text = replace_once(
        text,
        '''        project_name: projectName,\n        files: payloadFiles\n''',
        '''        project_name: projectName,\n        files: payloadFiles,\n        max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES,\n        max_archive_bytes: MAX_BROWSER_PROJECT_ARCHIVE_BYTES,\n        max_input_entries: MAX_BROWSER_DROP_FILES\n''',
        "main folder limits payload",
    )
    write_if_changed(path, text)


def patch_project_ui(root: Path) -> None:
    path = root / "app" / "project-ui.js"
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '''    const MAX_BROWSER_DROP_FILES = 2000;\n    const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;\n''',
        '''    const MAX_BROWSER_DROP_FILES = 2000;\n    const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;\n    const MAX_BROWSER_PROJECT_TOTAL_BYTES = 25000000;\n    const MAX_BROWSER_PROJECT_ARCHIVE_BYTES = 25000000;\n''',
        "project browser limits",
    )
    text = replace_once(
        text,
        '''    async function loadZip(file) {\n      const buffer = await file.arrayBuffer();\n''',
        '''    async function loadZip(file) {\n      if ((file.size || 0) > MAX_BROWSER_PROJECT_ARCHIVE_BYTES) {\n        els.status.textContent = `Project ZIP exceeds the ${MAX_BROWSER_PROJECT_ARCHIVE_BYTES.toLocaleString()} byte browser limit.`;\n        return;\n      }\n      const buffer = await file.arrayBuffer();\n''',
        "project ZIP preflight",
    )
    text = replace_once(
        text,
        '''      state.payload = { project_name: state.projectName, zip_base64: bytesToBase64(new Uint8Array(buffer)) };\n''',
        '''      state.payload = { project_name: state.projectName, zip_base64: bytesToBase64(new Uint8Array(buffer)), max_archive_bytes: MAX_BROWSER_PROJECT_ARCHIVE_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES, max_input_entries: MAX_BROWSER_DROP_FILES };\n''',
        "project ZIP payload",
    )
    text = replace_once(
        text,
        '''      const files = []; const warnings = [];\n      for (const file of selected) {\n        const path = file._codeprobeRelativePath || file.webkitRelativePath || file.name;\n        if ((file.size || 0) > MAX_BROWSER_PROJECT_TEXT_BYTES) { warnings.push(`${path}: skipped in browser because it exceeds 1 MB`); continue; }\n        try { files.push(await decodeTextFile(file)); } catch (error) { warnings.push(`${path}: ${error.message}`); }\n      }\n''',
        '''      const files = []; const warnings = [];\n      let admittedBytes = 0;\n      for (const file of selected) {\n        const path = file._codeprobeRelativePath || file.webkitRelativePath || file.name;\n        const fileBytes = Number(file.size || 0);\n        if (fileBytes > MAX_BROWSER_PROJECT_TEXT_BYTES) {\n          files.push({ path, content: "", size_bytes: fileBytes, preexcluded_reason: "file_too_large", preexcluded_detail: "Excluded before browser file reading." });\n          warnings.push(`${path}: skipped in browser because it exceeds 1 MB`);\n          continue;\n        }\n        if (admittedBytes + fileBytes > MAX_BROWSER_PROJECT_TOTAL_BYTES) {\n          files.push({ path, content: "", size_bytes: fileBytes, preexcluded_reason: "project_total_byte_limit", preexcluded_detail: "Excluded before browser file reading." });\n          warnings.push(`${path}: skipped because the project byte budget was reached`);\n          continue;\n        }\n        admittedBytes += fileBytes;\n        try { files.push(await decodeTextFile(file)); } catch (error) { warnings.push(`${path}: ${error.message}`); }\n      }\n''',
        "project folder preflight",
    )
    text = replace_once(
        text,
        '''      state.payload = { project_name: state.projectName, files };\n''',
        '''      state.payload = { project_name: state.projectName, files, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES, max_archive_bytes: MAX_BROWSER_PROJECT_ARCHIVE_BYTES, max_input_entries: MAX_BROWSER_DROP_FILES };\n''',
        "project folder payload",
    )
    write_if_changed(path, text)


def patch_tests(root: Path) -> None:
    path = root / "tests" / "test_project_mode.py"
    text = path.read_text(encoding="utf-8")
    text = replace_once(text, "import io\n", "import io\nimport os\nimport tempfile\n", "project test imports")
    text = replace_once(text, "import unittest\n", "import unittest\nfrom unittest import mock\n", "mock import")
    text = replace_once(
        text,
        "import codeprobe_runtime as engine  # noqa: E402\n",
        "import codeprobe_runtime as engine  # noqa: E402\nfrom codeprobe_engine import project_io  # noqa: E402\n",
        "project_io test import",
    )
    text = replace_once(text, "\n\nif __name__ == \"__main__\":", TEST_METHODS + "\n\nif __name__ == \"__main__\":", "project safety tests")
    write_if_changed(path, text)

    browser_path = root / "tests" / "test_browser_security.py"
    browser = browser_path.read_text(encoding="utf-8")
    browser = replace_once(browser, "\n\nif __name__ == \"__main__\":", BROWSER_TEST_METHOD + "\n\nif __name__ == \"__main__\":", "browser guard test")
    write_if_changed(browser_path, browser)


def patch_docs(root: Path) -> None:
    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    readme = replace_once(
        readme,
        "When a ZIP contains a single hosted-export wrapper such as `repository-main/`, CodeProbe strips that wrapper before evaluating `.codeprobeignore`; the report records this in `input_packaging`.",
        "When a ZIP contains a single hosted-export wrapper such as `repository-main/`, CodeProbe strips that wrapper before evaluating `.codeprobeignore`; the report records this in `input_packaging`. Folder traversal does not follow symbolic links, junctions or special files. ZIP metadata is checked before member decompression and the default boundary limits the compressed archive to 25 MB, the total admitted input to 25 MB, one source file to 1 MB, the inventory to 2,000 entries and any single-member compression ratio to 100:1.",
        "README input boundary",
    )
    readme = replace_once(
        readme,
        "- Static analysis cannot reconstruct the development process; commits, tests and explanation remain essential.\n",
        "- Static analysis cannot reconstruct the development process; commits, tests and explanation remain essential.\n- Deliberately bounded project ingestion may exclude exceptionally large legitimate repositories; lower limits are configurable, while hard ceilings cannot be bypassed by payload metadata.\n",
        "README limit caveat",
    )
    write_if_changed(readme_path, readme)

    schema_path = root / "docs" / "03-report-schema.md"
    schema = schema_path.read_text(encoding="utf-8")
    schema = replace_once(
        schema,
        '''    "common_root_reason": "single common non-source top-level directory; treated as hosted/export ZIP wrapper"\n  },\n''',
        '''    "common_root_reason": "single common non-source top-level directory; treated as hosted/export ZIP wrapper",\n    "limits": {\n      "max_files": 300,\n      "max_file_bytes": 1000000,\n      "max_total_bytes": 25000000,\n      "max_archive_bytes": 25000000,\n      "max_input_entries": 2000,\n      "max_compression_ratio": 100.0\n    }\n  },\n''',
        "report input limits",
    )
    schema = replace_once(
        schema,
        "The project aggregate is only as meaningful as its inclusion/exclusion record.",
        "The `input_packaging.limits` object records the validated resource boundary used for the run. The project aggregate is only as meaningful as its inclusion/exclusion record.",
        "report limit explanation",
    )
    write_if_changed(schema_path, schema)

    changelog_path = root / "CHANGELOG.md"
    changelog = changelog_path.read_text(encoding="utf-8")
    marker = "### Fixed\n\n"
    insertion = (
        "### Fixed\n\n"
        "- Bound folder and ZIP project ingestion before content reads: reject redirects and special files, verify stable regular-file identity, preflight classic ZIP metadata, cap compressed and uncompressed resources and avoid decompression for ignored or ineligible members.\n"
    )
    changelog = replace_once(changelog, marker, insertion, "changelog Phase 1 entry")
    write_if_changed(changelog_path, changelog)


def update_browser_integrity(root: Path) -> None:
    app = root / "app"
    manifest_path = app / "resource-integrity.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["assets"]:
        target = (app / item["path"]).resolve()
        content = target.read_bytes()
        digest = hashlib.sha256(content).digest()
        item["size_bytes"] = len(content)
        item["sha256_hex"] = digest.hex()
        item["sri_sha256"] = "sha256-" + base64.b64encode(digest).decode("ascii")
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

    sri = {item["path"]: item["sri_sha256"] for item in manifest["assets"]}
    replacements = {
        app / "index.html": ("codeprobe-ui.js", sri["codeprobe-ui.js"]),
        app / "project.html": ("project-ui.js", sri["project-ui.js"]),
    }
    for html_path, (asset, value) in replacements.items():
        text = html_path.read_text(encoding="utf-8")
        pattern = re.compile(rf'(<script src="{re.escape(asset)}" defer integrity=")[^"]+("[^>]*></script>)')
        text, count = pattern.subn(rf"\g<1>{value}\g<2>", text, count=1)
        if count != 1:
            raise RuntimeError(f"could not refresh HTML SRI for {asset}")
        write_if_changed(html_path, text)


def apply(root: Path) -> None:
    root = root.resolve()
    patch_runtime(root)
    patch_project_io(root)
    patch_analyse_cli(root)
    patch_calibration(root)
    patch_main_ui(root)
    patch_project_ui(root)
    patch_tests(root)
    patch_docs(root)
    update_browser_integrity(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    apply(args.root)
