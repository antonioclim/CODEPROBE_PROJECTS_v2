"""Shared, bounded project-input helpers for CodeProbe command-line tools."""

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
DEFAULT_MAX_IGNORE_RULES = 1_000
READ_CHUNK_BYTES = 65_536


class ProjectInputError(ValueError):
    """Raised when a project source crosses a declared safety boundary."""


def stderr_warning(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _safe_text(value: object) -> str:
    return ascii(os.fspath(value) if isinstance(value, os.PathLike) else str(value))


def _bounded_positive_int(
    name: str,
    value: object,
    *,
    minimum: int = 1,
    maximum: int,
) -> int:
    if isinstance(value, bool):
        raise ProjectInputError(f"{name} must be an integer between {minimum} and {maximum}")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProjectInputError(
            f"{name} must be an integer between {minimum} and {maximum}"
        ) from exc
    if result < minimum or result > maximum:
        raise ProjectInputError(f"{name} must be between {minimum} and {maximum}")
    return result


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
    if isinstance(max_bytes, bool):
        raise ProjectInputError("max_bytes must be a non-negative integer")
    try:
        max_bytes = int(max_bytes)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProjectInputError(
            "max_bytes must be a non-negative integer"
        ) from exc
    if max_bytes < 0:
        raise ProjectInputError("max_bytes must be a non-negative integer")
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
    max_entries = _bounded_positive_int(
        "max_entries", max_entries, maximum=20_000
    )
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise ProjectInputError(
            f"cannot inspect project root: {_safe_text(exc)}"
        ) from exc
    if stat.S_ISLNK(root_metadata.st_mode) or _is_reparse_point(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ProjectInputError("project root must be a real directory")
    built_in = engine.parse_ignore_patterns(engine.default_project_ignore_text())
    pending = [root]
    captured: list[tuple[Path, os.stat_result]] = []
    seen_physical_entries: dict[tuple[int, int], str] = {}
    root_inode = int(getattr(root_metadata, "st_ino", 0) or 0)
    if root_inode:
        seen_physical_entries[(int(getattr(root_metadata, "st_dev", 0) or 0), root_inode)] = "."
    observed_entries = 0
    while pending:
        directory = pending.pop()
        _inspect_no_redirects(directory, root, final_directory=True) if directory != root else None
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    observed_entries += 1
                    if observed_entries > max_entries:
                        raise ProjectInputError(
                            f"project inventory exceeds the {max_entries}-entry limit"
                        )
                    entries.append(entry)
        except ProjectInputError:
            raise
        except OSError as exc:
            raise ProjectInputError(f"cannot enumerate project directory {_safe_text(directory)}: {_safe_text(exc)}") from exc
        entries.sort(key=lambda item: item.name.casefold())
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
            inode = int(getattr(metadata, "st_ino", 0) or 0)
            if inode:
                physical_key = (int(getattr(metadata, "st_dev", 0) or 0), inode)
                previous = seen_physical_entries.get(physical_key)
                if previous is not None:
                    raise ProjectInputError(
                        "hard-linked duplicate project entries are forbidden: "
                        f"{_safe_text(relative)} aliases {_safe_text(previous)}"
                    )
                seen_physical_entries[physical_key] = relative
            if stat.S_ISDIR(metadata.st_mode):
                if not _directory_is_builtin_ignored(relative, built_in):
                    child_directories.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ProjectInputError(f"special filesystem entry is forbidden in project input: {_safe_text(relative)}")
            captured.append((path, metadata))
        pending.extend(reversed(child_directories))
    return sorted(
        captured,
        key=lambda item: item[0].relative_to(root).as_posix().casefold(),
    )


def list_bounded_regular_files(
    root: Path,
    *,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> List[Path]:
    """List safe regular files below ``root`` without following redirects."""
    return [
        path
        for path, _metadata in _walk_metadata(root, max_entries=max_entries)
    ]


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
    max_ignore_rules: int = DEFAULT_MAX_IGNORE_RULES,
) -> List[Dict[str, Any]]:
    """Return a bounded payload for a folder without following redirects."""
    max_file_bytes = _bounded_positive_int(
        "max_file_bytes", max_file_bytes, maximum=16_000_000
    )
    max_total_bytes = _bounded_positive_int(
        "max_total_bytes", max_total_bytes, maximum=256_000_000
    )
    max_entries = _bounded_positive_int(
        "max_entries", max_entries, maximum=20_000
    )
    max_files = _bounded_positive_int(
        "max_files", max_files, maximum=10_000
    )
    max_ignore_bytes = _bounded_positive_int(
        "max_ignore_bytes", max_ignore_bytes, maximum=1_000_000
    )
    max_ignore_rules = _bounded_positive_int(
        "max_ignore_rules", max_ignore_rules, maximum=10_000
    )
    root = _absolute(root)
    metadata_entries = _walk_metadata(root, max_entries=max_entries)
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
    rules = engine.parse_ignore_patterns(
        built_in_text + ("\n" + embedded_text if embedded_text else "")
    )
    if len(rules) > max_ignore_rules:
        raise ProjectInputError(
            f"active ignore rule count exceeds {max_ignore_rules}"
        )

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
        remaining = max_total_bytes - total_read
        if remaining <= 0 or metadata.st_size > remaining:
            if include_binary_placeholders:
                files.append(
                    {"path": relative, "content": "", "size_bytes": metadata.st_size}
                )
            if warning_sink:
                warning_sink(
                    f"{relative}: skipped because the folder read budget is "
                    f"{max_total_bytes} bytes"
                )
            continue
        data = read_bounded_regular_file(
            path,
            root=root,
            max_bytes=min(max_file_bytes, remaining),
        )
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
    max_ignore_bytes: int = DEFAULT_MAX_IGNORE_BYTES,
    max_ignore_rules: int = DEFAULT_MAX_IGNORE_RULES,
) -> Dict[str, Any]:
    """Build a bounded engine payload from a folder or ZIP archive."""
    max_file_bytes = _bounded_positive_int(
        "max_file_bytes", max_file_bytes, maximum=16_000_000
    )
    max_total_bytes = _bounded_positive_int(
        "max_total_bytes", max_total_bytes, maximum=256_000_000
    )
    max_entries = _bounded_positive_int(
        "max_entries", max_entries, maximum=20_000
    )
    max_files = _bounded_positive_int(
        "max_files", max_files, maximum=10_000
    )
    max_archive_bytes = _bounded_positive_int(
        "max_archive_bytes", max_archive_bytes, maximum=64_000_000
    )
    max_ignore_bytes = _bounded_positive_int(
        "max_ignore_bytes", max_ignore_bytes, maximum=1_000_000
    )
    max_ignore_rules = _bounded_positive_int(
        "max_ignore_rules", max_ignore_rules, maximum=10_000
    )
    path = _absolute(path)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProjectInputError(f"project sample is unavailable: {_safe_text(path)}: {_safe_text(exc)}") from exc
    common = {
        "max_file_bytes": max_file_bytes,
        "max_total_bytes": max_total_bytes,
        "max_zip_entries": max_entries,
        "max_files": max_files,
        "max_zip_bytes": max_archive_bytes,
        "max_ignore_bytes": max_ignore_bytes,
        "max_ignore_rules": max_ignore_rules,
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
                max_ignore_bytes=max_ignore_bytes,
                max_ignore_rules=max_ignore_rules,
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
