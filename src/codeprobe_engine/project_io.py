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
MAX_DIRECTORY_DEPTH = 64


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
    try:
        result = engine.integer_value(value, name)
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


def _canonical_relative(path: Path, root: Path) -> str:
    """Return the engine's Unicode-NFC portable identity for a local path."""
    relative = path.relative_to(root).as_posix()
    if engine.project_path_is_unsafe(relative):
        raise ProjectInputError(f"project path is unsafe: {_safe_text(relative)}")
    canonical = engine.normalise_project_path(relative)
    if not canonical or canonical == "fragment.txt" and relative not in {"fragment.txt", "./fragment.txt"}:
        raise ProjectInputError(f"project path is not canonical: {_safe_text(relative)}")
    return canonical


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
    # A replacement by a FIFO must not block before fstat can reject it.
    # Platforms without this flag retain the checks, without that guarantee.
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return os.open(path, flags)


def read_bounded_regular_file(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    consumed_files: dict[Path, tuple[int, int, int, int, int]] | None = None,
) -> bytes:
    """Read one stable regular file without following links and with a hard cap."""
    try:
        max_bytes = engine.integer_value(max_bytes, "max_bytes")
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
            verified = os.fstat(verification)
            if not stat.S_ISREG(verified.st_mode):
                raise ProjectInputError(f"project entry is not a regular file: {_safe_text(path)}")
            if _identity(verified) != _identity(after_path):
                raise ProjectInputError(f"project file changed during read: {_safe_text(path)}")
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
    if consumed_files is not None:
        identity = _identity(after_path)
        if not identity[1]:
            raise ProjectInputError(f"physical input identity is unavailable: {_safe_text(path)}")
        previous = consumed_files.get(path)
        if previous is not None and previous != identity:
            raise ProjectInputError(f"project file changed between reads: {_safe_text(path)}")
        consumed_files[path] = identity
    return b"".join(chunks)


def _directory_is_ignored(relative: str, rules: list[engine.IgnoreRule]) -> bool:
    probe = relative.rstrip("/") + "/__codeprobe_inventory_probe__.py"
    # A filename rule such as *.py cannot establish that every descendant is
    # ignored: the same directory may contain assessed JavaScript or C files.
    return engine.project_path_is_ignored(probe, [rule for rule in rules if rule.directory_only])


def _negation_may_reinclude(relative: str, rules: list[engine.IgnoreRule]) -> bool:
    """Keep only subtrees compatible with a negation's fixed path prefix.

    A basename-only or leading-wildcard negation may genuinely match at any
    depth; the independent inventory and directory-depth limits still apply.
    This conservative test need not expand unrelated fixed-prefix subtrees.
    """
    prefix = relative.rstrip("/") + "/"
    for rule in rules:
        if not rule.negated:
            continue
        pattern = rule.pattern.replace("\\", "/").strip()
        if not rule.anchored and "/" not in pattern:
            return True
        wildcard_positions = [pattern.find(char) for char in "*?[" if char in pattern]
        if wildcard_positions:
            fixed = pattern[:min(wildcard_positions)]
            if not fixed or fixed.startswith(prefix) or prefix.startswith(fixed):
                return True
        elif pattern.startswith(prefix) or (rule.directory_only and
                (relative == pattern or prefix.startswith(pattern + "/"))):
            return True
    return False


def _walk_metadata(
    root: Path,
    *,
    max_entries: int,
    root_rule_loader: Callable[[list[tuple[Path, os.stat_result]]], list[engine.IgnoreRule]] | None = None,
    unexpanded_directories: list[str] | None = None,
) -> list[tuple[Path, os.stat_result]]:
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
    rules = engine.parse_ignore_patterns(engine.default_project_ignore_text())
    pending = [root]
    captured: list[tuple[Path, os.stat_result]] = []
    seen_physical_entries: dict[tuple[int, int], str] = {}
    seen_portable_paths: dict[str, str] = {}
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
            raw_relative = path.relative_to(root).as_posix()
            relative = _canonical_relative(path, root)
            portable = relative.casefold()
            previous_path = seen_portable_paths.get(portable)
            if previous_path is not None:
                raise ProjectInputError(
                    "Unicode/case-equivalent project paths are forbidden: "
                    f"{_safe_text(raw_relative)} collides with {_safe_text(previous_path)}"
                )
            seen_portable_paths[portable] = raw_relative
            try:
                # DirEntry.stat() exposes zero identity fields on Windows.  A
                # fresh lstat supplies the file index needed to detect aliases.
                metadata = path.lstat()
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
                child_directories.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ProjectInputError(f"special filesystem entry is forbidden in project input: {_safe_text(relative)}")
            captured.append((path, metadata))
        # Validate every root identity before a root control file can influence
        # traversal. Root aliases therefore cannot acquire transient authority.
        if directory == root and root_rule_loader is not None:
            rules = root_rule_loader(captured)
        for child in reversed(child_directories):
            relative = _canonical_relative(child, root)
            if _directory_is_ignored(relative, rules) and not _negation_may_reinclude(relative, rules):
                if unexpanded_directories is not None:
                    unexpanded_directories.append(relative)
                continue
            if len(child.relative_to(root).parts) > MAX_DIRECTORY_DEPTH:
                raise ProjectInputError(
                    f"project directory depth exceeds {MAX_DIRECTORY_DEPTH}: {_safe_text(relative)}"
                )
            pending.append(child)
    return sorted(
        captured,
        key=lambda item: _canonical_relative(item[0], root).casefold(),
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


def _decoding_provenance(data: bytes, warning: str) -> dict[str, Any]:
    return {
        "encoding": "latin-1" if warning else ("utf-8-sig" if data.startswith(b"\xef\xbb\xbf") else "utf-8"),
        "normalisation": "none",
        "warnings": [warning] if warning else [],
    }


def read_folder_files(
    root: Path,
    *,
    include_binary_placeholders: bool = True,
    warning_sink: WarningSink = None,
    consumed_files: dict[Path, tuple[int, int, int, int, int]] | None = None,
    max_file_bytes: int = engine.PROJECT_MAX_FILE_BYTES_DEFAULT,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_files: int = engine.PROJECT_MAX_FILES_DEFAULT,
    max_ignore_bytes: int = DEFAULT_MAX_IGNORE_BYTES,
    max_ignore_rules: int = DEFAULT_MAX_IGNORE_RULES,
    ignore_text: str = "",
    include_documentation: bool = False,
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
    if not isinstance(ignore_text, str) or len(ignore_text.encode("utf-8")) > max_ignore_bytes:
        raise ProjectInputError(f"ignore_text must be text within the {max_ignore_bytes}-byte limit")
    if type(include_documentation) is not bool:
        raise ProjectInputError("include_documentation must be a boolean")
    root = _absolute(root)
    reader_options = {"consumed_files": consumed_files} if consumed_files is not None else {}
    built_in_text = engine.default_project_ignore_text()
    embedded_text = ""
    embedded_provenance = None

    def load_root_rules(entries: list[tuple[Path, os.stat_result]]) -> list[engine.IgnoreRule]:
        nonlocal embedded_text, embedded_provenance
        ignore_entry = next(
            ((path, metadata) for path, metadata in entries
             if _canonical_relative(path, root) == ".codeprobeignore"), None,
        )
        if ignore_entry is not None:
            ignore_path, ignore_metadata = ignore_entry
            if ignore_metadata.st_size > max_ignore_bytes:
                raise ProjectInputError(f".codeprobeignore exceeds the {max_ignore_bytes}-byte limit")
            embedded_bytes = read_bounded_regular_file(
                ignore_path, root=root, max_bytes=max_ignore_bytes, **reader_options,
            )
            embedded_text, warning = engine.decode_text_bytes(embedded_bytes)
            if embedded_text is None:
                raise ProjectInputError(f".codeprobeignore is not readable text: {warning}")
            embedded_provenance = _decoding_provenance(embedded_bytes, warning)
        rules = engine.parse_ignore_patterns(
            built_in_text + "\n" + embedded_text + "\n" + ignore_text
        )
        if len(rules) > max_ignore_rules:
            raise ProjectInputError(f"active ignore rule count exceeds {max_ignore_rules}")
        return rules

    unexpanded: list[str] = []
    metadata_entries = _walk_metadata(
        root, max_entries=max_entries, root_rule_loader=load_root_rules,
        unexpanded_directories=unexpanded,
    )
    rules = engine.parse_ignore_patterns(built_in_text + "\n" + embedded_text + "\n" + ignore_text)

    files = engine._NativeProjectFiles(unexpanded_directories=sorted(unexpanded))
    total_read = 0
    analysable_seen = 0
    metadata_limits = {"max_file_bytes": max_file_bytes, "max_ignore_bytes": max_ignore_bytes,
                       "max_compression_ratio": 1000.0}
    for path, metadata in metadata_entries:
        relative = _canonical_relative(path, root)
        if relative == ".codeprobeignore":
            files.append(engine._NativeProjectFile(
                path=relative, content=embedded_text, size_bytes=metadata.st_size,
                intake_provenance=embedded_provenance,
            ))
            continue
        reason, detail = engine._candidate_reason_for_metadata(
            relative, size_bytes=metadata.st_size, compressed_size=metadata.st_size,
            limits=metadata_limits, include_documentation=include_documentation,
        )
        if not reason and relative.rsplit("/", 1)[-1] == ".codeprobeignore":
            reason, detail = "nested_ignore_file", "Only the project-root .codeprobeignore controls the project."
        if not reason and engine.project_path_is_ignored(relative, rules):
            reason, detail = "ignored_by_codeprobeignore", "Matched built-in, project-root or explicit ignore rules."
        if not reason and analysable_seen >= max_files:
            reason, detail = "project_file_limit", f"Maximum analysed file count is {max_files}."
        remaining = max_total_bytes - total_read
        if not reason and metadata.st_size > remaining:
            reason, detail = "project_total_byte_limit", f"Reading this file would exceed the {max_total_bytes}-byte folder budget."
            if warning_sink:
                warning_sink(f"{relative}: {detail}")
        if reason:
            if include_binary_placeholders:
                files.append(engine._NativeProjectFile(
                    path=relative, content="", size_bytes=metadata.st_size,
                    pre_exclusion_reason=reason, pre_exclusion_detail=detail,
                ))
            continue
        data = read_bounded_regular_file(
            path,
            root=root,
            max_bytes=min(max_file_bytes, remaining),
            **reader_options,
        )
        total_read += len(data)
        text, warning = engine.decode_text_bytes(data)
        provenance = _decoding_provenance(data, warning) if text is not None else None
        if text is None:
            reason, detail = "undecodable_text", warning
        else:
            reason = engine.project_exclusion_reason(relative, text, include_documentation) or ""
            detail = "Excluded after a bounded content read and before consuming an analysed-file slot." if reason else ""
        if warning and warning_sink:
            warning_sink(f"{relative}: {warning}")
        if not reason:
            analysable_seen += 1
        if not reason or include_binary_placeholders:
            files.append(engine._NativeProjectFile(
                path=relative, content="" if reason else text, size_bytes=len(data),
                pre_exclusion_reason=reason, pre_exclusion_detail=detail,
                intake_provenance=provenance,
            ))
    return files


def project_payload_from_path(
    path: Path,
    *,
    include_binary_placeholders: bool = True,
    consumed_files: dict[Path, tuple[int, int, int, int, int]] | None = None,
    max_file_bytes: int = engine.PROJECT_MAX_FILE_BYTES_DEFAULT,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_files: int = engine.PROJECT_MAX_FILES_DEFAULT,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_ignore_bytes: int = DEFAULT_MAX_IGNORE_BYTES,
    max_ignore_rules: int = DEFAULT_MAX_IGNORE_RULES,
    ignore_text: str = "",
    include_documentation: bool = False,
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
    if not isinstance(ignore_text, str) or len(ignore_text.encode("utf-8")) > max_ignore_bytes:
        raise ProjectInputError(f"ignore_text must be text within the {max_ignore_bytes}-byte limit")
    if type(include_documentation) is not bool:
        raise ProjectInputError("include_documentation must be a boolean")
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
        "ignore_text": ignore_text,
        "include_documentation": include_documentation,
    }
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        raise ProjectInputError("project sample must not be a link or reparse point")
    if stat.S_ISDIR(metadata.st_mode):
        return {
            "project_name": path.name,
            "files": read_folder_files(
                path,
                include_binary_placeholders=include_binary_placeholders,
                consumed_files=consumed_files,
                max_file_bytes=max_file_bytes,
                max_total_bytes=max_total_bytes,
                max_entries=max_entries,
                max_files=max_files,
                max_ignore_bytes=max_ignore_bytes,
                max_ignore_rules=max_ignore_rules,
                ignore_text=ignore_text,
                include_documentation=include_documentation,
            ),
            **common,
        }
    if stat.S_ISREG(metadata.st_mode) and path.suffix.lower() == ".zip":
        archive = read_bounded_regular_file(
            path, root=path.parent, max_bytes=max_archive_bytes,
            consumed_files=consumed_files,
        )
        return {
            "project_name": path.stem,
            "zip_base64": base64.b64encode(archive).decode("ascii"),
            **common,
        }
    raise ProjectInputError(f"project sample must be a directory or ZIP archive: {_safe_text(path)}")
