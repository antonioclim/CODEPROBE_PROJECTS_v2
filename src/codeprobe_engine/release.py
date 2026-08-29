"""Release-boundary, manifest and package-audit helpers for CodeProbe."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence

MANIFEST_NAME = "release/release-manifest.json"
MANIFEST_SCHEMA = "codeprobe-release-manifest/v1"
APP_NAME = "CodeProbe"
EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"}
EXCLUDED_DIRS_CASEFOLD = {value.casefold() for value in EXCLUDED_DIRS}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
SHA256_LENGTH = 64
TOP_LEVEL_FIELDS = {
    "schema_version",
    "app_name",
    "app_version",
    "file_count",
    "total_source_size_bytes",
    "files",
    "manifest_sha256",
}
FILE_FIELDS = {"path", "size_bytes", "sha256"}


class ReleaseSetError(ValueError):
    """Raised when the source tree is not a safe, regular-file release set."""


class ManifestError(ValueError):
    """Raised when committed release evidence does not verify exactly."""


def _safe_text(value: object) -> str:
    """Render untrusted filesystem or JSON text without terminal-unsafe code points."""
    text = os.fspath(value) if isinstance(value, (Path, os.PathLike)) else str(value)
    return ascii(text)[1:-1]


@dataclass(frozen=True)
class ReleaseSnapshotEntry:
    """An immutable release member captured after strict manifest verification."""

    path: str
    content: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(read_regular_file(path))


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Replace ``path`` with ``content`` without exposing a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, previous_mode)
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def atomic_write_text(path: Path, content: str) -> None:
    """UTF-8 text variant of :func:`atomic_write_bytes`."""
    atomic_write_bytes(path, content.encode("utf-8"))


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _relative_parts_below_root(path: Path, root: Path) -> tuple[str, ...]:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ReleaseSetError(f"release file path is outside its root: {_safe_text(path)}") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ReleaseSetError(f"release file path is not canonical below its root: {_safe_text(path)}")
    return relative.parts


def _validate_no_symlink_ancestry(path: Path, root: Path | None) -> os.stat_result:
    if root is not None:
        root = root.resolve()
        parts = _relative_parts_below_root(path, root)
        current = root
        for part in parts[:-1]:
            current /= part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise ReleaseSetError(f"cannot inspect release path {_safe_text(current)}: {_safe_text(exc)}") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ReleaseSetError(f"unsafe release path ancestor: {_safe_text(current)}")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseSetError(f"cannot inspect release file {_safe_text(path)}: {_safe_text(exc)}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseSetError(f"release entry is not a regular file: {_safe_text(path)}")
    return metadata


def _open_regular_for_read(path: Path, root: Path | None) -> int:
    file_flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        file_flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        file_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    if (
        root is None
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        return os.open(path, file_flags)

    root = root.resolve()
    relative_parts = _relative_parts_below_root(path, root)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    directory_descriptor = os.open(root, directory_flags)
    try:
        for part in relative_parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(relative_parts[-1], file_flags, dir_fd=directory_descriptor)
    finally:
        os.close(directory_descriptor)


def read_regular_file(path: Path, *, root: Path | None = None) -> bytes:
    """Read one regular file without following a final symlink.

    Metadata is checked before and after the read. This turns a concurrent source
    mutation into a controlled validation failure rather than a mixed snapshot.
    """
    path_before = _validate_no_symlink_ancestry(path, root)
    try:
        descriptor = _open_regular_for_read(path, root)
    except OSError as exc:
        raise ReleaseSetError(f"unsafe or unreadable release file: {_safe_text(path)}: {_safe_text(exc)}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseSetError(f"release entry is not a regular file: {_safe_text(path)}")
        _validate_no_symlink_ancestry(path, root)
        if (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino):
            raise ReleaseSetError(f"release file changed before read: {_safe_text(path)}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except ReleaseSetError:
        raise
    except OSError as exc:
        raise ReleaseSetError(f"I/O failure while reading release file {_safe_text(path)}: {_safe_text(exc)}") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    try:
        path_after = _validate_no_symlink_ancestry(path, root)
    except ReleaseSetError as exc:
        raise ReleaseSetError(f"release file changed during read: {_safe_text(path)}: {_safe_text(exc)}") from exc
    if _stat_identity(before) != _stat_identity(after) or (
        path_after.st_dev,
        path_after.st_ino,
    ) != (after.st_dev, after.st_ino):
        raise ReleaseSetError(f"release file changed during read: {_safe_text(path)}")
    return b"".join(chunks)


def _walk_release_files(root: Path, directory: Path) -> Iterable[Path]:
    pending = [directory]
    directory_snapshots: list[tuple[Path, os.stat_result]] = []
    files: list[Path] = []
    while pending:
        current = pending.pop()
        try:
            directory_before = current.lstat()
            if stat.S_ISLNK(directory_before.st_mode) or not stat.S_ISDIR(directory_before.st_mode):
                raise ReleaseSetError(
                    "release directory changed to an unsafe entry: "
                    f"{_safe_text(current.relative_to(root).as_posix() or '.')}"
                )
            entries = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError as exc:
            raise ReleaseSetError(
                f"cannot enumerate release directory {_safe_text(current)}: {_safe_text(exc)}"
            ) from exc
        directory_snapshots.append((current, directory_before))
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root)
            if entry.name.casefold() in EXCLUDED_DIRS_CASEFOLD or path.suffix.lower() in EXCLUDED_SUFFIXES:
                continue
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReleaseSetError(
                    f"cannot inspect release entry {_safe_text(relative.as_posix())}: {_safe_text(exc)}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ReleaseSetError(
                    f"symbolic links are forbidden in the release set: {_safe_text(relative.as_posix())}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                child_directories.append(path)
            elif not stat.S_ISREG(metadata.st_mode):
                raise ReleaseSetError(
                    f"non-regular release entry is forbidden: {_safe_text(relative.as_posix())}"
                )
            elif relative.as_posix() != MANIFEST_NAME:
                files.append(path)
        pending.extend(reversed(child_directories))

    for current, directory_before in reversed(directory_snapshots):
        try:
            directory_after = current.lstat()
        except OSError as exc:
            raise ReleaseSetError(
                f"release directory changed during enumeration: {_safe_text(current)}: {_safe_text(exc)}"
            ) from exc
        if (
            not stat.S_ISDIR(directory_after.st_mode)
            or _stat_identity(directory_before) != _stat_identity(directory_after)
        ):
            raise ReleaseSetError(
                "release directory changed during enumeration: "
                f"{_safe_text(current.relative_to(root).as_posix() or '.')}"
            )
    yield from files


def iter_release_files(root: Path) -> Iterable[Path]:
    """Yield safe regular release files, excluding evidence self-reference.

    Excluded cache and build directories are not traversed. Any symbolic link or
    special file elsewhere in the release set is rejected explicitly.
    """
    root = root.resolve()
    try:
        metadata = root.stat()
    except OSError as exc:
        raise ReleaseSetError(f"release root is unavailable: {_safe_text(exc)}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseSetError(f"release root is not a directory: {_safe_text(root)}")
    paths = sorted(tuple(_walk_release_files(root, root)), key=lambda path: path.relative_to(root).as_posix())
    portable_keys: dict[str, str] = {_portable_path_key(MANIFEST_NAME): MANIFEST_NAME}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        path_problem = _path_error(relative)
        if path_problem:
            raise ReleaseSetError(f"unsafe release path {_safe_text(relative)!r}: {path_problem}")
        portable_key = _portable_path_key(relative)
        if portable_key in portable_keys:
            raise ReleaseSetError(
                "release paths collide on a portable filesystem: "
                f"{_safe_text(portable_keys[portable_key])!r} and {_safe_text(relative)!r}"
            )
        portable_keys[portable_key] = relative
    yield from paths


def validate_release_set(root: Path) -> tuple[Path, ...]:
    """Return the complete safe release membership, including the manifest."""
    root = root.resolve()
    files = tuple(iter_release_files(root))
    manifest_path = root / MANIFEST_NAME
    try:
        manifest_metadata = manifest_path.lstat()
    except FileNotFoundError as exc:
        raise ReleaseSetError(f"required release manifest is missing: {MANIFEST_NAME}") from exc
    except OSError as exc:
        raise ReleaseSetError(f"cannot inspect {MANIFEST_NAME}: {exc}") from exc
    if stat.S_ISLNK(manifest_metadata.st_mode):
        raise ReleaseSetError(f"symbolic links are forbidden in the release set: {MANIFEST_NAME}")
    if not stat.S_ISREG(manifest_metadata.st_mode):
        raise ReleaseSetError(f"release manifest is not a regular file: {MANIFEST_NAME}")
    return files + (manifest_path,)


def build_release_manifest(
    root: Path,
    *,
    app_version: str,
    schema_version: str = MANIFEST_SCHEMA,
) -> Dict[str, Any]:
    """Create a deterministic manifest from stable regular-file snapshots."""
    if schema_version != MANIFEST_SCHEMA:
        raise ValueError(f"schema_version must be {MANIFEST_SCHEMA!r}")
    root = root.resolve()
    files: List[Dict[str, Any]] = []
    for path in iter_release_files(root):
        relative = path.relative_to(root).as_posix()
        content = read_regular_file(path, root=root)
        files.append({"path": relative, "size_bytes": len(content), "sha256": sha256_bytes(content)})
    captured_paths = tuple(item["path"] for item in files)
    current_files = tuple(iter_release_files(root))
    current_paths = tuple(path.relative_to(root).as_posix() for path in current_files)
    if current_paths != captured_paths:
        raise ReleaseSetError("release membership changed while the manifest snapshot was captured")
    current_by_path = {path.relative_to(root).as_posix(): path for path in current_files}
    for item in files:
        content = read_regular_file(current_by_path[item["path"]], root=root)
        if len(content) != item["size_bytes"] or sha256_bytes(content) != item["sha256"]:
            raise ReleaseSetError(
                f"release file changed while the manifest snapshot was captured: {_safe_text(item['path'])}"
            )
    total_size = sum(item["size_bytes"] for item in files)
    payload: Dict[str, Any] = {
        "schema_version": schema_version,
        "app_name": APP_NAME,
        "app_version": app_version,
        "file_count": len(files),
        "total_source_size_bytes": total_size,
        "files": files,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["manifest_sha256"] = sha256_bytes(canonical)
    return payload


def write_release_manifest(root: Path, output: Path, *, app_version: str) -> Dict[str, Any]:
    manifest = build_release_manifest(root, app_version=app_version)
    atomic_write_text(output, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return manifest


def write_manifest(root: Path, app_version: Optional[str] = None) -> Path:
    """Write ``release/release-manifest.json`` in ``root`` and return its path."""
    if app_version is None:
        import codeprobe_runtime

        app_version = codeprobe_runtime.APP_VERSION
    output = root / MANIFEST_NAME
    output.parent.mkdir(parents=True, exist_ok=True)
    write_release_manifest(root, output, app_version=app_version)
    return output


def zip_summary(zip_path: Path) -> Dict[str, Any]:
    """Return package-level size and member accounting for a release ZIP."""
    zip_path = zip_path.resolve()
    members: List[Dict[str, Any]] = []
    with zipfile.ZipFile(zip_path, "r") as archive:
        for info in sorted((item for item in archive.infolist() if not item.is_dir()), key=lambda item: item.filename):
            members.append({
                "path": info.filename,
                "size_bytes": info.file_size,
                "compressed_size_bytes": info.compress_size,
                "crc32": f"{info.CRC:08x}",
            })
    uncompressed = sum(item["size_bytes"] for item in members)
    compressed_members = sum(item["compressed_size_bytes"] for item in members)
    zip_size = zip_path.stat().st_size
    return {
        "schema_version": "codeprobe-zip-package-audit/v1",
        "zip_name": zip_path.name,
        "zip_size_bytes": zip_size,
        "zip_sha256": sha256_file(zip_path),
        "file_count": len(members),
        "total_uncompressed_member_bytes": uncompressed,
        "total_compressed_member_bytes": compressed_members,
        "zip_container_overhead_bytes": zip_size - compressed_members,
        "compression_ratio": round((compressed_members / uncompressed), 6) if uncompressed else None,
        "members": members,
    }


def write_zip_summary(zip_path: Path, output: Path) -> Dict[str, Any]:
    """Write a JSON package audit sidecar for a release ZIP."""
    summary = zip_summary(zip_path)
    output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return summary


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {_safe_text(key)!r}")
        result[key] = value
    return result


def _canonical_manifest_hash(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_bytes(canonical)


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA256_LENGTH and all(character in "0123456789abcdef" for character in value)


def _path_error(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return "path must be a non-empty string"
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return "path contains a control character"
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return "path is not valid UTF-8"
    if value != unicodedata.normalize("NFC", value):
        return "path is not Unicode NFC-normalised"
    if "\\" in value:
        return "path must use POSIX separators"
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        return "path is not a canonical relative POSIX path"
    if any(part.casefold() in EXCLUDED_DIRS_CASEFOLD for part in path.parts) or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return "path names an excluded release location"
    if value == MANIFEST_NAME:
        return "manifest must not list itself"
    forbidden = set('<>:"|?*')
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{index}" for index in range(1, 10)), *(f"LPT{index}" for index in range(1, 10))}
    for part in path.parts:
        if any(character in forbidden for character in part):
            return "path contains a character forbidden on a supported extraction platform"
        if part.endswith((".", " ")):
            return "path component ends with a dot or space"
        if len(part.encode("utf-8")) > 255:
            return "path component exceeds the portable 255-byte limit"
        if part.split(".", 1)[0].upper() in reserved:
            return "path uses a reserved device name"
    return None


def _portable_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _parse_manifest(content: bytes, *, app_version: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, [f"{MANIFEST_NAME} is not valid UTF-8: {_safe_text(exc)}"]
    try:
        manifest = json.loads(text, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        return None, [f"{MANIFEST_NAME} is not valid unambiguous JSON: {_safe_text(exc)}"]
    if not isinstance(manifest, dict):
        return None, [f"{MANIFEST_NAME} top level must be an object"]

    errors: list[str] = []
    fields = set(manifest)
    if fields != TOP_LEVEL_FIELDS:
        missing = sorted(TOP_LEVEL_FIELDS - fields)
        extra = sorted(fields - TOP_LEVEL_FIELDS)
        if missing:
            errors.append(f"manifest fields missing: {', '.join(_safe_text(value) for value in missing)}")
        if extra:
            errors.append(f"unexpected manifest fields: {', '.join(_safe_text(value) for value in extra)}")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        errors.append(f"manifest schema_version must be {MANIFEST_SCHEMA!r}")
    if manifest.get("app_name") != APP_NAME:
        errors.append(f"manifest app_name must be {APP_NAME!r}")
    if manifest.get("app_version") != app_version:
        errors.append(f"manifest app_version must be {app_version!r}")
    if type(manifest.get("file_count")) is not int or manifest.get("file_count", -1) < 0:
        errors.append("manifest file_count must be a non-negative integer")
    if type(manifest.get("total_source_size_bytes")) is not int or manifest.get("total_source_size_bytes", -1) < 0:
        errors.append("manifest total_source_size_bytes must be a non-negative integer")
    if not _valid_sha256(manifest.get("manifest_sha256")):
        errors.append("manifest_sha256 must be a lower-case SHA-256 digest")
    else:
        try:
            canonical_hash = _canonical_manifest_hash(manifest)
        except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
            errors.append(f"manifest payload cannot be canonicalised as UTF-8 JSON: {_safe_text(exc)}")
        else:
            if manifest["manifest_sha256"] != canonical_hash:
                errors.append("manifest_sha256 does not match the canonical manifest payload")

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        errors.append("manifest files must be an array")
        return manifest, errors
    seen: set[str] = set()
    portable_paths: dict[str, str] = {_portable_path_key(MANIFEST_NAME): MANIFEST_NAME}
    previous: str | None = None
    total_size = 0
    for index, item in enumerate(raw_files):
        prefix = f"manifest files[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        fields = set(item)
        if fields != FILE_FIELDS:
            errors.append(f"{prefix} must contain exactly path, size_bytes and sha256")
        relative = item.get("path")
        path_problem = _path_error(relative)
        if path_problem:
            errors.append(f"{prefix} {path_problem}")
        elif relative in seen:
            errors.append(f"duplicate manifest path: {_safe_text(relative)}")
        elif previous is not None and relative <= previous:
            errors.append(f"manifest paths are not in strict lexical order at: {_safe_text(relative)}")
        else:
            portable_key = _portable_path_key(relative)
            if portable_key in portable_paths:
                errors.append(
                    "manifest paths collide on a portable filesystem: "
                    f"{_safe_text(portable_paths[portable_key])} and {_safe_text(relative)}"
                )
            portable_paths[portable_key] = relative
            seen.add(relative)
            previous = relative
        size = item.get("size_bytes")
        if type(size) is not int or size < 0:
            errors.append(f"{prefix} size_bytes must be a non-negative integer")
        else:
            total_size += size
        if not _valid_sha256(item.get("sha256")):
            errors.append(f"{prefix} sha256 must be a lower-case SHA-256 digest")
    if type(manifest.get("file_count")) is int and manifest["file_count"] != len(raw_files):
        errors.append("manifest file_count does not equal the files array length")
    if type(manifest.get("total_source_size_bytes")) is int and manifest["total_source_size_bytes"] != total_size:
        errors.append("manifest total_source_size_bytes does not equal the sum of file sizes")
    return manifest, errors


def _validated_snapshot(root: Path, *, app_version: str) -> tuple[tuple[ReleaseSnapshotEntry, ...], list[str]]:
    root = root.resolve()
    try:
        release_paths = validate_release_set(root)
        manifest_path = root / MANIFEST_NAME
        manifest_content = read_regular_file(manifest_path, root=root)
    except ReleaseSetError as exc:
        return (), [str(exc)]
    manifest, errors = _parse_manifest(manifest_content, app_version=app_version)
    if manifest is None or errors:
        return (), errors

    assert isinstance(manifest.get("files"), list)
    current = {path.relative_to(root).as_posix(): path for path in release_paths if path != manifest_path}
    recorded_items = manifest["files"]
    recorded = {item["path"]: item for item in recorded_items}
    for relative in sorted(set(recorded) - set(current)):
        errors.append(f"recorded file missing from current release set: {_safe_text(relative)}")
    for relative in sorted(set(current) - set(recorded)):
        errors.append(f"current file missing from manifest: {_safe_text(relative)}")

    snapshots: list[ReleaseSnapshotEntry] = []
    for item in recorded_items:
        relative = item["path"]
        path = current.get(relative)
        if path is None:
            continue
        try:
            content = read_regular_file(path, root=root)
        except ReleaseSetError as exc:
            errors.append(str(exc))
            continue
        if len(content) != item["size_bytes"]:
            errors.append(f"size mismatch: {_safe_text(relative)}")
        if sha256_bytes(content) != item["sha256"]:
            errors.append(f"hash mismatch: {_safe_text(relative)}")
        snapshots.append(ReleaseSnapshotEntry(relative, content))

    try:
        membership_after = tuple(path.relative_to(root).as_posix() for path in iter_release_files(root))
    except ReleaseSetError as exc:
        errors.append(str(exc))
    else:
        if membership_after != tuple(sorted(current)):
            errors.append("release membership changed while the immutable snapshot was captured")
    if errors:
        return (), errors
    snapshots.append(ReleaseSnapshotEntry(MANIFEST_NAME, manifest_content))
    return tuple(snapshots), []


def verify_manifest(root: Path, *, app_version: str | None = None) -> List[str]:
    """Verify manifest metadata, membership, sizes and hashes exactly."""
    if app_version is None:
        import codeprobe_runtime

        app_version = codeprobe_runtime.APP_VERSION
    _, errors = _validated_snapshot(root, app_version=app_version)
    return errors


def read_verified_release_snapshot(root: Path, *, app_version: str) -> tuple[ReleaseSnapshotEntry, ...]:
    """Capture immutable package input after exact manifest verification."""
    snapshot, errors = _validated_snapshot(root, app_version=app_version)
    if errors:
        raise ManifestError("; ".join(errors))
    return snapshot
