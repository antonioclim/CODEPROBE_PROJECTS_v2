#!/usr/bin/env python3
"""Validate, stage and publish a fixed-metadata CodeProbe release packet."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site
):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import errno
import json
import os
import re
import shutil
import socket
import stat
import tempfile
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))
if str(TOOLS) not in sys.path:
    sys.path.append(str(TOOLS))

import codeprobe_runtime as engine  # noqa: E402
import check_release  # noqa: E402
from codeprobe_engine.release import (  # noqa: E402
    ManifestError,
    ReleaseSetError,
    ReleaseSnapshotEntry,
    read_regular_file,
    read_regular_file_with_metadata,
    read_verified_release_snapshot,
    sha256_bytes,
    sha256_file,
    validate_release_set,
    zip_summary,
)

DETERMINISTIC_ZIP_DATETIME = (2020, 1, 1, 0, 0, 0)
PACKAGE_ROOT = f"CodeProbe_Project_Kit_v{engine.APP_VERSION}"
PORTABLE_ZIP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip\Z")
PORTABLE_MEMBER_ROOT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
PORTABLE_NAME_MAX_BYTES = 255
LOCK_SCHEMA = "codeprobe-release-publication-lock/v1"
JOURNAL_SCHEMA = "codeprobe-release-publication-journal/v1"
CONTROL_FILE_LIMIT_BYTES = 256 * 1024
TRANSACTION_STATES = frozenset({
    "prepared",
    "readiness_withdrawn",
    "zip_installed",
    "audit_installed",
    "checksum_installed",
    "committed",
    "rollback_started",
    "rollback_zip_restored",
    "rollback_audit_restored",
    "rollback_checksum_restored",
    "rolled_back",
})
TRANSACTION_ID_RE = re.compile(r"[0-9a-f]{32}\Z")


class PublicationError(RuntimeError):
    """Raised when a release packet cannot be published safely."""

    def __init__(self, message: str, *, recovery_path: Path | None = None) -> None:
        super().__init__(message)
        self.recovery_path = recovery_path


@dataclass(frozen=True)
class ReleaseTargets:
    zip_path: Path
    checksum_path: Path
    audit_path: Path

    def ordered_for_commit(self) -> tuple[Path, Path, Path]:
        # The checksum is the final readiness marker.
        return self.zip_path, self.audit_path, self.checksum_path

    def all(self) -> tuple[Path, Path, Path]:
        return self.zip_path, self.checksum_path, self.audit_path


@dataclass(frozen=True)
class PriorTarget:
    existed: bool
    backup_path: Path | None = None
    content: bytes | None = None
    mode: int | None = None
    mtime_ns: int | None = None
    fingerprint: tuple[int, int, int, int, int, str] | None = None


@dataclass(frozen=True)
class RecoveryResult:
    """Outcome of a deterministic recovery inspection."""

    status: str
    detail: str
    recovered: bool = False


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _reject_lexical_symlink(path: Path) -> None:
    metadata = _lstat_or_none(path)
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise PublicationError(f"release output must not be a symbolic link: {path}")


def _reject_in_checkout_symlink_components(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return
    current = root
    for part in relative.parts[:-1]:
        current /= part
        metadata = _lstat_or_none(current)
        if metadata is None:
            return
        if stat.S_ISLNK(metadata.st_mode):
            raise PublicationError(f"release output path traverses a symbolic link inside the checkout: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise PublicationError(f"release output parent component is not a directory: {current}")


def _plan_release_targets(
    lexical_root: Path,
    resolved_root: Path,
    requested_output: Path,
) -> ReleaseTargets:
    lexical_zip = _absolute_without_resolving(requested_output)
    try:
        checkout_relative_zip = lexical_zip.relative_to(lexical_root)
    except ValueError:
        bound_zip = lexical_zip
    else:
        bound_zip = resolved_root.joinpath(*checkout_relative_zip.parts)
    lexical_targets = (
        lexical_zip,
        lexical_zip.with_name(lexical_zip.name + ".sha256.txt"),
        lexical_zip.with_name(lexical_zip.name + ".package_audit.json"),
    )
    bound_targets = (
        bound_zip,
        bound_zip.with_name(bound_zip.name + ".sha256.txt"),
        bound_zip.with_name(bound_zip.name + ".package_audit.json"),
    )
    if not PORTABLE_ZIP_NAME.fullmatch(lexical_zip.name):
        raise PublicationError("release output must have a portable basename ending in .zip")
    for target in lexical_targets:
        if target.name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
            raise PublicationError(f"release output uses a reserved device name: {target.name}")
        if len(os.fsencode(target.name)) > PORTABLE_NAME_MAX_BYTES:
            raise PublicationError(f"release packet filename is too long for a portable filesystem: {target.name}")
    _reject_in_checkout_symlink_components(lexical_root, lexical_zip)
    _reject_in_checkout_symlink_components(resolved_root, bound_zip)
    for target in dict.fromkeys((*lexical_targets, *bound_targets)):
        _reject_lexical_symlink(target)

    output = bound_zip.resolve(strict=False)
    if not PORTABLE_ZIP_NAME.fullmatch(output.name):
        raise PublicationError("release output must have a portable basename ending in .zip")
    try:
        relative = output.relative_to(resolved_root)
    except ValueError:
        pass
    else:
        if not relative.parts or relative.parts[0] != "dist":
            raise PublicationError("release output inside the checkout must be under dist/")

    targets = ReleaseTargets(
        output,
        output.with_name(output.name + ".sha256.txt"),
        output.with_name(output.name + ".package_audit.json"),
    )
    if len(set(targets.all())) != 3:
        raise PublicationError("release packet target names must be distinct")
    for target in targets.all():
        if target.name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
            raise PublicationError(f"release output uses a reserved device name: {target.name}")
        if len(os.fsencode(target.name)) > PORTABLE_NAME_MAX_BYTES:
            raise PublicationError(f"release packet filename is too long for a portable filesystem: {target.name}")
    return targets


def plan_release_targets(root: Path, requested_output: Path) -> ReleaseTargets:
    """Resolve and validate the three public release names without writing."""
    lexical_root = _absolute_without_resolving(root)
    resolved_root = lexical_root.resolve()
    return _plan_release_targets(lexical_root, resolved_root, requested_output)


def _source_identities(root: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    for path in validate_release_set(root):
        metadata = path.lstat()
        identities.add((metadata.st_dev, metadata.st_ino))
    return identities


def _validate_destination_targets(targets: ReleaseTargets, root: Path) -> None:
    identities = _source_identities(root)
    for target in targets.all():
        metadata = _lstat_or_none(target)
        if metadata is None:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise PublicationError(f"release output must not be a symbolic link: {target}")
        if not stat.S_ISREG(metadata.st_mode):
            raise PublicationError(f"release output is not a regular file: {target}")
        if (metadata.st_dev, metadata.st_ino) in identities:
            raise PublicationError(f"release output aliases a source file: {target}")


def _write_bytes_fsynced(
    path: Path,
    content: bytes,
    *,
    mode: int = 0o644,
    times_ns: tuple[int, int] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, mode)
    if times_ns is not None:
        # This path was exclusively created in the private stage directory.
        os.utime(path, ns=times_ns)
    _fsync_file_metadata(path)


def _host_mode_matches(
    actual: int,
    expected: int,
    *,
    platform_name: str = os.name,
) -> bool:
    """Compare the host mode without claiming unsupported Windows POSIX bits."""
    if platform_name == "nt":
        return bool(actual & stat.S_IWRITE) == bool(expected & stat.S_IWRITE)
    return actual == expected


def _fsync_file_metadata(path: Path) -> None:
    """Persist post-write metadata where the host provides that guarantee."""
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if os.name == "nt" and exc.errno in {errno.EACCES, errno.EBADF, errno.EINVAL}:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if os.name != "nt" or exc.errno not in {errno.EACCES, errno.EBADF, errno.EINVAL}:
                raise
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            if os.name != "nt":
                raise
    finally:
        os.close(descriptor)


def _write_deterministic_member(archive: zipfile.ZipFile, content: bytes, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname, date_time=DETERMINISTIC_ZIP_DATETIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _validate_member_root(package_root: str) -> None:
    if (
        not PORTABLE_MEMBER_ROOT.fullmatch(package_root)
        or package_root.endswith((".", " "))
        or package_root.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
        or len(os.fsencode(package_root)) > PORTABLE_NAME_MAX_BYTES
    ):
        raise PublicationError("archive member root must be one portable path segment")


def build_staged_zip(
    snapshot: tuple[ReleaseSnapshotEntry, ...],
    output: Path,
    *,
    package_root: str = PACKAGE_ROOT,
) -> Path:
    """Build one new ZIP from immutable bytes at a private staging path."""
    _validate_member_root(package_root)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for entry in snapshot:
            _write_deterministic_member(archive, entry.content, f"{package_root}/{entry.path}")
    os.chmod(output, 0o644)
    with output.open("r+b") as handle:
        os.fsync(handle.fileno())
    return output


def _stage_sidecars(targets: ReleaseTargets) -> None:
    checksum = f"{sha256_file(targets.zip_path)}  {targets.zip_path.name}\n".encode("utf-8")
    audit = (json.dumps(zip_summary(targets.zip_path), indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _write_bytes_fsynced(targets.checksum_path, checksum)
    _write_bytes_fsynced(targets.audit_path, audit)


def _verify_zip(
    zip_path: Path,
    snapshot: tuple[ReleaseSnapshotEntry, ...],
    *,
    package_root: str,
) -> None:
    expected = [(f"{package_root}/{entry.path}", entry.content) for entry in snapshot]
    with zipfile.ZipFile(zip_path, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        expected_names = [name for name, _ in expected]
        if names != expected_names or len(names) != len(set(names)):
            raise PublicationError("staged ZIP membership or order does not match the immutable snapshot")
        if archive.testzip() is not None:
            raise PublicationError("staged ZIP failed its CRC check")
        for info, (name, content) in zip(infos, expected):
            member_mode = info.external_attr >> 16
            if (
                info.date_time != DETERMINISTIC_ZIP_DATETIME
                or info.create_system != 3
                or not stat.S_ISREG(member_mode)
                or stat.S_IMODE(member_mode) != 0o644
                or info.extra
                or info.comment
            ):
                raise PublicationError(f"staged ZIP metadata is not deterministic: {name}")
            if archive.read(info) != content:
                raise PublicationError(f"staged ZIP content mismatch: {name}")


def verify_staged_packet(
    targets: ReleaseTargets,
    snapshot: tuple[ReleaseSnapshotEntry, ...],
    *,
    package_root: str = PACKAGE_ROOT,
) -> None:
    """Verify the complete staged packet before any public path is replaced."""
    _verify_zip(targets.zip_path, snapshot, package_root=package_root)
    expected_checksum = f"{sha256_file(targets.zip_path)}  {targets.zip_path.name}\n".encode("utf-8")
    if read_regular_file(targets.checksum_path) != expected_checksum:
        raise PublicationError("staged ZIP checksum sidecar is inconsistent")
    try:
        audit = json.loads(read_regular_file(targets.audit_path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"staged package audit is invalid: {exc}") from exc
    if audit != zip_summary(targets.zip_path):
        raise PublicationError("staged package audit sidecar is inconsistent")


def _packet_bytes(targets: ReleaseTargets) -> dict[Path, bytes]:
    return {target: read_regular_file(target) for target in targets.all()}


def _same_existing_packet(targets: ReleaseTargets, expected: dict[Path, bytes]) -> bool:
    for target in targets.all():
        metadata = _lstat_or_none(target)
        if (
            metadata is None
            or not stat.S_ISREG(metadata.st_mode)
            or not _host_mode_matches(stat.S_IMODE(metadata.st_mode), 0o644)
        ):
            return False
        try:
            if read_regular_file(target) != expected[target]:
                return False
        except ReleaseSetError:
            return False
    return True


def _fingerprint(path: Path) -> tuple[int, int, int, int, int, str] | None:
    before = _lstat_or_none(path)
    if before is None:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise PublicationError(f"release output changed to an unsafe entry: {path}")
    content, after = read_regular_file_with_metadata(path)
    return (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        stat.S_IMODE(after.st_mode),
        sha256_bytes(content),
    )


def _snapshot_prior_targets(
    targets: ReleaseTargets,
    backup_dir: Path,
) -> dict[Path, PriorTarget]:
    priors: dict[Path, PriorTarget] = {}
    fingerprints: dict[Path, tuple[int, int, int, int, int, str] | None] = {}
    for index, target in enumerate(targets.all()):
        metadata = _lstat_or_none(target)
        if metadata is None:
            priors[target] = PriorTarget(False)
            fingerprints[target] = None
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise PublicationError(f"release output changed to an unsafe entry: {target}")
        content, metadata_after = read_regular_file_with_metadata(target)
        metadata = metadata_after
        backup = backup_dir / str(index)
        mode = stat.S_IMODE(metadata.st_mode)
        _write_bytes_fsynced(
            backup,
            content,
            mode=mode,
            times_ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
        )
        fingerprint = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            mode,
            sha256_bytes(content),
        )
        priors[target] = PriorTarget(True, backup, content, mode, metadata.st_mtime_ns, fingerprint)
        fingerprints[target] = fingerprint
    _fsync_directory(backup_dir)
    for target, fingerprint in fingerprints.items():
        if _fingerprint(target) != fingerprint:
            raise PublicationError(f"release output changed while backups were captured: {target}")
    return priors


def _verify_prior_state(priors: dict[Path, PriorTarget]) -> list[str]:
    errors: list[str] = []
    for target, prior in priors.items():
        try:
            metadata = _lstat_or_none(target)
            if not prior.existed:
                if metadata is not None:
                    errors.append(f"expected absent target after rollback: {target}")
                continue
            if metadata is None or not stat.S_ISREG(metadata.st_mode):
                errors.append(f"prior target was not restored: {target}")
                continue
            content, metadata = read_regular_file_with_metadata(target)
        except BaseException as exc:
            errors.append(f"cannot verify restored target {target}: {exc}")
            continue
        if (
            content != prior.content
            or not _host_mode_matches(stat.S_IMODE(metadata.st_mode), prior.mode)
            or metadata.st_mtime_ns != prior.mtime_ns
        ):
            errors.append(f"prior target metadata or bytes differ after rollback: {target}")
    return errors


def _rollback(
    priors: dict[Path, PriorTarget],
    parent: Path,
    attempted_targets: set[Path],
    published_bytes: dict[Path, bytes],
) -> list[str]:
    errors: list[str] = []
    for target, prior in reversed(tuple(priors.items())):
        try:
            current = _fingerprint(target)
            if target not in attempted_targets:
                if current != prior.fingerprint:
                    errors.append(f"untouched target changed concurrently and was not overwritten: {target}")
                continue
            if current == prior.fingerprint:
                continue
            if current is not None:
                current_content = read_regular_file(target)
                if current_content != published_bytes[target]:
                    errors.append(f"attempted target changed concurrently and was not overwritten: {target}")
                    continue
            if prior.existed:
                assert prior.backup_path is not None
                os.replace(prior.backup_path, target)
            else:
                target.unlink(missing_ok=True)
        except BaseException as exc:
            errors.append(f"{target}: {exc}")
    try:
        _fsync_directory(parent)
    except BaseException as exc:
        errors.append(f"cannot synchronise rollback directory: {exc}")
    try:
        errors.extend(_verify_prior_state(priors))
    except BaseException as exc:  # Defensive: recovery evidence must never be deleted on verification uncertainty.
        errors.append(f"cannot verify rollback state: {exc}")
    return errors


def _commit_staged_target(source: Path, destination: Path) -> None:
    """Install one staged packet member at its final destination."""
    os.replace(source, destination)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_utc_timestamp(value: Any, label: str) -> str:
    rendered = str(value or "")
    if not rendered.endswith("Z"):
        raise PublicationError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(rendered[:-1] + "+00:00")
    except ValueError as exc:
        raise PublicationError(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise PublicationError(f"{label} is not a UTC timestamp")
    return rendered


def _lock_path(parent: Path, basename: str) -> Path:
    return parent / f".{basename}.publish.lock"


def _transaction_prefix(basename: str) -> str:
    return f".{basename}.transaction-"


def _legacy_stage_prefix(basename: str) -> str:
    return f".{basename}.staging-"


def _transaction_dir(parent: Path, basename: str, transaction_id: str) -> Path:
    return parent / f"{_transaction_prefix(basename)}{transaction_id}"


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_control_json(path: Path) -> dict[str, Any]:
    try:
        content = read_regular_file(path)
    except ReleaseSetError as exc:
        raise PublicationError(f"unsafe or unreadable recovery control file: {path}: {exc}") from exc
    if len(content) > CONTROL_FILE_LIMIT_BYTES:
        raise PublicationError(f"recovery control file exceeds the size ceiling: {path}")
    try:
        decoded = content.decode("utf-8", errors="strict")
        payload = json.loads(decoded, object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PublicationError(f"invalid recovery control file {path}: {exc}", recovery_path=path) from exc
    if not isinstance(payload, dict):
        raise PublicationError(f"recovery control file must contain a JSON object: {path}", recovery_path=path)
    return payload


def _atomic_write_control_json(path: Path, payload: dict[str, Any]) -> None:
    _reject_lexical_symlink(path)
    encoded = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if len(encoded) > CONTROL_FILE_LIMIT_BYTES:
        raise PublicationError(f"recovery control data exceeds the size ceiling: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        _write_bytes_fsynced(temporary, encoded, mode=0o600)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while creating publication lock")
        view = view[written:]


def _create_lock(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError as exc:
        raise PublicationError(f"another publication or recovery lock exists: {path}", recovery_path=path) from exc
    try:
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _windows_process_alive(pid: int) -> bool | None:
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    process_query_limited_information = 0x1000
    still_active = 259
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: the PID does not exist.
            return False
        if error == 5:  # Access denied is evidence that a process exists.
            return True
        return None
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return None
        return exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def _local_process_alive(pid: int) -> bool | None:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if pid == os.getpid():
        return True
    if os.name == "nt":
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _validate_transaction_id(value: Any) -> str:
    transaction_id = str(value or "")
    if not TRANSACTION_ID_RE.fullmatch(transaction_id):
        raise PublicationError("publication control data contains an invalid transaction identifier")
    return transaction_id


def _validate_lock_payload(
    payload: dict[str, Any],
    targets: ReleaseTargets,
    *,
    app_version: str,
) -> tuple[str, Path]:
    required = {
        "schema",
        "transaction_id",
        "hostname",
        "pid",
        "app_version",
        "basename",
        "transaction_dir",
        "created_at_utc",
    }
    if set(payload) != required:
        raise PublicationError("publication lock has an unexpected field set")
    if payload.get("schema") != LOCK_SCHEMA:
        raise PublicationError("publication lock schema is unsupported")
    transaction_id = _validate_transaction_id(payload.get("transaction_id"))
    if payload.get("app_version") != app_version:
        raise PublicationError("publication lock belongs to a different application version")
    if payload.get("basename") != targets.zip_path.name:
        raise PublicationError("publication lock belongs to a different output packet")
    expected_dir_name = _transaction_dir(
        targets.zip_path.parent,
        targets.zip_path.name,
        transaction_id,
    ).name
    if payload.get("transaction_dir") != expected_dir_name:
        raise PublicationError("publication lock transaction path is inconsistent")
    hostname = str(payload.get("hostname") or "")
    if not hostname:
        raise PublicationError("publication lock has no hostname")
    pid = payload.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise PublicationError("publication lock has an invalid process identifier")
    _validate_utc_timestamp(payload.get("created_at_utc"), "publication lock created_at_utc")
    return transaction_id, targets.zip_path.parent / expected_dir_name


def _target_mapping(targets: ReleaseTargets) -> dict[str, Path]:
    return {
        "zip": targets.zip_path,
        "checksum": targets.checksum_path,
        "audit": targets.audit_path,
    }


def _record_path(path: Path, *, relative_path: str) -> dict[str, Any]:
    content, metadata = read_regular_file_with_metadata(path)
    return {
        "path": relative_path,
        "size_bytes": len(content),
        "sha256": sha256_bytes(content),
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
    }


def _serialise_prior(
    targets: ReleaseTargets,
    priors: dict[Path, PriorTarget],
    transaction_dir: Path,
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for key, target in _target_mapping(targets).items():
        prior = priors[target]
        record: dict[str, Any] = {"existed": prior.existed}
        if prior.existed:
            assert prior.backup_path is not None
            assert prior.content is not None
            assert prior.mode is not None
            assert prior.mtime_ns is not None
            record.update(
                {
                    "path": prior.backup_path.relative_to(transaction_dir).as_posix(),
                    "size_bytes": len(prior.content),
                    "sha256": sha256_bytes(prior.content),
                    "mode": prior.mode,
                    "mtime_ns": prior.mtime_ns,
                }
            )
        output[key] = record
    return output


def _new_records(
    staged: ReleaseTargets,
    transaction_dir: Path,
) -> dict[str, dict[str, Any]]:
    return {
        key: _record_path(path, relative_path=path.relative_to(transaction_dir).as_posix())
        for key, path in _target_mapping(staged).items()
    }


def _write_journal_state(
    journal_path: Path,
    journal: dict[str, Any],
    state: str,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    if state not in TRANSACTION_STATES:
        raise PublicationError(f"unsupported publication transaction state: {state}")
    journal["state"] = state
    journal["sequence"] = int(journal.get("sequence", 0)) + 1
    journal["updated_at_utc"] = _utc_now()
    _atomic_write_control_json(journal_path, journal)
    if fault_hook is not None:
        fault_hook(state)


def _validate_record(
    record: Any,
    transaction_dir: Path,
    *,
    label: str,
) -> Path:
    if not isinstance(record, dict):
        raise PublicationError(f"{label} transaction record is not an object")
    required = {"path", "size_bytes", "sha256", "mode", "mtime_ns"}
    fields = set(record)
    if fields not in (required, required | {"existed"}):
        raise PublicationError(f"{label} transaction record has unexpected fields")
    relative = str(record.get("path") or "")
    pure = Path(relative)
    if (
        not relative
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != relative
    ):
        raise PublicationError(f"{label} transaction path is unsafe")
    path = transaction_dir.joinpath(*pure.parts)
    try:
        path.relative_to(transaction_dir)
    except ValueError as exc:
        raise PublicationError(f"{label} transaction path escapes its directory") from exc
    if not isinstance(record.get("size_bytes"), int) or record["size_bytes"] < 0:
        raise PublicationError(f"{label} transaction size is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256") or "")):
        raise PublicationError(f"{label} transaction digest is invalid")
    if (
        not isinstance(record.get("mode"), int)
        or isinstance(record["mode"], bool)
        or record["mode"] < 0
        or record["mode"] > 0o777
    ):
        raise PublicationError(f"{label} transaction mode is invalid")
    if not isinstance(record.get("mtime_ns"), int) or record["mtime_ns"] < 0:
        raise PublicationError(f"{label} transaction timestamp is invalid")
    return path


def _record_matches(path: Path, record: dict[str, Any]) -> bool:
    metadata = _lstat_or_none(path)
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        return False
    try:
        content, metadata = read_regular_file_with_metadata(path)
    except ReleaseSetError:
        return False
    return (
        len(content) == record["size_bytes"]
        and sha256_bytes(content) == record["sha256"]
        and _host_mode_matches(stat.S_IMODE(metadata.st_mode), record["mode"])
    )


def _prior_record_matches(path: Path, record: dict[str, Any]) -> bool:
    metadata = _lstat_or_none(path)
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        return False
    try:
        content, metadata = read_regular_file_with_metadata(path)
    except ReleaseSetError:
        return False
    return (
        len(content) == record["size_bytes"]
        and sha256_bytes(content) == record["sha256"]
        and _host_mode_matches(stat.S_IMODE(metadata.st_mode), record["mode"])
        and metadata.st_mtime_ns == record["mtime_ns"]
    )


def _validate_journal(
    journal: dict[str, Any],
    transaction_dir: Path,
    targets: ReleaseTargets,
    *,
    app_version: str,
    transaction_id: str,
) -> tuple[dict[str, Path], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    required = {
        "schema",
        "transaction_id",
        "hostname",
        "pid",
        "app_version",
        "basename",
        "package_root",
        "state",
        "sequence",
        "created_at_utc",
        "updated_at_utc",
        "targets",
        "new",
        "prior",
    }
    if set(journal) != required:
        raise PublicationError("publication journal has an unexpected field set", recovery_path=transaction_dir)
    if journal.get("schema") != JOURNAL_SCHEMA:
        raise PublicationError("publication journal schema is unsupported", recovery_path=transaction_dir)
    if journal.get("transaction_id") != transaction_id:
        raise PublicationError("publication journal and lock identifiers differ", recovery_path=transaction_dir)
    if journal.get("app_version") != app_version:
        raise PublicationError("publication journal belongs to another application version", recovery_path=transaction_dir)
    if journal.get("basename") != targets.zip_path.name:
        raise PublicationError("publication journal belongs to another output packet", recovery_path=transaction_dir)
    if not isinstance(journal.get("hostname"), str) or not journal["hostname"]:
        raise PublicationError("publication journal hostname is invalid", recovery_path=transaction_dir)
    if not isinstance(journal.get("pid"), int) or isinstance(journal["pid"], bool) or journal["pid"] <= 0:
        raise PublicationError("publication journal process identifier is invalid", recovery_path=transaction_dir)
    try:
        _validate_member_root(str(journal.get("package_root") or ""))
    except PublicationError as exc:
        raise PublicationError("publication journal package root is invalid", recovery_path=transaction_dir) from exc
    if journal.get("state") not in TRANSACTION_STATES:
        raise PublicationError("publication journal state is unsupported", recovery_path=transaction_dir)
    if not isinstance(journal.get("sequence"), int) or isinstance(journal["sequence"], bool) or journal["sequence"] <= 0:
        raise PublicationError("publication journal sequence is invalid", recovery_path=transaction_dir)
    try:
        _validate_utc_timestamp(journal.get("created_at_utc"), "publication journal created_at_utc")
        _validate_utc_timestamp(journal.get("updated_at_utc"), "publication journal updated_at_utc")
    except PublicationError as exc:
        raise PublicationError(str(exc), recovery_path=transaction_dir) from exc
    expected_targets = {key: path.name for key, path in _target_mapping(targets).items()}
    if journal.get("targets") != expected_targets:
        raise PublicationError("publication journal target names are inconsistent", recovery_path=transaction_dir)
    new = journal.get("new")
    prior = journal.get("prior")
    if not isinstance(new, dict) or set(new) != set(expected_targets):
        raise PublicationError("publication journal new-packet inventory is invalid", recovery_path=transaction_dir)
    if not isinstance(prior, dict) or set(prior) != set(expected_targets):
        raise PublicationError("publication journal prior-packet inventory is invalid", recovery_path=transaction_dir)
    new_paths: dict[str, Path] = {}
    for key, record in new.items():
        new_paths[key] = _validate_record(record, transaction_dir, label=f"new {key}")
        expected_relative = f"new/{expected_targets[key]}"
        if record["path"] != expected_relative:
            raise PublicationError(f"new {key} transaction path is inconsistent", recovery_path=transaction_dir)
        if not _record_matches(new_paths[key], record):
            raise PublicationError(f"new {key} transaction bytes do not match the journal", recovery_path=transaction_dir)
    prior_indexes = {"zip": 0, "checksum": 1, "audit": 2}
    for key, record in prior.items():
        if not isinstance(record, dict) or set(record) not in ({"existed"}, {"existed", "path", "size_bytes", "sha256", "mode", "mtime_ns"}):
            raise PublicationError(f"prior {key} transaction record is invalid", recovery_path=transaction_dir)
        if record.get("existed") is True:
            backup = _validate_record(record, transaction_dir, label=f"prior {key}")
            expected_relative = f"backup/{prior_indexes[key]}"
            if record["path"] != expected_relative:
                raise PublicationError(f"prior {key} backup path is inconsistent", recovery_path=transaction_dir)
            if not _prior_record_matches(backup, record):
                raise PublicationError(f"prior {key} backup does not match the journal", recovery_path=transaction_dir)
        elif record.get("existed") is not False or set(record) != {"existed"}:
            raise PublicationError(f"prior {key} transaction record is invalid", recovery_path=transaction_dir)
    return new_paths, new, prior


def _classify_public_target(
    target: Path,
    new_record: dict[str, Any],
    prior_record: dict[str, Any],
) -> str:
    metadata = _lstat_or_none(target)
    if metadata is None:
        return "prior" if prior_record.get("existed") is False else "absent"
    if not stat.S_ISREG(metadata.st_mode):
        return "unknown"
    if _record_matches(target, new_record):
        return "new"
    if prior_record.get("existed") is True and _prior_record_matches(target, prior_record):
        return "prior"
    return "unknown"


def _copy_for_install(
    source: Path,
    destination: Path,
    install_dir: Path,
    *,
    mode: int,
    mtime_ns: int | None = None,
) -> None:
    install_dir.mkdir(exist_ok=True)
    temporary = install_dir / f"{destination.name}.{uuid.uuid4().hex}.install"
    content = read_regular_file(source)
    times = None if mtime_ns is None else (mtime_ns, mtime_ns)
    try:
        _write_bytes_fsynced(temporary, content, mode=mode, times_ns=times)
        _commit_staged_target(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _verify_public_packet(targets: ReleaseTargets) -> None:
    expected_checksum = f"{sha256_file(targets.zip_path)}  {targets.zip_path.name}\n".encode("utf-8")
    if read_regular_file(targets.checksum_path) != expected_checksum:
        raise PublicationError("published checksum readiness marker is inconsistent")
    try:
        audit = json.loads(read_regular_file(targets.audit_path).decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PublicationError(f"published package audit is invalid: {exc}") from exc
    if audit != zip_summary(targets.zip_path):
        raise PublicationError("published package audit sidecar is inconsistent")


def _require_public_states(
    targets: ReleaseTargets,
    new: dict[str, dict[str, Any]],
    prior: dict[str, dict[str, Any]],
    expected: dict[str, frozenset[str]],
    *,
    recovery_path: Path,
) -> dict[str, str]:
    states = {
        key: _classify_public_target(target, new[key], prior[key])
        for key, target in _target_mapping(targets).items()
    }
    unexpected = {
        key: state
        for key, state in states.items()
        if state not in expected.get(key, frozenset())
    }
    if unexpected:
        rendered = ", ".join(f"{key}={value}" for key, value in sorted(unexpected.items()))
        raise PublicationError(
            f"public release state changed outside the transaction: {rendered}",
            recovery_path=recovery_path,
        )
    return states


def _complete_or_absent_packet(targets: ReleaseTargets) -> str:
    present = [path.exists() for path in targets.all()]
    if not any(present):
        return "absent"
    if not all(present):
        return "partial"
    try:
        _verify_public_packet(targets)
    except (OSError, PublicationError, ReleaseSetError, zipfile.BadZipFile):
        return "invalid"
    return "complete"


def _restore_prior_packet(
    transaction_dir: Path,
    targets: ReleaseTargets,
    new: dict[str, dict[str, Any]],
    prior: dict[str, dict[str, Any]],
    journal_path: Path,
    journal: dict[str, Any],
    *,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    mapping = _target_mapping(targets)
    install_dir = transaction_dir / "install"
    _write_journal_state(journal_path, journal, "rollback_started", fault_hook)

    allowed = frozenset({"new", "prior", "absent"})
    _require_public_states(
        targets,
        new,
        prior,
        {key: allowed for key in mapping},
        recovery_path=transaction_dir,
    )

    # The checksum is a readiness marker. Withdraw it before any other restoration.
    if _lstat_or_none(targets.checksum_path) is not None:
        targets.checksum_path.unlink()
        _fsync_directory(targets.checksum_path.parent)

    for key, state in (("zip", "rollback_zip_restored"), ("audit", "rollback_audit_restored")):
        _require_public_states(
            targets,
            new,
            prior,
            {name: allowed for name in mapping},
            recovery_path=transaction_dir,
        )
        target = mapping[key]
        record = prior[key]
        if record["existed"]:
            backup = transaction_dir / record["path"]
            _copy_for_install(
                backup,
                target,
                install_dir,
                mode=record["mode"],
                mtime_ns=record["mtime_ns"],
            )
        else:
            target.unlink(missing_ok=True)
            _fsync_directory(target.parent)
        _write_journal_state(journal_path, journal, state, fault_hook)

    _require_public_states(
        targets,
        new,
        prior,
        {name: allowed for name in mapping},
        recovery_path=transaction_dir,
    )
    checksum_record = prior["checksum"]
    if checksum_record["existed"]:
        backup = transaction_dir / checksum_record["path"]
        _copy_for_install(
            backup,
            targets.checksum_path,
            install_dir,
            mode=checksum_record["mode"],
            mtime_ns=checksum_record["mtime_ns"],
        )
    else:
        targets.checksum_path.unlink(missing_ok=True)
        _fsync_directory(targets.checksum_path.parent)
    _write_journal_state(journal_path, journal, "rollback_checksum_restored", fault_hook)

    for key, target in mapping.items():
        record = prior[key]
        if record["existed"]:
            if not _prior_record_matches(target, record):
                raise PublicationError(f"prior {key} target was not restored", recovery_path=transaction_dir)
        elif _lstat_or_none(target) is not None:
            raise PublicationError(f"prior absent {key} target was not restored", recovery_path=transaction_dir)
    _write_journal_state(journal_path, journal, "rolled_back", fault_hook)


def _remove_transaction_dir(path: Path) -> None:
    _remove_stage(path)
    _fsync_directory(path.parent)


def _cleanup_empty_legacy_staging(parent: Path, basename: str) -> int:
    removed = 0
    prefix = _legacy_stage_prefix(basename)
    for candidate in sorted(parent.glob(prefix + "*")):
        metadata = _lstat_or_none(candidate)
        if metadata is None:
            continue
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise PublicationError(f"legacy staging path is unsafe and requires manual inspection: {candidate}", recovery_path=candidate)
        try:
            next(candidate.iterdir())
        except StopIteration:
            candidate.rmdir()
            removed += 1
        else:
            raise PublicationError(f"non-empty legacy staging directory requires manual inspection: {candidate}", recovery_path=candidate)
    if removed:
        _fsync_directory(parent)
    return removed


def _remove_control_path(path: Path) -> None:
    path.unlink(missing_ok=True)
    _fsync_directory(path.parent)


def _create_mutation_marker(path: Path, transaction_id: str) -> None:
    payload = (f"transaction_id={transaction_id}\n").encode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError as exc:
        raise PublicationError("public-mutation marker already exists", recovery_path=path.parent) from exc
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _recover_locked_transaction(
    lock_path: Path,
    lock: dict[str, Any],
    targets: ReleaseTargets,
    *,
    app_version: str,
    fault_hook: Callable[[str], None] | None = None,
    owner_override: bool = False,
) -> RecoveryResult:
    transaction_id, transaction_dir = _validate_lock_payload(lock, targets, app_version=app_version)
    host = str(lock["hostname"])
    if host != socket.gethostname():
        raise PublicationError(
            f"publication lock belongs to another host and cannot be declared stale: {host}",
            recovery_path=lock_path,
        )
    alive = _local_process_alive(lock["pid"])
    if alive is True and not owner_override:
        raise PublicationError("publication lock is owned by a live local process", recovery_path=lock_path)
    if alive is None and not owner_override:
        raise PublicationError("publication lock process state is indeterminate", recovery_path=lock_path)

    siblings = sorted(targets.zip_path.parent.glob(_transaction_prefix(targets.zip_path.name) + "*"))
    if not transaction_dir.exists():
        if siblings:
            raise PublicationError("stale lock has no matching transaction directory", recovery_path=lock_path)
        packet_state = _complete_or_absent_packet(targets)
        if packet_state not in {"complete", "absent"}:
            raise PublicationError(
                "stale lock has no transaction directory and the public packet is not provably complete or absent",
                recovery_path=lock_path,
            )
        _remove_control_path(lock_path)
        detail = (
            "A complete verified public packet was retained."
            if packet_state == "complete"
            else "No public packet existed and no mutation evidence remained."
        )
        return RecoveryResult("stale-lock-removed", detail, True)
    unexpected = [candidate for candidate in siblings if candidate != transaction_dir]
    if unexpected:
        raise PublicationError(
            "multiple publication transaction directories require manual inspection",
            recovery_path=unexpected[0],
        )
    metadata = transaction_dir.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PublicationError("publication transaction path is unsafe", recovery_path=transaction_dir)
    journal_path = transaction_dir / "journal.json"
    mutation_marker = transaction_dir / "public-mutation.started"
    journal_metadata = _lstat_or_none(journal_path)
    marker_metadata = _lstat_or_none(mutation_marker)
    if journal_metadata is None:
        if marker_metadata is not None:
            raise PublicationError("publication transaction journal is missing after public mutation was authorised", recovery_path=transaction_dir)
        _remove_transaction_dir(transaction_dir)
        _remove_control_path(lock_path)
        return RecoveryResult("pre-mutation-transaction-removed", "Interrupted private staging was removed before any public mutation.", True)
    if stat.S_ISLNK(journal_metadata.st_mode) or not stat.S_ISREG(journal_metadata.st_mode):
        raise PublicationError("publication transaction journal path is unsafe", recovery_path=transaction_dir)
    if marker_metadata is not None:
        if stat.S_ISLNK(marker_metadata.st_mode) or not stat.S_ISREG(marker_metadata.st_mode):
            raise PublicationError("public-mutation marker path is unsafe", recovery_path=transaction_dir)
        expected_marker = f"transaction_id={transaction_id}\n".encode("ascii")
        if read_regular_file(mutation_marker) != expected_marker:
            raise PublicationError("public-mutation marker is inconsistent", recovery_path=transaction_dir)
    journal = _read_control_json(journal_path)
    if journal.get("hostname") != lock.get("hostname") or journal.get("pid") != lock.get("pid"):
        raise PublicationError("publication journal owner does not match the lock", recovery_path=transaction_dir)
    _new_paths, new, prior = _validate_journal(
        journal,
        transaction_dir,
        targets,
        app_version=app_version,
        transaction_id=transaction_id,
    )
    mapping = _target_mapping(targets)
    states = {
        key: _classify_public_target(mapping[key], new[key], prior[key])
        for key in mapping
    }
    if journal["state"] != "prepared" and marker_metadata is None:
        raise PublicationError(
            "publication journal records public mutation without its durable marker",
            recovery_path=transaction_dir,
        )
    if "unknown" in states.values():
        raise PublicationError(
            "public release state contains bytes not attributable to the interrupted transaction",
            recovery_path=transaction_dir,
        )
    absent_keys = {key for key, value in states.items() if value == "absent"}
    if absent_keys - {"checksum"}:
        raise PublicationError(
            "a non-readiness packet member is unexpectedly absent",
            recovery_path=transaction_dir,
        )

    if all(value == "new" for value in states.values()):
        _verify_public_packet(targets)
        if journal["state"] != "committed":
            _write_journal_state(journal_path, journal, "committed", fault_hook)
        _remove_transaction_dir(transaction_dir)
        _remove_control_path(lock_path)
        return RecoveryResult("new-packet-committed", "A complete verified new packet was retained.", True)

    if all(value == "prior" for value in states.values()):
        _remove_transaction_dir(transaction_dir)
        _remove_control_path(lock_path)
        return RecoveryResult("prior-packet-restored", "The prior packet was already complete.", True)

    if states["checksum"] == "new":
        raise PublicationError(
            "checksum readiness marker is new while another packet member is not; state is ambiguous",
            recovery_path=transaction_dir,
        )

    _restore_prior_packet(
        transaction_dir,
        targets,
        new,
        prior,
        journal_path,
        journal,
        fault_hook=fault_hook,
    )
    _remove_transaction_dir(transaction_dir)
    _remove_control_path(lock_path)
    return RecoveryResult("prior-packet-restored", "A mixed interrupted packet was rolled back.", True)


def recover_release(
    root: Path,
    requested_output: Path,
    *,
    app_version: str,
    _fault_hook: Callable[[str], None] | None = None,
    _owner_override: bool = False,
) -> RecoveryResult:
    """Recover one interrupted packet or establish that no recovery is required."""
    lexical_root = _absolute_without_resolving(root)
    resolved_root = lexical_root.resolve()
    targets = _plan_release_targets(lexical_root, resolved_root, requested_output)
    targets.zip_path.parent.mkdir(parents=True, exist_ok=True)
    parent = targets.zip_path.parent.resolve()
    if parent != targets.zip_path.parent:
        raise PublicationError("release output parent changed during recovery planning")
    lock_path = _lock_path(parent, targets.zip_path.name)
    lock_metadata = _lstat_or_none(lock_path)
    if lock_metadata is None:
        transactions = sorted(parent.glob(_transaction_prefix(targets.zip_path.name) + "*"))
        if transactions:
            raise PublicationError(
                "orphaned publication transaction has no lock and requires manual inspection",
                recovery_path=transactions[0],
            )
        _cleanup_empty_legacy_staging(parent, targets.zip_path.name)
        return RecoveryResult("clean", "No interrupted publication was found.", False)
    if stat.S_ISLNK(lock_metadata.st_mode) or not stat.S_ISREG(lock_metadata.st_mode):
        raise PublicationError("publication lock path is unsafe", recovery_path=lock_path)
    lock = _read_control_json(lock_path)
    return _recover_locked_transaction(
        lock_path,
        lock,
        targets,
        app_version=app_version,
        fault_hook=_fault_hook,
        owner_override=_owner_override,
    )


@contextmanager
def _publication_lock(parent: Path, basename: str, payload: dict[str, Any]):
    lock_path = _lock_path(parent, basename)
    _create_lock(lock_path, payload)
    retain_lock = False
    try:
        yield lock_path
    except PublicationError as exc:
        retain_lock = exc.recovery_path is not None
        raise
    finally:
        if not retain_lock:
            try:
                _remove_control_path(lock_path)
            except OSError as exc:
                raise PublicationError(
                    f"release packet state is consistent but publication lock cleanup failed: {lock_path}: {exc}",
                    recovery_path=lock_path,
                ) from exc


def _remove_stage(stage_dir: Path) -> None:
    cleanup_errors: list[str] = []

    def make_writable_and_retry(function, path: str, _error_info) -> None:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            function(path)
        except OSError as exc:
            cleanup_errors.append(f"{path}: {exc}")

    shutil.rmtree(stage_dir, onerror=make_writable_and_retry)
    if stage_dir.exists():
        detail = "; ".join(cleanup_errors[:4]) or "transaction directory still exists"
        raise PublicationError(
            f"release packet state is consistent but transaction cleanup failed; recovery retained at {stage_dir}: {detail}",
            recovery_path=stage_dir,
        )


def publish_release(
    root: Path,
    requested_output: Path,
    *,
    app_version: str,
    package_root: str | None = None,
    _fault_hook: Callable[[str], None] | None = None,
) -> ReleaseTargets:
    """Publish a verified packet with durable crash recovery and readiness semantics."""
    lexical_root = _absolute_without_resolving(root)
    root = lexical_root.resolve()
    targets = _plan_release_targets(lexical_root, root, requested_output)
    targets.zip_path.parent.mkdir(parents=True, exist_ok=True)
    parent = targets.zip_path.parent.resolve()
    if parent != targets.zip_path.parent:
        raise PublicationError("release output parent changed during publication planning")

    # Recovery must not depend on the current source tree remaining valid.
    recover_release(root, targets.zip_path, app_version=app_version)
    _validate_destination_targets(targets, root)
    snapshot = read_verified_release_snapshot(root, app_version=app_version)
    canonical_root = package_root or f"CodeProbe_Project_Kit_v{app_version}"
    _validate_member_root(canonical_root)
    transaction_id = uuid.uuid4().hex
    transaction_dir = _transaction_dir(parent, targets.zip_path.name, transaction_id)
    lock_payload = {
        "schema": LOCK_SCHEMA,
        "transaction_id": transaction_id,
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "app_version": app_version,
        "basename": targets.zip_path.name,
        "transaction_dir": transaction_dir.name,
        "created_at_utc": _utc_now(),
    }

    with _publication_lock(parent, targets.zip_path.name, lock_payload) as lock_path:
        if _fault_hook is not None:
            _fault_hook("lock_acquired")
        journal_written = False
        try:
            transaction_dir.mkdir(mode=0o700)
            new_dir = transaction_dir / "new"
            backup_dir = transaction_dir / "backup"
            install_dir = transaction_dir / "install"
            for directory in (new_dir, backup_dir, install_dir):
                directory.mkdir()
                _fsync_directory(directory)
            _fsync_directory(transaction_dir)
            _fsync_directory(parent)
            if _fault_hook is not None:
                _fault_hook("transaction_created")
            journal_path = transaction_dir / "journal.json"
            staged = ReleaseTargets(
                new_dir / targets.zip_path.name,
                new_dir / targets.checksum_path.name,
                new_dir / targets.audit_path.name,
            )
            build_staged_zip(snapshot, staged.zip_path, package_root=canonical_root)
            _stage_sidecars(staged)
            verify_staged_packet(staged, snapshot, package_root=canonical_root)
            _fsync_directory(new_dir)
            expected_stage = _packet_bytes(staged)
            expected_final = {
                targets.zip_path: expected_stage[staged.zip_path],
                targets.checksum_path: expected_stage[staged.checksum_path],
                targets.audit_path: expected_stage[staged.audit_path],
            }
            if _same_existing_packet(targets, expected_final):
                _remove_transaction_dir(transaction_dir)
                return targets

            _validate_destination_targets(targets, root)
            priors = _snapshot_prior_targets(targets, backup_dir)
            journal: dict[str, Any] = {
                "schema": JOURNAL_SCHEMA,
                "transaction_id": transaction_id,
                "hostname": socket.gethostname(),
                "pid": os.getpid(),
                "app_version": app_version,
                "basename": targets.zip_path.name,
                "package_root": canonical_root,
                "state": "prepared",
                "sequence": 0,
                "created_at_utc": _utc_now(),
                "updated_at_utc": _utc_now(),
                "targets": {key: path.name for key, path in _target_mapping(targets).items()},
                "new": _new_records(staged, transaction_dir),
                "prior": _serialise_prior(targets, priors, transaction_dir),
            }
            _write_journal_state(journal_path, journal, "prepared", _fault_hook)
            journal_written = True
            prior_expected = {key: frozenset({"prior"}) for key in _target_mapping(targets)}
            _require_public_states(
                targets,
                journal["new"],
                journal["prior"],
                prior_expected,
                recovery_path=transaction_dir,
            )
            _create_mutation_marker(transaction_dir / "public-mutation.started", transaction_id)
            if _fault_hook is not None:
                _fault_hook("mutation_authorised")

            # A checksum sidecar is the readiness marker and must be absent in every mixed state.
            current_checksum = _lstat_or_none(targets.checksum_path)
            if current_checksum is not None:
                if not stat.S_ISREG(current_checksum.st_mode):
                    raise PublicationError("checksum readiness marker changed to an unsafe entry")
                targets.checksum_path.unlink()
                _fsync_directory(parent)
            _write_journal_state(journal_path, journal, "readiness_withdrawn", _fault_hook)

            staged_by_key = _target_mapping(staged)
            final_by_key = _target_mapping(targets)
            # Missing public bytes are classified as prior when the recorded prior
            # target did not exist and as absent when a prior target was withdrawn.
            expected_progress = {
                "zip": "prior",
                "audit": "prior",
                "checksum": (
                    "prior"
                    if journal["prior"]["checksum"]["existed"] is False
                    else "absent"
                ),
            }
            for key, state in (("zip", "zip_installed"), ("audit", "audit_installed"), ("checksum", "checksum_installed")):
                _require_public_states(
                    targets,
                    journal["new"],
                    journal["prior"],
                    {name: frozenset({value}) for name, value in expected_progress.items()},
                    recovery_path=transaction_dir,
                )
                record = journal["new"][key]
                _copy_for_install(
                    staged_by_key[key],
                    final_by_key[key],
                    install_dir,
                    mode=record["mode"],
                )
                expected_progress[key] = "new"
                _write_journal_state(journal_path, journal, state, _fault_hook)

            _require_public_states(
                targets,
                journal["new"],
                journal["prior"],
                {key: frozenset({"new"}) for key in final_by_key},
                recovery_path=transaction_dir,
            )
            _verify_public_packet(targets)
            _write_journal_state(journal_path, journal, "committed", _fault_hook)
            _remove_transaction_dir(transaction_dir)
            return targets
        except BaseException as exc:
            if isinstance(exc, SystemExit):
                raise
            if not journal_written:
                try:
                    if transaction_dir.exists():
                        _remove_transaction_dir(transaction_dir)
                except BaseException as cleanup_exc:
                    raise PublicationError(
                        f"publication failed before public mutation and transaction cleanup failed: {cleanup_exc}",
                        recovery_path=transaction_dir,
                    ) from exc
                raise
            try:
                result = _recover_locked_transaction(
                    lock_path,
                    _read_control_json(lock_path),
                    targets,
                    app_version=app_version,
                    owner_override=True,
                )
            except BaseException as recovery_exc:
                if isinstance(recovery_exc, PublicationError):
                    raise recovery_exc from exc
                raise PublicationError(
                    f"publication failed and rollback is incomplete; recovery retained at {transaction_dir}: {recovery_exc}",
                    recovery_path=transaction_dir,
                ) from exc
            if result.status == "new-packet-committed":
                raise PublicationError(
                    f"publication was interrupted after the complete new packet became ready; the new packet was retained: {exc}"
                ) from exc
            raise PublicationError(
                f"publication failed; prior outputs were restored by deterministic recovery ({result.status}): {exc}"
            ) from exc

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and publish a fixed-metadata CodeProbe source release packet.")
    parser.add_argument("--out", help="Output ZIP path. Defaults to dist/CodeProbe_Project_Kit_v<version>.zip.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip unittest discovery during release validation.")
    parser.add_argument("--recover-only", action="store_true", help="Recover an interrupted publication without building a new packet.")
    args = parser.parse_args(argv)

    requested = Path(args.out) if args.out else ROOT / "dist" / f"CodeProbe_Project_Kit_v{engine.APP_VERSION}.zip"
    try:
        plan_release_targets(ROOT, requested)
    except (OSError, PublicationError) as exc:
        parser.error(str(exc))

    # An invalid current checkout must not prevent recovery of the prior packet.
    try:
        recovery = recover_release(ROOT, requested, app_version=engine.APP_VERSION)
    except (OSError, PublicationError, ReleaseSetError) as exc:
        print(f"[FAIL] release-recovery: {exc}")
        return 1
    print(f"[PASS] release-recovery: {recovery.status}: {recovery.detail}")
    if args.recover_only:
        return 0

    results = check_release.run_checks(skip_tests=args.skip_tests)
    for result in results:
        status = "SKIP" if result.skipped else ("PASS" if result.ok else "FAIL")
        print(f"[{status}] {result.name}: {result.detail}")
    if not all(result.ok for result in results):
        return 1

    try:
        targets = publish_release(ROOT, requested, app_version=engine.APP_VERSION)
    except (ManifestError, OSError, PublicationError, ReleaseSetError, zipfile.BadZipFile) as exc:
        print(f"[FAIL] release-publication: {exc}")
        return 1
    print(f"release: {targets.zip_path}")
    print(f"sha256: {sha256_file(targets.zip_path)}")
    print(f"sha256 sidecar: {targets.checksum_path}")
    print(f"package audit: {targets.audit_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
