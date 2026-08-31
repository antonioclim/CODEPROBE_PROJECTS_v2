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
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

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
        os.utime(path, ns=times_ns, follow_symlinks=False)
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
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
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
    content = read_regular_file(path)
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise PublicationError(f"release output changed while it was fingerprinted: {path}")
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
        content = read_regular_file(target)
        metadata_after = target.lstat()
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            metadata_after.st_dev,
            metadata_after.st_ino,
            metadata_after.st_size,
            metadata_after.st_mtime_ns,
            metadata_after.st_ctime_ns,
        ):
            raise PublicationError(f"release output changed while its backup was captured: {target}")
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
            content = read_regular_file(target)
        except BaseException as exc:
            errors.append(f"cannot verify restored target {target}: {exc}")
            continue
        if (
            content != prior.content
            or stat.S_IMODE(metadata.st_mode) != prior.mode
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


@contextmanager
def _publication_lock(parent: Path, basename: str):
    lock_path = parent / f".{basename}.publish.lock"
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise PublicationError(f"another publication or recovery lock exists: {lock_path}") from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
    except BaseException as exc:
        try:
            lock_path.unlink(missing_ok=True)
        except OSError as cleanup_exc:
            raise PublicationError(
                f"publication lock initialisation failed and the lock could not be removed: {lock_path}: {cleanup_exc}",
                recovery_path=lock_path,
            ) from exc
        raise PublicationError(f"publication lock initialisation failed: {exc}") from exc
    finally:
        os.close(descriptor)
    retain_lock = False
    try:
        yield lock_path
    except PublicationError as exc:
        retain_lock = exc.recovery_path is not None
        raise
    finally:
        if not retain_lock:
            try:
                lock_path.unlink(missing_ok=True)
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
        detail = "; ".join(cleanup_errors[:4]) or "staging directory still exists"
        raise PublicationError(
            f"release packet state is consistent but staging cleanup failed; recovery retained at {stage_dir}: {detail}",
            recovery_path=stage_dir,
        )


def publish_release(
    root: Path,
    requested_output: Path,
    *,
    app_version: str,
    package_root: str | None = None,
) -> ReleaseTargets:
    """Publish a verified three-file packet with detected-failure rollback."""
    lexical_root = _absolute_without_resolving(root)
    root = lexical_root.resolve()
    targets = _plan_release_targets(lexical_root, root, requested_output)
    _validate_destination_targets(targets, root)
    snapshot = read_verified_release_snapshot(root, app_version=app_version)
    canonical_root = package_root or f"CodeProbe_Project_Kit_v{app_version}"
    _validate_member_root(canonical_root)

    targets.zip_path.parent.mkdir(parents=True, exist_ok=True)
    parent = targets.zip_path.parent.resolve()
    if parent != targets.zip_path.parent:
        raise PublicationError("release output parent changed during publication planning")

    with _publication_lock(parent, targets.zip_path.name):
        _validate_destination_targets(targets, root)
        stage_dir = Path(tempfile.mkdtemp(prefix=f".{targets.zip_path.name}.staging-", dir=parent))
        cleanup_stage = True
        try:
            new_dir = stage_dir / "new"
            backup_dir = stage_dir / "backup"
            new_dir.mkdir()
            backup_dir.mkdir()
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
                return targets

            _validate_destination_targets(targets, root)
            priors = _snapshot_prior_targets(targets, backup_dir)
            staged_by_final = {
                targets.zip_path: staged.zip_path,
                targets.checksum_path: staged.checksum_path,
                targets.audit_path: staged.audit_path,
            }
            attempted_targets: set[Path] = set()
            try:
                for final_target in targets.ordered_for_commit():
                    attempted_targets.add(final_target)
                    os.replace(staged_by_final[final_target], final_target)
                _fsync_directory(parent)
                for final_target, expected_content in expected_final.items():
                    if read_regular_file(final_target) != expected_content:
                        raise PublicationError(f"published release verification failed: {final_target}")
            except BaseException as exc:
                try:
                    rollback_errors = _rollback(priors, parent, attempted_targets, expected_final)
                except BaseException as rollback_exc:  # Defensive against future rollback implementation changes.
                    rollback_errors = [f"rollback raised unexpectedly: {rollback_exc}"]
                if rollback_errors:
                    cleanup_stage = False
                    detail = "; ".join(rollback_errors[:6])
                    raise PublicationError(
                        f"publication failed and rollback is incomplete; recovery retained at {stage_dir}: {detail}",
                        recovery_path=stage_dir,
                    ) from exc
                raise PublicationError(f"publication failed; prior outputs were restored: {exc}") from exc
            return targets
        finally:
            if cleanup_stage:
                _remove_stage(stage_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and publish a fixed-metadata CodeProbe source release packet.")
    parser.add_argument("--out", help="Output ZIP path. Defaults to dist/CodeProbe_Project_Kit_v<version>.zip.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip unittest discovery during release validation.")
    args = parser.parse_args(argv)

    requested = Path(args.out) if args.out else ROOT / "dist" / f"CodeProbe_Project_Kit_v{engine.APP_VERSION}.zip"
    try:
        plan_release_targets(ROOT, requested)
    except (OSError, PublicationError) as exc:
        parser.error(str(exc))

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
