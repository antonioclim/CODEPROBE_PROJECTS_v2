"""Durable rollback journal for abrupt interruption of release publication.

The public CodeProbe packet consists of a deterministic ZIP and two sidecars.
A sequence of independent ``os.replace`` calls cannot be made filesystem-atomic.
This module therefore records every public replacement before it occurs, keeps
byte-exact backups of the preceding packet and either accepts a demonstrably
consistent completed packet or restores the preceding generation after an
uncatchable interruption.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import shutil
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Any, Final


RECOVERY_SCHEMA: Final = "codeprobe-release-recovery/v1"
RECOVERY_DIR_NAME: Final = ".codeprobe-release-recovery"
JOURNAL_NAME: Final = "active.json"
MAX_JOURNAL_BYTES: Final = 512 * 1024
MAX_BACKUP_BYTES: Final = 512 * 1024 * 1024
_REAL_REPLACE = os.replace
_PROCESS_NONCE = uuid.uuid4().hex
_ACTIVE_OUTPUTS: set[Path] = set()


class ReleaseRecoveryError(RuntimeError):
    """Raised when recovery metadata is unsafe, corrupt or irreconcilable."""


def _fsync_directory(directory: Path) -> None:
    """Best-effort directory flush with explicit unsupported-platform limits."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(directory), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_bytes_durable(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _REAL_REPLACE(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _write_json_durable(path: Path, payload: dict[str, Any]) -> None:
    rendered = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(rendered) > MAX_JOURNAL_BYTES:
        raise ReleaseRecoveryError("release recovery journal exceeds its size ceiling")
    _write_bytes_durable(path, rendered)


def _recovery_dir(output_dir: Path) -> Path:
    return output_dir / RECOVERY_DIR_NAME


def _journal_path(output_dir: Path) -> Path:
    return _recovery_dir(output_dir) / JOURNAL_NAME


def _safe_relative_name(value: object) -> str:
    rendered = str(value)
    candidate = Path(rendered)
    if (
        not rendered
        or candidate.is_absolute()
        or len(candidate.parts) != 1
        or candidate.name != rendered
        or candidate.name in {".", ".."}
        or "/" in rendered
        or "\\" in rendered
    ):
        raise ReleaseRecoveryError(f"unsafe recovery path component: {rendered!r}")
    return rendered


def _read_journal(output_dir: Path) -> dict[str, Any] | None:
    path = _journal_path(output_dir)
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ReleaseRecoveryError("release recovery journal is not a regular file")
    data = path.read_bytes()
    if len(data) > MAX_JOURNAL_BYTES:
        raise ReleaseRecoveryError("release recovery journal exceeds its size ceiling")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseRecoveryError("release recovery journal is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema") != RECOVERY_SCHEMA:
        raise ReleaseRecoveryError("unsupported release recovery journal schema")
    if not isinstance(payload.get("records"), list):
        raise ReleaseRecoveryError("release recovery journal records are invalid")
    _safe_relative_name(payload.get("transaction_id", ""))
    return payload


def _is_public_packet_destination(destination: Path) -> bool:
    name = destination.name
    if name.startswith(".") or RECOVERY_DIR_NAME in destination.parts:
        return False
    lowered = name.lower()
    return (
        lowered.endswith(".zip")
        or lowered.endswith(".zip.sha256")
        or lowered.endswith(".sha256")
        or lowered.endswith(".package-audit.json")
        or lowered.endswith(".audit.json")
    )


def _output_dir_for(source: Path, destination: Path) -> Path | None:
    del source
    if not _is_public_packet_destination(destination):
        return None
    return destination.parent.resolve(strict=False)


def _record_paths(output_dir: Path, record: dict[str, Any]) -> tuple[Path, Path | None]:
    target_name = _safe_relative_name(record.get("target"))
    target = output_dir / target_name
    backup_name = record.get("backup")
    backup = None
    if backup_name is not None:
        backup = _recovery_dir(output_dir) / _safe_relative_name(backup_name)
    if target.parent.resolve(strict=False) != output_dir.resolve(strict=False):
        raise ReleaseRecoveryError("recovery target escapes the output directory")
    if backup is not None and backup.parent != _recovery_dir(output_dir):
        raise ReleaseRecoveryError("recovery backup escapes the recovery directory")
    return target, backup


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _packet_consistent(output_dir: Path, payload: dict[str, Any]) -> bool:
    records = payload.get("records", [])
    if len(records) < 3 or any(item.get("state") != "applied" for item in records):
        return False
    targets: dict[str, Path] = {}
    for record in records:
        target, _ = _record_paths(output_dir, record)
        if target.exists() and target.is_file() and not target.is_symlink():
            targets[target.name.lower()] = target
    zip_targets = [path for name, path in targets.items() if name.endswith(".zip")]
    checksum_targets = [path for name, path in targets.items() if name.endswith(".sha256")]
    audit_targets = [
        path
        for name, path in targets.items()
        if name.endswith(".package-audit.json") or name.endswith(".audit.json")
    ]
    if len(zip_targets) != 1 or not checksum_targets or not audit_targets:
        return False
    zip_digest = _sha256_file(zip_targets[0])
    try:
        checksum_text = checksum_targets[0].read_text(encoding="utf-8")
        checksum_token = checksum_text.split()[0].lower()
    except (OSError, UnicodeDecodeError, IndexError):
        return False
    if checksum_token != zip_digest:
        return False
    try:
        audit_payload = json.loads(audit_targets[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False

    def contains_digest(value: object) -> bool:
        if isinstance(value, str):
            return value.lower() == zip_digest
        if isinstance(value, dict):
            return any(contains_digest(item) for item in value.values())
        if isinstance(value, list):
            return any(contains_digest(item) for item in value)
        return False

    return contains_digest(audit_payload)


def _cleanup_recovery(output_dir: Path) -> None:
    recovery = _recovery_dir(output_dir)
    if recovery.exists():
        shutil.rmtree(recovery)
        _fsync_directory(output_dir)
    _ACTIVE_OUTPUTS.discard(output_dir.resolve(strict=False))


def _rollback(output_dir: Path, payload: dict[str, Any]) -> None:
    records = payload.get("records", [])
    for record in reversed(records):
        target, backup = _record_paths(output_dir, record)
        existed = bool(record.get("existed"))
        if existed:
            if backup is None or not backup.exists() or backup.is_symlink() or not backup.is_file():
                raise ReleaseRecoveryError(f"required release backup is missing for {target.name}")
            expected_size = record.get("backup_size")
            expected_sha = record.get("backup_sha256")
            if backup.stat().st_size != expected_size or _sha256_file(backup) != expected_sha:
                raise ReleaseRecoveryError(f"release backup integrity mismatch for {target.name}")
            temporary = output_dir / f".{target.name}.recovery-{uuid.uuid4().hex}.tmp"
            shutil.copyfile(backup, temporary)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            _REAL_REPLACE(temporary, target)
            if isinstance(record.get("mode"), int):
                os.chmod(target, stat.S_IMODE(record["mode"]))
        else:
            target.unlink(missing_ok=True)
        _fsync_directory(output_dir)
    _cleanup_recovery(output_dir)


def recover_pending_transaction(output_dir: str | os.PathLike[str]) -> str:
    """Recover or finalise a transaction left by this or a dead process.

    Returns ``none`` when no journal exists, ``committed`` when a complete and
    internally consistent new packet was retained and ``rolled-back`` when the
    byte-exact preceding packet was restored.
    """

    directory = Path(output_dir).resolve(strict=False)
    payload = _read_journal(directory)
    if payload is None:
        return "none"
    if payload.get("process_nonce") == _PROCESS_NONCE:
        return "active"
    if _packet_consistent(directory, payload):
        _cleanup_recovery(directory)
        return "committed"
    _rollback(directory, payload)
    return "rolled-back"


def _new_transaction(output_dir: Path) -> dict[str, Any]:
    recovery = _recovery_dir(output_dir)
    recovery.mkdir(parents=True, exist_ok=False)
    _fsync_directory(output_dir)
    payload: dict[str, Any] = {
        "schema": RECOVERY_SCHEMA,
        "transaction_id": uuid.uuid4().hex,
        "process_nonce": _PROCESS_NONCE,
        "records": [],
    }
    _write_json_durable(_journal_path(output_dir), payload)
    _ACTIVE_OUTPUTS.add(output_dir.resolve(strict=False))
    return payload


def _ensure_transaction(output_dir: Path) -> dict[str, Any]:
    payload = _read_journal(output_dir)
    if payload is not None and payload.get("process_nonce") != _PROCESS_NONCE:
        recover_pending_transaction(output_dir)
        payload = None
    if payload is None:
        payload = _new_transaction(output_dir)
    _ACTIVE_OUTPUTS.add(output_dir.resolve(strict=False))
    return payload


def _snapshot_target(output_dir: Path, payload: dict[str, Any], target: Path) -> dict[str, Any]:
    for existing in payload["records"]:
        if existing.get("target") == target.name:
            return existing
    if target.is_symlink():
        raise ReleaseRecoveryError(f"refusing to snapshot symbolic-link target {target.name}")
    existed = target.exists()
    record: dict[str, Any] = {
        "target": target.name,
        "existed": existed,
        "backup": None,
        "backup_size": None,
        "backup_sha256": None,
        "mode": None,
        "state": "prepared",
    }
    if existed:
        if not target.is_file():
            raise ReleaseRecoveryError(f"release target is not a regular file: {target.name}")
        if target.stat().st_size > MAX_BACKUP_BYTES:
            raise ReleaseRecoveryError(f"release target exceeds recovery backup ceiling: {target.name}")
        backup_name = f"{len(payload['records']):02d}-{target.name}.previous"
        backup = _recovery_dir(output_dir) / backup_name
        with target.open("rb") as source, backup.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        record.update(
            {
                "backup": backup_name,
                "backup_size": backup.stat().st_size,
                "backup_sha256": _sha256_file(backup),
                "mode": target.stat().st_mode,
            }
        )
    payload["records"].append(record)
    _write_json_durable(_journal_path(output_dir), payload)
    _fsync_directory(_recovery_dir(output_dir))
    return record


def crash_safe_replace(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> None:
    """Replace a path and journal public release-packet destinations.

    Non-packet replacements remain ordinary atomic replacements. Public packet
    destinations are classified by the destination, not by the staging source,
    so a staging directory and an output directory may be different.
    """

    source_path = Path(source)
    destination_path = Path(destination)
    output_dir = _output_dir_for(source_path, destination_path)
    if output_dir is None:
        _REAL_REPLACE(source_path, destination_path)
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = _ensure_transaction(output_dir)
    record = _snapshot_target(output_dir, payload, destination_path)
    _REAL_REPLACE(source_path, destination_path)
    if destination_path.is_file():
        with destination_path.open("rb") as handle:
            os.fsync(handle.fileno())
    _fsync_directory(output_dir)
    record["state"] = "applied"
    _write_json_durable(_journal_path(output_dir), payload)


def finalise_current_process_transactions() -> None:
    """Commit complete packets or rollback incomplete packets at normal exit."""

    for output_dir in sorted(_ACTIVE_OUTPUTS):
        try:
            payload = _read_journal(output_dir)
            if payload is None:
                continue
            if _packet_consistent(output_dir, payload):
                _cleanup_recovery(output_dir)
            else:
                _rollback(output_dir, payload)
        except Exception:
            # Keep the journal and backups for explicit fail-closed recovery.
            continue


atexit.register(finalise_current_process_transactions)


__all__ = [
    "ReleaseRecoveryError",
    "crash_safe_replace",
    "recover_pending_transaction",
    "finalise_current_process_transactions",
]
