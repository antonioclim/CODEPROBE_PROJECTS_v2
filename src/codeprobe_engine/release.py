"""Release-manifest helpers for CodeProbe."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

MANIFEST_NAME = "release/release-manifest.json"
EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def iter_release_files(root: Path) -> Iterable[Path]:
    """Yield release files, excluding caches and build outputs."""
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if set(relative.parts) & EXCLUDED_DIRS:
            continue
        if path.suffix.lower() in EXCLUDED_SUFFIXES:
            continue
        if relative.as_posix() == MANIFEST_NAME:
            continue
        yield path


def build_release_manifest(root: Path, *, app_version: str, schema_version: str = "codeprobe-release-manifest/v1") -> Dict[str, Any]:
    """Create a deterministic manifest of release files and SHA-256 hashes."""
    root = root.resolve()
    files: List[Dict[str, Any]] = []
    for path in iter_release_files(root):
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "size_bytes": path.stat().st_size, "sha256": sha256_file(path)})
    total_size = sum(item["size_bytes"] for item in files)
    payload: Dict[str, Any] = {
        "schema_version": schema_version,
        "app_name": "CodeProbe",
        "app_version": app_version,
        "file_count": len(files),
        "total_source_size_bytes": total_size,
        "files": files,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
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
    """Return package-level size and member accounting for a release ZIP.

    The result is intentionally separate from release/release-manifest.json because the
    final ZIP hash cannot be embedded inside the ZIP without changing the hash.
    This sidecar-style summary is the correct audit artefact for comparing two
    downloaded releases whose compressed sizes differ.
    """
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


def verify_manifest(root: Path) -> List[str]:
    """Verify ``release/release-manifest.json`` against current files."""
    root = root.resolve()
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.exists():
        return [f"{MANIFEST_NAME} is missing; restore the tracked manifest from version control before refreshing release evidence"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{MANIFEST_NAME} is not valid JSON: {exc}"]
    errors: List[str] = []
    recorded = {item.get("path"): item for item in manifest.get("files", []) if isinstance(item, dict)}
    current = {path.relative_to(root).as_posix(): path for path in iter_release_files(root)}
    for relative, item in sorted(recorded.items()):
        if relative not in current:
            errors.append(f"recorded file missing from current release set: {relative}")
            continue
        if item.get("sha256") != sha256_file(current[relative]):
            errors.append(f"hash mismatch: {relative}")
    for relative in sorted(set(current) - set(recorded)):
        errors.append(f"current file missing from manifest: {relative}")
    return errors
