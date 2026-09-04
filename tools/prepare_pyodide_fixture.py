#!/usr/bin/env python3
"""Prepare the exact Pyodide core fixture used by the functional browser gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "app" / "pyodide-provenance.json"
READ_CHUNK_BYTES = 65_536
TIMEOUT_SECONDS = 45


class FixtureError(RuntimeError):
    """Raised when a runtime fixture cannot be prepared safely."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_provenance(path: Path = PROVENANCE) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"cannot read Pyodide provenance: {type(exc).__name__}") from exc
    if not isinstance(data, dict) or data.get("schema") != "codeprobe-pyodide-provenance/v1":
        raise FixtureError("unsupported Pyodide provenance schema")
    base = str(data.get("distribution_base_url") or "")
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme != "https" or not parsed.netloc or not base.endswith("/"):
        raise FixtureError("distribution_base_url must be an absolute HTTPS directory URL")
    records = data.get("startup_artifacts")
    if not isinstance(records, list) or not records:
        raise FixtureError("startup_artifacts must be a non-empty array")
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise FixtureError("startup artefact records must be objects")
        name = str(record.get("name") or "")
        if not name or name in names or Path(name).name != name:
            raise FixtureError(f"invalid or duplicate startup artefact name: {name!r}")
        names.add(name)
        size = record.get("size_bytes")
        digest = str(record.get("sha256_hex") or "")
        if type(size) is not int or size <= 0:
            raise FixtureError(f"{name} has an invalid size")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise FixtureError(f"{name} has an invalid SHA-256 value")
    return data


def _verify_bytes(name: str, content: bytes, record: dict[str, Any]) -> None:
    expected_size = int(record["size_bytes"])
    if len(content) != expected_size:
        raise FixtureError(f"{name} size mismatch: expected {expected_size}, received {len(content)}")
    actual = hashlib.sha256(content).hexdigest()
    if actual != record["sha256_hex"]:
        raise FixtureError(f"{name} SHA-256 mismatch")


def _download(url: str, *, expected_size: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/octet-stream", "User-Agent": "CodeProbe-runtime-fixture/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            final = response.geturl()
            if final != url:
                raise FixtureError(f"runtime artefact redirected unexpectedly: {final}")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) != expected_size:
                raise FixtureError(
                    f"runtime artefact Content-Length mismatch: expected {expected_size}, received {declared}"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(min(READ_CHUNK_BYTES, expected_size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    raise FixtureError("runtime artefact exceeded its recorded size")
                chunks.append(chunk)
    except FixtureError:
        raise
    except (OSError, ValueError) as exc:
        raise FixtureError(f"runtime artefact download failed: {type(exc).__name__}") from exc
    return b"".join(chunks)


def _read_local(source: Path, *, expected_size: int) -> bytes:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise FixtureError(f"fixture source is unavailable: {source.name}") from exc
    if source.is_symlink() or not source.is_file() or metadata.st_size > expected_size:
        raise FixtureError(f"fixture source is not a bounded regular file: {source.name}")
    try:
        content = source.read_bytes()
    except OSError as exc:
        raise FixtureError(f"fixture source could not be read: {source.name}") from exc
    return content


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise FixtureError(f"fixture destination is not a regular file: {path.name}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def prepare_fixture(
    output_dir: Path,
    *,
    source_dir: Path | None = None,
    provenance_path: Path = PROVENANCE,
) -> dict[str, Any]:
    provenance = load_provenance(provenance_path)
    if output_dir.is_symlink():
        raise FixtureError("fixture output directory must not be a symbolic link")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not output_dir.is_dir():
        raise FixtureError("fixture output path is not a directory")
    if source_dir is not None and source_dir.is_symlink():
        raise FixtureError("fixture source directory must not be a symbolic link")
    source_root = source_dir.resolve() if source_dir is not None else None
    if source_root is not None and not source_root.is_dir():
        raise FixtureError("fixture source path is not a directory")
    base = str(provenance["distribution_base_url"])
    prepared = []
    for record in provenance["startup_artifacts"]:
        name = str(record["name"])
        if source_root is None:
            content = _download(urllib.parse.urljoin(base, name), expected_size=int(record["size_bytes"]))
            source = "network"
        else:
            content = _read_local(source_root / name, expected_size=int(record["size_bytes"]))
            source = "local"
        _verify_bytes(name, content, record)
        _write_atomic(output_dir / name, content)
        prepared.append({
            "name": name,
            "size_bytes": len(content),
            "sha256_hex": hashlib.sha256(content).hexdigest(),
            "source": source,
        })
    return {
        "schema": "codeprobe-pyodide-functional-fixture/v1",
        "version": provenance["version"],
        "source": "local" if source_root is not None else "network",
        "artifacts": prepared,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--provenance", type=Path, default=PROVENANCE)
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = prepare_fixture(
            args.output_dir,
            source_dir=args.source_dir,
            provenance_path=args.provenance,
        )
        if args.json_out:
            _write_atomic(
                args.json_out.resolve(),
                (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
            )
    except FixtureError as exc:
        print(f"[FAIL] pyodide-fixture: {exc}")
        return 1
    print(
        f"[PASS] pyodide-fixture: {len(summary['artifacts'])} verified startup artefacts "
        f"prepared for Pyodide {summary['version']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
