#!/usr/bin/env python3
"""Prepare the exact Pyodide core fixture used by the functional browser gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.append(str(ROOT / "src"))

from codeprobe_engine.release import (  # noqa: E402
    ReleaseSetError,
    read_regular_file,
    validate_diagnostic_outputs,
)

PROVENANCE = ROOT / "app" / "pyodide-provenance.json"
READ_CHUNK_BYTES = 65_536
TIMEOUT_SECONDS = 45
CORE_NAMES = frozenset({
    "pyodide.js", "pyodide-lock.json", "python_stdlib.zip",
    "pyodide.asm.js", "pyodide.asm.wasm",
})


class FixtureError(RuntimeError):
    """Raised when a runtime fixture cannot be prepared safely."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise FixtureError(f"non-finite JSON constant: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise FixtureError("non-finite JSON number")
    return result


def load_provenance(path: Path = PROVENANCE) -> dict[str, Any]:
    try:
        data = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (OSError, ValueError, RecursionError) as exc:
        raise FixtureError(f"cannot read Pyodide provenance: {type(exc).__name__}") from exc
    if not isinstance(data, dict) or data.get("schema") != "codeprobe-pyodide-provenance/v1":
        raise FixtureError("unsupported Pyodide provenance schema")
    version = data.get("version")
    if not isinstance(version, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version) is None:
        raise FixtureError("version must be a numeric major.minor.patch string")
    base = data.get("distribution_base_url")
    if not isinstance(base, str) or any(ord(char) < 33 or ord(char) > 126 for char in base) or "\\" in base:
        raise FixtureError("distribution_base_url must be an absolute HTTPS directory URL")
    try:
        parsed = urllib.parse.urlparse(base)
        valid_url = (
            parsed.scheme == "https" and parsed.hostname is not None
            and parsed.username is None and parsed.password is None
            and parsed.port != 0 and not parsed.query and not parsed.fragment
            and base.endswith("/")
        )
    except ValueError:
        valid_url = False
    if not valid_url:
        raise FixtureError("distribution_base_url must be an absolute HTTPS directory URL")
    records = data.get("startup_artifacts")
    if not isinstance(records, list) or len(records) != len(CORE_NAMES):
        raise FixtureError("startup_artifacts must contain exactly the five core artefacts")
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise FixtureError("startup artefact records must be objects")
        name = record.get("name")
        if not isinstance(name, str) or name not in CORE_NAMES or name in names:
            raise FixtureError(f"invalid or duplicate startup artefact name: {name!r}")
        names.add(name)
        size = record.get("size_bytes")
        digest = record.get("sha256_hex")
        if type(size) is not int or size <= 0:
            raise FixtureError(f"{name} has an invalid size")
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise FixtureError(f"{name} has an invalid SHA-256 value")
    if names != CORE_NAMES:
        raise FixtureError("startup_artifacts must contain exactly the five core artefacts")
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
        return read_regular_file(source, max_bytes=expected_size)
    except (ReleaseSetError, OSError, ValueError) as exc:
        raise FixtureError(f"fixture source is not a bounded regular file or changed: {source.name!r}: {exc}") from exc


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


def _preflight_outputs(destinations: list[Path], inputs: list[Path]) -> list[Path]:
    try:
        return list(validate_diagnostic_outputs(destinations, inputs=inputs))
    except ReleaseSetError as exc:
        raise FixtureError(f"unsafe fixture output: {exc}") from exc


def prepare_fixture(
    output_dir: Path,
    *,
    source_dir: Path | None = None,
    provenance_path: Path = PROVENANCE,
    json_out: Path | None = None,
) -> dict[str, Any]:
    provenance = load_provenance(provenance_path)
    try:
        if output_dir.is_symlink():
            raise FixtureError("fixture output directory must not be a symbolic link")
        output_dir = output_dir.resolve()
        if output_dir.exists() and not output_dir.is_dir():
            raise FixtureError("fixture output path is not a directory")
        if source_dir is not None and source_dir.is_symlink():
            raise FixtureError("fixture source directory must not be a symbolic link")
        source_root = source_dir.resolve() if source_dir is not None else None
        if source_root is not None and not source_root.is_dir():
            raise FixtureError("fixture source path is not a directory")
    except FixtureError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise FixtureError(f"fixture directory cannot be inspected: {type(exc).__name__}") from exc
    records = provenance["startup_artifacts"]
    destinations = [output_dir / record["name"] for record in records]
    if json_out is not None:
        destinations.append(json_out)
    inputs = [provenance_path]
    if source_root is not None:
        inputs.extend(source_root / record["name"] for record in records)
    for directory in (ROOT / "src", ROOT / "tools"):
        inputs.extend(directory.rglob("*.py"))
    destinations = _preflight_outputs(destinations, inputs)
    source = "local" if source_root is not None else "network"
    summary = {
        "schema": "codeprobe-pyodide-functional-fixture/v1",
        "version": provenance["version"],
        "source": source,
        "artifacts": [{
            "name": record["name"],
            "size_bytes": record["size_bytes"],
            "sha256_hex": record["sha256_hex"],
            "source": source,
        } for record in records],
    }
    try:
        summary_bytes = (json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise FixtureError("fixture summary cannot be encoded") from exc
    base = provenance["distribution_base_url"]
    for record, destination in zip(records, destinations):
        name = record["name"]
        if source_root is None:
            content = _download(urllib.parse.urljoin(base, name), expected_size=record["size_bytes"])
        else:
            content = _read_local(source_root / name, expected_size=record["size_bytes"])
        _verify_bytes(name, content, record)
        _preflight_outputs(destinations, inputs)
        try:
            _write_atomic(destination, content)
        except OSError as exc:
            raise FixtureError(f"cannot publish fixture artefact: {name}: {type(exc).__name__}") from exc
    if json_out is not None:
        _preflight_outputs(destinations, inputs)
        try:
            _write_atomic(destinations[-1], summary_bytes)
        except OSError as exc:
            raise FixtureError(f"cannot publish fixture summary: {type(exc).__name__}") from exc
    return summary


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
            json_out=args.json_out,
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
