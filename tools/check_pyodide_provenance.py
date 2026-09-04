#!/usr/bin/env python3
"""Validate CodeProbe's deterministic Pyodide startup provenance boundary."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any


CONFIG_SCHEMA = "codeprobe-runtime-config/v1"
PROVENANCE_SCHEMA = "codeprobe-pyodide-provenance/v1"
REQUIRED_ARTIFACTS = (
    "pyodide.js",
    "pyodide-lock.json",
    "python_stdlib.zip",
    "pyodide.asm.js",
    "pyodide.asm.wasm",
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class PyodideProvenanceError(ValueError):
    """Raised when provenance metadata is incomplete or inconsistent."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PyodideProvenanceError(f"{label} must be an object")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise PyodideProvenanceError(f"{label} must be a positive integer")
    return value


def _sha256(value: Any, label: str) -> str:
    rendered = str(value)
    if not SHA256_PATTERN.fullmatch(rendered):
        raise PyodideProvenanceError(f"{label} must be lower-case SHA-256 hex")
    return rendered


def _sri_for_hex(digest: str) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(digest)).decode("ascii")


def load_unique_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_pairs)
    value = decoder.decode(text)
    if not isinstance(value, dict):
        raise PyodideProvenanceError(f"{path.name} must contain a JSON object")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PyodideProvenanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def audit_pyodide_provenance(root: Path) -> list[str]:
    errors: list[str] = []
    root_path = Path(root)
    config_path = root_path / "app" / "runtime-config.json"
    provenance_path = root_path / "app" / "pyodide-provenance.json"
    loader_path = root_path / "app" / "pyodide-loader.js"
    resource_integrity_path = root_path / "app" / "resource-integrity.json"
    main_ui_path = root_path / "app" / "codeprobe-ui.js"
    project_ui_path = root_path / "app" / "project-ui.js"
    engine_path = root_path / "src" / "codeprobe_runtime.py"
    try:
        config = load_unique_json(config_path)
        provenance = load_unique_json(provenance_path)
        resource_integrity = load_unique_json(resource_integrity_path)
    except (OSError, UnicodeError, json.JSONDecodeError, PyodideProvenanceError) as exc:
        return [str(exc)]

    try:
        if config.get("schema") != CONFIG_SCHEMA:
            raise PyodideProvenanceError(f"runtime config schema must be {CONFIG_SCHEMA}")
        if config.get("production") is not True:
            raise PyodideProvenanceError("runtime config must declare production: true")
        pyodide = _object(config.get("pyodide"), "runtime config pyodide")
        version = str(pyodide.get("version", ""))
        if not VERSION_PATTERN.fullmatch(version):
            raise PyodideProvenanceError("Pyodide version must be exact semantic version text")
        if pyodide.get("mode") not in {"cdn", "local"}:
            raise PyodideProvenanceError("Pyodide mode must be cdn or local")
        if pyodide.get("require_integrity") is not True:
            raise PyodideProvenanceError("production Pyodide loading must require integrity")
        if pyodide.get("verify_core_startup_set") is not True:
            raise PyodideProvenanceError("production Pyodide loading must verify the core startup set")
        configured_loader_digest = _sha256(
            pyodide.get("expected_loader_sha256"),
            "configured loader digest",
        )
        if pyodide.get("provenance_url") != "pyodide-provenance.json":
            raise PyodideProvenanceError("runtime config must use the packaged provenance manifest")
        expected_base = f"https://cdn.jsdelivr.net/pyodide/v{version}/full/"
        if pyodide.get("index_url") != expected_base:
            raise PyodideProvenanceError("CDN index URL is not pinned to the declared Pyodide version")
        if pyodide.get("loader_url") != expected_base + "pyodide.js":
            raise PyodideProvenanceError("CDN loader URL is not pinned to the declared Pyodide version")

        if provenance.get("schema") != PROVENANCE_SCHEMA:
            raise PyodideProvenanceError(f"provenance schema must be {PROVENANCE_SCHEMA}")
        if provenance.get("version") != version:
            raise PyodideProvenanceError("provenance version differs from runtime configuration")
        if provenance.get("distribution_base_url") != expected_base:
            raise PyodideProvenanceError("provenance distribution URL is not the pinned CDN base")
        upstream = _object(provenance.get("upstream"), "provenance upstream")
        if upstream.get("repository") != "pyodide/pyodide":
            raise PyodideProvenanceError("upstream repository must be pyodide/pyodide")
        if upstream.get("tag") != version:
            raise PyodideProvenanceError("upstream tag differs from the declared version")
        if not COMMIT_PATTERN.fullmatch(str(upstream.get("commit", ""))):
            raise PyodideProvenanceError("upstream commit must be a lower-case 40-character SHA")
        core = _object(upstream.get("core_release_asset"), "core release asset")
        if core.get("name") != f"pyodide-core-{version}.tar.bz2":
            raise PyodideProvenanceError("core release asset name differs from the declared version")
        _positive_integer(core.get("size_bytes"), "core release asset size")
        core_digest = _sha256(core.get("sha256_hex"), "core release asset digest")
        if core.get("sri_sha256") != _sri_for_hex(core_digest):
            raise PyodideProvenanceError("core release asset SRI does not match SHA-256")

        lock_info = _object(provenance.get("lock_info"), "lock_info")
        if lock_info.get("version") != version:
            raise PyodideProvenanceError("lock metadata version differs from the declared version")
        if not VERSION_PATTERN.fullmatch(str(lock_info.get("python", ""))):
            raise PyodideProvenanceError("lock metadata requires an exact Python version")
        _positive_integer(lock_info.get("package_count"), "lock package count")

        records = provenance.get("startup_artifacts")
        if not isinstance(records, list):
            raise PyodideProvenanceError("startup_artifacts must be an array")
        by_name: dict[str, dict[str, Any]] = {}
        for raw_record in records:
            record = _object(raw_record, "startup artefact")
            name = str(record.get("name", ""))
            if name not in REQUIRED_ARTIFACTS or name in by_name:
                raise PyodideProvenanceError(f"unexpected or duplicate startup artefact: {name}")
            _positive_integer(record.get("size_bytes"), f"{name} size")
            digest = _sha256(record.get("sha256_hex"), f"{name} digest")
            if record.get("sri_sha256") != _sri_for_hex(digest):
                raise PyodideProvenanceError(f"{name} SRI does not match SHA-256")
            by_name[name] = record
        missing = sorted(set(REQUIRED_ARTIFACTS) - set(by_name))
        if missing:
            raise PyodideProvenanceError(
                "provenance is missing startup artefacts: " + ", ".join(missing)
            )
        if by_name["pyodide.js"]["sha256_hex"] != configured_loader_digest:
            raise PyodideProvenanceError("configured loader digest differs from provenance")
        if not str(provenance.get("assurance_boundary", "")).strip():
            raise PyodideProvenanceError("provenance must state its assurance boundary")
    except PyodideProvenanceError as exc:
        errors.append(str(exc))

    try:
        loader = loader_path.read_text(encoding="utf-8")
        main_ui = main_ui_path.read_text(encoding="utf-8")
        project_ui = project_ui_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(str(exc))
    else:
        required_loader_fragments = (
            "loadVerifiedStartupSet",
            "withVerifiedBootstrapFetch",
            "responseForVerifiedArtifact",
            'appendVerifiedScript("pyodide.js"',
            'appendVerifiedScript("pyodide.asm.js"',
            "lockFileURL:",
            "stdLibURL:",
            "loadVerifiedPyodide",
            "loadVerifiedEngine",
            "decodeSourceBytes",
            "normaliseProjectPath",
            "Loaded Pyodide version mismatch",
            "Loaded Python version mismatch",
            "Pyodide bootstrap did not consume the verified",
        )
        for fragment in required_loader_fragments:
            if fragment not in loader:
                errors.append(f"pyodide-loader.js is missing {fragment}")

        record_match = re.search(
            r"const\s+PACKAGED_ENGINE_RECORD\s*=\s*Object\.freeze\(\{(?P<body>.*?)\}\);",
            loader,
            re.S,
        )
        if not record_match:
            errors.append("pyodide-loader.js is missing the packaged engine integrity record")
        else:
            body = record_match.group("body")
            path_match = re.search(r'path:\s*"(?P<value>[^"]+)"', body)
            size_match = re.search(r"size_bytes:\s*(?P<value>[0-9]+)", body)
            digest_match = re.search(r'sha256_hex:\s*"(?P<value>[0-9a-f]{64})"', body)
            if not path_match or path_match.group("value") != "../src/codeprobe_runtime.py":
                errors.append("packaged engine record path is invalid")
            try:
                engine_bytes = engine_path.read_bytes()
            except OSError as exc:
                errors.append(f"packaged engine could not be read: {type(exc).__name__}")
            else:
                if not size_match or int(size_match.group("value")) != len(engine_bytes):
                    errors.append("packaged engine record size differs from the exact engine bytes")
                actual_digest = hashlib.sha256(engine_bytes).hexdigest()
                if not digest_match or digest_match.group("value") != actual_digest:
                    errors.append("packaged engine record digest differs from the exact engine bytes")
                integrity_records = resource_integrity.get("assets")
                if not isinstance(integrity_records, list):
                    errors.append("resource-integrity.json assets must be an array")
                else:
                    engine_records = [
                        item for item in integrity_records
                        if isinstance(item, dict) and item.get("path") == "../src/codeprobe_runtime.py"
                    ]
                    if len(engine_records) != 1:
                        errors.append("resource-integrity.json must contain exactly one packaged engine record")
                    else:
                        integrity_record = engine_records[0]
                        if integrity_record.get("size_bytes") != len(engine_bytes):
                            errors.append("resource-integrity packaged engine size differs from exact bytes")
                        if integrity_record.get("sha256_hex") != actual_digest:
                            errors.append("resource-integrity packaged engine digest differs from exact bytes")
                        if size_match and integrity_record.get("size_bytes") != int(size_match.group("value")):
                            errors.append("embedded and resource-integrity engine sizes disagree")
                        if digest_match and integrity_record.get("sha256_hex") != digest_match.group("value"):
                            errors.append("embedded and resource-integrity engine digests disagree")

        direct_engine_fetch = re.compile(
            r"""fetch\s*\(\s*(?:new\s+URL\s*\(\s*)?["'](?:\.\./)?src/codeprobe_runtime\.py["']"""
        )
        for name, source in (("codeprobe-ui.js", main_ui), ("project-ui.js", project_ui)):
            if "CodeProbeRuntime.loadVerifiedPyodide" not in source:
                errors.append(f"{name} does not use the verified Pyodide entry point")
            if "CodeProbeRuntime.loadVerifiedEngine" not in source:
                errors.append(f"{name} does not use the verified Python-engine entry point")
            if re.search(r"\bwindow\.loadPyodide\s*\(|(?<![.\w])loadPyodide\s*\(", source):
                errors.append(f"{name} bypasses the verified Pyodide entry point")
            if direct_engine_fetch.search(source):
                errors.append(f"{name} fetches the Python engine outside the verified entry point")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = audit_pyodide_provenance(root)
    if errors:
        for error in errors[:20]:
            print(f"[FAIL] pyodide-provenance: {error}")
        return 1
    print(
        "[PASS] pyodide-provenance: production configuration, measured core startup metadata "
        "and verified browser entry points are consistent"
    )
    print(
        "[LIMITATION] pyodide-provenance: optional packages, upstream build reproducibility, "
        "availability and the complete current vulnerability status remain outside this deterministic check"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
