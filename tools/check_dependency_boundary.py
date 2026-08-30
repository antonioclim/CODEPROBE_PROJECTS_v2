#!/usr/bin/env python3
"""Check CodeProbe's deterministic offline dependency boundary.

This checker deliberately does not query a package registry, an advisory
database or the configured Pyodide distribution.  It verifies the dependency
claims that can be established from a checkout alone: the absence of an
unapproved package-manager graph, standard-library or repository-local Python
imports, the declared Pyodide locations, literal remote executable locations
and pinned GitHub Actions references.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]

PYODIDE_SCHEMA = "codeprobe-runtime-config/v1"
PYODIDE_VERSION = "0.25.0"
PYODIDE_ORIGIN = "https://cdn.jsdelivr.net"
PYODIDE_LOADER_URL = f"{PYODIDE_ORIGIN}/pyodide/v{PYODIDE_VERSION}/full/pyodide.js"
PYODIDE_INDEX_URL = f"{PYODIDE_ORIGIN}/pyodide/v{PYODIDE_VERSION}/full/"
PYODIDE_LOCAL_LOADER_URL = f"vendor/pyodide/v{PYODIDE_VERSION}/full/pyodide.js"
PYODIDE_LOCAL_INDEX_URL = f"vendor/pyodide/v{PYODIDE_VERSION}/full/"
EXAMPLE_DIGEST_PLACEHOLDER = "PUT_REAL_SHA256_OF_LOCAL_OR_CDN_PYODIDE_JS_HERE"

APPROVED_ACTIONS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/setup-node": ("820762786026740c76f36085b0efc47a31fe5020", "v7.0.0"),
}

APPROVED_LOCAL_IMPORTS = {
    "audit_institutional_pack",
    "build_release",
    "calibrate_corpus",
    "calibrate_profile",
    "check_dependency_boundary",
    "check_file_references",
    "check_naming",
    "check_release",
    "check_release_reproducibility",
    "codeprobe_engine",
    "codeprobe_runtime",
    "compare_releases",
    "final_audit",
}

APPROVED_STDLIB_IMPORTS = {
    "__future__",
    "abc",
    "argparse",
    "ast",
    "base64",
    "collections",
    "contextlib",
    "copy",
    "csv",
    "dataclasses",
    "difflib",
    "fnmatch",
    "functools",
    "hashlib",
    "http",
    "importlib",
    "io",
    "json",
    "keyword",
    "math",
    "os",
    "pathlib",
    "py_compile",
    "re",
    "shutil",
    "socket",
    "stat",
    "statistics",
    "subprocess",
    "sys",
    "tarfile",
    "tempfile",
    "time",
    "tokenize",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "webbrowser",
    "zipfile",
    "zlib",
}

EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "dist",
}

EXACT_PACKAGE_MANIFEST_NAMES = {
    "bower.json",
    "bun.lock",
    "bun.lockb",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "environment.yaml",
    "environment.yml",
    "jsr.json",
    "jsr.jsonc",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "package.json",
    "pdm.lock",
    "pipfile",
    "pipfile.lock",
    "pixi.lock",
    "pixi.toml",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "pnpm-workspace.yaml",
    "pnpm-workspace.yml",
    "poetry.lock",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "uv.lock",
    "yarn.lock",
}

PYTHON_REQUIREMENT_NAME = re.compile(
    r"^(?:[a-z0-9_.-]+[-_.])?(?:requirements?|constraints?)"
    r"(?:[-_.][a-z0-9_.-]+)?\.(?:in|lock|txt)$",
    re.IGNORECASE,
)
PYTHON_LOCK_NAME = re.compile(r"^pylock(?:\.[a-z0-9_.-]+)?\.toml$", re.IGNORECASE)
LOWER_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REMOTE_URL = re.compile(r"https?://[^\s\"'`<>\\]+", re.IGNORECASE)
PROTOCOL_RELATIVE_URL = re.compile(r"[\"'](?P<url>//[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[^\"']*)?)[\"']")
HTML_PROTOCOL_RELATIVE_URL = re.compile(
    r"\b(?:href|src)\s*=\s*(?:[\"']?)(?P<url>//[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[^\s\"'>]*)?)",
    re.IGNORECASE,
)
REMOTE_USES = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*(?P<quote>[\"']?)(?P<reference>[^\s#\"']+)(?P=quote)"
    r"\s*(?:#\s*(?P<comment>\S+)\s*)?$"
)
DYNAMIC_JAVASCRIPT_LOADERS = (
    (re.compile(r"\bimport\s*\("), "dynamic JavaScript import"),
    (re.compile(r"\brequire\s*\("), "dynamic CommonJS import"),
    (re.compile(r"\bimportScripts\s*\("), "dynamic worker import"),
    (re.compile(r"\bmicropip\.install\s*\("), "micropip package installation"),
    (re.compile(r"\b(?:loadPackage|loadPackagesFromImports)\s*\("), "dynamic Pyodide package loading"),
)
PACKAGE_MANAGER_COMMAND = re.compile(
    r"(?:^|\s)(?:-m\s+pip\s+install|npm\s+(?:ci|install)|npx(?:\s|$)|pip(?:3)?\s+install|"
    r"pnpm\s+(?:add|install)|(?:[^\s/]+/)?python(?:3(?:\.\d+)?)?\s+-m\s+pip\s+install|"
    r"yarn\s+(?:add|install))(?:\s|$)",
    re.IGNORECASE,
)
QUOTED_YAML_KEY = re.compile(r"^\s*(?:-\s*)?[\"'][^\"']+[\"']\s*:")
FLOW_CRITICAL_YAML_KEY = re.compile(
    r"[,{]\s*[\"']?(?:permissions|persist-credentials|uses)[\"']?\s*:"
)

CONFIG_TOP_LEVEL_FIELDS = {"schema", "pyodide", "privacy"}
PYODIDE_FIELDS = {
    "mode",
    "version",
    "loader_url",
    "index_url",
    "local_loader_url",
    "local_index_url",
    "expected_loader_sha256",
    "require_integrity",
}
PRIVACY_FIELDS = {
    "history_enabled_default",
    "store_source_in_history",
    "clear_pyodide_payload_after_run",
}

EXTERNAL_RUNTIME_LIMITATION = (
    "Pyodide vulnerability status, upstream provenance and the complete CDN or "
    "vendored distribution are not audited by this deterministic offline check."
)


class DuplicateJsonKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield checkout files without descending into release-excluded directories."""
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name.casefold() not in EXCLUDED_DIRECTORY_NAMES
        )
        base = Path(directory)
        for name in sorted(file_names):
            yield base / name


def _read_text(path: Path, root: Path, errors: list[str]) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"unreadable UTF-8 file {_relative(path, root)}: {exc}")
        return None


def _is_package_manifest(path: Path, root: Path) -> bool:
    name = path.name.lower()
    if name in EXACT_PACKAGE_MANIFEST_NAMES:
        return True
    if PYTHON_REQUIREMENT_NAME.fullmatch(name):
        return True
    if PYTHON_LOCK_NAME.fullmatch(name):
        return True
    relative_parts = [part.lower() for part in path.relative_to(root).parts]
    return (
        "requirements" in relative_parts[:-1]
        and path.suffix.lower() in {".in", ".lock", ".txt"}
    )


def check_package_manifests(root: Path) -> list[str]:
    errors: list[str] = []
    for path in _iter_files(root):
        if _is_package_manifest(path, root):
            errors.append(
                f"unapproved package manifest {_relative(path, root)}; "
                "no package-audit path is configured"
            )
    return errors


def check_vendor_boundary(root: Path) -> list[str]:
    """Reject vendored runtime bytes until a provenance inventory is introduced."""
    vendor = root / "app" / "vendor"
    if not vendor.exists():
        return []
    allowed = {Path("pyodide/README.md")}
    errors: list[str] = []
    for path in _iter_files(vendor):
        relative = path.relative_to(vendor)
        if relative not in allowed:
            errors.append(
                f"unapproved vendored runtime file app/vendor/{relative.as_posix()}; "
                "no provenance inventory is configured"
            )
    return errors


def _python_files(root: Path) -> Iterable[Path]:
    for path in _iter_files(root):
        if path.suffix.lower() in {".py", ".pyw"}:
            yield path


def _local_module_names(root: Path) -> set[str]:
    names: set[str] = set()
    for area_name in ("src", "tools", "tests"):
        area = root / area_name
        if not area.is_dir():
            continue
        names.update(path.stem for path in area.glob("*.py"))
        names.update(path.name for path in area.iterdir() if path.is_dir() and (path / "__init__.py").is_file())
    return names


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    current: ast.expr = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _literal_command_text(node: ast.Call) -> str:
    values: list[str] = []
    for argument in node.args:
        for child in ast.walk(argument):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                values.append(child.value)
    return " ".join(values).lower()


def _literal_value_text(node: ast.AST) -> str:
    return " ".join(
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ).lower()


def check_python_imports(root: Path) -> list[str]:
    errors: list[str] = []
    stdlib_names = APPROVED_STDLIB_IMPORTS
    local_names = _local_module_names(root) & APPROVED_LOCAL_IMPORTS
    dynamic_call_leaves = {
        "__import__",
        "import_module",
        "load_entry_point",
        "module_from_spec",
        "resolve_name",
        "run_module",
        "spec_from_file_location",
    }
    process_call_leaves = {"call", "check_call", "check_output", "Popen", "run", "system"}
    for path in _python_files(root):
        source = _read_text(path, root, errors)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError) as exc:
            errors.append(f"cannot inspect Python imports in {_relative(path, root)}: {exc}")
            continue
        dynamic_aliases: set[str] = set()
        process_aliases: set[str] = set()
        assigned_command_text: dict[str, str] = {}
        for candidate in ast.walk(tree):
            if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                value = candidate.value
                targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target]
                literal_text = _literal_value_text(value) if value is not None else ""
                for target in targets:
                    if isinstance(target, ast.Name) and literal_text:
                        assigned_command_text[target.id] = literal_text
            if not isinstance(candidate, ast.ImportFrom) or candidate.level != 0 or not candidate.module:
                continue
            imported_module = candidate.module.split(".", 1)[0]
            for alias in candidate.names:
                local_name = alias.asname or alias.name
                if imported_module in {"importlib", "pkg_resources", "pkgutil", "runpy"}:
                    if alias.name in dynamic_call_leaves:
                        dynamic_aliases.add(local_name)
                if imported_module in {"os", "subprocess"} and alias.name in process_call_leaves:
                    process_aliases.add(local_name)
        for node in ast.walk(tree):
            imported: list[tuple[str, int]] = []
            if isinstance(node, ast.Import):
                imported.extend((alias.name.split(".", 1)[0], node.lineno) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.append((node.module.split(".", 1)[0], node.lineno))
            for module_name, line_number in imported:
                if module_name not in stdlib_names and module_name not in local_names:
                    errors.append(
                        f"third-party or unresolved import {module_name!r} in "
                        f"{_relative(path, root)}:{line_number}"
                    )
            if isinstance(node, ast.Attribute) and node.attr in dynamic_call_leaves:
                errors.append(
                    f"dynamic package-loading reference {node.attr!r} in "
                    f"{_relative(path, root)}:{node.lineno}"
                )
            elif (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in dynamic_aliases
            ):
                errors.append(
                    f"dynamic package-loading reference {node.id!r} in "
                    f"{_relative(path, root)}:{node.lineno}"
                )
            if isinstance(node, ast.Call):
                call_name = _call_name(node)
                call_leaf = call_name.rsplit(".", 1)[-1]
                if call_leaf in dynamic_call_leaves or call_name in dynamic_aliases:
                    errors.append(
                        f"dynamic package-loading construct {call_name!r} in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                command_text = _literal_command_text(node)
                if node.args and isinstance(node.args[0], ast.Name):
                    command_text = f"{command_text} {assigned_command_text.get(node.args[0].id, '')}".strip()
                if (
                    call_leaf in process_call_leaves or call_name in process_aliases
                ) and PACKAGE_MANAGER_COMMAND.search(command_text):
                    errors.append(
                        f"package-manager command launched by {call_name!r} in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
    return errors


def check_javascript_package_loading(root: Path) -> list[str]:
    errors: list[str] = []
    app = root / "app"
    if not app.is_dir():
        return ["missing browser application directory: app"]
    for suffix in ("*.cjs", "*.js", "*.mjs"):
        for path in sorted(app.rglob(suffix)):
            source = _read_text(path, root, errors)
            if source is None:
                continue
            for pattern, label in DYNAMIC_JAVASCRIPT_LOADERS:
                match = pattern.search(source)
                if match:
                    line_number = source.count("\n", 0, match.start()) + 1
                    errors.append(
                        f"{label} in {_relative(path, root)}:{line_number}"
                    )
    return errors


def _load_json_object(path: Path, root: Path, errors: list[str]) -> dict[str, Any] | None:
    source = _read_text(path, root, errors)
    if source is None:
        return None
    try:
        payload = json.loads(source, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, DuplicateJsonKeyError, RecursionError) as exc:
        errors.append(f"invalid JSON in {_relative(path, root)}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"JSON root is not an object in {_relative(path, root)}")
        return None
    return payload


def _field_set_error(label: str, actual: set[str], expected: set[str]) -> str | None:
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing {', '.join(missing)}")
    if unexpected:
        details.append(f"unexpected {', '.join(unexpected)}")
    return f"{label} fields are invalid ({'; '.join(details)})" if details else None


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme != "https" or not hostname or username or password:
        return ""
    host = hostname.lower()
    if port is not None:
        host = f"{host}:{port}"
    return f"https://{host}"


def _validate_runtime_config(
    path: Path,
    root: Path,
    *,
    example: bool,
) -> list[str]:
    errors: list[str] = []
    payload = _load_json_object(path, root, errors)
    if payload is None:
        return errors
    label = _relative(path, root)

    field_error = _field_set_error(label, set(payload), CONFIG_TOP_LEVEL_FIELDS)
    if field_error:
        errors.append(field_error)
    if payload.get("schema") != PYODIDE_SCHEMA:
        errors.append(f"{label} has an invalid schema")

    pyodide = payload.get("pyodide")
    if not isinstance(pyodide, dict):
        errors.append(f"{label} pyodide configuration is not an object")
        return errors
    field_error = _field_set_error(f"{label} pyodide", set(pyodide), PYODIDE_FIELDS)
    if field_error:
        errors.append(field_error)

    privacy = payload.get("privacy")
    if not isinstance(privacy, dict):
        errors.append(f"{label} privacy configuration is not an object")
    else:
        field_error = _field_set_error(f"{label} privacy", set(privacy), PRIVACY_FIELDS)
        if field_error:
            errors.append(field_error)
        for name in PRIVACY_FIELDS:
            if name in privacy and not isinstance(privacy[name], bool):
                errors.append(f"{label} privacy field {name!r} is not Boolean")

    if pyodide.get("version") != PYODIDE_VERSION:
        errors.append(f"{label} does not declare Pyodide {PYODIDE_VERSION}")
    mode = pyodide.get("mode")
    if mode not in {"cdn", "local"}:
        errors.append(f"{label} has an invalid Pyodide mode")
    if example and mode != "local":
        errors.append(f"{label} must demonstrate local Pyodide mode")
    if not example and mode == "local":
        errors.append(
            f"{label} cannot select local Pyodide until a vendored provenance inventory exists"
        )

    expected_locations = {
        "loader_url": PYODIDE_LOADER_URL,
        "index_url": PYODIDE_INDEX_URL,
        "local_loader_url": PYODIDE_LOCAL_LOADER_URL,
        "local_index_url": PYODIDE_LOCAL_INDEX_URL,
    }
    for field_name, expected in expected_locations.items():
        actual = pyodide.get(field_name)
        if actual != expected:
            errors.append(f"{label} has an inconsistent {field_name}")
        if field_name in {"loader_url", "index_url"} and isinstance(actual, str):
            if _origin(actual) != PYODIDE_ORIGIN:
                errors.append(f"{label} {field_name} is not on the approved HTTPS origin")

    require_integrity = pyodide.get("require_integrity")
    digest = pyodide.get("expected_loader_sha256")
    if not isinstance(require_integrity, bool):
        errors.append(f"{label} require_integrity is not Boolean")
    if not isinstance(digest, str):
        errors.append(f"{label} expected_loader_sha256 is not a string")
    elif example:
        if digest != EXAMPLE_DIGEST_PLACEHOLDER:
            errors.append(f"{label} does not contain the documented digest placeholder")
        if require_integrity is not True:
            errors.append(f"{label} must demonstrate required loader integrity")
    elif digest and not LOWER_HEX_SHA256.fullmatch(digest):
        errors.append(f"{label} loader SHA-256 is not 64 lower-case hexadecimal characters")
    elif require_integrity is True and not LOWER_HEX_SHA256.fullmatch(digest):
        errors.append(f"{label} requires integrity without a valid loader SHA-256")
    return errors


def check_pyodide_configs(root: Path) -> list[str]:
    return (
        _validate_runtime_config(root / "app" / "runtime-config.json", root, example=False)
        + _validate_runtime_config(root / "app" / "runtime-config.example.json", root, example=True)
    )


def check_remote_executable_origins(root: Path) -> list[str]:
    errors: list[str] = []
    app = root / "app"
    if not app.is_dir():
        return ["missing browser application directory: app"]
    for suffix in ("*.cjs", "*.html", "*.js", "*.json", "*.mjs"):
        for path in sorted(app.rglob(suffix)):
            source = _read_text(path, root, errors)
            if source is None:
                continue
            allowed_complete_urls = {PYODIDE_LOADER_URL, PYODIDE_INDEX_URL}
            if path.suffix.lower() == ".html":
                allowed_complete_urls.add(PYODIDE_ORIGIN)
            for match in REMOTE_URL.finditer(source):
                url = match.group(0).rstrip(").,;]")
                if _origin(url) != PYODIDE_ORIGIN:
                    errors.append(
                        f"unapproved remote executable origin in {_relative(path, root)}: {_origin(url) or url}"
                    )
                elif url not in allowed_complete_urls:
                    errors.append(
                        f"unapproved remote executable URL in {_relative(path, root)}: {url}"
                    )
            for match in PROTOCOL_RELATIVE_URL.finditer(source):
                errors.append(
                    f"protocol-relative remote executable URL in {_relative(path, root)}: "
                    f"{match.group('url')}"
                )
            if path.suffix.lower() == ".html":
                for match in HTML_PROTOCOL_RELATIVE_URL.finditer(source):
                    error = (
                        f"protocol-relative remote executable URL in {_relative(path, root)}: "
                        f"{match.group('url')}"
                    )
                    if error not in errors:
                        errors.append(error)
    return errors


def _strip_yaml_comment(line: str) -> str:
    quote = ""
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in {"'", '"'}:
            if not quote:
                quote = character
            elif quote == character:
                quote = ""
            continue
        if character == "#" and not quote:
            return line[:index]
    return line


def _indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _check_yaml_lexical_policy(lines: list[str], path: Path, root: Path) -> list[str]:
    """Reject YAML forms that the deliberately narrow security parser cannot prove safe."""
    errors: list[str] = []
    relative = _relative(path, root)
    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line).rstrip()
        if not code.strip():
            continue
        if "\\u" in code or "\\U" in code or "\\x" in code:
            errors.append(f"escaped YAML key or value is unsupported in {relative}:{index + 1}")
        if QUOTED_YAML_KEY.match(code):
            errors.append(f"quoted YAML mapping key is unsupported in {relative}:{index + 1}")
        if FLOW_CRITICAL_YAML_KEY.search(code):
            errors.append(f"flow-style security key is unsupported in {relative}:{index + 1}")
        if PACKAGE_MANAGER_COMMAND.search(code):
            errors.append(f"package-manager command is forbidden in {relative}:{index + 1}")
    return errors


def _check_permissions(lines: list[str], path: Path, root: Path) -> list[str]:
    errors: list[str] = []
    permission_blocks = 0
    top_level_permission_blocks = 0
    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line).rstrip()
        match = re.match(r"^(?P<space>\s*)permissions\s*:\s*(?P<value>.*)$", code)
        if not match:
            continue
        permission_blocks += 1
        if len(match.group("space")) == 0:
            top_level_permission_blocks += 1
        value = match.group("value").strip().lower()
        scalar_value = value.strip("\"'")
        if scalar_value == "write-all" or (
            value.startswith("{") and re.search(r":\s*[\"']?write(?:-all)?[\"']?\b", value)
        ):
            errors.append(f"write permission in {_relative(path, root)}:{index + 1}")
        if value:
            if value.startswith("{") and value != "{}":
                errors.append(
                    f"non-empty flow-style permissions are unsupported in {_relative(path, root)}:{index + 1}"
                )
            elif scalar_value != "{}":
                errors.append(f"non-read permission in {_relative(path, root)}:{index + 1}")
            continue
        block_indent = len(match.group("space"))
        for offset in range(index + 1, len(lines)):
            child_code = _strip_yaml_comment(lines[offset]).rstrip()
            if not child_code.strip():
                continue
            if _indentation(child_code) <= block_indent:
                break
            child_match = re.match(r"^\s*[A-Za-z0-9_-]+\s*:\s*(?P<value>[^\s#]+)", child_code)
            child_value = child_match.group("value").strip("\"'").lower() if child_match else ""
            if child_value in {"write", "write-all"}:
                errors.append(f"write permission in {_relative(path, root)}:{offset + 1}")
            elif child_match and child_value not in {"none", "read"}:
                errors.append(f"non-read permission in {_relative(path, root)}:{offset + 1}")
    if permission_blocks == 0:
        errors.append(f"workflow lacks an explicit read-only permissions declaration: {_relative(path, root)}")
    elif top_level_permission_blocks == 0:
        errors.append(f"workflow lacks top-level read-only permissions: {_relative(path, root)}")
    return errors


def _direct_with_values(lines: list[str], uses_index: int, field_name: str) -> list[str]:
    uses_line = _strip_yaml_comment(lines[uses_index]).rstrip()
    uses_indent = _indentation(uses_line)
    key_indent = uses_indent + 2 if re.match(r"^\s*-\s*uses\s*:", uses_line) else uses_indent
    with_index: int | None = None
    for index in range(uses_index + 1, len(lines)):
        code = _strip_yaml_comment(lines[index]).rstrip()
        if not code.strip():
            continue
        indent = _indentation(code)
        if indent < key_indent:
            break
        if indent == key_indent and re.match(r"^\s*with\s*:\s*$", code):
            with_index = index
            break
        if indent == key_indent and re.match(r"^\s*(?:uses|run)\s*:", code):
            break
    if with_index is None:
        return []

    direct_indent: int | None = None
    values: list[str] = []
    for index in range(with_index + 1, len(lines)):
        code = _strip_yaml_comment(lines[index]).rstrip()
        if not code.strip():
            continue
        indent = _indentation(code)
        if indent <= key_indent:
            break
        if direct_indent is None:
            direct_indent = indent
        if indent != direct_indent:
            continue
        match = re.match(
            rf"^\s*{re.escape(field_name)}\s*:\s*(?P<value>[^\s#]+)\s*$",
            code,
        )
        if match:
            values.append(match.group("value").strip("\"'").lower())
    return values


def _checkout_disables_credentials(lines: list[str], uses_index: int) -> bool:
    return _direct_with_values(lines, uses_index, "persist-credentials") == ["false"]


def _setup_node_disables_package_manager_cache(lines: list[str], uses_index: int) -> bool:
    return _direct_with_values(lines, uses_index, "package-manager-cache") == ["false"]


def _check_local_action(
    reference: str,
    root: Path,
    visited: set[Path],
) -> list[str]:
    errors: list[str] = []
    relative_reference = PurePosixPath(reference)
    if (
        not reference.startswith("./")
        or ".." in relative_reference.parts
        or "\\" in reference
    ):
        return [f"unsafe local action path: {reference}"]
    candidate = root.joinpath(*relative_reference.parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return [f"local action escapes the checkout: {reference}"]

    is_reusable_workflow = candidate.is_file() and candidate.suffix.lower() in {".yaml", ".yml"}
    if is_reusable_workflow:
        manifest = candidate
    else:
        manifests = [path for path in (candidate / "action.yml", candidate / "action.yaml") if path.is_file()]
        if len(manifests) != 1:
            return [f"local action must have exactly one action.yml or action.yaml: {reference}"]
        manifest = manifests[0]
    if manifest in visited:
        return []
    visited.add(manifest)

    source = _read_text(manifest, root, errors)
    if source is None:
        return errors
    lines = source.splitlines()
    errors.extend(_check_yaml_lexical_policy(lines, manifest, root))
    manifest_relative = manifest.relative_to(root)
    is_reusable_workflow = (
        is_reusable_workflow
        and len(manifest_relative.parts) == 3
        and manifest_relative.parts[:2] == (".github", "workflows")
    )
    if not is_reusable_workflow:
        using_values = [
            match.group("value")
            for line in lines
            if (match := re.match(r"^\s*using\s*:\s*(?P<value>[^\s#]+)\s*$", _strip_yaml_comment(line)))
        ]
        if using_values != ["composite"]:
            errors.append(
                f"local action must be an explicitly declared composite action: {_relative(manifest, root)}"
            )
    errors.extend(_check_yaml_uses(lines, manifest, root, visited))
    return errors


def _check_yaml_uses(
    lines: list[str],
    path: Path,
    root: Path,
    visited: set[Path],
) -> list[str]:
    errors: list[str] = []
    relative = _relative(path, root)
    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line)
        if "uses" not in code:
            continue
        uses_match = REMOTE_USES.match(line)
        if not uses_match:
            if re.match(r"^\s*(?:-\s*)?(?:[\"']uses[\"']|uses)\s*:", code) or re.search(
                r"[{,]\s*[\"']?uses[\"']?\s*:", code
            ):
                errors.append(f"invalid or unpinned uses reference in {relative}:{index + 1}")
            continue
        reference = uses_match.group("reference")
        if reference.startswith("./"):
            errors.extend(_check_local_action(reference, root, visited))
            continue
        if "@" not in reference:
            errors.append(f"unpinned remote action in {relative}:{index + 1}")
            continue
        action_name, revision = reference.rsplit("@", 1)
        approved = APPROVED_ACTIONS.get(action_name)
        if approved is None:
            errors.append(f"unapproved remote action {action_name!r} in {relative}:{index + 1}")
            continue
        expected_revision, expected_tag = approved
        if revision != expected_revision:
            errors.append(f"incorrect pin for {action_name} in {relative}:{index + 1}")
        if uses_match.group("comment") != expected_tag:
            errors.append(
                f"{action_name} lacks the same-line tag comment {expected_tag} in {relative}:{index + 1}"
            )
        if action_name == "actions/checkout" and not _checkout_disables_credentials(lines, index):
            errors.append(
                f"actions/checkout must set persist-credentials: false in {relative}:{index + 1}"
            )
        if action_name == "actions/setup-node" and not _setup_node_disables_package_manager_cache(lines, index):
            errors.append(
                f"actions/setup-node must set package-manager-cache: false in {relative}:{index + 1}"
            )
    return errors


def _check_workflow(path: Path, root: Path) -> list[str]:
    errors: list[str] = []
    source = _read_text(path, root, errors)
    if source is None:
        return errors
    lines = source.splitlines()
    relative = _relative(path, root)
    errors.extend(_check_yaml_lexical_policy(lines, path, root))
    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line)
        if re.search(r"\bpull_request_target\b", code):
            errors.append(f"pull_request_target is forbidden in {relative}:{index + 1}")
    errors.extend(_check_yaml_uses(lines, path, root, {path.resolve()}))
    errors.extend(_check_permissions(lines, path, root))
    return errors


def check_workflows(root: Path) -> list[str]:
    workflow_directory = root / ".github" / "workflows"
    workflows: list[Path] = []
    if workflow_directory.is_dir():
        workflows.extend(sorted(workflow_directory.glob("*.yml")))
        workflows.extend(sorted(workflow_directory.glob("*.yaml")))
    if not workflows:
        return ["no GitHub Actions workflow exists under .github/workflows"]
    errors: list[str] = []
    for path in workflows:
        errors.extend(_check_workflow(path, root))
    return errors


def audit_dependency_boundary(root: Path = ROOT) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    errors.extend(check_package_manifests(root))
    errors.extend(check_vendor_boundary(root))
    errors.extend(check_python_imports(root))
    errors.extend(check_javascript_package_loading(root))
    errors.extend(check_pyodide_configs(root))
    errors.extend(check_remote_executable_origins(root))
    errors.extend(check_workflows(root))
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the deterministic offline dependency and supply-chain boundary."
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="Checkout root to inspect.")
    args = parser.parse_args(argv)

    errors = audit_dependency_boundary(args.root)
    if errors:
        print(f"[FAIL] dependency-boundary: {len(errors)} problem(s)")
        for error in errors:
            print(f"- {error}")
    else:
        print(
            "[PASS] dependency-boundary: package manifests, imports, runtime configuration, "
            "literal runtime locations and workflow pins verified"
        )
    print(f"[LIMITATION] external-runtime-assurance: {EXTERNAL_RUNTIME_LIMITATION}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
