#!/usr/bin/env python3
"""Check CodeProbe's deterministic offline dependency boundary.

This checker deliberately does not query a package registry, an advisory
database or the configured Pyodide distribution.  It verifies the dependency
claims that can be established from a checkout alone: the absence of an
unapproved package-manager graph, standard-library or repository-local Python
imports, standard-library shadow modules, the declared Pyodide locations,
bounded remote executable constructions and pinned GitHub Actions references.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site
):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import ast
import json
import os
import re
import shlex
import tokenize
from html.parser import HTMLParser
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
APPROVED_SOURCE_ENTRIES = {"codeprobe_engine", "codeprobe_runtime.py"}
APPROVED_SOURCE_ENTRY_TYPES = {
    "codeprobe_engine": "directory",
    "codeprobe_runtime.py": "file",
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
    "errno",
    "fnmatch",
    "functools",
    "hashlib",
    "html",
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
    "shlex",
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
    "build.gradle",
    "build.gradle.kts",
    "bower.json",
    "bun.lock",
    "bun.lockb",
    "conda-lock.yaml",
    "conda-lock.yml",
    "composer.json",
    "composer.lock",
    "cargo.lock",
    "cargo.toml",
    "deno.json",
    "deno.jsonc",
    "deno.lock",
    "environment.yaml",
    "environment.yml",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "jsr.json",
    "jsr.jsonc",
    "npm-shrinkwrap.json",
    "noxfile.py",
    "package-lock.json",
    "package.json",
    "pdm.lock",
    "pipfile",
    "pipfile.lock",
    "pom.xml",
    "pixi.lock",
    "pixi.toml",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "pnpm-workspace.yaml",
    "pnpm-workspace.yml",
    "poetry.lock",
    "pyproject.toml",
    "pubspec.lock",
    "pubspec.yaml",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "uv.lock",
    "yarn.lock",
}

PYTHON_REQUIREMENT_NAME = re.compile(
    r"^(?:[a-z0-9_.-]+[-_.])?(?:requirements?|constraints?)"
    r"(?:[-_.][a-z0-9_.-]+)?(?:\.(?:in|lock|txt))?$",
    re.IGNORECASE,
)
PYTHON_LOCK_NAME = re.compile(r"^pylock(?:\.[a-z0-9_.-]+)?\.toml$", re.IGNORECASE)
LOWER_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REMOTE_URL = re.compile(r"https?://[^\s\"'`<>\\]+", re.IGNORECASE)
PROTOCOL_RELATIVE_URL = re.compile(r"[\"'](?P<url>/{2,}[^\"']+)[\"']")
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
    (
        re.compile(r"\b(?:micropip|pyodide)\s*\["),
        "computed JavaScript package-loader access",
    ),
)
MAX_JAVASCRIPT_ANALYSIS_CHARACTERS = 2_000_000
MAX_JAVASCRIPT_REMOTE_BINDINGS = 256
MAX_JAVASCRIPT_TAIL_ANALYSIS_CHARACTERS = 8_000_000
MAX_WORKFLOW_COMMAND_CHARACTERS = 65_536
TEMPLATE_DYNAMIC_TOKEN = re.compile(
    r"\b(?:import|importScripts|loadPackage|loadPackagesFromImports|micropip|pyodide)\b"
)
PEP_723_SCRIPT_BLOCK = re.compile(r"^#\s*///\s*script\s*$")
UNAPPROVED_VENDOR_DIRECTORY_NAMES = {
    "pypackages",
    "bower_components",
    "jspm_packages",
    "node_modules",
    "site-packages",
    "thirdparty",
    "third-party",
    "third_party",
    "vendor",
    "vendored",
    "vendors",
}
QUOTED_YAML_KEY = re.compile(r"^\s*(?:-\s*)?[\"'][^\"']+[\"']\s*:")
FLOW_CRITICAL_YAML_KEY = re.compile(
    r"[,{]\s*[\"']?(?:env|on|package-manager-cache|permissions|"
    r"persist-credentials|pull_request_target|run|runs|steps|uses|with)[\"']?\s*:"
)
TAGGED_SECURITY_YAML_KEY = re.compile(
    r"^\s*(?:-\s*)?![^\s]+\s+[\"']?"
    r"(?:env|on|package-manager-cache|permissions|persist-credentials|"
    r"pull_request_target|run|runs|steps|uses|with)[\"']?\s*:"
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
        name = path.name.casefold()
        if path.suffix.lower() in {".conda", ".egg", ".tgz", ".whl"} or name.endswith(
            (".tar.bz2", ".tar.gz", ".tar.xz")
        ):
            errors.append(
                f"unapproved packaged dependency artefact {_relative(path, root)}; "
                "no provenance inventory is configured"
            )
    return errors


def check_vendor_boundary(root: Path) -> list[str]:
    """Reject vendored runtime bytes until a provenance inventory is introduced."""
    errors: list[str] = []
    vendor = root / "app" / "vendor"
    if vendor.exists():
        allowed = {Path("pyodide/README.md")}
        for path in _iter_files(vendor):
            relative = path.relative_to(vendor)
            if relative in allowed:
                continue
            errors.append(
                f"unapproved vendored runtime file app/vendor/{relative.as_posix()}; "
                "no provenance inventory is configured"
            )

    for directory, directory_names, _file_names in os.walk(root, followlinks=False):
        base = Path(directory)
        retained: list[str] = []
        for name in sorted(directory_names):
            candidate = base / name
            folded = name.casefold()
            vendor_name = folded.strip("._-")
            if vendor_name in UNAPPROVED_VENDOR_DIRECTORY_NAMES and candidate != vendor:
                errors.append(
                    f"unapproved vendored dependency directory {_relative(candidate, root)}; "
                    "no provenance inventory is configured"
                )
                continue
            if folded in EXCLUDED_DIRECTORY_NAMES:
                continue
            retained.append(name)
        directory_names[:] = retained

    source_root = root / "src"
    if not source_root.is_dir():
        errors.append("missing source directory: src")
    else:
        for child in sorted(source_root.iterdir()):
            if child.name.casefold() in EXCLUDED_DIRECTORY_NAMES:
                continue
            if child.name not in APPROVED_SOURCE_ENTRIES:
                errors.append(
                    f"unapproved source-tree entry {_relative(child, root)}; "
                    "no first-party inventory entry exists"
                )
        for name, expected_type in APPROVED_SOURCE_ENTRY_TYPES.items():
            candidate = source_root / name
            has_expected_type = (
                candidate.is_dir() if expected_type == "directory" else candidate.is_file()
            ) and not candidate.is_symlink()
            if not has_expected_type:
                errors.append(
                    f"source-tree entry src/{name} is missing or is not a regular "
                    f"{expected_type}"
                )
    return errors


def check_standard_library_shadowing(root: Path) -> list[str]:
    """Reject checkout modules that can pre-empt standard-library imports."""
    errors: list[str] = []
    standard_names = {name.casefold() for name in APPROVED_STDLIB_IMPORTS}
    for area in (root, root / "tools", root / "tests"):
        if not area.is_dir():
            continue
        for path in sorted(path for path in area.iterdir() if path.is_file()):
            folded_name = path.name.casefold()
            module_name = folded_name.split(".", 1)[0]
            importable_suffix = (
                folded_name.endswith((".py", ".pyc", ".pyd", ".so"))
                or ".cpython-" in folded_name and folded_name.endswith(".so")
            )
            if importable_suffix and module_name in standard_names:
                errors.append(
                    f"standard-library shadow module is forbidden: {_relative(path, root)}"
                )
        for path in sorted(area.iterdir()):
            package_initialisers = (
                child
                for child in path.iterdir()
                if child.is_file()
                and child.name.casefold().startswith("__init__.")
                and child.name.casefold().endswith((".py", ".pyc", ".pyd", ".so"))
            ) if path.is_dir() else ()
            if path.is_dir() and path.name.casefold() in standard_names and any(package_initialisers):
                errors.append(
                    f"standard-library shadow package is forbidden: {_relative(path, root)}"
                )
    return errors


def check_first_party_shadowing(root: Path) -> list[str]:
    """Reject duplicate first-party module names outside their canonical paths."""
    errors: list[str] = []
    canonical_runtime = root / "src" / "codeprobe_runtime.py"
    canonical_engine = root / "src" / "codeprobe_engine"
    module_names = {"codeprobe_engine", "codeprobe_runtime"}
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        base = Path(directory)
        retained: list[str] = []
        for name in sorted(directory_names):
            candidate = base / name
            if name.casefold() in module_names and candidate != canonical_engine:
                errors.append(
                    f"noncanonical first-party shadow package is forbidden: "
                    f"{_relative(candidate, root)}"
                )
            if name.casefold() not in EXCLUDED_DIRECTORY_NAMES:
                retained.append(name)
        directory_names[:] = retained
        for name in sorted(file_names):
            candidate = base / name
            if (
                candidate.suffix.casefold() == ".py"
                and candidate.stem.casefold() in module_names
                and candidate != canonical_runtime
            ):
                errors.append(
                    f"noncanonical first-party shadow module is forbidden: "
                    f"{_relative(candidate, root)}"
                )
    return errors


def _python_files(root: Path) -> Iterable[Path]:
    for path in _iter_files(root):
        if path.suffix.lower() in {".py", ".pyw"}:
            yield path
            continue
        if path.suffix:
            continue
        try:
            with path.open("rb") as handle:
                first_line = handle.readline(256)
        except OSError:
            continue
        if first_line.startswith(b"#!"):
            folded_line = first_line.lower()
            if b"python" in folded_line or re.search(
                rb"(?:^|[\s/])uv(?:\s|$).*\b(?:run|script)\b",
                folded_line,
            ):
                yield path


def _contains_pep_723_script_block(source: str) -> bool:
    lines = iter(source.splitlines(keepends=True))
    try:
        tokens = tokenize.generate_tokens(lines.__next__)
        in_script_block = False
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            if not in_script_block and PEP_723_SCRIPT_BLOCK.fullmatch(token.string):
                in_script_block = True
            elif in_script_block and re.fullmatch(r"#\s*///\s*", token.string):
                return True
        return False
    except (IndentationError, tokenize.TokenError):
        return False


def _local_module_names(root: Path) -> set[str]:
    names: set[str] = set()
    for area_name in ("src", "tools", "tests"):
        area = root / area_name
        if not area.is_dir():
            continue
        names.update(path.stem for path in area.glob("*.py"))
        names.update(path.name for path in area.iterdir() if path.is_dir() and (path / "__init__.py").is_file())
    return names


def _expression_name(node: ast.expr) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _call_name(node: ast.Call) -> str:
    return _expression_name(node.func)


def _annotate_python_scopes(
    node: ast.AST,
    scope_path: tuple[int, ...] | None = None,
    conditional_depth: int = 0,
) -> None:
    """Attach a lexical scope path used by the bounded constant evaluator."""
    if scope_path is None:
        scope_path = (id(node),)
    setattr(node, "_codeprobe_scope_path", scope_path)
    setattr(node, "_codeprobe_conditional_depth", conditional_depth)
    child_scope = scope_path
    if isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Lambda)):
        child_scope = scope_path + (id(node),)
    child_conditional_depth = conditional_depth + int(
        isinstance(
            node,
            (
                ast.AsyncFor,
                ast.For,
                ast.If,
                ast.Match,
                ast.Try,
                ast.While,
            ),
        )
    )
    for child in ast.iter_child_nodes(node):
        _annotate_python_scopes(child, child_scope, child_conditional_depth)


def _assignment_candidates(
    node: ast.AST,
    name: str,
    assignments: dict[str, tuple[ast.AST, ...]],
) -> tuple[tuple[ast.AST, ...], bool]:
    """Return nearest-scope assignments and whether an outer value is ambiguous."""
    candidates = assignments.get(name, ())
    use_scope = getattr(node, "_codeprobe_scope_path", None)
    if use_scope is None:
        use_line = getattr(node, "lineno", sys.maxsize)
        eligible = tuple(
            assigned
            for assigned in candidates
            if getattr(assigned, "lineno", 0) <= use_line
        )
    else:
        same_scope = tuple(
            assigned
            for assigned in candidates
            if getattr(assigned, "_codeprobe_scope_path", None) == use_scope
        )
        if same_scope:
            use_line = getattr(node, "lineno", sys.maxsize)
            eligible = tuple(
                assigned
                for assigned in same_scope
                if getattr(assigned, "lineno", 0) <= use_line
            )
            if len(eligible) > 1 and any(
                getattr(assigned, "_codeprobe_conditional_depth", 0) > 0
                for assigned in eligible
            ):
                return (), True
        else:
            outer = tuple(
                assigned
                for assigned in candidates
                if (
                    isinstance(
                        getattr(assigned, "_codeprobe_scope_path", None), tuple
                    )
                    and use_scope[: len(getattr(assigned, "_codeprobe_scope_path"))]
                    == getattr(assigned, "_codeprobe_scope_path")
                )
            )
            if not outer:
                return (), False
            nearest_depth = max(
                len(getattr(assigned, "_codeprobe_scope_path")) for assigned in outer
            )
            eligible = tuple(
                assigned
                for assigned in outer
                if len(getattr(assigned, "_codeprobe_scope_path")) == nearest_depth
            )
            if len(eligible) != 1:
                return (), True
            return eligible, False
    latest_position = max(
        (
            getattr(assigned, "lineno", 0),
            getattr(assigned, "col_offset", 0),
        )
        for assigned in eligible
    ) if eligible else (-1, -1)
    return (
        tuple(
            assigned
            for assigned in eligible
            if (
                getattr(assigned, "lineno", 0),
                getattr(assigned, "col_offset", 0),
            )
            == latest_position
        ),
        False,
    )


def _static_string_parts(
    node: ast.AST,
    assignments: dict[str, tuple[ast.AST, ...]],
    *,
    resolving: frozenset[str] = frozenset(),
    depth: int = 0,
) -> tuple[str, ...] | None:
    if depth > 64:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,) if len(node.value) <= 4_096 else None
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        try:
            value = node.value.decode("utf-8")
        except UnicodeError:
            return None
        return (value,) if len(value) <= 4_096 else None
    if isinstance(node, ast.Attribute) and _expression_name(node) == "sys.executable":
        return ("python",)
    if isinstance(node, (ast.List, ast.Tuple)):
        values: list[str] = []
        for element in node.elts:
            resolved = _static_string_parts(
                element,
                assignments,
                resolving=resolving,
                depth=depth + 1,
            )
            if resolved is None:
                return None
            values.extend(resolved)
            if len(values) > 256 or sum(map(len, values)) > 4_096:
                return None
        return tuple(values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string_parts(
            node.left,
            assignments,
            resolving=resolving,
            depth=depth + 1,
        )
        right = _static_string_parts(
            node.right,
            assignments,
            resolving=resolving,
            depth=depth + 1,
        )
        if left is None or right is None or len(left) != 1 or len(right) != 1:
            return None
        combined = left[0] + right[0]
        return (combined,) if len(combined) <= 4_096 else None
    if isinstance(node, ast.JoinedStr):
        values: list[str] = []
        for element in node.values:
            if isinstance(element, ast.FormattedValue):
                if element.conversion != -1 or element.format_spec is not None:
                    return None
                resolved = _static_string_parts(
                    element.value,
                    assignments,
                    resolving=resolving,
                    depth=depth + 1,
                )
            else:
                resolved = _static_string_parts(
                    element,
                    assignments,
                    resolving=resolving,
                    depth=depth + 1,
                )
            if resolved is None or len(resolved) != 1:
                return None
            values.append(resolved[0])
        combined = "".join(values)
        return (combined,) if len(combined) <= 4_096 else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
    ):
        separator = _static_string_parts(
            node.func.value,
            assignments,
            resolving=resolving,
            depth=depth + 1,
        )
        values = _static_string_parts(
            node.args[0],
            assignments,
            resolving=resolving,
            depth=depth + 1,
        )
        if separator is None or len(separator) != 1 or values is None:
            return None
        combined = separator[0].join(values)
        return (combined,) if len(combined) <= 4_096 else None
    if (
        isinstance(node, ast.Call)
        and _call_name(node) == "map"
        and len(node.args) == 2
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "str"
    ):
        return _static_string_parts(
            node.args[1],
            assignments,
            resolving=resolving,
            depth=depth + 1,
        )
    if isinstance(node, ast.Name) and node.id not in resolving:
        assigned_values, _ambiguous = _assignment_candidates(
            node,
            node.id,
            assignments,
        )
        if assigned_values:
            values: list[str] = []
            for assigned in assigned_values:
                resolved = _static_string_parts(
                    assigned,
                    assignments,
                    resolving=resolving | {node.id},
                    depth=depth + 1,
                )
                if resolved is None:
                    return None
                values.extend(resolved)
                if len(values) > 256 or sum(map(len, values)) > 4_096:
                    return None
            return tuple(values)
    return None


def _is_package_manager_command(parts: tuple[str, ...] | None) -> bool:
    if not parts:
        return False
    if len(parts) == 1:
        if re.match(
            r"^\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+)\s+)*\$[\"']",
            parts[0],
        ):
            return True
        statements = _shell_statements(parts[0])
        if len(statements) > 1:
            return any(_is_package_manager_command((statement,)) for statement in statements)
        try:
            arguments = shlex.split(parts[0], posix=True)
        except ValueError:
            simplified = parts[0].replace("\"", "").replace("'", "")
            return bool(
                re.match(
                    r"^\s*(?:(?:env\s+)?[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
                    r"(?:(?:[^\s/]+/)?(?:bun|conda|deno|hatch|mamba|micromamba|npm|npx|"
                    r"pdm|pip3?|pipx|pnpm|poetry|rye|uv|yarn)\b|"
                    r"(?:[^\s/]+/)?python(?:3(?:\.\d+)?)?\s+-m\s+"
                    r"(?:pip3?|pdm|poetry|uv)\b)",
                    simplified,
                    re.IGNORECASE,
                )
            )
        if len(arguments) == 1 and arguments[0] != parts[0] and any(
            character.isspace() for character in arguments[0]
        ):
            return _is_package_manager_command((arguments[0],))
    else:
        arguments = list(parts)
    arguments = [argument for argument in arguments if argument]
    while arguments and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", arguments[0]):
        arguments.pop(0)
    if not arguments:
        return False

    executable = arguments[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if executable.endswith(".exe"):
        executable = executable[:-4]
    managers = {
        "bun",
        "conda",
        "deno",
        "hatch",
        "mamba",
        "micromamba",
        "npm",
        "npx",
        "pdm",
        "pip",
        "pip3",
        "pipx",
        "pnpm",
        "poetry",
        "rye",
        "uv",
        "yarn",
    }
    if executable in managers:
        return True
    if executable == "env":
        remainder = arguments[1:]
        while remainder and (
            remainder[0].startswith("-")
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", remainder[0])
        ):
            remainder.pop(0)
        return _is_package_manager_command(tuple(remainder))
    if executable in {"command", "exec", "nohup", "sudo"}:
        remainder = arguments[1:]
        while remainder and remainder[0].startswith("-"):
            remainder.pop(0)
        return _is_package_manager_command(tuple(remainder))
    if executable == "py" or re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        return len(arguments) >= 3 and arguments[1] == "-m" and arguments[2].casefold() in managers
    if executable in {"bash", "cmd", "dash", "ksh", "powershell", "pwsh", "sh", "zsh"}:
        for flag in ("-c", "/c", "-command"):
            if flag in [argument.casefold() for argument in arguments[1:]]:
                index = [argument.casefold() for argument in arguments].index(flag)
                if index + 1 < len(arguments):
                    return _is_package_manager_command((arguments[index + 1],))
    return False


def _literal_fragments(
    node: ast.AST,
    assignments: dict[str, tuple[ast.AST, ...]],
) -> tuple[str, ...] | None:
    fragments: list[str] = []
    pending = [node]
    resolved_names: set[str] = set()
    visited = 0
    total_length = 0
    while pending and visited < 16_384 and len(fragments) < 4_096:
        current = pending.pop()
        visited += 1
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            value = current.value
        elif isinstance(current, ast.Constant) and isinstance(current.value, bytes):
            try:
                value = current.value.decode("utf-8")
            except UnicodeError:
                continue
        else:
            if isinstance(current, ast.Name) and current.id not in resolved_names:
                assigned_values, ambiguous = _assignment_candidates(
                    current,
                    current.id,
                    assignments,
                )
                if ambiguous:
                    return None
                if assigned_values:
                    resolved_names.add(current.id)
                    pending.extend(reversed(assigned_values))
            pending.extend(reversed(tuple(ast.iter_child_nodes(current))))
            continue
        total_length += len(value)
        if total_length > 65_536:
            return None
        fragments.append(value)
    return None if pending else tuple(fragments)


def _static_process_head(
    node: ast.AST,
    assignments: dict[str, tuple[ast.AST, ...]],
    *,
    resolving: frozenset[str] = frozenset(),
    depth: int = 0,
) -> str | None:
    """Resolve only an argv executable without expanding dynamic arguments."""
    if depth > 64:
        return None
    if isinstance(node, (ast.List, ast.Tuple)):
        if not node.elts:
            return None
        return _static_process_head(
            node.elts[0], assignments, resolving=resolving, depth=depth + 1
        )
    if isinstance(node, ast.Name) and node.id not in resolving:
        candidates, ambiguous = _assignment_candidates(node, node.id, assignments)
        if ambiguous or len(candidates) != 1:
            return None
        return _static_process_head(
            candidates[0],
            assignments,
            resolving=resolving | {node.id},
            depth=depth + 1,
        )
    if (
        isinstance(node, ast.Call)
        and _expression_name(node.func) == "shutil.which"
        and len(node.args) == 1
        and not node.keywords
    ):
        resolved = _static_string_parts(node.args[0], assignments)
    else:
        resolved = _static_string_parts(node, assignments)
    return resolved[0] if resolved and len(resolved) == 1 else None


def check_python_imports(root: Path) -> list[str]:
    errors: list[str] = []
    stdlib_names = APPROVED_STDLIB_IMPORTS
    local_names = _local_module_names(root) & APPROVED_LOCAL_IMPORTS
    dynamic_call_leaves = {
        "__import__",
        "ExtensionFileLoader",
        "SourceFileLoader",
        "SourcelessFileLoader",
        "exec_module",
        "import_module",
        "load_entry_point",
        "load_module",
        "module_from_spec",
        "resolve_name",
        "run_module",
        "spec_from_file_location",
    }
    process_call_leaves = {
        "Popen",
        "call",
        "check_call",
        "check_output",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "getoutput",
        "getstatusoutput",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "run",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "startfile",
        "system",
    }
    dynamic_module_names = {"importlib", "pkg_resources", "pkgutil", "runpy"}
    for path in _python_files(root):
        source = _read_text(path, root, errors)
        if source is None:
            continue
        if _contains_pep_723_script_block(source):
            errors.append(
                f"unapproved PEP 723 inline package metadata in {_relative(path, root)}"
            )
        try:
            tree = ast.parse(source, filename=str(path))
        except (RecursionError, SyntaxError, ValueError) as exc:
            errors.append(f"cannot inspect Python imports in {_relative(path, root)}: {exc}")
            continue
        try:
            _annotate_python_scopes(tree)
        except RecursionError:
            errors.append(
                f"Python source exceeds static analysis limits in {_relative(path, root)}"
            )
            continue
        dynamic_aliases: set[str] = {"__import__"}
        code_execution_aliases: set[str] = {"compile", "eval", "exec"}
        dynamic_module_aliases: set[str] = set()
        getattr_aliases = {"getattr", "object.__getattribute__"}
        vars_aliases = {"vars"}
        process_module_aliases: set[str] = set()
        process_aliases: set[str] = set()
        process_alias_leaves: dict[str, str] = {}
        assignment_lists: dict[str, list[ast.AST]] = {}
        for candidate in ast.walk(tree):
            if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                value = candidate.value
                targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target]
                for target in targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if value is not None:
                        assignment_lists.setdefault(target.id, []).append(value)
            if isinstance(candidate, ast.Import):
                for alias in candidate.names:
                    imported_module = alias.name.split(".", 1)[0]
                    if imported_module in dynamic_module_names:
                        dynamic_module_aliases.add(alias.asname or imported_module)
                    if imported_module in {"os", "subprocess"}:
                        process_module_aliases.add(alias.asname or imported_module)
                continue
            if (
                not isinstance(candidate, ast.ImportFrom)
                or candidate.level != 0
                or not candidate.module
            ):
                continue
            imported_module = candidate.module.split(".", 1)[0]
            for alias in candidate.names:
                local_name = alias.asname or alias.name
                if imported_module in dynamic_module_names:
                    if alias.name in dynamic_call_leaves:
                        dynamic_aliases.add(local_name)
                if imported_module in {"os", "subprocess"} and alias.name in process_call_leaves:
                    process_aliases.add(local_name)
                    process_alias_leaves[local_name] = alias.name
        assignments = {
            name: tuple(values) for name, values in assignment_lists.items()
        }
        module_edges: dict[str, set[str]] = {}
        process_edges: dict[str, set[str]] = {}
        dynamic_edges: dict[str, set[str]] = {}
        getattr_edges: dict[str, set[str]] = {}
        vars_edges: dict[str, set[str]] = {}
        code_execution_edges: dict[str, set[str]] = {}

        def close_aliases(aliases: set[str], edges: dict[str, set[str]]) -> None:
            pending = list(aliases)
            while pending:
                source = pending.pop()
                for target in edges.get(source, set()):
                    if target not in aliases:
                        aliases.add(target)
                        pending.append(target)

        for name, values in assignments.items():
            for value in values:
                if not isinstance(value, ast.expr):
                    continue
                assigned_name = _expression_name(value)
                if assigned_name:
                    module_edges.setdefault(assigned_name, set()).add(name)
        close_aliases(dynamic_module_aliases, module_edges)
        close_aliases(process_module_aliases, module_edges)

        for name, values in assignments.items():
            for value in values:
                if not isinstance(value, ast.expr):
                    continue
                assigned_name = _expression_name(value)
                assigned_leaf = assigned_name.rsplit(".", 1)[-1]
                assigned_root = assigned_name.split(".", 1)[0]
                if (
                    assigned_leaf in process_call_leaves
                    and assigned_root in process_module_aliases
                ):
                    process_aliases.add(name)
                    process_alias_leaves[name] = assigned_leaf
                elif assigned_name:
                    process_edges.setdefault(assigned_name, set()).add(name)
                if assigned_name in process_alias_leaves:
                    process_alias_leaves[name] = process_alias_leaves[assigned_name]
                if assigned_name == "__import__" or (
                    assigned_leaf in dynamic_call_leaves
                    and assigned_root in dynamic_module_aliases
                ):
                    dynamic_aliases.add(name)
                elif assigned_name:
                    dynamic_edges.setdefault(assigned_name, set()).add(name)
                if assigned_name:
                    getattr_edges.setdefault(assigned_name, set()).add(name)
                    vars_edges.setdefault(assigned_name, set()).add(name)
                    code_execution_edges.setdefault(assigned_name, set()).add(name)

        close_aliases(process_aliases, process_edges)
        close_aliases(dynamic_aliases, dynamic_edges)
        close_aliases(getattr_aliases, getattr_edges)
        close_aliases(vars_aliases, vars_edges)
        close_aliases(code_execution_aliases, code_execution_edges)

        changed_process_origins = True
        while changed_process_origins:
            changed_process_origins = False
            for source, targets in process_edges.items():
                origin = process_alias_leaves.get(source)
                if origin is None:
                    continue
                for target in targets:
                    if target not in process_alias_leaves:
                        process_alias_leaves[target] = origin
                        changed_process_origins = True

        def current_alias_binding(
            name: str,
            use: ast.AST,
            aliases: set[str],
            module_aliases: set[str],
            leaves: set[str],
        ) -> tuple[bool, bool]:
            assigned_values, ambiguous = _assignment_candidates(
                use,
                name,
                assignments,
            )
            if ambiguous:
                return False, True
            if not assigned_values:
                return name in aliases, False
            for assigned in assigned_values:
                if not isinstance(assigned, ast.expr):
                    continue
                assigned_name = _expression_name(assigned)
                assigned_leaf = assigned_name.rsplit(".", 1)[-1]
                assigned_root = assigned_name.split(".", 1)[0]
                if (
                    (assigned_name in aliases and assigned_name != name)
                    or (
                        assigned_leaf in leaves
                        and assigned_root in module_aliases
                    )
                ):
                    return True, False
            return False, False

        for candidate in ast.walk(tree):
            if not isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                continue
            targets = candidate.targets if isinstance(candidate, ast.Assign) else [candidate.target]
            if all(isinstance(target, ast.Name) for target in targets):
                continue
            value = candidate.value
            if not isinstance(value, ast.AST):
                continue
            for referenced in ast.walk(value):
                referenced_name = (
                    _expression_name(referenced)
                    if isinstance(referenced, (ast.Attribute, ast.Name))
                    else ""
                )
                referenced_leaf = referenced_name.rsplit(".", 1)[-1]
                referenced_root = referenced_name.split(".", 1)[0]
                if referenced_name and (
                    referenced_name in process_aliases
                    or (
                        referenced_leaf in process_call_leaves
                        and referenced_root in process_module_aliases
                    )
                ):
                    errors.append(
                        f"unsupported destructuring of a process launcher in "
                        f"{_relative(path, root)}:{candidate.lineno}"
                    )
                    break
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
            if (
                isinstance(node, ast.Attribute)
                and node.attr in dynamic_call_leaves
                and _expression_name(node).split(".", 1)[0] in dynamic_module_aliases
            ):
                errors.append(
                    f"dynamic package-loading reference {node.attr!r} in "
                    f"{_relative(path, root)}:{node.lineno}"
                )
            elif (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in dynamic_aliases
            ):
                is_current_dynamic, ambiguous_dynamic = current_alias_binding(
                    node.id,
                    node,
                    dynamic_aliases,
                    dynamic_module_aliases,
                    dynamic_call_leaves,
                )
                if ambiguous_dynamic:
                    errors.append(
                        f"ambiguous dynamic-loader alias in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                elif is_current_dynamic:
                    errors.append(
                        f"dynamic package-loading reference {node.id!r} in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
            if isinstance(node, ast.Attribute) and node.attr == "__dict__":
                namespace_root = _expression_name(node.value).split(".", 1)[0]
                if namespace_root in dynamic_module_aliases:
                    errors.append(
                        f"unsupported dynamic-loader namespace lookup in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                if namespace_root in process_module_aliases:
                    errors.append(
                        f"unsupported process-launcher namespace lookup in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "modules"
                and _expression_name(node.value).split(".", 1)[0] == "sys"
            ):
                errors.append(
                    f"unsupported dynamic module-registry lookup in "
                    f"{_relative(path, root)}:{node.lineno}"
                )
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id == "__builtins__"
            ):
                errors.append(
                    f"unsupported built-in namespace lookup in "
                    f"{_relative(path, root)}:{node.lineno}"
                )
            if isinstance(node, ast.NamedExpr):
                assigned_name = _expression_name(node.value)
                assigned_leaf = assigned_name.rsplit(".", 1)[-1]
                assigned_root = assigned_name.split(".", 1)[0]
                if (
                    assigned_name in process_aliases
                    or (
                        assigned_leaf in process_call_leaves
                        and assigned_root in process_module_aliases
                    )
                ):
                    errors.append(
                        f"unsupported named-expression process wrapper in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                if (
                    assigned_name in dynamic_aliases
                    or (
                        assigned_leaf in dynamic_call_leaves
                        and assigned_root in dynamic_module_aliases
                    )
                ):
                    errors.append(
                        f"unsupported named-expression dynamic loader in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
            if isinstance(node, ast.Call):
                call_name = _call_name(node)
                call_leaf = call_name.rsplit(".", 1)[-1]
                if (
                    _relative(path, root) == "tools/check_release_reproducibility.py"
                    and call_name == "run_command"
                ):
                    command_node = node.args[0] if node.args else None
                    resolved_head = (
                        _static_process_head(command_node, assignments)
                        if isinstance(command_node, ast.AST)
                        else None
                    )
                    if not resolved_head:
                        errors.append(
                            f"reproducibility process broker has an unresolved executable in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                    elif _is_package_manager_command((resolved_head,)):
                        errors.append(
                            f"package-manager command launched by reproducibility process broker in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                code_execution_call = False
                ambiguous_code_execution = False
                if call_name in code_execution_aliases:
                    code_execution_call, ambiguous_code_execution = current_alias_binding(
                        call_name,
                        node,
                        code_execution_aliases,
                        set(),
                        set(),
                    )
                if ambiguous_code_execution:
                    errors.append(
                        f"ambiguous dynamic-code alias in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                elif code_execution_call:
                    errors.append(
                        f"dynamic Python code execution is forbidden in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                if call_name in vars_aliases and node.args:
                    namespace_root = _expression_name(node.args[0]).split(".", 1)[0]
                    if namespace_root in dynamic_module_aliases:
                        errors.append(
                            f"unsupported dynamic-loader namespace lookup in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                    if namespace_root in process_module_aliases:
                        errors.append(
                            f"unsupported process-launcher namespace lookup in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                dynamic_alias_call = False
                ambiguous_dynamic_alias = False
                if call_name in dynamic_aliases:
                    dynamic_alias_call, ambiguous_dynamic_alias = current_alias_binding(
                        call_name,
                        node,
                        dynamic_aliases,
                        dynamic_module_aliases,
                        dynamic_call_leaves,
                    )
                is_dynamic_call = call_name == "__import__" or dynamic_alias_call or (
                    call_leaf in dynamic_call_leaves
                    and call_name.split(".", 1)[0] in dynamic_module_aliases
                )
                if ambiguous_dynamic_alias:
                    errors.append(
                        f"ambiguous dynamic-loader alias in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                if is_dynamic_call:
                    errors.append(
                        f"dynamic package-loading construct {call_name!r} in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                if call_name in getattr_aliases and len(node.args) >= 2:
                    receiver_name = _expression_name(node.args[0])
                    attribute_parts = _static_string_parts(node.args[1], assignments)
                    attribute_name = "".join(attribute_parts) if attribute_parts else ""
                    if (
                        receiver_name.split(".", 1)[0] in dynamic_module_aliases
                        and (
                            attribute_name in dynamic_call_leaves
                            or attribute_parts is None
                        )
                    ):
                        errors.append(
                            f"dynamic package-loading reflection in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                    if (
                        receiver_name.split(".", 1)[0] in process_module_aliases
                        and (
                            attribute_name in process_call_leaves
                            or attribute_parts is None
                        )
                    ):
                        errors.append(
                            f"dynamic process-execution reflection in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "__getattribute__"
                    and call_name not in getattr_aliases
                ):
                    receiver_name = _expression_name(node.func.value)
                    attribute_index = 0
                    receiver_root = receiver_name.split(".", 1)[0]
                    if (
                        receiver_root not in dynamic_module_aliases
                        and receiver_root not in process_module_aliases
                        and node.args
                    ):
                        receiver_name = _expression_name(node.args[0])
                        receiver_root = receiver_name.split(".", 1)[0]
                        attribute_index = 1
                    attribute_parts = (
                        _static_string_parts(node.args[attribute_index], assignments)
                        if len(node.args) > attribute_index
                        else None
                    )
                    attribute_name = "".join(attribute_parts) if attribute_parts else ""
                    if receiver_root in dynamic_module_aliases and (
                        attribute_name in dynamic_call_leaves
                        or attribute_parts is None
                    ):
                        errors.append(
                            f"dynamic package-loading reflection in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                    if receiver_root in process_module_aliases and (
                        attribute_name in process_call_leaves
                        or attribute_parts is None
                    ):
                        errors.append(
                            f"dynamic process-execution reflection in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                process_alias_call = False
                ambiguous_process_alias = False
                if call_name in process_aliases:
                    process_alias_call, ambiguous_process_alias = current_alias_binding(
                        call_name,
                        node,
                        process_aliases,
                        process_module_aliases,
                        process_call_leaves,
                    )
                is_process_call = process_alias_call or (
                    call_leaf in process_call_leaves
                    and call_name.split(".", 1)[0] in process_module_aliases
                )
                if ambiguous_process_alias:
                    errors.append(
                        f"ambiguous process-launcher alias in "
                        f"{_relative(path, root)}:{node.lineno}"
                    )
                if is_process_call:
                    if any(keyword.arg is None for keyword in node.keywords):
                        errors.append(
                            f"unsupported indirect process arguments in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                    command_nodes = [
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "executable"
                    ]
                    effective_process_leaf = process_alias_leaves.get(call_name, call_leaf)
                    command_index = 1 if effective_process_leaf in {
                        "spawnl",
                        "spawnle",
                        "spawnlp",
                        "spawnlpe",
                        "spawnv",
                        "spawnve",
                        "spawnvp",
                        "spawnvpe",
                    } else 0
                    command_nodes.extend(node.args[command_index:command_index + 1])
                    command_nodes.extend(
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg in {"args", "cmd", "command"}
                    )
                    command_parts: list[str] = []
                    analysis_limited = False
                    command_heads: list[str] = []
                    for command_node in command_nodes:
                        resolved = _static_string_parts(command_node, assignments)
                        if resolved is not None:
                            command_parts.extend(resolved)
                            continue
                        head = _static_process_head(command_node, assignments)
                        if head is None:
                            analysis_limited = True
                        else:
                            command_heads.append(head)
                    is_reproducibility_broker = (
                        _relative(path, root) == "tools/check_release_reproducibility.py"
                        and call_name == "subprocess.run"
                        and any(
                            isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and parent.name == "run_command"
                            and node in ast.walk(parent)
                            for parent in ast.walk(tree)
                        )
                    )
                    if analysis_limited:
                        if not is_reproducibility_broker:
                            errors.append(
                                f"process command exceeds static analysis limits in "
                                f"{_relative(path, root)}:{node.lineno}"
                            )
                    if any(_is_package_manager_command((head,)) for head in command_heads):
                        errors.append(
                            f"package-manager command launched by {call_name!r} in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                    if _is_package_manager_command(tuple(command_parts)):
                        errors.append(
                            f"package-manager command launched by {call_name!r} in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
            if isinstance(node, ast.Lambda):
                for child in ast.walk(node.body):
                    if not isinstance(child, ast.Call):
                        continue
                    child_name = _call_name(child)
                    child_leaf = child_name.rsplit(".", 1)[-1]
                    if child_name in process_aliases or (
                        child_leaf in process_call_leaves
                        and child_name.split(".", 1)[0] in process_module_aliases
                    ):
                        errors.append(
                            f"unsupported lambda process wrapper in "
                            f"{_relative(path, root)}:{node.lineno}"
                        )
                        break
    return errors


def check_javascript_package_loading(root: Path) -> list[str]:
    errors: list[str] = []
    app = root / "app"
    if not app.is_dir():
        return ["missing browser application directory: app"]
    for path in sorted(_iter_files(app)):
        if path.suffix.casefold() not in {".cjs", ".js", ".mjs"}:
            continue
        source = _read_text(path, root, errors)
        if source is None:
            continue
        if len(source) > MAX_JAVASCRIPT_ANALYSIS_CHARACTERS:
            errors.append(
                f"JavaScript source exceeds static analysis limits in "
                f"{_relative(path, root)}"
            )
            continue
        _without_comments, executable_code, literals = _javascript_views(source)
        for start, _end, _value, quote in literals:
            if quote != "`":
                continue
            template = source[start:_end]
            if (
                re.search(r"(?<!\\)\$\{", template)
                and TEMPLATE_DYNAMIC_TOKEN.search(template)
            ):
                line_number = source.count("\n", 0, start) + 1
                errors.append(
                    f"unsupported loader token in interpolated template at "
                    f"{_relative(path, root)}:{line_number}"
                )
        for pattern, label in DYNAMIC_JAVASCRIPT_LOADERS:
            match = pattern.search(executable_code)
            if match:
                line_number = executable_code.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{label} in {_relative(path, root)}:{line_number}"
                )
    return errors


def _decode_javascript_string(raw: str) -> str:
    result: list[str] = []
    index = 0
    simple_escapes = {
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
    }
    while index < len(raw):
        character = raw[index]
        if character != "\\" or index + 1 >= len(raw):
            result.append(character)
            index += 1
            continue
        escaped = raw[index + 1]
        if escaped in {"\n", "\r"}:
            index += 2
            if escaped == "\r" and index < len(raw) and raw[index] == "\n":
                index += 1
            continue
        if escaped == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", raw[index + 2:index + 4]):
            result.append(chr(int(raw[index + 2:index + 4], 16)))
            index += 4
            continue
        if escaped == "u":
            if index + 2 < len(raw) and raw[index + 2] == "{":
                close = raw.find("}", index + 3, index + 10)
                digits = raw[index + 3:close] if close >= 0 else ""
                if digits and re.fullmatch(r"[0-9A-Fa-f]{1,6}", digits):
                    codepoint = int(digits, 16)
                    if codepoint > sys.maxunicode:
                        result.append(raw[index : close + 1])
                        index = close + 1
                        continue
                    result.append(chr(codepoint))
                    index = close + 1
                    continue
            digits = raw[index + 2:index + 6]
            if re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                result.append(chr(int(digits, 16)))
                index += 6
                continue
        result.append(simple_escapes.get(escaped, escaped))
        index += 2
    return "".join(result)


JAVASCRIPT_REGEX_PREFIX_CHARACTERS = set("([{=,:;!&|?+-*~^<>%")
JAVASCRIPT_REGEX_PREFIX_WORDS = {
    "await",
    "case",
    "catch",
    "delete",
    "do",
    "else",
    "in",
    "instanceof",
    "new",
    "of",
    "return",
    "throw",
    "typeof",
    "void",
    "yield",
}


def _previous_javascript_token(characters: list[str], end: int) -> tuple[str, str]:
    index = end - 1
    while index >= 0 and characters[index].isspace():
        index -= 1
    if index < 0:
        return "", "start"
    character = characters[index]
    if re.match(r"[A-Za-z0-9_$]", character):
        token_end = index + 1
        while index >= 0 and re.match(r"[A-Za-z0-9_$]", characters[index]):
            index -= 1
        return "".join(characters[index + 1 : token_end]), "word"
    if character == ">" and index >= 1 and characters[index - 1] == "=":
        return "=>", "operator"
    return character, "punctuation"


def _is_javascript_regex_start(
    source: str,
    index: int,
    executable_code: list[str],
) -> bool:
    following = source[index + 1] if index + 1 < len(source) else ""
    if following in {"", "/", "*", "="}:
        return False
    token, kind = _previous_javascript_token(executable_code, index)
    return (
        kind == "start"
        or token in JAVASCRIPT_REGEX_PREFIX_CHARACTERS
        or token == "=>"
        or (kind == "word" and token in JAVASCRIPT_REGEX_PREFIX_WORDS)
    )


def _javascript_views(
    source: str,
) -> tuple[str, str, list[tuple[int, int, str, str]]]:
    without_comments = list(source)
    executable_code = list(source)
    literals: list[tuple[int, int, str, str]] = []
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
            for position in range(index, end):
                without_comments[position] = " "
                executable_code[position] = " "
            index = end
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            end = len(source) if close < 0 else close + 2
            for position in range(index, end):
                if source[position] != "\n":
                    without_comments[position] = " "
                    executable_code[position] = " "
            index = end
            continue
        if source[index] == "/" and _is_javascript_regex_start(
            source,
            index,
            executable_code,
        ):
            end = index + 1
            escaped = False
            inside_class = False
            while end < len(source):
                character = source[end]
                if character == "\n":
                    break
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == "[":
                    inside_class = True
                elif character == "]":
                    inside_class = False
                elif character == "/" and not inside_class:
                    end += 1
                    while end < len(source) and source[end].isalpha():
                        end += 1
                    break
                end += 1
            for position in range(index, end):
                if source[position] != "\n":
                    without_comments[position] = " "
                    executable_code[position] = " "
            index = end
            continue
        quote = source[index]
        if quote not in {"\"", "'", "`"}:
            index += 1
            continue
        start = index
        index += 1
        raw: list[str] = []
        while index < len(source):
            character = source[index]
            if character == "\\" and index + 1 < len(source):
                raw.extend((character, source[index + 1]))
                index += 2
                continue
            if character == quote:
                index += 1
                break
            raw.append(character)
            index += 1
        end = index
        for position in range(start, end):
            if source[position] != "\n":
                executable_code[position] = " "
        literals.append((start, end, _decode_javascript_string("".join(raw)), quote))
    return "".join(without_comments), "".join(executable_code), literals


def _normalise_browser_url(value: str) -> str:
    value = re.sub(r"[\t\n\r\f]+", "", value).replace("\\", "/")
    return value.strip(" \x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0e\x0f"
                       "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
                       "\x1c\x1d\x1e\x1f\x7f")


def _remote_value_errors(value: str, relative: str) -> list[str]:
    errors: list[str] = []
    normalised = _normalise_browser_url(value)
    for match in REMOTE_URL.finditer(normalised):
        url = match.group(0).rstrip(").,;]")
        if _origin(url) != PYODIDE_ORIGIN:
            errors.append(
                f"unapproved remote executable origin in {relative}: {_origin(url) or url}"
            )
        elif url not in {PYODIDE_LOADER_URL, PYODIDE_INDEX_URL}:
            errors.append(f"unapproved remote executable URL in {relative}: {url}")
    if normalised.startswith("//"):
        errors.append(
            f"protocol-relative remote executable URL in {relative}: {normalised}"
        )
    return errors


def _javascript_assignment_before(source: str, offset: int) -> str | None:
    """Return a simple identifier assigned immediately before a string literal."""
    index = offset - 1
    while index >= 0 and (source[index].isspace() or source[index] == "("):
        index -= 1
    if index < 0 or source[index] != "=":
        return None
    index -= 1
    while index >= 0 and source[index].isspace():
        index -= 1
    end = index + 1
    while index >= 0 and re.match(r"[A-Za-z0-9_$]", source[index]):
        index -= 1
    name = source[index + 1 : end]
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
        return None
    if index >= 0 and source[index] in {".", "=", ">"}:
        return None
    return name


def _check_javascript_remote_locations(source: str, path: Path, root: Path) -> list[str]:
    relative = _relative(path, root)
    if len(source) > MAX_JAVASCRIPT_ANALYSIS_CHARACTERS:
        return [f"JavaScript source exceeds static analysis limits in {relative}"]
    without_comments, executable_code, literals = _javascript_views(source)
    errors: list[str] = []
    if re.search(r"\\u(?:\{[0-9A-Fa-f]+\}|[0-9A-Fa-f]{4})", executable_code):
        errors.append(f"escaped JavaScript identifier is unsupported in {relative}")
    for _start, _end, value, _quote in literals:
        errors.extend(_remote_value_errors(value, relative))

    index = 0
    while index < len(literals):
        _start, end, value, _quote = literals[index]
        combined_parts = [value]
        next_index = index + 1
        concatenated = False
        while next_index < len(literals):
            next_start, next_end, next_value, _next_quote = literals[next_index]
            between = without_comments[end:next_start]
            if not re.fullmatch(r"[\s()+]*\+[\s()+]*", between):
                break
            concatenated = True
            combined_parts.append(next_value)
            end = next_end
            next_index += 1
        if concatenated and _remote_value_errors("".join(combined_parts), relative):
            errors.append(f"remote executable URL concatenation in {relative}")
            index = next_index
        else:
            index += 1

    remote_literals: list[tuple[int, int, str, str]] = []
    for literal in literals:
        start, end, value, _quote = literal
        normalised = _normalise_browser_url(value)
        is_remote = bool(_remote_value_errors(value, relative)) or any(
            remote in normalised
            for remote in (PYODIDE_LOADER_URL, PYODIDE_INDEX_URL, PYODIDE_ORIGIN)
        )
        if is_remote:
            remote_literals.append(literal)

    if len(remote_literals) > MAX_JAVASCRIPT_REMOTE_BINDINGS:
        errors.append(
            f"JavaScript remote-binding analysis exceeds static limits in {relative}"
        )
        return list(dict.fromkeys(errors))

    tail_work = 0
    for start, end, _value, _quote in remote_literals:
        suffix = without_comments[end:]
        tail_work += len(suffix)
        if tail_work > MAX_JAVASCRIPT_TAIL_ANALYSIS_CHARACTERS:
            errors.append(
                f"JavaScript tail analysis exceeds static limits in {relative}"
            )
            return list(dict.fromkeys(errors))
        prefix = re.split(r"[;\n]", without_comments[:start])[-1]
        if re.match(r"\s*\)*\s*\.concat\s*\(", suffix) or re.search(
            r"\bnew\s+URL\s*\([^)]*,\s*$",
            prefix,
            re.DOTALL,
        ):
            errors.append(f"remote executable URL concatenation in {relative}")

    remote_variables: dict[str, tuple[str, int]] = {}
    remote_bindings: list[tuple[str, str, int]] = []
    for start, end, value, _quote in remote_literals:
        assignment_name = _javascript_assignment_before(without_comments, start)
        if assignment_name:
            remote_variables[assignment_name] = (value, end)
            remote_bindings.append((assignment_name, value, end))

    alias_pattern = re.compile(
        r"\b(?:const|let|var)\s+(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=\s*(?P<source>[A-Za-z_$][A-Za-z0-9_$]*)\s*"
        r"(?:;|(?=\r?$))",
        re.MULTILINE,
    )
    alias_edges: dict[str, list[tuple[str, int]]] = {}
    for match in alias_pattern.finditer(executable_code):
        alias_edges.setdefault(match.group("source"), []).append(
            (match.group("alias"), match.end())
        )
    pending_aliases = list(remote_variables)
    while pending_aliases:
        source_name = pending_aliases.pop()
        for alias_name, alias_end in alias_edges.get(source_name, []):
            if alias_name in remote_variables:
                continue
            remote_variables[alias_name] = (remote_variables[source_name][0], alias_end)
            remote_bindings.append(
                (alias_name, remote_variables[source_name][0], alias_end)
            )
            pending_aliases.append(alias_name)

    if len(remote_bindings) > MAX_JAVASCRIPT_REMOTE_BINDINGS:
        errors.append(
            f"JavaScript remote-binding analysis exceeds static limits in {relative}"
        )
        return list(dict.fromkeys(errors))

    for name, _value, assignment_end in remote_bindings:
        escaped_name = re.escape(name)
        later = executable_code[assignment_end:]
        tail_work += len(later)
        if tail_work > MAX_JAVASCRIPT_TAIL_ANALYSIS_CHARACTERS:
            errors.append(
                f"JavaScript tail analysis exceeds static limits in {relative}"
            )
            return list(dict.fromkeys(errors))
        shadow = re.search(
            rf"(?<![.A-Za-z0-9_$])(?:(?:const|let|var)\s+)?"
            rf"{escaped_name}\s*=",
            later,
        )
        if shadow:
            later = later[:shadow.start()]
        if (
            re.search(
                rf"(?:\(\s*)*\b{escaped_name}\b(?:\s*\))*\s*"
                rf"(?:\+|\?*\.\s*concat\s*\()",
                later,
            )
            or re.search(rf"\+\s*(?:\(\s*)*\b{escaped_name}\b", later)
            or any(
                re.search(r"\bnew\s+URL\s*\(", statement)
                and re.search(rf"\b{escaped_name}\b", statement)
                for statement in re.split(r"[;\n]", later)
            )
            or any(
                quote == "`"
                and start >= assignment_end
                and re.search(rf"\$\{{\s*{escaped_name}\s*\}}", value)
                for start, _end, value, quote in literals
            )
        ):
            errors.append(f"remote executable URL concatenation in {relative}")

    return list(dict.fromkeys(errors))


class _ExecutableHTMLParser(HTMLParser):
    """Collect only HTML fields that can select executable browser resources."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.executable_locations: list[str] = []
        self.csp_values: list[str] = []
        self.inline_scripts: list[str] = []
        self.inline_documents: list[str] = []
        self.embedded_documents: list[str] = []
        self.navigation_locations: list[str] = []
        self.has_meta_refresh = False
        self._inside_script = False
        self._external_script = False
        self._script_fragments: list[str] = []

    @staticmethod
    def _values(attributes: list[tuple[str, str | None]], name: str) -> list[str]:
        return [
            value
            for attribute, value in attributes
            if attribute.casefold() == name and value is not None
        ]

    def _inspect_tag(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
        *,
        self_closing: bool,
    ) -> None:
        folded_tag = tag.casefold()
        self.inline_scripts.extend(
            value
            for attribute, value in attributes
            if attribute.casefold().startswith("on") and value is not None
        )
        if folded_tag == "script":
            sources = self._values(attributes, "src")
            sources.extend(self._values(attributes, "href"))
            sources.extend(self._values(attributes, "xlink:href"))
            self.executable_locations.extend(sources)
            if not self_closing:
                self._inside_script = True
                self._external_script = bool(sources)
                self._script_fragments = []
            return
        if folded_tag in {"frame", "iframe"}:
            self.embedded_documents.append(folded_tag)
            self.executable_locations.extend(self._values(attributes, "src"))
            self.inline_documents.extend(self._values(attributes, "srcdoc"))
            return
        if folded_tag == "object":
            self.embedded_documents.append(folded_tag)
            self.executable_locations.extend(self._values(attributes, "data"))
            return
        if folded_tag == "embed":
            self.embedded_documents.append(folded_tag)
            self.executable_locations.extend(self._values(attributes, "src"))
            return
        if folded_tag == "link":
            relationships = {
                token.casefold()
                for value in self._values(attributes, "rel")
                for token in value.split()
            }
            preload_types = {
                token.casefold()
                for value in self._values(attributes, "as")
                for token in value.split()
            }
            if relationships & {"modulepreload", "stylesheet"} or (
                "preload" in relationships
                and bool(preload_types & {"script", "style"})
            ):
                self.executable_locations.extend(self._values(attributes, "href"))
            return
        if folded_tag == "base":
            self.executable_locations.extend(self._values(attributes, "href"))
            return
        if folded_tag == "meta":
            equivalents = {
                value.casefold() for value in self._values(attributes, "http-equiv")
            }
            if "content-security-policy" in equivalents:
                self.csp_values.extend(self._values(attributes, "content"))
            if "refresh" in equivalents:
                self.has_meta_refresh = True
            return
        if folded_tag == "a":
            self.navigation_locations.extend(self._values(attributes, "href"))
        elif folded_tag == "form":
            self.navigation_locations.extend(self._values(attributes, "action"))
        elif folded_tag in {"button", "input"}:
            self.navigation_locations.extend(self._values(attributes, "formaction"))

    def handle_starttag(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
    ) -> None:
        self._inspect_tag(tag, attributes, self_closing=False)

    def handle_startendtag(
        self,
        tag: str,
        attributes: list[tuple[str, str | None]],
    ) -> None:
        self._inspect_tag(tag, attributes, self_closing=True)

    def handle_data(self, data: str) -> None:
        if self._inside_script and not self._external_script:
            self._script_fragments.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() != "script" or not self._inside_script:
            return
        if not self._external_script:
            self.inline_scripts.append("".join(self._script_fragments))
        self._inside_script = False
        self._external_script = False
        self._script_fragments = []

    def finish(self) -> None:
        if self._inside_script and not self._external_script:
            self.inline_scripts.append("".join(self._script_fragments))
        self._inside_script = False
        self._external_script = False
        self._script_fragments = []


def _check_csp_remote_locations(value: str, relative: str) -> list[str]:
    errors: list[str] = []
    compact = re.sub(r"[\t\n\r\f]+", "", value).replace("\\", "/")
    source_directives = {"base-uri", "form-action", "frame-ancestors"}
    approved_sources = {
        "'none'",
        "'self'",
        "'wasm-unsafe-eval'",
        "blob:",
        "data:",
        PYODIDE_ORIGIN,
    }
    for directive in compact.split(";"):
        fields = directive.split()
        if not fields:
            continue
        directive_name = fields[0].casefold()
        if not (
            directive_name.endswith("-src")
            or directive_name in source_directives
        ):
            continue
        for source in fields[1:]:
            if source not in approved_sources:
                errors.append(
                    f"unapproved CSP executable source in {relative}: {source}"
                )
    return errors


def _check_html_resource_location(value: str, relative: str) -> list[str]:
    normalised = _normalise_browser_url(value)
    errors: list[str] = []
    scheme = urlsplit(normalised).scheme.casefold()
    if scheme in {"blob", "data", "javascript"}:
        errors.append(
            f"unapproved executable URL scheme in {relative}: {scheme}:"
        )
    for match in REMOTE_URL.finditer(normalised):
        url = match.group(0).rstrip(").,;]")
        if _origin(url) != PYODIDE_ORIGIN:
            errors.append(
                f"unapproved remote executable origin in {relative}: "
                f"{_origin(url) or url}"
            )
        else:
            errors.append(f"unapproved remote executable URL in {relative}: {url}")
    if normalised.startswith("//"):
        errors.append(
            f"protocol-relative remote executable URL in {relative}: {normalised}"
        )
    return errors


def _check_html_executable_locations(source: str, path: Path, root: Path) -> list[str]:
    relative = _relative(path, root)
    parser = _ExecutableHTMLParser()
    try:
        parser.feed(source)
        parser.close()
    except (AssertionError, RecursionError, ValueError) as exc:
        return [f"cannot inspect HTML executable locations in {relative}: {exc}"]
    finally:
        parser.finish()

    errors: list[str] = []
    if not parser.csp_values:
        errors.append(f"missing Content-Security-Policy declaration in {relative}")
    elif not any(
        re.search(r"(?:^|;)\s*(?:default-src|script-src)\s+", value, re.IGNORECASE)
        for value in parser.csp_values
    ):
        errors.append(f"Content-Security-Policy lacks script-src or default-src in {relative}")
    for value in parser.executable_locations:
        errors.extend(_check_html_resource_location(value, relative))
        normalised = _normalise_browser_url(value)
        if not urlsplit(normalised).scheme and not normalised.startswith("//"):
            target = (path.parent / normalised.split("?", 1)[0].split("#", 1)[0]).resolve()
            app_root = (root / "app").resolve()
            try:
                target.relative_to(app_root)
            except ValueError:
                errors.append(f"local executable resource escapes app in {relative}: {value}")
            else:
                if not target.is_file():
                    errors.append(f"local executable resource is missing in {relative}: {value}")
    if parser.inline_documents:
        errors.append(f"inline frame document is unsupported in {relative}")
    if parser.embedded_documents:
        errors.append(f"embedded active document is unsupported in {relative}")
    if parser.has_meta_refresh:
        errors.append(f"meta refresh is unsupported in {relative}")
    for value in parser.navigation_locations:
        scheme = urlsplit(_normalise_browser_url(value)).scheme.casefold()
        if scheme in {"blob", "data", "javascript"}:
            errors.append(f"unapproved navigation URL scheme in {relative}: {scheme}:")
    for value in parser.csp_values:
        errors.extend(_check_csp_remote_locations(value, relative))
    if parser.inline_scripts:
        errors.append(f"inline script or event handler is unsupported in {relative}")
    return list(dict.fromkeys(errors))


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
    for path in sorted(_iter_files(app)):
        suffix_name = path.suffix.casefold()
        if suffix_name not in {".cjs", ".html", ".js", ".json", ".mjs"}:
            continue
        raw_source = _read_text(path, root, errors)
        if raw_source is None:
            continue
        if suffix_name == ".html":
            errors.extend(_check_html_executable_locations(raw_source, path, root))
            continue
        if suffix_name in {".cjs", ".js", ".mjs"}:
            errors.extend(_check_javascript_remote_locations(raw_source, path, root))
            continue

        relative = _relative(path, root)
        try:
            payload = json.loads(
                raw_source,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (json.JSONDecodeError, DuplicateJsonKeyError, RecursionError) as exc:
            errors.append(f"invalid JSON in {relative}: {exc}")
            continue
        pending: list[tuple[Any, int]] = [(payload, 0)]
        visited = 0
        string_characters = 0
        while pending:
            value, depth = pending.pop()
            visited += 1
            if visited > 65_536 or depth > 128:
                errors.append(f"JSON remote-origin analysis exceeds static limits in {relative}")
                break
            if isinstance(value, str):
                string_characters += len(value)
                if string_characters > 4_000_000:
                    errors.append(f"JSON remote-origin analysis exceeds static limits in {relative}")
                    break
                errors.extend(_remote_value_errors(value, relative))
            elif isinstance(value, dict):
                pending.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
    return list(dict.fromkeys(errors))


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
        if (
            character == "#"
            and not quote
            and (index == 0 or line[index - 1].isspace())
        ):
            return line[:index]
    return line


def _indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _yaml_executable_payloads(lines: list[str]) -> list[tuple[int, str, str]]:
    payloads: list[tuple[int, str, str]] = []
    key_pattern = re.compile(
        r"^(?P<space>\s*)(?P<dash>-\s*)?(?P<key>run|env)\s*:\s*(?P<value>.*)$"
    )
    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line).rstrip()
        match = key_pattern.match(code)
        if not match:
            continue
        key = match.group("key")
        value = match.group("value").strip()
        fragments = [value]
        should_collect_block = key == "env" and not value
        should_collect_block = should_collect_block or (
            key == "run"
            and (not value or re.fullmatch(r"[|>][0-9+-]*", value) is not None)
        )
        if should_collect_block:
            fragments = []
            key_indent = len(match.group("space")) + (2 if match.group("dash") else 0)
            direct_indent: int | None = None
            for child_index in range(index + 1, len(lines)):
                child = _strip_yaml_comment(lines[child_index]).rstrip()
                if not child.strip():
                    continue
                if _indentation(child) <= key_indent:
                    break
                if direct_indent is None:
                    direct_indent = _indentation(child)
                if key == "run" or _indentation(child) == direct_indent:
                    fragments.append(child.strip())
        if key == "env" and should_collect_block:
            payloads.extend(
                (index + 1, key, fragment) for fragment in fragments
            )
        else:
            separator = " " if value.startswith(">") else "\n"
            payloads.append((index + 1, key, separator.join(fragments)))
    return payloads


def _expand_workflow_environment(
    command: str,
    environment: dict[str, set[str]],
) -> str | None:
    expanded = command
    if len(expanded) > MAX_WORKFLOW_COMMAND_CHARACTERS:
        return None
    assignment_pattern = re.compile(
        r"(?:^|[;\s])(?P<name>[A-Za-z_][A-Za-z0-9_]*)="
        r"(?P<value>[\"']?[A-Za-z0-9_./-]+[\"']?)(?=$|[;\s])"
    )
    local_environment = {name: set(values) for name, values in environment.items()}
    for match in assignment_pattern.finditer(command):
        local_environment.setdefault(match.group("name"), set()).add(
            match.group("value").strip("\"'")
        )
    variable_pattern = re.compile(
        r"\$(?P<plain>[A-Za-z_][A-Za-z0-9_]*)"
        r"|\$\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}"
        r"|%((?P<windows>[A-Za-z_][A-Za-z0-9_]*))%"
        r"|\$\{\{\s*env\.(?P<github>[A-Za-z_][A-Za-z0-9_]*)\s*\}\}"
    )
    for _ in range(16):
        changed = False

        projected_length = len(expanded)
        for match in variable_pattern.finditer(expanded):
            name = (
                match.group("plain")
                or match.group("braced")
                or match.group("windows")
                or match.group("github")
            )
            values = local_environment.get(name, set())
            if len(values) == 1:
                projected_length += len(next(iter(values))) - len(match.group(0))
                if projected_length > MAX_WORKFLOW_COMMAND_CHARACTERS:
                    return None

        def replace_variable(match: re.Match[str]) -> str:
            nonlocal changed
            name = (
                match.group("plain")
                or match.group("braced")
                or match.group("windows")
                or match.group("github")
            )
            values = local_environment.get(name, set())
            if len(values) != 1:
                return match.group(0)
            changed = True
            return next(iter(values))

        expanded = variable_pattern.sub(replace_variable, expanded)
        if len(expanded) > MAX_WORKFLOW_COMMAND_CHARACTERS:
            return None
        if not changed:
            break
    return re.sub(r"\\\s+", " ", expanded)


def _has_unresolved_executable(command: str) -> bool:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return True
    while arguments and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", arguments[0]):
        arguments.pop(0)
    while arguments:
        executable = arguments[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if executable == "env":
            arguments.pop(0)
            while arguments and (
                arguments[0].startswith("-")
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", arguments[0])
            ):
                option = arguments.pop(0)
                if option in {"-u", "--unset"} and arguments:
                    arguments.pop(0)
            continue
        if executable in {"command", "exec", "nohup", "sudo"}:
            arguments.pop(0)
            while arguments and arguments[0].startswith("-"):
                arguments.pop(0)
            continue
        break
    if not arguments:
        return False
    executable = arguments[0]
    if "$" in executable or re.fullmatch(r"%[^%]+%", executable) is not None:
        return True
    folded = executable.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    lowered_arguments = [argument.casefold() for argument in arguments]
    if folded in {"bash", "cmd", "dash", "ksh", "powershell", "pwsh", "sh", "zsh"}:
        for flag in ("-c", "/c", "-command"):
            if flag in lowered_arguments[1:]:
                index = lowered_arguments.index(flag)
                return index + 1 >= len(arguments) or _has_unresolved_executable(arguments[index + 1])
    if folded == "py" or re.fullmatch(r"python(?:3(?:\.\d+)?)?", folded):
        if "-c" in lowered_arguments[1:]:
            index = lowered_arguments.index("-c")
            if index + 1 >= len(arguments):
                return True
            payload = arguments[index + 1]
            return bool(re.search(r"\$|%[^%]+%|\b(?:eval|exec|__import__)\b", payload))
    return False


def _run_step_uses_bash(lines: list[str], run_index: int) -> bool:
    run_code = _strip_yaml_comment(lines[run_index]).rstrip()
    run_match = re.match(r"^(?P<space>\s*)(?P<dash>-\s*)?run\s*:", run_code)
    if not run_match:
        return False
    key_indent = len(run_match.group("space")) + (2 if run_match.group("dash") else 0)
    item_indent = max(0, key_indent - 2)
    item_pattern = re.compile(rf"^\s{{{item_indent}}}-\s+")
    start = run_index
    for index in range(run_index, -1, -1):
        code = _strip_yaml_comment(lines[index]).rstrip()
        if code.strip() and item_pattern.match(code):
            start = index
            break
    end = len(lines)
    for index in range(start + 1, len(lines)):
        code = _strip_yaml_comment(lines[index]).rstrip()
        if code.strip() and item_pattern.match(code):
            end = index
            break
    for index in range(start, end):
        code = _strip_yaml_comment(lines[index]).rstrip()
        match = re.match(
            r"^(?P<space>\s*)(?P<dash>-\s*)?shell\s*:\s*"
            r"[\"']?bash[\"']?\s*$",
            code,
        )
        if match and len(match.group("space")) + (2 if match.group("dash") else 0) == key_indent:
            return True
    return False


def _shell_statements(command: str) -> tuple[str, ...]:
    statements: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if escaped:
            current.append(character)
            escaped = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            current.append(character)
            escaped = True
            index += 1
            continue
        if quote:
            current.append(character)
            if character == quote:
                quote = ""
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            current.append(character)
            index += 1
            continue
        separator_width = 0
        if character in {"\n", ";", "|"}:
            separator_width = 1
            if character == "|" and index + 1 < len(command) and command[index + 1] == "|":
                separator_width = 2
        elif command.startswith("&&", index):
            separator_width = 2
        if separator_width:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            index += separator_width
            continue
        current.append(character)
        index += 1
    statement = "".join(current).strip()
    if statement:
        statements.append(statement)
    return tuple(statements)


def _check_yaml_lexical_policy(lines: list[str], path: Path, root: Path) -> list[str]:
    """Reject YAML forms that the deliberately narrow security parser cannot prove safe."""
    errors: list[str] = []
    relative = _relative(path, root)
    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line).rstrip()
        if not code.strip():
            continue
        if re.match(r"^\s*(?:-\s*)?\?\s", code):
            errors.append(
                f"explicit YAML mapping keys are unsupported in {relative}:{index + 1}"
            )
        if "\\u" in code or "\\U" in code or "\\x" in code:
            errors.append(f"escaped YAML key or value is unsupported in {relative}:{index + 1}")
        if QUOTED_YAML_KEY.match(code):
            errors.append(f"quoted YAML mapping key is unsupported in {relative}:{index + 1}")
        if FLOW_CRITICAL_YAML_KEY.search(code):
            errors.append(f"flow-style security key is unsupported in {relative}:{index + 1}")
        if TAGGED_SECURITY_YAML_KEY.match(code):
            errors.append(
                f"YAML tags on security-sensitive mapping keys are unsupported in "
                f"{relative}:{index + 1}"
            )
        shell_scalar = re.match(
            r"^\s*(?:-\s*)?shell\s*:\s*(?P<value>.+)$",
            code,
        )
        if shell_scalar and shell_scalar.group("value").strip().strip("\"'") != "bash":
            errors.append(
                f"workflow shell must be bash in {relative}:{index + 1}"
            )
        run_scalar = re.match(r"^\s*(?:-\s*)?run\s*:\s*(?P<value>.*)$", code)
        if run_scalar:
            value = run_scalar.group("value").strip()
            if value[:1] in {"\"", "'"} and not value.endswith(value[0]):
                errors.append(
                    f"multi-line quoted run scalar is unsupported in {relative}:{index + 1}"
                )
        if re.match(
            r"^\s*(?:-\s*)?(?:env|permissions|run|uses)\s*:\s*!",
            code,
        ):
            errors.append(
                f"YAML tags in security-sensitive values are unsupported in "
                f"{relative}:{index + 1}"
            )
        if re.match(r"^\s*(?:-\s*)?env\s*:\s*\{", code):
            errors.append(
                f"flow-style env is unsupported in {relative}:{index + 1}"
            )
        if re.search(
            r"(?:^\s*(?:-\s*)?\*[A-Za-z0-9_-]+\s*:"
            r"|:\s*[&*][A-Za-z0-9_-]+(?:\s|$)"
            r"|^\s*-\s*&[A-Za-z0-9_-]+(?:\s|$))",
            code,
        ):
            errors.append(f"YAML anchors and aliases are unsupported in {relative}:{index + 1}")

    environment: dict[str, set[str]] = {}
    runs: list[tuple[int, str]] = []
    for line_number, key, payload in _yaml_executable_payloads(lines):
        if key == "run":
            runs.append((line_number, payload))
            continue
        match = re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*\s*:\s*(?P<value>.+)",
            payload,
        )
        if match:
            name = payload.split(":", 1)[0].strip()
            environment.setdefault(name, set()).add(
                match.group("value").strip().strip("\"'")
            )
    for line_number, payload in runs:
        referenced_names: set[str] = set()
        for variable_match in re.finditer(
                r"\$([A-Za-z_][A-Za-z0-9_]*)"
                r"|\$\{([A-Za-z_][A-Za-z0-9_]*)\}"
                r"|%([A-Za-z_][A-Za-z0-9_]*)%"
                r"|\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}",
                payload,
        ):
            referenced_names.update(
                group for group in variable_match.groups() if group is not None
            )
        for name in sorted(referenced_names):
            if len(environment.get(name, set())) > 1:
                errors.append(
                    f"ambiguous workflow environment variable {name!r} in "
                    f"{relative}:{line_number}"
                )
        expanded = _expand_workflow_environment(payload, environment)
        if expanded is None:
            errors.append(
                f"workflow command exceeds static analysis limits in "
                f"{relative}:{line_number}"
            )
            continue
        statements = _shell_statements(expanded)
        if any(_has_unresolved_executable(statement) for statement in statements):
            errors.append(
                f"unsupported dynamic workflow executable in "
                f"{relative}:{line_number}"
            )
        if any(
            _is_package_manager_command((statement,))
            for statement in statements
        ):
            errors.append(
                f"package-manager command is forbidden in {relative}:{line_number}"
            )

    for index, line in enumerate(lines):
        code = _strip_yaml_comment(line).rstrip()
        if re.match(r"^\s*(?:-\s*)?run\s*:", code) and not _run_step_uses_bash(
            lines,
            index,
        ):
            errors.append(
                f"workflow run step lacks a direct shell: bash in "
                f"{relative}:{index + 1}"
            )
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
    errors.extend(check_first_party_shadowing(root))
    errors.extend(check_standard_library_shadowing(root))
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
            "[PASS] dependency-boundary: manifests, source inventory, imports, runtime "
            "locations and workflow policy verified"
        )
    print(f"[LIMITATION] external-runtime-assurance: {EXTERNAL_RUNTIME_LIMITATION}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
