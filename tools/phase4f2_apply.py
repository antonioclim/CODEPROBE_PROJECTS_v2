#!/usr/bin/env python3
"""Apply the deterministic Phase 4F2 changes to an exact Phase 4F1 tree."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


EXPECTED_BASE_TREE = "f5e8d04d24f2fdcdb278c7fc166fe501dddf946b"
NEW_PATHS = (
    "SECURITY.md",
    ".github/CODEOWNERS",
    "CITATION.cff",
    "app/analysis-watchdog.js",
    "app/pyodide-support-policy.json",
    "docs/18-release-recovery.md",
    "docs/19-runtime-lifecycle.md",
    "docs/20-analysis-deadline.md",
    "src/codeprobe_engine/release_recovery.py",
    "tools/recover_release.py",
    "tools/check_pyodide_lifecycle.py",
    "tests/test_release_recovery.py",
    "tests/test_pseudonymisation.py",
    "tests/test_pyodide_lifecycle.py",
    "tests/test_analysis_deadline.py",
    "tests/test_phase4f2_governance.py",
)


class ApplyError(RuntimeError):
    """Raised when the expected Phase 4F1 source shape is not present."""


def run(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise ApplyError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n{completed.stdout}"
        )
    return completed.stdout.strip()


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ApplyError(message)


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise ApplyError(f"{label}: expected one occurrence, found {count}")
    return source.replace(old, new, 1)


def append_section(source: str, marker: str, content: str) -> str:
    if marker in source:
        return source
    return source.rstrip() + "\n\n" + content.strip() + "\n"


def line_offsets(source: str) -> list[int]:
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def replace_python_function(source: str, name: str, replacement: str) -> str:
    tree = ast.parse(source)
    target = next(
        (
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ),
        None,
    )
    if target is None or target.end_lineno is None:
        raise ApplyError(f"Python function {name} was not found")
    offsets = line_offsets(source)
    start = offsets[target.lineno - 1]
    end = offsets[target.end_lineno]
    return source[:start] + replacement.rstrip() + "\n" + source[end:]


def javascript_function_span(source: str, name: str) -> tuple[int, int]:
    match = re.search(
        rf"(?m)^[ \t]*(?:async\s+)?function\s+{re.escape(name)}\s*\(",
        source,
    )
    if not match:
        raise ApplyError(f"JavaScript function {name} was not found")
    brace = source.find("{", match.end())
    if brace < 0:
        raise ApplyError(f"JavaScript function {name} has no body")
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = brace
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
        elif block_comment:
            if character == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        else:
            if character == "/" and following == "/":
                line_comment = True
                index += 1
            elif character == "/" and following == "*":
                block_comment = True
                index += 1
            elif character in {"'", '"', "`"}:
                quote = character
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return match.start(), index + 1
        index += 1
    raise ApplyError(f"JavaScript function {name} is unbalanced")


def insert_python_import(source: str, statement: str, anchor: str | None = None) -> str:
    if statement in source:
        return source
    if anchor and anchor in source:
        return source.replace(anchor, anchor + statement + "\n", 1)
    tree = ast.parse(source)
    imports = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    if not imports:
        raise ApplyError(f"cannot place import {statement}")
    end_line = imports[-1].end_lineno or imports[-1].lineno
    lines = source.splitlines(keepends=True)
    lines.insert(end_line, statement + "\n")
    return "".join(lines)


def copy_new_files(source_root: Path, work_root: Path) -> None:
    for relative in NEW_PATHS:
        source = source_root / relative
        destination = work_root / relative
        require(source.is_file(), f"staged Phase 4F2 file is missing: {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def patch_release_replacements(work_root: Path) -> None:
    release_path = work_root / "src/codeprobe_engine/release.py"
    release = read(release_path)
    if "from .release_recovery import crash_safe_replace" not in release:
        release = insert_python_import(
            release,
            "from .release_recovery import crash_safe_replace",
        )
    replacements = release.count("os.replace(")
    require(replacements > 0, "release.py no longer contains the expected os.replace calls")
    release = release.replace("os.replace(", "crash_safe_replace(")
    write(release_path, release)

    build_path = work_root / "tools/build_release.py"
    build = read(build_path)
    if "from codeprobe_engine.release_recovery import crash_safe_replace" not in build:
        marker = re.search(r"(?m)^from codeprobe_engine\.[^\n]+\n", build)
        require(marker is not None, "cannot place build_release recovery import")
        build = (
            build[: marker.start()]
            + "from codeprobe_engine.release_recovery import crash_safe_replace\n"
            + build[marker.start() :]
        )
    replacements = build.count("os.replace(")
    require(replacements > 0, "build_release.py no longer contains the expected os.replace calls")
    build = build.replace("os.replace(", "crash_safe_replace(")
    write(build_path, build)

    init_path = work_root / "src/codeprobe_engine/__init__.py"
    init = read(init_path)
    statement = (
        "from .release_recovery import (ReleaseRecoveryError, crash_safe_replace, "
        "recover_pending_transaction)"
    )
    if statement not in init:
        init = init.rstrip() + "\n\n" + statement + "\n"
    write(init_path, init)


def patch_pseudonymisation(work_root: Path) -> None:
    path = work_root / "tools/calibrate_profile.py"
    source = read(path)
    for statement in ("import hmac", "import os", "import re", "import secrets"):
        source = insert_python_import(source, statement)

    helper_marker = "_PSEUDONYM_KEY, _PSEUDONYM_KEY_SOURCE = _load_pseudonym_key()"
    if helper_marker not in source:
        helper = r'''
def _load_pseudonym_key() -> tuple[bytes, str]:
    raw = os.environ.get("CODEPROBE_PSEUDONYM_KEY_HEX")
    if raw is None:
        return secrets.token_bytes(32), "process-random"
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise ValueError(
            "CODEPROBE_PSEUDONYM_KEY_HEX must contain exactly 64 hexadecimal characters"
        )
    return bytes.fromhex(raw), "environment-private"


_PSEUDONYM_KEY, _PSEUDONYM_KEY_SOURCE = _load_pseudonym_key()


def _hmac_token(value: object, *, domain: bytes, length: int) -> str:
    rendered = str(value).encode("utf-8")
    return hmac.new(
        _PSEUDONYM_KEY,
        domain + rendered,
        hashlib.sha256,
    ).hexdigest()[:length]


def pseudonymisation_metadata() -> dict[str, object]:
    return {
        "algorithm": "HMAC-SHA-256",
        "sample_token_hex_chars": 24,
        "group_token_hex_chars": 16,
        "key_scope": "process-private",
        "key_source": _PSEUDONYM_KEY_SOURCE,
        "key_serialised": False,
        "linkability": "within-one-controlled-key-scope",
    }

'''
        insertion = source.find("\ndef _pseudonymous_identifier")
        require(insertion >= 0, "cannot place pseudonymisation helper")
        source = source[: insertion + 1] + helper.lstrip("\n") + source[insertion + 1 :]

    source = replace_python_function(
        source,
        "_pseudonymous_identifier",
        '''def _pseudonymous_identifier(value: object) -> str:\n    return _hmac_token(value, domain=b"", length=24)''',
    )
    source = replace_python_function(
        source,
        "_group_token",
        '''def _group_token(value: object) -> str:\n    return _hmac_token(value, domain=b"group\\0", length=16)''',
    )

    if 'profile["pseudonymisation"] = pseudonymisation_metadata()' not in source:
        candidates = list(re.finditer(r"(?m)^(?P<i>[ \t]*)return\s+profile\s*$", source))
        require(candidates, "cannot attach pseudonymisation metadata to calibration profile")
        target = candidates[-1]
        statement = (
            f'{target.group("i")}profile["pseudonymisation"] = '
            "pseudonymisation_metadata()\n"
        )
        source = source[: target.start()] + statement + source[target.start() :]
    write(path, source)


def patch_runtime_config(work_root: Path) -> None:
    analysis = {
        "deadline_ms": 8000,
        "require_interrupt_buffer": True,
        "maximum_file_bytes": 262144,
        "maximum_project_bytes": 1048576,
    }
    for relative in ("app/runtime-config.json", "app/runtime-config.example.json"):
        path = work_root / relative
        payload = json.loads(read(path))
        payload["analysis"] = analysis
        write(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def patch_loader(work_root: Path) -> None:
    path = work_root / "app/pyodide-loader.js"
    source = read(path)
    if "analysis: {" not in source:
        marker = '''    privacy: {\n      history_enabled_default: false,\n      store_source_in_history: false,\n      clear_pyodide_payload_after_run: true\n    }\n'''
        require(marker in source, "loader default privacy block changed")
        replacement = marker[:-1] + ''',\n    analysis: {\n      deadline_ms: 8000,\n      require_interrupt_buffer: true,\n      maximum_file_bytes: 262144,\n      maximum_project_bytes: 1048576\n    }\n'''
        source = source.replace(marker, replacement, 1)

    if "Object.assign(config.analysis, raw.analysis);" not in source:
        marker = '''    if (raw.privacy && typeof raw.privacy === "object" && !Array.isArray(raw.privacy)) {\n      Object.assign(config.privacy, raw.privacy);\n    }\n'''
        require(marker in source, "loader mergeConfig privacy block changed")
        source = source.replace(
            marker,
            marker
            + '''    if (raw.analysis && typeof raw.analysis === "object" && !Array.isArray(raw.analysis)) {\n      Object.assign(config.analysis, raw.analysis);\n    }\n''',
            1,
        )

    if "Analysis deadline must be an integer" not in source:
        start, end = javascript_function_span(source, "validateRuntimeConfig")
        function = source[start:end]
        return_marker = "    return config;"
        require(return_marker in function, "validateRuntimeConfig return changed")
        validation = '''    const analysis = config.analysis || {};\n    if (!Number.isSafeInteger(analysis.deadline_ms) || analysis.deadline_ms < 100 || analysis.deadline_ms > 60000) {\n      throw new Error("Analysis deadline must be an integer between 100 and 60000 milliseconds.");\n    }\n    if (!Number.isSafeInteger(analysis.maximum_file_bytes) || analysis.maximum_file_bytes <= 0) {\n      throw new Error("Analysis maximum_file_bytes must be a positive safe integer.");\n    }\n    if (!Number.isSafeInteger(analysis.maximum_project_bytes) || analysis.maximum_project_bytes < analysis.maximum_file_bytes) {\n      throw new Error("Analysis maximum_project_bytes must be at least maximum_file_bytes.");\n    }\n    if (config.production && !analysis.require_interrupt_buffer) {\n      throw new Error("Production analysis requires an enforceable interrupt deadline.");\n    }\n'''
        function = function.replace(return_marker, validation + return_marker, 1)
        source = source[:start] + function + source[end:]

    if "CodeProbeAnalysisWatchdog.attach" not in source:
        marker = "      await verifyLoadedRuntime(runtime, provenance);\n"
        require(marker in source, "loader runtime verification marker changed")
        addition = '''      if (!window.CodeProbeAnalysisWatchdog || typeof window.CodeProbeAnalysisWatchdog.attach !== "function") {\n        if (config.production) {\n          throw new Error("Analysis deadline containment is unavailable because the watchdog did not load.");\n        }\n      } else {\n        const deadlineController = window.CodeProbeAnalysisWatchdog.attach(runtime, {\n          deadline_ms: config.analysis.deadline_ms,\n          require_interrupt_buffer: config.production ? config.analysis.require_interrupt_buffer : false\n        });\n        if (config.production && !deadlineController.supported) {\n          throw new Error("Analysis deadline containment is unavailable in this browser context.");\n        }\n        Object.defineProperty(runtime, "__codeprobeAnalysisDeadline", {\n          value: deadlineController,\n          configurable: false,\n          enumerable: false,\n          writable: false\n        });\n      }\n'''
        source = source.replace(marker, marker + addition, 1)
    write(path, source)


def patch_html(work_root: Path) -> None:
    for relative in ("app/index.html", "app/project.html"):
        path = work_root / relative
        source = read(path)
        if "analysis-watchdog.js" not in source:
            match = re.search(
                r'(?m)^(?P<i>[ \t]*)<script\b[^>]*src="pyodide-loader\.js"[^>]*></script>\s*$',
                source,
            )
            require(match is not None, f"{relative}: Pyodide loader script tag changed")
            indentation = match.group("i")
            tag = (
                f'{indentation}<script src="analysis-watchdog.js" '
                'integrity="sha256-PLACEHOLDER" crossorigin="anonymous"></script>\n'
            )
            source = source[: match.start()] + tag + source[match.start() :]
        write(path, source)


def patch_server(work_root: Path) -> None:
    path = work_root / "src/codeprobe_engine/server.py"
    source = read(path)
    if '"analysis-watchdog.js"' not in source:
        marker = '"pyodide-loader.js",'
        require(marker in source, "server public allowlist changed")
        source = source.replace(marker, '"analysis-watchdog.js",\n    ' + marker, 1)
    if '"Cross-Origin-Embedder-Policy"' not in source:
        marker = '"Cross-Origin-Opener-Policy": "same-origin",'
        require(marker in source, "server COOP header changed")
        source = source.replace(
            marker,
            '"Cross-Origin-Embedder-Policy": "require-corp",\n        '
            '"Cross-Origin-Resource-Policy": "same-origin",\n        '
            + marker,
            1,
        )
    write(path, source)


def patch_browser_functional(work_root: Path) -> None:
    path = work_root / "tools/check_browser_functional.js"
    source = read(path)
    if '"/app/analysis-watchdog.js"' not in source:
        marker = '["/app/pyodide-loader.js", path.join(ROOT, "app", "pyodide-loader.js")],'
        require(marker in source, "functional server file map changed")
        source = source.replace(
            marker,
            '["/app/analysis-watchdog.js", path.join(ROOT, "app", "analysis-watchdog.js")],\n    '
            + marker,
            1,
        )
    if '"Cross-Origin-Embedder-Policy": "require-corp"' not in source:
        marker = '"Cross-Origin-Opener-Policy": "same-origin",'
        require(marker in source, "functional server COOP header changed")
        source = source.replace(
            marker,
            '"Cross-Origin-Embedder-Policy": "require-corp",\n      '
            '"Cross-Origin-Resource-Policy": "same-origin",\n      '
            + marker,
            1,
        )
    if "async function testAnalysisDeadline" not in source:
        marker = "async function main() {"
        require(marker in source, "functional main function changed")
        function = r'''
async function testAnalysisDeadline(cdp, baseURL, serverState, resetRequests) {
  resetRequests();
  const page = await createPage(cdp);
  try {
    await navigate(cdp, page.sessionId, `${baseURL}/app/index.html?analysis-deadline=1`);
    await waitForEngineReady(cdp, page.sessionId);
    const result = await evaluate(
      cdp,
      page.sessionId,
      `window.CodeProbeRuntime.loadVerifiedPyodide().then(runtime => {
        const started = performance.now();
        try {
          runtime.runPython("while True:\\n    pass");
          return { interrupted: false, elapsed: performance.now() - started };
        } catch (error) {
          return {
            interrupted: /AnalysisDeadlineError|deadline|KeyboardInterrupt|interrupted/i.test(
              String(error && (error.name + " " + error.message) || error)
            ),
            name: String(error && error.name || ""),
            message: String(error && error.message || error),
            elapsed: performance.now() - started
          };
        }
      })`
    );
    assert(result && result.interrupted, `Infinite Python loop was not interrupted: ${JSON.stringify(result)}`);
    assert(result.elapsed >= 100, "Analysis deadline fired implausibly early.");
    assert(result.elapsed < 20_000, `Analysis deadline exceeded the 20-second outer ceiling: ${result.elapsed}`);
    expectedFixtureCounts(serverState);
  } finally {
    await closePage(cdp, page.targetId);
  }
}

'''
        source = source.replace(marker, function + marker, 1)
    if "await testAnalysisDeadline(" not in source:
        marker = "    await testIntegrityFailureAndRetry(cdp, baseURL, fixture.state, fixture.resetRequests);"
        require(marker in source, "functional test call sequence changed")
        source = source.replace(
            marker,
            "    await testAnalysisDeadline(cdp, baseURL, fixture.state, fixture.resetRequests);\n"
            + marker,
            1,
        )
    if "worker-backed Python deadline" not in source:
        marker = '    console.log("[PASS] browser-functional: failed integrity state recovered through a fresh verified retry");'
        require(marker in source, "functional success diagnostics changed")
        source = source.replace(
            marker,
            marker
            + '\n    console.log("[PASS] browser-functional: worker-backed Python deadline interrupted a non-terminating analysis");',
            1,
        )
    write(path, source)


def patch_lifecycle_gate(work_root: Path) -> None:
    path = work_root / "tools/check_release.py"
    source = read(path)
    source = insert_python_import(source, "import runpy")
    marker = "check_pyodide_lifecycle.py"
    if marker not in source:
        tree = ast.parse(source)
        target = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "main"
            ),
            None,
        )
        require(target is not None, "check_release main function was not found")
        insert_line = target.lineno
        if (
            target.body
            and isinstance(target.body[0], ast.Expr)
            and isinstance(target.body[0].value, ast.Constant)
            and isinstance(target.body[0].value.value, str)
        ):
            insert_line = target.body[0].end_lineno or target.body[0].lineno
        lines = source.splitlines(keepends=True)
        indentation = " " * 4
        addition = (
            f'{indentation}lifecycle = runpy.run_path(str(ROOT / "tools" / "check_pyodide_lifecycle.py"))\n'
            f'{indentation}lifecycle["check_policy"](ROOT / "app" / "pyodide-support-policy.json")\n'
        )
        lines.insert(insert_line, addition)
        source = "".join(lines)
    write(path, source)


def patch_documentation(work_root: Path) -> None:
    readme_path = work_root / "README.md"
    readme = append_section(
        read(readme_path),
        "<!-- phase4f2-runtime-controls:start -->",
        '''<!-- phase4f2-runtime-controls:start -->
## Runtime and release containment

The browser enforces an 8-second worker-backed Python deadline when production containment is available. The release builder records a durable rollback journal before changing any public packet member; `python3 -I -S -B tools/recover_release.py --output-dir <dir>` performs explicit recovery. The pinned Pyodide runtime is a reproducible development dependency and is not approved for a public release until the measured upgrade policy is satisfied.

Calibration exports use HMAC-SHA-256 pseudonyms under a private per-process key. They reduce casual linkage but do not turn potentially identifying source material into anonymous data.
<!-- phase4f2-runtime-controls:end -->''',
    )
    write(readme_path, readme)

    changelog_path = work_root / "CHANGELOG.md"
    changelog = read(changelog_path)
    marker = "<!-- phase4f2-changelog -->"
    if marker not in changelog:
        heading = re.search(r"(?m)^## \[?Unreleased\]?\s*$", changelog)
        require(heading is not None, "CHANGELOG has no Unreleased section")
        insertion = heading.end()
        block = '''

<!-- phase4f2-changelog -->
### Added

- Durable release rollback journal and explicit abrupt-interruption recovery command.
- Worker-backed Pyodide interrupt deadline with real-browser non-terminating-loop coverage.
- Expirable Pyodide lifecycle policy, private HMAC calibration pseudonyms and project-specific security, ownership and citation metadata.
'''
        changelog = changelog[:insertion] + block + changelog[insertion:]
    write(changelog_path, changelog)

    tools_path = work_root / "tools/README.md"
    tools = append_section(
        read(tools_path),
        "<!-- phase4f2-tools:start -->",
        '''<!-- phase4f2-tools:start -->
## Phase 4F2 controls

- `recover_release.py` reconciles a durable release-recovery journal after an abrupt interruption.
- `check_pyodide_lifecycle.py` fails when the pinned runtime review expires or provenance and policy disagree.
<!-- phase4f2-tools:end -->''',
    )
    write(tools_path, tools)

    catalogue_path = work_root / "docs/00-file-catalogue.md"
    catalogue = append_section(
        read(catalogue_path),
        "<!-- phase4f2-catalogue:start -->",
        '''<!-- phase4f2-catalogue:start -->
## Phase 4F2 recovery, deadline and governance files

- `SECURITY.md` — private vulnerability-reporting and disclosure boundary.
- `.github/CODEOWNERS` — ownership routing for high-risk trust and release surfaces.
- `CITATION.cff` — citation metadata without an invented DOI or ORCID.
- `app/analysis-watchdog.js` — worker-backed Pyodide interrupt deadline.
- `app/pyodide-support-policy.json` — expirable runtime lifecycle decision.
- `src/codeprobe_engine/release_recovery.py` — durable rollback journal.
- `tools/recover_release.py` — explicit recovery command.
- `tools/check_pyodide_lifecycle.py` — lifecycle gate.
- `docs/18-release-recovery.md`, `docs/19-runtime-lifecycle.md`, `docs/20-analysis-deadline.md` — assurance documentation.
<!-- phase4f2-catalogue:end -->''',
    )
    write(catalogue_path, catalogue)

    signed_path = work_root / "docs/13-signed-release-workflow.md"
    signed = read(signed_path)
    signed = signed.replace(
        "python3 tools/validate_release.py --skip-tests",
        "python3 -I -S -B tools/validate_release.py --skip-tests",
    )
    write(signed_path, signed)

    runtime_path = work_root / "src/codeprobe_runtime.py"
    runtime = read(runtime_path).replace("Phase 6", "the current runtime")
    write(runtime_path, runtime)


def update_rename_map(work_root: Path) -> None:
    path = work_root / "release/file-rename-map.csv"
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        require(fieldnames is not None and len(fieldnames) >= 2, "rename map header is invalid")
        rows = list(reader)
    source_field = next(
        (name for name in fieldnames if any(token in name.lower() for token in ("source", "current", "original"))),
        fieldnames[0],
    )
    target_field = next(
        (
            name
            for name in fieldnames
            if name != source_field
            and any(token in name.lower() for token in ("target", "final", "release", "new"))
        ),
        fieldnames[1],
    )
    identity_template = next(
        (
            row
            for row in rows
            if row.get(source_field) and row.get(source_field) == row.get(target_field)
        ),
        {name: "" for name in fieldnames},
    )
    existing = {row.get(source_field) for row in rows}
    for relative in NEW_PATHS:
        if relative in existing:
            continue
        row = dict(identity_template)
        row[source_field] = relative
        row[target_field] = relative
        for name in fieldnames:
            lowered = name.lower()
            if not row.get(name) and "status" in lowered:
                row[name] = "keep"
            elif not row.get(name) and any(token in lowered for token in ("reason", "note")):
                row[name] = "Phase 4F2 controlled addition"
        rows.append(row)
    rows.sort(key=lambda row: str(row.get(source_field, "")).casefold())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def refresh_browser_integrity(work_root: Path) -> None:
    manifest_path = work_root / "app/resource-integrity.json"
    payload = json.loads(read(manifest_path))
    assets = payload.get("assets")
    require(isinstance(assets, list), "browser integrity assets must be a list")
    if not any(item.get("path") == "analysis-watchdog.js" for item in assets):
        assets.append({"path": "analysis-watchdog.js"})
    for item in assets:
        relative = item.get("path")
        require(isinstance(relative, str) and relative, "browser integrity path is invalid")
        source = (manifest_path.parent / relative).resolve(strict=True)
        require(source.is_file(), f"browser integrity source is missing: {relative}")
        content = source.read_bytes()
        digest = hashlib.sha256(content).digest()
        item["size_bytes"] = len(content)
        item["sha256_hex"] = digest.hex()
        item["sri_sha256"] = "sha256-" + base64.b64encode(digest).decode("ascii")
    assets.sort(key=lambda item: item["path"])
    payload["note"] = (
        "SHA-256 and SRI values for packaged browser assets, the worker-backed "
        "analysis deadline, runtime policy metadata and the Python engine."
    )
    write(manifest_path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    sri = {
        Path(item["path"]).name: item["sri_sha256"]
        for item in assets
        if not str(item["path"]).startswith("../")
    }
    for relative in ("app/index.html", "app/project.html"):
        path = work_root / relative
        source = read(path)
        tags = list(re.finditer(r"<(?:script|link)\b[^>]+>", source, re.I))
        replacements: list[tuple[int, int, str]] = []
        for match in tags:
            tag = match.group(0)
            reference = re.search(r'(?:src|href)="([^"]+)"', tag, re.I)
            if not reference:
                continue
            name = Path(reference.group(1).split("?", 1)[0]).name
            if name not in sri:
                continue
            if re.search(r'\bintegrity="[^"]*"', tag, re.I):
                tag = re.sub(
                    r'\bintegrity="[^"]*"',
                    f'integrity="{sri[name]}"',
                    tag,
                    count=1,
                    flags=re.I,
                )
            else:
                tag = tag[:-1] + f' integrity="{sri[name]}">' 
            if "crossorigin=" not in tag.lower() and name.endswith((".js", ".css")):
                tag = tag[:-1] + ' crossorigin="anonymous">'
            replacements.append((match.start(), match.end(), tag))
        for start, end, replacement in reversed(replacements):
            source = source[:start] + replacement + source[end:]
        write(path, source)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    args = parser.parse_args()
    source_root = args.source_root.resolve(strict=True)
    work_root = args.work_root.resolve(strict=True)
    actual_tree = run("git", "rev-parse", "HEAD^{tree}", cwd=work_root)
    require(
        actual_tree == EXPECTED_BASE_TREE,
        f"Phase 4F2 requires tree {EXPECTED_BASE_TREE}, received {actual_tree}",
    )
    require(
        not run("git", "status", "--porcelain=v1", "--untracked-files=all", cwd=work_root),
        "Phase 4F2 worktree is not clean before transformation",
    )
    copy_new_files(source_root, work_root)
    patch_release_replacements(work_root)
    patch_pseudonymisation(work_root)
    patch_runtime_config(work_root)
    patch_loader(work_root)
    patch_html(work_root)
    patch_server(work_root)
    patch_browser_functional(work_root)
    patch_lifecycle_gate(work_root)
    patch_documentation(work_root)
    update_rename_map(work_root)
    refresh_browser_integrity(work_root)
    run("git", "diff", "--check", cwd=work_root)
    print("[PASS] phase4f2-apply: deterministic transformation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
