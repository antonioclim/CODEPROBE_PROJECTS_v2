#!/usr/bin/env python3
"""Run CodeProbe release checks from a source checkout.

The script deliberately uses only the Python standard library. JavaScript syntax
checking is performed with Node.js when it is available; otherwise that step is
reported as skipped rather than hidden.
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
import base64
import hashlib
import json
import os
import py_compile
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
APP = ROOT / "app"
TESTS = ROOT / "tests"
TOOLS = ROOT / "tools"
MAX_UNITTEST_FAILURE_IDENTIFIERS = 5
MAX_UNITTEST_FAILURE_IDENTIFIER_CHARACTERS = 300
MAX_UNITTEST_DETAIL_CHARACTERS = 1_024
MIN_UNITTEST_DISCOVERED = 369
MIN_UNITTEST_EXECUTED = 347
RESOURCE_INTEGRITY_SCHEMA = "codeprobe-browser-resource-integrity/v1"
REQUIRED_RESOURCE_ASSETS = {
    "codeprobe.css",
    "project.css",
    "pyodide-loader.js",
    "codeprobe-ui.js",
    "project-ui.js",
    "runtime-config.json",
    "pyodide-provenance.json",
    "../src/codeprobe_runtime.py",
}
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))
if str(TOOLS) not in sys.path:
    sys.path.append(str(TOOLS))

import codeprobe_runtime as engine  # noqa: E402
import audit_institutional_pack  # noqa: E402
import check_coverage  # noqa: E402
import check_dependency_boundary  # noqa: E402
import check_file_references  # noqa: E402
import check_pyodide_provenance  # noqa: E402
import final_audit  # noqa: E402
import check_naming  # noqa: E402
from codeprobe_engine import api as cp_api  # noqa: E402
from codeprobe_engine import metrics as cp_metrics  # noqa: E402
from codeprobe_engine.process_control import ProcessControlError, run_bounded_process  # noqa: E402
from codeprobe_engine.release import (  # noqa: E402
    AtomicWriteReceipt,
    MANIFEST_NAME,
    ReleaseSetError,
    atomic_write_bytes,
    atomic_write_text,
    build_release_manifest,
    read_regular_file,
    read_regular_file_with_metadata,
    sha256_bytes,
    validate_release_set,
    verify_manifest,
)


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    skipped: bool = False


def _python_files() -> Iterable[Path]:
    for base in (SRC, TOOLS, TESTS):
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" not in path.parts:
                yield path


def check_python_compile() -> CheckResult:
    try:
        with tempfile.TemporaryDirectory(prefix="codeprobe-pycompile-") as tmp:
            output_dir = Path(tmp)
            for index, path in enumerate(_python_files()):
                py_compile.compile(str(path), cfile=str(output_dir / f"{index}.pyc"), doraise=True)
        return CheckResult("python-compile", True, "all Python files compile")
    except Exception as exc:  # pragma: no cover - failure path reported by CLI
        return CheckResult("python-compile", False, str(exc))


def check_dependency_policy() -> CheckResult:
    errors = check_dependency_boundary.audit_dependency_boundary(ROOT)
    if errors:
        return CheckResult("dependency-boundary", False, "; ".join(errors[:10]))
    return CheckResult(
        "dependency-boundary",
        True,
        "declared dependency boundary, bounded process broker, pinned workflow actions and measured Pyodide core metadata verified",
    )


def check_unittest_suite(verbose: bool = False) -> CheckResult:
    cmd = [sys.executable, "-I", "-S", "-B", "-m", "unittest", "discover", "-s", "tests"]
    if verbose:
        cmd.append("-v")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }
    try:
        completed = run_bounded_process(
            cmd,
            cwd=ROOT,
            environment=environment,
            replace_environment=True,
            timeout=900,
            stdout_limit=1_000_000,
            stderr_limit=4_000_000,
        )
    except (ProcessControlError, OSError, ValueError) as exc:
        return CheckResult("unit-tests", False, f"unittest launch failed: {exc}")
    unittest_output = completed.stderr_text
    lines = unittest_output.strip().splitlines()
    count_matches = re.findall(r"^Ran (?P<count>[0-9]{1,9}) tests? in ", unittest_output, re.M)
    pass_count_field = r"(?:skipped|expected failures)=[0-9]{1,9}"
    pass_terminal = rf"OK(?: \({pass_count_field}(?:, {pass_count_field})?\))?"
    terminal_success = bool(
        lines
        and re.fullmatch(pass_terminal, lines[-1])
    )
    discovered = int(count_matches[0]) if len(count_matches) == 1 else 0
    skipped_matches = re.findall(r"skipped=(?P<count>[0-9]{1,9})", lines[-1] if lines else "")
    skipped = int(skipped_matches[0]) if len(skipped_matches) == 1 else 0
    executed = max(0, discovered - skipped)
    floor_met = (
        discovered >= MIN_UNITTEST_DISCOVERED
        and executed >= MIN_UNITTEST_EXECUTED
    )
    success = (
        completed.returncode == 0
        and not completed.timed_out
        and not completed.output_limit_exceeded
        and len(count_matches) == 1
        and terminal_success
        and floor_met
    )
    if success:
        detail = f"{discovered} test(s) passed"
    else:
        failure_count_field = (
            r"(?:failures|errors|skipped|expected failures|unexpected successes)=[0-9]{1,9}"
        )
        failure_summary = re.search(
            rf"^FAILED \((?P<counts>{failure_count_field}(?:, {failure_count_field}){{0,4}})\)$",
            unittest_output,
            re.M,
        )
        if failure_summary:
            summary = f"FAILED ({failure_summary.group('counts')})"
        elif (
            completed.returncode == 0
            and len(count_matches) == 1
            and terminal_success
            and not floor_met
        ):
            summary = (
                "unittest execution floor not met: "
                f"discovered {discovered}, executed {executed}; "
                f"required {MIN_UNITTEST_DISCOVERED}/{MIN_UNITTEST_EXECUTED}"
            )
        elif completed.timed_out:
            summary = "unittest exceeded the 900 second wall-clock limit"
        elif completed.output_limit_exceeded:
            summary = "unittest exceeded its captured-output limit"
        elif completed.returncode == 0:
            summary = "unittest output was not a recognised successful run"
        else:
            summary = f"unittest exited with code {completed.returncode}"
        identifiers = list(dict.fromkeys(re.findall(
            rf"^(?:FAIL|ERROR): [^()\r\n]{{1,200}} "
            rf"\((?P<identifier>[A-Za-z0-9_.]{{1,{MAX_UNITTEST_FAILURE_IDENTIFIER_CHARACTERS}}})\)"
            rf"(?: [^\r\n]{{0,500}})?\s*$",
            unittest_output,
            re.M,
        )))
        identity_detail = (
            "; failing tests: "
            + "; ".join(identifiers[:MAX_UNITTEST_FAILURE_IDENTIFIERS])
            if identifiers
            else ""
        )
        exception_types = list(dict.fromkeys(re.findall(
            r"^(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
            r"(?P<exception>[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception)):",
            unittest_output,
            re.M,
        )))
        exception_detail = (
            "; exception types: "
            + ", ".join(exception_types[:MAX_UNITTEST_FAILURE_IDENTIFIERS])
            if exception_types
            else ""
        )
        detail = (
            f"{summary}{identity_detail}{exception_detail}"
        )[:MAX_UNITTEST_DETAIL_CHARACTERS]
    return CheckResult("unit-tests", success, detail)


def extract_inline_scripts(html_path: Path) -> list[str]:
    html = html_path.read_text(encoding="utf-8")
    scripts: list[str] = []
    for match in re.finditer(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", html, re.S | re.I):
        attrs = match.group("attrs") or ""
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        body = match.group("body").strip()
        if body:
            scripts.append(body)
    return scripts


def browser_script_files() -> list[Path]:
    """Return local browser JavaScript files referenced by the HTML pages."""
    files: list[Path] = []
    for html in [APP / "index.html", APP / "project.html"]:
        text = html.read_text(encoding="utf-8")
        for match in re.finditer(r"<script\b(?P<attrs>[^>]*)>", text, re.I):
            attrs = match.group("attrs") or ""
            src_match = re.search(r"\bsrc\s*=\s*[\"'](?P<src>[^\"']+)[\"']", attrs, re.I)
            if not src_match:
                continue
            src = src_match.group("src")
            if src.startswith(("http://", "https://", "//")):
                continue
            path = (html.parent / src).resolve()
            try:
                path.relative_to(APP.resolve())
            except ValueError as exc:
                raise ReleaseSetError(
                    f"{html.name} script reference resolves outside app/: {src}"
                ) from exc
            if not path.is_file():
                raise ReleaseSetError(f"{html.name} script is missing: {src}")
            if path.suffix.lower() == ".js" and path not in files:
                files.append(path)
    return files


def check_javascript_syntax(*, require_node: bool = False) -> CheckResult:
    node = shutil.which("node")
    if not node:
        if require_node:
            return CheckResult("javascript-syntax", False, "Node.js is required but was not found")
        return CheckResult("javascript-syntax", True, "Node.js not available; skipped", skipped=True)
    try:
        checked = 0
        for script_path in browser_script_files():
            checked += 1
            completed = run_bounded_process(
                [node, "--check", str(script_path)],
                cwd=ROOT,
                timeout=30,
                stdout_limit=64_000,
                stderr_limit=64_000,
            )
            if completed.timed_out:
                return CheckResult("javascript-syntax", False, f"{script_path.relative_to(ROOT)}: Node.js timed out")
            if completed.output_limit_exceeded:
                return CheckResult("javascript-syntax", False, f"{script_path.relative_to(ROOT)}: Node.js output exceeded 64,000 bytes")
            if completed.returncode != 0:
                return CheckResult("javascript-syntax", False, f"{script_path.relative_to(ROOT)}: {completed.stderr_text.strip()}")
        return CheckResult("javascript-syntax", True, f"{checked} external browser script(s) pass node --check")
    except Exception as exc:  # pragma: no cover - failure path reported by CLI
        return CheckResult("javascript-syntax", False, str(exc))


def _sri_for_file(path: Path) -> str:
    digest = hashlib.sha256(read_regular_file(path, root=ROOT)).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def check_browser_security() -> CheckResult:
    errors: list[str] = []
    for html in [APP / "index.html", APP / "project.html"]:
        body = html.read_text(encoding="utf-8")
        if "unsafe-inline" in body:
            errors.append(f"{html.name} CSP contains unsafe-inline")
        if re.search(r"<style\b", body, re.I):
            errors.append(f"{html.name} contains inline <style>")
        if re.search(r"\sstyle\s*=", body, re.I):
            errors.append(f"{html.name} contains inline style attributes")
        if extract_inline_scripts(html):
            errors.append(f"{html.name} contains inline script bodies")
        for match in re.finditer(r"<(?:script|link)\b(?P<attrs>[^>]*)>", body, re.I):
            attrs = match.group("attrs") or ""
            target_match = re.search(r"\b(?:src|href)\s*=\s*[\"'](?P<target>[^\"']+)[\"']", attrs, re.I)
            if not target_match:
                continue
            target = target_match.group("target")
            if target.startswith(("http://", "https://", "//")):
                continue
            if target.endswith((".js", ".css")):
                path = (html.parent / target).resolve()
                try:
                    path.relative_to(APP.resolve())
                except ValueError:
                    errors.append(f"{html.name} reference resolves outside app/: {target}")
                    continue
                integrity_match = re.search(
                    r"\bintegrity\s*=\s*[\"'](?P<value>[^\"']+)[\"']",
                    attrs,
                    re.I,
                )
                if not integrity_match:
                    errors.append(f"{html.name} references {target} without SRI")
                elif not path.is_file():
                    errors.append(f"{html.name} references missing resource {target}")
                elif integrity_match.group("value") != _sri_for_file(path):
                    errors.append(f"{html.name} has stale SRI for {target}")
    if errors:
        return CheckResult("browser-security", False, "; ".join(errors[:10]))
    return CheckResult("browser-security", True, "CSP, inline-code and local SRI checks passed")


def check_resource_integrity() -> CheckResult:
    manifest_path = APP / "resource-integrity.json"
    if not manifest_path.exists():
        return CheckResult("browser-resource-integrity", False, "app/resource-integrity.json is missing")
    try:
        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key: {key}")
                result[key] = value
            return result

        manifest = json.loads(
            read_regular_file(manifest_path, root=ROOT).decode("utf-8"),
            object_pairs_hook=unique_object,
        )
        errors: list[str] = []
        if not isinstance(manifest, dict):
            return CheckResult("browser-resource-integrity", False, "manifest top level must be an object")
        if set(manifest) != {"schema", "note", "assets"}:
            errors.append("manifest must contain exactly schema, note and assets")
        if manifest.get("schema") != RESOURCE_INTEGRITY_SCHEMA:
            errors.append(f"manifest schema must be {RESOURCE_INTEGRITY_SCHEMA}")
        if not isinstance(manifest.get("note"), str) or not manifest.get("note", "").strip():
            errors.append("manifest note must be a non-empty string")
        assets = manifest.get("assets")
        if not isinstance(assets, list):
            return CheckResult("browser-resource-integrity", False, "; ".join(errors + ["manifest assets must be an array"]))
        seen: set[str] = set()
        seen_portable: set[str] = set()
        for index, item in enumerate(assets):
            if not isinstance(item, dict):
                errors.append(f"manifest assets[{index}] must be an object")
                continue
            if set(item) != {"path", "size_bytes", "sha256_hex", "sri_sha256"}:
                errors.append(f"manifest assets[{index}] has an invalid field set")
            relative = item.get("path")
            if not isinstance(relative, str) or relative not in REQUIRED_RESOURCE_ASSETS:
                errors.append(f"manifest assets[{index}] has an unapproved path")
                continue
            portable = relative.casefold()
            if relative in seen or portable in seen_portable:
                errors.append(f"duplicate asset path: {relative}")
                continue
            seen.add(relative)
            seen_portable.add(portable)
            path = (APP / relative).resolve()
            try:
                path.relative_to(ROOT.resolve())
            except ValueError:
                errors.append(f"asset resolves outside the checkout: {relative}")
                continue
            try:
                content = read_regular_file(path, root=ROOT)
            except (OSError, ReleaseSetError):
                errors.append(f"missing asset: {relative}")
                continue
            if type(item.get("size_bytes")) is not int or item.get("size_bytes") != len(content):
                errors.append(f"size mismatch: {relative}")
            actual_hex = hashlib.sha256(content).hexdigest()
            if item.get("sha256_hex") != actual_hex:
                errors.append(f"sha256 mismatch: {relative}")
            actual_sri = "sha256-" + base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
            if item.get("sri_sha256") != actual_sri:
                errors.append(f"SRI mismatch: {relative}")
        missing_assets = sorted(REQUIRED_RESOURCE_ASSETS - seen)
        if missing_assets:
            errors.append("required assets missing: " + ", ".join(missing_assets))
        if errors:
            return CheckResult("browser-resource-integrity", False, "; ".join(errors[:10]))
        return CheckResult("browser-resource-integrity", True, f"{len(assets)} asset(s) verified")
    except Exception as exc:  # pragma: no cover - failure path reported by CLI
        return CheckResult("browser-resource-integrity", False, str(exc))


def check_pyodide_boundary() -> CheckResult:
    errors = check_pyodide_provenance.audit_pyodide_provenance(ROOT)
    if errors:
        return CheckResult("pyodide-provenance", False, "; ".join(errors[:10]))
    return CheckResult(
        "pyodide-provenance",
        True,
        "production configuration and measured core startup metadata are consistent; optional-package integrity, upstream build reproducibility, availability and vulnerability status remain outside the check",
    )


def check_coverage_policy() -> CheckResult:
    try:
        policy_path = ROOT / check_coverage.DEFAULT_POLICY
        policy = check_coverage.load_policy(policy_path)
        files = check_coverage.discover_source_files(ROOT, policy)
        floors = policy["floors"]
        return CheckResult(
            "coverage-policy",
            True,
            f"{len(files)} production Python file(s) are in scope; "
            f"overall floor {float(floors['overall']):.2f}% on Python {policy['python_runtime']}",
        )
    except (OSError, ValueError, check_coverage.CoveragePolicyError) as exc:
        return CheckResult("coverage-policy", False, str(exc))

def check_version_consistency() -> CheckResult:
    expected = engine.APP_VERSION
    required_strings = {
        ROOT / "README.md": f"CodeProbe v{expected}",
        APP / "index.html": f"CodeProbe v{expected}",
        APP / "project.html": f"v{expected}",
        SRC / "codeprobe_engine" / "version.py": f'APP_VERSION = "{expected}"',
        ROOT / "CHANGELOG.md": f"## [{expected}]",
    }
    missing: list[str] = []
    for path, token in required_strings.items():
        if token not in path.read_text(encoding="utf-8", errors="replace"):
            missing.append(f"{path.relative_to(ROOT)} lacks {token!r}")
    if missing:
        return CheckResult("version-consistency", False, "; ".join(missing))
    return CheckResult("version-consistency", True, f"version {expected} is visible in release files")


def check_smoke_reports() -> CheckResult:
    try:
        file_result = cp_api.analyse_file({
            "code": "def add(left: int, right: int) -> int:\n    return left + right\n\nprint(add(1, 2))\n",
            "filename": "calculator.py",
            "language_hint": "python",
            "profile": "default",
        })
        report = file_result["report"]
        if engine.validate_report_shape(report, "file"):
            return CheckResult("smoke-reports", False, "; ".join(engine.validate_report_shape(report, "file")))
        if "tool_metadata" not in report or "metric_role_summary" not in report:
            return CheckResult("smoke-reports", False, "file metadata missing")

        project_result = cp_api.analyse_project({
            "project_name": "release-smoke",
            "files": [
                {"path": "src/main.py", "content": "def main():\n    return 0\n\nprint(main())\n", "size_bytes": 40},
                {"path": "README.md", "content": "# Notes\n", "size_bytes": 8},
            ],
        })
        project = project_result["project_report"]
        if engine.validate_report_shape(project, "project"):
            return CheckResult("smoke-reports", False, "; ".join(engine.validate_report_shape(project, "project")))
        if project["included_file_count"] != 1:
            return CheckResult("smoke-reports", False, "project filtering smoke check failed")
        if len(cp_metrics.metric_inventory()) < 10:
            return CheckResult("smoke-reports", False, "metric inventory unexpectedly small")
        return CheckResult("smoke-reports", True, "file, project and metric inventory checks passed")
    except Exception as exc:  # pragma: no cover - failure path reported by CLI
        return CheckResult("smoke-reports", False, str(exc))




def check_institutional_package() -> CheckResult:
    errors = audit_institutional_pack.run_audit(ROOT)
    if errors:
        return CheckResult("institutional-package", False, "; ".join(errors[:10]))
    return CheckResult("institutional-package", True, "teaching, review, deployment and release artefacts are present")


def check_naming_policy() -> CheckResult:
    errors = check_naming.run_checks(ROOT)
    if errors:
        return CheckResult("naming-policy", False, "; ".join(errors[:10]))
    return CheckResult("naming-policy", True, "file names and retired-path containment verified")



def check_final_audit(*, verify_persisted: bool = True) -> CheckResult:
    report = final_audit.build_audit(ROOT)
    if report.get("status") == "pass":
        if verify_persisted:
            errors = final_audit.verify_reports(ROOT, report)
            if errors:
                return CheckResult("final-audit", False, "; ".join(errors[:10]))
        return CheckResult(
            "final-audit",
            True,
            f"{report.get('file_count')} release-set source files audited; manifest verified separately",
        )
    detail_items = (
        report.get("release_set_errors")
        or report.get("missing_required_paths")
        or report.get("forbidden_paths_present")
        or report.get("reference_errors")
        or report.get("naming_errors")
        or report.get("institutional_errors")
        or ["final audit failed"]
    )
    return CheckResult("final-audit", False, "; ".join(map(str, detail_items[:10])))


def check_reference_integrity() -> CheckResult:
    errors = check_file_references.run_reference_audit(ROOT)
    if errors:
        return CheckResult("reference-integrity", False, "; ".join(errors[:10]))
    return CheckResult("reference-integrity", True, "high-confidence links and rename-map coverage verified")


def check_naming_stability() -> CheckResult:
    errors = check_naming.run_checks(ROOT)
    if errors:
        return CheckResult("naming-stability", False, "; ".join(errors[:10]))
    return CheckResult("naming-stability", True, "file names and legacy-path containment verified")


def check_final_package_audit() -> CheckResult:
    report = final_audit.build_audit(ROOT)
    if report.get("status") != "pass":
        details = []
        for key in ("release_set_errors", "missing_required_paths", "forbidden_paths_present", "reference_errors", "naming_errors", "institutional_errors"):
            details.extend(str(item) for item in report.get(key, [])[:5])
        return CheckResult("final-package-audit", False, "; ".join(details[:10]) or "final package audit failed")
    return CheckResult("final-package-audit", True, "final naming-stable package audit passed")


def check_release_set_safety(root: Path = ROOT) -> CheckResult:
    """Reject unsafe entries before subsequent check functions read the tree."""
    try:
        paths = validate_release_set(root)
    except ReleaseSetError as exc:
        return CheckResult("release-set-safety", False, str(exc))
    return CheckResult("release-set-safety", True, f"{len(paths)} regular release file(s); no symbolic links or special files")


def check_manifest(root: Path = ROOT) -> CheckResult:
    errors = verify_manifest(root, app_version=engine.APP_VERSION)
    return CheckResult("release-manifest", not errors, "verified" if not errors else "; ".join(errors[:10]))


EVIDENCE_PATHS = (
    Path("release/final-audit-report.json"),
    Path("release/final-audit-summary.md"),
    Path(MANIFEST_NAME),
)


@dataclass(frozen=True)
class EvidenceSnapshot:
    content: bytes
    mode: int
    atime_ns: int
    mtime_ns: int
    fingerprint: tuple[int, int, int, int, int, str]


ReleaseTreeSnapshot = dict[str, tuple[int, int, str]]


def capture_release_tree(
    root: Path = ROOT,
    *,
    exclude_evidence: bool = False,
) -> ReleaseTreeSnapshot:
    """Capture stable release membership, mode, size and content hashes."""
    root = root.resolve()
    excluded = {relative.as_posix() for relative in EVIDENCE_PATHS} if exclude_evidence else set()
    paths = validate_release_set(root)
    captured_names = tuple(path.relative_to(root).as_posix() for path in paths)
    snapshot: ReleaseTreeSnapshot = {}
    for path, relative in zip(paths, captured_names):
        if relative in excluded:
            continue
        content, metadata = read_regular_file_with_metadata(path, root=root)
        snapshot[relative] = (
            stat.S_IMODE(metadata.st_mode),
            len(content),
            sha256_bytes(content),
        )
    current_names = tuple(
        path.relative_to(root).as_posix() for path in validate_release_set(root)
    )
    if current_names != captured_names:
        raise ReleaseSetError("release membership changed while the tree snapshot was captured")
    return snapshot


def check_release_tree_stability(
    expected: ReleaseTreeSnapshot,
    root: Path = ROOT,
    *,
    exclude_evidence: bool = False,
) -> CheckResult:
    """Require the release tree to remain identical to a prior snapshot."""
    try:
        current = capture_release_tree(root, exclude_evidence=exclude_evidence)
    except (OSError, ReleaseSetError) as exc:
        return CheckResult("release-tree-stability", False, str(exc))
    if current == expected:
        return CheckResult(
            "release-tree-stability",
            True,
            f"{len(current)} release member(s) remained unchanged",
        )
    changed = sorted(set(expected) ^ set(current))
    changed.extend(
        path for path in sorted(set(expected) & set(current))
        if expected[path] != current[path]
    )
    return CheckResult(
        "release-tree-stability",
        False,
        "release tree changed during validation: " + ", ".join(changed[:10]),
    )


def _capture_evidence(path: Path, *, root: Path) -> EvidenceSnapshot:
    content, metadata = read_regular_file_with_metadata(path, root=root)
    mode = stat.S_IMODE(metadata.st_mode)
    return EvidenceSnapshot(
        content=content,
        mode=mode,
        atime_ns=metadata.st_atime_ns,
        mtime_ns=metadata.st_mtime_ns,
        fingerprint=(
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            mode,
            sha256_bytes(content),
        ),
    )


def _evidence_fingerprint(path: Path, *, root: Path) -> tuple[int, int, int, int, int, str]:
    return _capture_evidence(path, root=root).fingerprint


def _mode_matches(actual: int, expected: int) -> bool:
    if os.name == "nt":
        return bool(actual & stat.S_IWRITE) == bool(expected & stat.S_IWRITE)
    return actual == expected


def _fingerprint_matches(
    actual: tuple[int, int, int, int, int, str],
    expected: tuple[int, int, int, int, int, str],
) -> bool:
    return (
        actual[:4] == expected[:4]
        and _mode_matches(actual[4], expected[4])
        and actual[5] == expected[5]
    )


def _ownership_matches(
    current: tuple[int, int, int, int, int, str],
    candidate: AtomicWriteReceipt,
) -> bool:
    return (
        current[:3] == candidate[:3]
        and _mode_matches(current[4], candidate[3])
        and current[5] == candidate[4]
    )


def _snapshot_matches(restored: EvidenceSnapshot, expected: EvidenceSnapshot) -> bool:
    return (
        restored.content == expected.content
        and _mode_matches(restored.mode, expected.mode)
        and restored.mtime_ns == expected.mtime_ns
    )


def _restore_evidence(
    path: Path,
    snapshot: EvidenceSnapshot,
    *,
    root: Path,
) -> None:
    try:
        atomic_write_bytes(
            path,
            snapshot.content,
            mode=snapshot.mode,
            times_ns=(snapshot.atime_ns, snapshot.mtime_ns),
        )
    except BaseException:
        # A rename can succeed even when its caller receives an interruption
        # or an ambiguous I/O error. Accept it only after complete verification.
        restored = _capture_evidence(path, root=root)
        if _snapshot_matches(restored, snapshot):
            return
        raise
    restored = _capture_evidence(path, root=root)
    if not _snapshot_matches(restored, snapshot):
        raise OSError("restored evidence bytes or metadata do not match the prior state")


def diagnostic_output_is_outside_release_set(path: Path, root: Path = ROOT) -> bool:
    """Return whether an explicit diagnostic output avoids the release set."""
    root = root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return True
    return bool(relative.parts) and relative.parts[0] == "dist"


def refresh_release_evidence(
    root: Path = ROOT,
    *,
    expected_source: ReleaseTreeSnapshot | None = None,
) -> CheckResult:
    """Refresh the complete evidence set with verified detected-failure rollback."""
    root = root.resolve()
    try:
        initial_paths = validate_release_set(root)
        initial_members = tuple(
            path.relative_to(root).as_posix()
            for path in initial_paths
        )
    except ReleaseSetError as exc:
        return CheckResult("release-evidence", False, f"not written because the release set is unsafe: {exc}")
    missing = [relative.as_posix() for relative in EVIDENCE_PATHS if not (root / relative).is_file()]
    if missing:
        return CheckResult(
            "release-evidence",
            False,
            f"not written because tracked evidence is missing: {', '.join(missing)}",
        )
    report = final_audit.build_audit(root)
    if report.get("status") != "pass":
        return CheckResult("release-evidence", False, "not written because the final audit failed")

    try:
        if expected_source is not None:
            stability = check_release_tree_stability(
                expected_source,
                root,
                exclude_evidence=True,
            )
            if not stability.ok:
                return CheckResult(
                    "release-evidence",
                    False,
                    f"not written because {stability.detail}",
                )

        report_bytes = final_audit.render_report(report).encode("utf-8")
        summary_bytes = final_audit.render_summary(report).encode("utf-8")
        prospective = {
            EVIDENCE_PATHS[0].as_posix(): report_bytes,
            EVIDENCE_PATHS[1].as_posix(): summary_bytes,
        }
        manifest = build_release_manifest(
            root,
            app_version=engine.APP_VERSION,
            content_overrides=prospective,
        )
        manifest_bytes = (
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        generated = {
            EVIDENCE_PATHS[0]: report_bytes,
            EVIDENCE_PATHS[1]: summary_bytes,
            EVIDENCE_PATHS[2]: manifest_bytes,
        }
        if final_audit.build_audit(root) != report:
            return CheckResult(
                "release-evidence",
                False,
                "not written because the final audit inputs changed during preparation",
            )

        snapshots: dict[Path, EvidenceSnapshot] = {}
        for relative in EVIDENCE_PATHS:
            snapshots[relative] = _capture_evidence(root / relative, root=root)
    except (OSError, ReleaseSetError) as exc:
        return CheckResult("release-evidence", False, f"not written because existing evidence could not be read: {exc}")
    except (TypeError, ValueError) as exc:
        return CheckResult("release-evidence", False, f"not written because evidence preparation failed: {exc}")

    attempted: list[Path] = []
    replacement_candidates: dict[Path, AtomicWriteReceipt] = {}
    try:
        for relative, content in generated.items():
            for pending in EVIDENCE_PATHS:
                if pending in attempted:
                    continue
                if not _fingerprint_matches(
                    _evidence_fingerprint(root / pending, root=root),
                    snapshots[pending].fingerprint,
                ):
                    raise RuntimeError(
                        f"tracked evidence changed concurrently before replacement: {pending.as_posix()}"
                    )
            attempted.append(relative)

            def remember_candidate(
                receipt: AtomicWriteReceipt,
                selected: Path = relative,
            ) -> None:
                replacement_candidates[selected] = receipt

            installed = atomic_write_bytes(
                root / relative,
                content,
                prepared_receipt=remember_candidate,
            )
            replacement_candidates[relative] = installed
            if not _ownership_matches(
                _evidence_fingerprint(root / relative, root=root),
                installed,
            ):
                raise RuntimeError(f"evidence replacement did not persist: {relative.as_posix()}")

        post_report = final_audit.build_audit(root)
        errors = []
        if post_report.get("status") != "pass":
            errors.append("post-write final audit failed")
        else:
            errors.extend(final_audit.verify_reports(root, post_report))
        errors.extend(verify_manifest(root, app_version=engine.APP_VERSION))
        if expected_source is not None:
            stability = check_release_tree_stability(
                expected_source,
                root,
                exclude_evidence=True,
            )
            if not stability.ok:
                errors.append(stability.detail)
        if errors:
            raise RuntimeError("; ".join(errors[:10]))
    except BaseException as exc:
        rollback_errors: list[str] = []
        for relative in reversed(attempted):
            path = root / relative
            try:
                current = _evidence_fingerprint(path, root=root)
                if _fingerprint_matches(current, snapshots[relative].fingerprint):
                    continue
                if relative not in replacement_candidates or not _ownership_matches(
                    current,
                    replacement_candidates[relative],
                ):
                    rollback_errors.append(
                        f"{relative.as_posix()}: changed concurrently and was not overwritten"
                    )
                    continue
                _restore_evidence(path, snapshots[relative], root=root)
            except BaseException as rollback_exc:
                rollback_errors.append(
                    f"{relative.as_posix()}: {type(rollback_exc).__name__}"
                )
        for relative, snapshot in snapshots.items():
            try:
                restored = _capture_evidence(root / relative, root=root)
                if not _snapshot_matches(restored, snapshot):
                    rollback_errors.append(
                        f"{relative.as_posix()}: prior bytes or metadata were not restored"
                    )
            except BaseException as verify_exc:
                rollback_errors.append(
                    f"{relative.as_posix()}: rollback verification raised {type(verify_exc).__name__}"
                )
        try:
            current_members = tuple(
                path.relative_to(root).as_posix()
                for path in validate_release_set(root)
            )
            if current_members != initial_members:
                rollback_errors.append("release membership was not restored")
        except BaseException as membership_exc:
            rollback_errors.append(
                "rollback release-membership verification raised "
                f"{type(membership_exc).__name__}"
            )
        if rollback_errors:
            detail = "; ".join(rollback_errors[:3])
            if not isinstance(exc, Exception):
                raise RuntimeError(
                    f"evidence refresh was interrupted and rollback is incomplete ({detail})"
                ) from exc
            return CheckResult(
                "release-evidence",
                False,
                f"refresh failed; rollback incomplete ({detail}): {exc}",
            )
        if not isinstance(exc, Exception):
            raise
        return CheckResult("release-evidence", False, f"refresh failed and was rolled back: {exc}")
    return CheckResult(
        "release-evidence",
        True,
        "prepared audit reports and manifest committed with verified rollback protection",
    )


def run_checks(
    skip_tests: bool = False,
    verbose_tests: bool = False,
    require_node: bool = False,
    write_manifest_file: bool = False,
    verify_manifest_file: bool = True,
    verify_persisted_evidence: bool = True,
) -> list[CheckResult]:
    safety = check_release_set_safety()
    if not safety.ok:
        return [safety]
    try:
        initial_source = capture_release_tree(exclude_evidence=write_manifest_file)
    except (OSError, ReleaseSetError) as exc:
        return [safety, CheckResult("release-tree-snapshot", False, str(exc))]
    dependency = check_dependency_policy()
    checks = [safety, dependency, check_python_compile()]
    if skip_tests:
        checks.append(
            CheckResult("unit-tests", True, "explicitly skipped", skipped=True)
        )
    else:
        if dependency.ok:
            checks.append(check_unittest_suite(verbose=verbose_tests))
        else:
            checks.append(
                CheckResult(
                    "unit-tests",
                    True,
                    "not run because the dependency boundary failed",
                    skipped=True,
                )
            )
    checks.extend([
        check_javascript_syntax(require_node=require_node),
        check_browser_security(),
        check_resource_integrity(),
        check_pyodide_boundary(),
        check_coverage_policy(),
        check_version_consistency(),
        check_smoke_reports(),
        check_institutional_package(),
        check_reference_integrity(),
        check_naming_policy(),
        check_final_audit(verify_persisted=verify_persisted_evidence and not write_manifest_file),
    ])
    stability = check_release_tree_stability(
        initial_source,
        exclude_evidence=write_manifest_file,
    )
    checks.append(stability)
    prerequisites_ok = all(result.ok and not result.skipped for result in checks)
    if write_manifest_file:
        if prerequisites_ok:
            checks.append(
                refresh_release_evidence(expected_source=initial_source)
            )
        else:
            skipped_mandatory = any(result.skipped for result in checks)
            checks.append(
                CheckResult(
                    "release-evidence",
                    not skipped_mandatory,
                    "not written because a mandatory check was skipped"
                    if skipped_mandatory
                    else "not written because an earlier validation check failed",
                    skipped=not skipped_mandatory,
                )
            )
    if verify_manifest_file or write_manifest_file:
        checks.append(check_manifest())
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run CodeProbe release validation checks.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip the unittest suite and run only fast checks.")
    parser.add_argument("--verbose-tests", action="store_true", help="Run unittest discovery with -v.")
    parser.add_argument(
        "--require-node",
        action="store_true",
        help="Fail JavaScript syntax validation when Node.js is unavailable.",
    )
    parser.add_argument(
        "--write-release-evidence",
        "--write-manifest",
        dest="write_manifest",
        action="store_true",
        help=f"Refresh audit reports and {MANIFEST_NAME} only after all preceding checks pass.",
    )
    parser.add_argument("--json-out", help="Write machine-readable check results to this path.")
    args = parser.parse_args(argv)

    json_output = Path(args.json_out) if args.json_out else None
    if json_output is not None and not diagnostic_output_is_outside_release_set(json_output):
        parser.error("--json-out must be outside the release set; use dist/ or a path outside the checkout")

    results = run_checks(
        skip_tests=args.skip_tests,
        verbose_tests=args.verbose_tests,
        require_node=args.require_node,
        write_manifest_file=args.write_manifest,
    )
    for result in results:
        status = "SKIP" if result.skipped else ("PASS" if result.ok else "FAIL")
        print(f"[{status}] {result.name}: {result.detail}")

    if json_output is not None:
        payload = {"app_version": engine.APP_VERSION, "results": [result.__dict__ for result in results]}
        try:
            atomic_write_text(json_output, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        except (OSError, ReleaseSetError) as exc:
            print(f"[FAIL] diagnostic-output: {exc}")
            return 1

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
