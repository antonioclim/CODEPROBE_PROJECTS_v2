#!/usr/bin/env python3
"""Run CodeProbe release checks from a source checkout.

The script deliberately uses only the Python standard library. JavaScript syntax
checking is performed with Node.js when it is available; otherwise that step is
reported as skipped rather than hidden.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import py_compile
import re
import shutil
import subprocess
import sys
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
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import codeprobe_runtime as engine  # noqa: E402
import audit_institutional_pack  # noqa: E402
import check_file_references  # noqa: E402
import final_audit  # noqa: E402
import check_naming  # noqa: E402
from codeprobe_engine import api as cp_api  # noqa: E402
from codeprobe_engine import metrics as cp_metrics  # noqa: E402
from codeprobe_engine.release import (  # noqa: E402
    MANIFEST_NAME,
    ReleaseSetError,
    atomic_write_bytes,
    atomic_write_text,
    read_regular_file,
    validate_release_set,
    verify_manifest,
    write_manifest,
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


def check_unittest_suite(verbose: bool = False) -> CheckResult:
    cmd = [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"]
    if verbose:
        cmd.append("-v")
    completed = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    lines = (completed.stdout + completed.stderr).strip().splitlines()
    detail = lines[-1] if lines else "no unittest output"
    return CheckResult("unit-tests", completed.returncode == 0, detail)


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
            if path.is_file() and path.suffix.lower() == ".js" and path not in files:
                files.append(path)
    return files


def check_javascript_syntax() -> CheckResult:
    node = shutil.which("node")
    if not node:
        return CheckResult("javascript-syntax", True, "Node.js not available; skipped", skipped=True)
    try:
        checked = 0
        for script_path in browser_script_files():
            checked += 1
            completed = subprocess.run([node, "--check", str(script_path)], text=True, capture_output=True)
            if completed.returncode != 0:
                return CheckResult("javascript-syntax", False, f"{script_path.relative_to(ROOT)}: {completed.stderr.strip()}")
        return CheckResult("javascript-syntax", True, f"{checked} external browser script(s) pass node --check")
    except Exception as exc:  # pragma: no cover - failure path reported by CLI
        return CheckResult("javascript-syntax", False, str(exc))


def _sri_for_file(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
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
            if target.endswith((".js", ".css")) and "integrity=" not in attrs:
                errors.append(f"{html.name} references {target} without SRI")
    if errors:
        return CheckResult("browser-security", False, "; ".join(errors[:10]))
    return CheckResult("browser-security", True, "CSP, inline-code and local SRI checks passed")


def check_resource_integrity() -> CheckResult:
    manifest_path = APP / "resource-integrity.json"
    if not manifest_path.exists():
        return CheckResult("browser-resource-integrity", False, "app/resource-integrity.json is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        errors: list[str] = []
        for item in manifest.get("assets", []):
            relative = item.get("path")
            if not isinstance(relative, str):
                errors.append("manifest item without path")
                continue
            path = APP / relative
            if not path.is_file():
                errors.append(f"missing asset: {relative}")
                continue
            actual_hex = hashlib.sha256(path.read_bytes()).hexdigest()
            if item.get("sha256_hex") != actual_hex:
                errors.append(f"sha256 mismatch: {relative}")
            actual_sri = _sri_for_file(path)
            if item.get("sri_sha256") != actual_sri:
                errors.append(f"SRI mismatch: {relative}")
        if errors:
            return CheckResult("browser-resource-integrity", False, "; ".join(errors[:10]))
        return CheckResult("browser-resource-integrity", True, f"{len(manifest.get('assets', []))} asset(s) verified")
    except Exception as exc:  # pragma: no cover - failure path reported by CLI
        return CheckResult("browser-resource-integrity", False, str(exc))

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
        return CheckResult("final-audit", True, f"{report.get('file_count')} release-set files audited")
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
    """Reject unsafe filesystem entries before any other checker can read them."""
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


def diagnostic_output_is_outside_release_set(path: Path, root: Path = ROOT) -> bool:
    """Return whether an explicit diagnostic output avoids the release set."""
    root = root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return True
    return bool(relative.parts) and relative.parts[0] == "dist"


def refresh_release_evidence(root: Path = ROOT) -> CheckResult:
    """Refresh tracked release evidence only after a successful in-memory audit."""
    root = root.resolve()
    try:
        validate_release_set(root)
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

    snapshots: dict[Path, bytes] = {}
    try:
        for relative in EVIDENCE_PATHS:
            snapshots[relative] = read_regular_file(root / relative, root=root)
    except (OSError, ReleaseSetError) as exc:
        return CheckResult("release-evidence", False, f"not written because existing evidence could not be read: {exc}")
    try:
        final_audit.write_reports(root, report)
        write_manifest(root, engine.APP_VERSION)
        post_report = final_audit.build_audit(root)
        errors = []
        if post_report.get("status") != "pass":
            errors.append("post-write final audit failed")
        else:
            errors.extend(final_audit.verify_reports(root, post_report))
        errors.extend(verify_manifest(root, app_version=engine.APP_VERSION))
        if errors:
            raise RuntimeError("; ".join(errors[:10]))
    except Exception as exc:
        rollback_errors: list[str] = []
        for relative, content in snapshots.items():
            path = root / relative
            try:
                atomic_write_bytes(path, content)
            except OSError as rollback_exc:
                rollback_errors.append(f"{relative.as_posix()}: {rollback_exc}")
        if rollback_errors:
            detail = "; ".join(rollback_errors[:3])
            return CheckResult("release-evidence", False, f"refresh failed; rollback incomplete ({detail}): {exc}")
        return CheckResult("release-evidence", False, f"refresh failed and was rolled back: {exc}")
    return CheckResult("release-evidence", True, "audit reports and release manifest refreshed with atomic file replacement")


def run_checks(
    skip_tests: bool = False,
    verbose_tests: bool = False,
    write_manifest_file: bool = False,
    verify_manifest_file: bool = True,
    verify_persisted_evidence: bool = True,
) -> list[CheckResult]:
    safety = check_release_set_safety()
    if not safety.ok:
        return [safety]
    checks = [safety, check_python_compile()]
    if not skip_tests:
        checks.append(check_unittest_suite(verbose=verbose_tests))
    checks.extend([
        check_javascript_syntax(),
        check_browser_security(),
        check_resource_integrity(),
        check_version_consistency(),
        check_smoke_reports(),
        check_institutional_package(),
        check_reference_integrity(),
        check_naming_policy(),
        check_final_audit(verify_persisted=verify_persisted_evidence and not write_manifest_file),
    ])
    prerequisites_ok = all(result.ok for result in checks)
    if write_manifest_file:
        if prerequisites_ok:
            checks.append(refresh_release_evidence())
        else:
            checks.append(CheckResult(
                "release-evidence",
                True,
                "not written because an earlier validation check failed",
                skipped=True,
            ))
    if verify_manifest_file or write_manifest_file:
        checks.append(check_manifest())
    return checks


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run CodeProbe release validation checks.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip the unittest suite and run only fast checks.")
    parser.add_argument("--verbose-tests", action="store_true", help="Run unittest discovery with -v.")
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

    results = run_checks(skip_tests=args.skip_tests, verbose_tests=args.verbose_tests, write_manifest_file=args.write_manifest)
    for result in results:
        status = "SKIP" if result.skipped else ("PASS" if result.ok else "FAIL")
        print(f"[{status}] {result.name}: {result.detail}")

    if json_output is not None:
        payload = {"app_version": engine.APP_VERSION, "results": [result.__dict__ for result in results]}
        try:
            atomic_write_text(json_output, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"[FAIL] diagnostic-output: {exc}")
            return 1

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
