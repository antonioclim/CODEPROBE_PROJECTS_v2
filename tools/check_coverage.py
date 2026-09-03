#!/usr/bin/env python3
"""Measure and enforce CodeProbe's supported Python line-coverage policy."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import dis
import io
import json
import os
import platform
import re
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import Any, Iterable, Mapping, Sequence


POLICY_SCHEMA = "codeprobe-supported-coverage/v1"
DEFAULT_POLICY = "tools/coverage-policy.json"
PYTHON_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class CoveragePolicyError(ValueError):
    """Raised when the coverage policy or result is not trustworthy."""


@dataclass(frozen=True)
class FileCoverage:
    path: str
    executed: int
    executable: int

    @property
    def percentage(self) -> float:
        return 100.0 if self.executable == 0 else 100.0 * self.executed / self.executable


@dataclass(frozen=True)
class AggregateCoverage:
    name: str
    executed: int
    executable: int

    @property
    def percentage(self) -> float:
        return 100.0 if self.executable == 0 else 100.0 * self.executed / self.executable


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoveragePolicyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoveragePolicyError(f"cannot read coverage policy: {exc}") from exc
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise CoveragePolicyError(f"coverage policy schema must be {POLICY_SCHEMA}")
    runtime = policy.get("python_runtime")
    if not isinstance(runtime, str) or not PYTHON_VERSION_PATTERN.fullmatch(runtime):
        raise CoveragePolicyError("coverage policy python_runtime must be an exact version")
    if policy.get("measurement_model") != "sys.monitoring executable-line coverage":
        raise CoveragePolicyError("coverage policy measurement_model is unsupported")
    if not isinstance(policy.get("include_roots"), list) or not policy["include_roots"]:
        raise CoveragePolicyError("coverage policy requires include_roots")
    roots = [_relative_path(str(value), "coverage root") for value in policy["include_roots"]]
    if len(roots) != len(set(roots)):
        raise CoveragePolicyError("coverage policy contains duplicate roots")
    if not isinstance(policy.get("exclude_paths"), list):
        raise CoveragePolicyError("coverage policy exclude_paths must be an array")
    if isinstance(policy.get("minimum_tests"), bool) or not isinstance(policy.get("minimum_tests"), int):
        raise CoveragePolicyError("coverage policy minimum_tests must be an integer")
    if policy["minimum_tests"] <= 0:
        raise CoveragePolicyError("coverage policy minimum_tests must be positive")
    limitations = policy.get("limitations")
    if (
        not isinstance(limitations, list)
        or not limitations
        or any(not isinstance(value, str) or not value.strip() for value in limitations)
        or len(limitations) != len(set(limitations))
    ):
        raise CoveragePolicyError("coverage policy limitations must be unique non-empty strings")
    floors = policy.get("floors")
    if not isinstance(floors, dict):
        raise CoveragePolicyError("coverage policy requires floors")
    _positive_percentage(floors.get("overall"), "overall floor")
    root_floors = _mapping(floors.get("roots"), "root floors")
    if set(root_floors) != set(roots):
        raise CoveragePolicyError("root coverage floors must exactly match include_roots")
    for root, value in root_floors.items():
        _relative_path(str(root), "root floor path")
        _positive_percentage(value, f"root floor {root}")
    file_floors = _mapping(floors.get("files"), "file floors")
    if not file_floors:
        raise CoveragePolicyError("coverage policy requires high-risk file floors")
    for file_name, value in file_floors.items():
        _relative_path(str(file_name), "file floor path")
        _positive_percentage(value, f"file floor {file_name}")
    return policy


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CoveragePolicyError(f"{label} must be an object")
    return value


def _percentage(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CoveragePolicyError(f"{label} must be numeric")
    rendered = float(value)
    if not 0.0 <= rendered <= 100.0:
        raise CoveragePolicyError(f"{label} must be between 0 and 100")
    return rendered


def _positive_percentage(value: Any, label: str) -> float:
    rendered = _percentage(value, label)
    if rendered <= 0.0:
        raise CoveragePolicyError(f"{label} must be greater than zero")
    return rendered


def _relative_path(value: str, label: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise CoveragePolicyError(f"{label} must be a canonical relative path")
    rendered = path.as_posix()
    if rendered != value or rendered.startswith("./"):
        raise CoveragePolicyError(f"{label} must use canonical POSIX form")
    return rendered


def _exclusion_map(policy: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in policy["exclude_paths"]:
        if not isinstance(item, dict):
            raise CoveragePolicyError("coverage exclusions must be objects")
        path = _relative_path(str(item.get("path", "")), "coverage exclusion")
        reason = str(item.get("reason", "")).strip()
        if not reason:
            raise CoveragePolicyError(f"coverage exclusion {path} requires a reason")
        if path in result:
            raise CoveragePolicyError(f"duplicate coverage exclusion: {path}")
        result[path] = reason
    return result


def discover_source_files(root: Path, policy: Mapping[str, Any]) -> list[Path]:
    exclusions = _exclusion_map(policy)
    files: list[Path] = []
    seen: set[str] = set()
    for raw_root in policy["include_roots"]:
        relative_root = _relative_path(str(raw_root), "coverage root")
        directory = root / relative_root
        if not directory.is_dir():
            raise CoveragePolicyError(f"coverage root is missing: {relative_root}")
        for path in sorted(directory.rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            if "__pycache__" in path.parts or relative in exclusions:
                continue
            if relative in seen:
                raise CoveragePolicyError(f"duplicate coverage path: {relative}")
            seen.add(relative)
            files.append(path)
    for path in exclusions:
        if not (root / path).is_file():
            raise CoveragePolicyError(f"coverage exclusion does not name a file: {path}")
    floor_files = set(_mapping(policy["floors"].get("files"), "file floors"))
    missing_floor_files = sorted(floor_files - seen)
    if missing_floor_files:
        raise CoveragePolicyError(
            "file coverage floors are outside the measured set: " + ", ".join(missing_floor_files)
        )
    return files


def executable_lines(path: Path) -> set[int]:
    source = path.read_text(encoding="utf-8")
    code = compile(source, str(path), "exec", dont_inherit=True)
    lines: set[int] = set()
    pending = [code]
    while pending:
        current = pending.pop()
        for _, line in dis.findlinestarts(current):
            if isinstance(line, int) and line > 0:
                lines.add(line)
        for value in current.co_consts:
            if isinstance(value, types.CodeType):
                pending.append(value)
    return lines


def _monitoring_api() -> Any:
    monitoring = getattr(sys, "monitoring", None)
    if monitoring is None:
        raise CoveragePolicyError(
            "supported coverage requires CPython with the sys.monitoring API"
        )
    return monitoring


class _SupportedCoverageMonitor:
    """Count line events only for the declared production-code set.

    The monitor uses CPython's ``sys.monitoring`` API rather than ``sys.settrace``.
    Deliberately adversarial tests may clear or disrupt a conventional tracing
    function, while monitoring events remain independent and apply to worker
    threads in the same interpreter. Access to the version-specific API is
    deferred until measurement starts so the release gate remains importable on
    every supported Python version.
    """

    def __init__(self, measured_files: Sequence[Path]) -> None:
        self._monitoring = _monitoring_api()
        self._preferred_tool_ids = (
            self._monitoring.COVERAGE_ID,
            self._monitoring.PROFILER_ID,
            3,
            4,
            self._monitoring.DEBUGGER_ID,
            self._monitoring.OPTIMIZER_ID,
        )
        self._measured = {str(path.resolve(strict=True)) for path in measured_files}
        self._code_paths: dict[CodeType, str | None] = {}
        self.executed: dict[str, set[int]] = {path: set() for path in self._measured}
        self._tool_id: int | None = None

    def _path_for_code(self, code: CodeType) -> str | None:
        cached = self._code_paths.get(code, ...)
        if cached is not ...:
            return cached
        try:
            candidate = os.path.realpath(os.path.abspath(code.co_filename))
        except (OSError, TypeError, ValueError):
            candidate = str(code.co_filename)
        selected = candidate if candidate in self._measured else None
        self._code_paths[code] = selected
        return selected

    def _on_python_start(self, code: CodeType, instruction_offset: int) -> object:
        del instruction_offset
        path = self._path_for_code(code)
        if path is not None and self._tool_id is not None:
            self._monitoring.set_local_events(
                self._tool_id,
                code,
                self._monitoring.events.LINE,
            )
        # The code object's classification does not change during this run.
        # Disable further PY_START callbacks for this code while retaining any
        # local LINE events installed above.
        return self._monitoring.DISABLE

    def _on_line(self, code: CodeType, line_number: int) -> object:
        path = self._path_for_code(code)
        if path is not None:
            self.executed[path].add(int(line_number))
        # Coverage is Boolean at each bytecode location. Once observed, repeated
        # callbacks add cost but no information.
        return self._monitoring.DISABLE

    def __enter__(self) -> "_SupportedCoverageMonitor":
        for tool_id in self._preferred_tool_ids:
            if self._monitoring.get_tool(tool_id) is None:
                self._tool_id = tool_id
                break
        if self._tool_id is None:
            raise CoveragePolicyError(
                "no sys.monitoring tool identifier is available for coverage"
            )
        self._monitoring.use_tool_id(self._tool_id, "codeprobe-supported-coverage")
        self._monitoring.register_callback(
            self._tool_id,
            self._monitoring.events.PY_START,
            self._on_python_start,
        )
        self._monitoring.register_callback(
            self._tool_id,
            self._monitoring.events.LINE,
            self._on_line,
        )
        self._monitoring.set_events(
            self._tool_id,
            self._monitoring.events.PY_START,
        )
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        if self._tool_id is None:
            return
        tool_id = self._tool_id
        self._tool_id = None
        self._monitoring.set_events(tool_id, 0)
        self._monitoring.register_callback(
            tool_id,
            self._monitoring.events.PY_START,
            None,
        )
        self._monitoring.register_callback(
            tool_id,
            self._monitoring.events.LINE,
            None,
        )
        self._monitoring.free_tool_id(tool_id)


def _run_tests(root: Path, stream: io.StringIO) -> unittest.result.TestResult:
    previous_directory = Path.cwd()
    previous_path = list(sys.path)
    additions = [str(root / "src"), str(root / "tools"), str(root)]
    for value in reversed(additions):
        if value not in sys.path:
            sys.path.insert(0, value)
    try:
        os.chdir(root)
        suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern="test*.py")
        runner = unittest.TextTestRunner(stream=stream, verbosity=1)
        return runner.run(suite)
    finally:
        sys.path[:] = previous_path
        os.chdir(previous_directory)


def collect_coverage(root: Path, policy: Mapping[str, Any]) -> tuple[list[FileCoverage], int, str]:
    _monitoring_api()
    measured_files = discover_source_files(root, policy)
    output = io.StringIO()
    with _SupportedCoverageMonitor(measured_files) as monitor:
        result = _run_tests(root, output)
    if not result.wasSuccessful():
        detail = output.getvalue()
        raise CoveragePolicyError(
            "coverage test run failed:\n" + "\n".join(detail.splitlines()[-80:])
        )
    if result.testsRun < int(policy["minimum_tests"]):
        raise CoveragePolicyError(
            f"coverage run executed {result.testsRun} tests; policy requires at least {policy['minimum_tests']}"
        )

    rows: list[FileCoverage] = []
    for path in measured_files:
        absolute = str(path.resolve(strict=True))
        executable = executable_lines(path)
        executed = executable.intersection(monitor.executed.get(absolute, set()))
        rows.append(
            FileCoverage(
                path=path.relative_to(root).as_posix(),
                executed=len(executed),
                executable=len(executable),
            )
        )
    return rows, result.testsRun, output.getvalue()


def aggregate(rows: Iterable[FileCoverage], name: str) -> AggregateCoverage:
    selected = list(rows)
    return AggregateCoverage(
        name=name,
        executed=sum(row.executed for row in selected),
        executable=sum(row.executable for row in selected),
    )


def evaluate_floors(
    rows: Sequence[FileCoverage],
    policy: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    by_path = {row.path: row for row in rows}
    floors = _mapping(policy["floors"], "floors")
    overall = aggregate(rows, "overall")
    overall_floor = _percentage(floors["overall"], "overall floor")
    if overall.percentage + 1e-9 < overall_floor:
        failures.append(f"overall {overall.percentage:.2f}% is below {overall_floor:.2f}%")
    for root_name, raw_floor in _mapping(floors["roots"], "root floors").items():
        prefix = str(root_name).rstrip("/") + "/"
        root_rows = [row for row in rows if row.path.startswith(prefix)]
        if not root_rows:
            failures.append(f"root floor has no measured files: {root_name}")
            continue
        root_result = aggregate(root_rows, str(root_name))
        floor = _percentage(raw_floor, f"root floor {root_name}")
        if root_result.percentage + 1e-9 < floor:
            failures.append(
                f"{root_name} {root_result.percentage:.2f}% is below {floor:.2f}%"
            )
    for path, raw_floor in _mapping(floors["files"], "file floors").items():
        row = by_path[str(path)]
        floor = _percentage(raw_floor, f"file floor {path}")
        if row.percentage + 1e-9 < floor:
            failures.append(f"{path} {row.percentage:.2f}% is below {floor:.2f}%")
    return failures


def result_payload(
    rows: Sequence[FileCoverage],
    policy: Mapping[str, Any],
    *,
    tests_run: int,
    floor_failures: Sequence[str],
) -> dict[str, Any]:
    roots: dict[str, dict[str, Any]] = {}
    for root_name in policy["include_roots"]:
        prefix = str(root_name).rstrip("/") + "/"
        value = aggregate([row for row in rows if row.path.startswith(prefix)], str(root_name))
        roots[str(root_name)] = {
            "executed": value.executed,
            "executable": value.executable,
            "percentage": round(value.percentage, 4),
        }
    overall = aggregate(rows, "overall")
    return {
        "schema": "codeprobe-supported-coverage-result/v1",
        "python": platform.python_version(),
        "tests_run": tests_run,
        "overall": {
            "executed": overall.executed,
            "executable": overall.executable,
            "percentage": round(overall.percentage, 4),
        },
        "roots": roots,
        "files": [
            {
                "path": row.path,
                "executed": row.executed,
                "executable": row.executable,
                "percentage": round(row.percentage, 4),
            }
            for row in rows
        ],
        "floor_failures": list(floor_failures),
        "limitations": list(policy.get("limitations") or []),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure supported Python line coverage.")
    parser.add_argument("--policy", default=DEFAULT_POLICY)
    parser.add_argument("--json-out")
    parser.add_argument("--no-enforce", action="store_true", help="Measure without applying floors.")
    parser.add_argument(
        "--allow-version-drift",
        action="store_true",
        help="Permit measurement outside the policy's pinned Python runtime.",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[1]
    try:
        policy = load_policy(root / args.policy)
        expected_python = str(policy.get("python_runtime", ""))
        actual_python = platform.python_version()
        if actual_python != expected_python and not args.allow_version_drift:
            raise CoveragePolicyError(
                f"coverage policy requires Python {expected_python}; received {actual_python}"
            )
        rows, tests_run, _ = collect_coverage(root, policy)
        failures = [] if args.no_enforce else evaluate_floors(rows, policy)
        payload = result_payload(
            rows,
            policy,
            tests_run=tests_run,
            floor_failures=failures,
        )
        if args.json_out:
            output = Path(args.json_out)
            try:
                output.resolve(strict=False).relative_to(root.resolve(strict=True))
            except ValueError:
                pass
            else:
                raise CoveragePolicyError("--json-out must be outside the repository checkout")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (CoveragePolicyError, OSError, UnicodeError, ValueError) as exc:
        print(f"[FAIL] supported-coverage: {exc}")
        return 1

    print(
        f"[PASS] supported-coverage: {tests_run} tests; overall "
        f"{payload['overall']['percentage']:.2f}% "
        f"({payload['overall']['executed']}/{payload['overall']['executable']} executable lines)"
    )
    for root_name, value in payload["roots"].items():
        print(
            f"[INFO] supported-coverage: {root_name} {value['percentage']:.2f}% "
            f"({value['executed']}/{value['executable']})"
        )
    file_floors = _mapping(policy["floors"]["files"], "file floors")
    for path in file_floors:
        row = next(item for item in payload["files"] if item["path"] == path)
        print(
            f"[INFO] supported-coverage: {path} {row['percentage']:.2f}% "
            f"({row['executed']}/{row['executable']})"
        )
    if failures:
        for failure in failures:
            print(f"[FAIL] supported-coverage-floor: {failure}")
        return 1
    print(
        "[LIMITATION] supported-coverage: line execution is measured in-process; child-process "
        "wrappers and browser JavaScript are verified by separate behavioural gates"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
