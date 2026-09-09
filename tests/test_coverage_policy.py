from __future__ import annotations

import hashlib
import io
import json
import errno
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import check_coverage as coverage  # noqa: E402


class CoveragePolicyTests(unittest.TestCase):
    def _output_fixture(self, parent: Path):
        root = parent / "kit"
        (root / "tools").mkdir(parents=True)
        (root / "src").mkdir()
        (root / "tests").mkdir()
        source = root / "src" / "sample.py"
        source.write_bytes(b"value = 1\n")
        test = root / "tests" / "test_sample.py"
        test.write_bytes(b"# inert fixture; collection is replaced\n")
        fixture = root / "tests" / "sample.json"
        fixture.write_bytes(b'{"answer": 42}\n')
        policy = json.loads((ROOT / "tools" / "coverage-policy.json").read_text(encoding="utf-8"))
        policy_path = parent / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        rows = [coverage.FileCoverage(path, 1, 1) for path in policy["floors"]["files"]]
        return root, (policy_path, source, test, fixture), rows

    def _check_output_aliases(self, kind: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs, rows = self._output_fixture(parent)
            before = {path: path.read_bytes() for path in inputs}
            for index, source in enumerate(inputs):
                with self.subTest(input=source.name, kind=kind):
                    output = parent / f"alias-{index}.json"
                    if kind == "same":
                        output = source
                    elif kind == "resolved":
                        (source.parent / "unused").mkdir(exist_ok=True)
                        output = source.parent / "unused" / ".." / source.name
                    else:
                        try:
                            if kind == "hardlink":
                                os.link(source, output)
                            else:
                                output.symlink_to(source)
                        except OSError as exc:
                            if exc.errno in {errno.EACCES, errno.EPERM, errno.ENOTSUP}:
                                self.skipTest(f"{kind} unavailable: {exc}")
                            raise
                    with mock.patch.object(coverage, "__file__", str(root / "tools" / "check_coverage.py")), \
                            mock.patch.object(coverage, "collect_coverage", return_value=(rows, 1, "")) as collect, \
                            mock.patch.object(sys, "stdout", io.StringIO()):
                        status = coverage.main(["--policy", str(inputs[0]), "--allow-version-drift", "--json-out", str(output)])
                    self.assertEqual(status, 1)
                    collect.assert_not_called()
                    self.assertEqual(before, {path: path.read_bytes() for path in inputs})
                    if kind == "resolved":
                        self.assertEqual(list((source.parent / "unused").iterdir()), [])

    def test_output_rejects_same_and_resolved_input_paths_before_collection(self) -> None:
        self._check_output_aliases("same")
        self._check_output_aliases("resolved")

    def test_output_rejects_hardlinks_to_policy_source_tests_and_fixtures(self) -> None:
        self._check_output_aliases("hardlink")

    def test_output_rejects_symlinks_to_policy_source_tests_and_fixtures(self) -> None:
        self._check_output_aliases("symlink")

    def test_distinct_output_is_complete_and_encoding_failure_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs, rows = self._output_fixture(parent)
            before = {path: path.read_bytes() for path in inputs}
            output = parent / "reports" / "coverage.json"
            with mock.patch.object(coverage, "__file__", str(root / "tools" / "check_coverage.py")), \
                    mock.patch.object(coverage, "collect_coverage", return_value=(rows, 1, "")), \
                    mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(coverage.main(["--policy", str(inputs[0]), "--allow-version-drift", "--json-out", str(output)]), 0)
                valid = output.read_bytes()
                self.assertEqual(json.loads(valid)["overall"]["percentage"], 100.0)
                with mock.patch.object(coverage, "result_payload", return_value={"text": "\ud800"}):
                    self.assertEqual(coverage.main(["--policy", str(inputs[0]), "--allow-version-drift", "--json-out", str(output)]), 1)
            self.assertEqual(output.read_bytes(), valid)
            self.assertEqual(before, {path: path.read_bytes() for path in inputs})

    def test_repository_policy_is_well_formed_and_measures_production_code(self) -> None:
        policy = coverage.load_policy(ROOT / "tools" / "coverage-policy.json")
        files = coverage.discover_source_files(ROOT, policy)
        paths = {path.relative_to(ROOT).as_posix() for path in files}
        self.assertIn("src/codeprobe_runtime.py", paths)
        self.assertIn("src/codeprobe_engine/release.py", paths)
        self.assertIn("src/codeprobe_engine/process_control.py", paths)
        self.assertIn("src/codeprobe_engine/server.py", paths)
        self.assertIn("tools/check_release.py", paths)
        self.assertIn("tools/check_pyodide_provenance.py", paths)
        self.assertNotIn("tools/check_coverage.py", paths)
        self.assertTrue(all(not path.startswith("tests/") for path in paths))

    def test_executable_line_inventory_ignores_comments_and_blank_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.py"
            path.write_text(
                "# comment\n\nvalue = 1\n\ndef add(number):\n    return value + number\n",
                encoding="utf-8",
            )
            lines = coverage.executable_lines(path)
        self.assertIn(3, lines)
        self.assertIn(5, lines)
        self.assertIn(6, lines)
        self.assertNotIn(1, lines)
        self.assertNotIn(2, lines)

    def test_floor_evaluation_is_weighted_by_executable_lines(self) -> None:
        rows = [
            coverage.FileCoverage("src/a.py", 90, 100),
            coverage.FileCoverage("tools/b.py", 1, 100),
        ]
        policy = {
            "floors": {
                "overall": 50,
                "roots": {"src": 80, "tools": 0},
                "files": {"src/a.py": 80},
            }
        }
        failures = coverage.evaluate_floors(rows, policy)
        self.assertTrue(any("overall 45.50%" in failure for failure in failures))
        self.assertFalse(any("src 90.00%" in failure for failure in failures))

    def test_duplicate_policy_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaisesRegex(coverage.CoveragePolicyError, "duplicate JSON key"):
                coverage.load_policy(path)


    def test_monitoring_is_not_silenced_by_a_test_that_clears_sys_trace(self) -> None:
        if not hasattr(sys, "monitoring"):
            with self.assertRaisesRegex(
                coverage.CoveragePolicyError,
                "requires CPython with the sys.monitoring API",
            ):
                coverage._monitoring_api()
            return

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            source = root / "src" / "example.py"
            source.write_text(
                "def first():\n    return 1\n\ndef second():\n    return 2\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_trace_reset.py").write_text(
                "import sys\nimport unittest\nfrom example import first, second\n\n"
                "class TraceResetTests(unittest.TestCase):\n"
                "    def test_a_clear_trace(self):\n"
                "        sys.settrace(None)\n"
                "        self.assertEqual(first(), 1)\n\n"
                "    def test_b_following_test_is_traced(self):\n"
                "        self.assertEqual(second(), 2)\n",
                encoding="utf-8",
            )
            policy = {
                "include_roots": ["src"],
                "exclude_paths": [],
                "minimum_tests": 2,
                "floors": {"overall": 0, "roots": {"src": 0}, "files": {}},
            }
            rows, tests_run, _ = coverage.collect_coverage(root, policy)
        self.assertEqual(tests_run, 2)
        row = rows[0]
        self.assertGreaterEqual(row.executed, 1)

    def test_missing_monitoring_api_is_a_controlled_runtime_error(self) -> None:
        with mock.patch.object(coverage.sys, "monitoring", None, create=True):
            with self.assertRaisesRegex(
                coverage.CoveragePolicyError,
                "requires CPython with the sys.monitoring API",
            ):
                coverage._monitoring_api()

    @unittest.skipUnless(hasattr(sys, "monitoring"), "Line diagnostics require sys.monitoring")
    def test_line_diagnostics_retain_taken_and_untaken_branch_evidence(self) -> None:
        source_text = (
            "def choose(flag):\n"
            "    if flag:\n"
            "        return 'taken'\n"
            "    return 'untaken'\n"
        )
        with tempfile.TemporaryDirectory(prefix="coverage_lines_") as tmp:
            root = Path(tmp)
            # Fresh names avoid reusing imports from a deleted fixture directory.
            # The interpreter owns these two bounded modules until it exits.
            module_name = root.name
            relative = "src/" + module_name + ".py"
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / relative).write_bytes(source_text.encode("utf-8"))
            (root / "tests" / ("test_" + module_name + ".py")).write_text(
                "import unittest\nfrom " + module_name + " import choose\n\n"
                "class BranchTests(unittest.TestCase):\n"
                "    def test_taken(self):\n"
                "        self.assertEqual(choose(True), 'taken')\n",
                encoding="utf-8",
            )
            policy = {
                "include_roots": ["src"], "exclude_paths": [], "minimum_tests": 1,
                "floors": {"overall": 50, "roots": {"src": 50}, "files": {relative: 50}},
            }
            # Select only this owned fixture for diagnostics; measurement is real.
            with mock.patch.object(coverage, "_BROKER_DIAGNOSTIC_PATH", relative), \
                    mock.patch.object(unittest, "defaultTestLoader", unittest.TestLoader()):
                rows, tests_run, _ = coverage.collect_coverage(root, policy)
                payload = coverage.result_payload(
                    rows, policy, tests_run=tests_run,
                    floor_failures=coverage.evaluate_floors(rows, policy),
                )
        self.assertEqual(tests_run, 1)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.executed_line_numbers, (1, 2, 3))
        self.assertEqual(row.executable_line_numbers, (1, 2, 3, 4))
        self.assertEqual((row.executed, row.executable), (3, 4))
        self.assertEqual(row.source_sha256, hashlib.sha256(source_text.encode("utf-8")).hexdigest())
        decoded = json.loads(json.dumps(payload))
        detail = decoded["line_diagnostics"]["files"][0]
        self.assertEqual(detail["executed_line_numbers"], [1, 2, 3])
        self.assertEqual(detail["executable_line_numbers"], [1, 2, 3, 4])
        self.assertEqual(detail["source_sha256"], row.source_sha256)
        self.assertEqual(decoded["overall"]["percentage"], 75.0)
        self.assertEqual(decoded["floor_failures"], [])

    def test_cli_retains_line_diagnostics_when_the_coverage_floor_fails(self) -> None:
        relative = "src/codeprobe_engine/process_control.py"
        row = coverage.FileCoverage(
            relative, 1, 2, executed_line_numbers=(1,), executable_line_numbers=(1, 2),
            source_sha256="a" * 64,
        )
        policy = {
            "python_runtime": coverage.platform.python_version(),
            "include_roots": ["src"],
            "floors": {"overall": 58, "roots": {"src": 58}, "files": {relative: 58}},
        }
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "coverage.json"
            with mock.patch.object(coverage, "load_policy", return_value=policy), \
                    mock.patch.object(coverage, "collect_coverage", return_value=([row], 1, "")) as collect, \
                    mock.patch.object(sys, "stdout", stdout):
                status = coverage.main(["--json-out", str(destination)])
            payload = json.loads(destination.read_text(encoding="utf-8"))
        collect.assert_called_once_with(ROOT, policy)
        self.assertEqual(status, 1)
        self.assertEqual(len(payload["floor_failures"]), 3)
        self.assertEqual(payload["overall"]["percentage"], 50.0)
        prefix = "SUPPORTED_COVERAGE_LINE_DIAGNOSTIC="
        diagnostics = [line[len(prefix):] for line in stdout.getvalue().splitlines()
                       if line.startswith(prefix)]
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(json.loads(diagnostics[0]), payload["line_diagnostics"])
        self.assertEqual(payload["line_diagnostics"]["files"][0]["executed_line_numbers"], [1])
        self.assertEqual(payload["line_diagnostics"]["files"][0]["executable_line_numbers"], [1, 2])
        self.assertEqual(payload["line_diagnostics"]["runtime_flags"]["isolated"], sys.flags.isolated)
        self.assertIn("[FAIL] supported-coverage-floor:", stdout.getvalue())

    def test_repository_policy_pins_the_running_standard_python(self) -> None:
        policy = coverage.load_policy(ROOT / "tools" / "coverage-policy.json")
        self.assertRegex(policy["python_runtime"], r"^3\.14\.[0-9]+$")
        self.assertEqual(policy["schema"], coverage.POLICY_SCHEMA)

    def test_repository_floors_form_a_nonzero_high_risk_ratchet(self) -> None:
        policy = coverage.load_policy(ROOT / "tools" / "coverage-policy.json")
        self.assertGreaterEqual(policy["minimum_tests"], 369)
        self.assertGreaterEqual(policy["floors"]["overall"], 72.0)
        self.assertGreaterEqual(policy["floors"]["roots"]["src"], 69.0)
        self.assertGreaterEqual(policy["floors"]["roots"]["tools"], 75.0)
        expected = {
            "src/codeprobe_engine/process_control.py",
            "src/codeprobe_engine/server.py",
            "src/codeprobe_engine/release.py",
            "src/codeprobe_engine/project_io.py",
            "src/codeprobe_runtime.py",
            "tools/build_release.py",
            "tools/check_dependency_boundary.py",
            "tools/check_pyodide_provenance.py",
            "tools/check_release.py",
            "tools/check_release_reproducibility.py",
            "tools/final_audit.py",
        }
        self.assertEqual(set(policy["floors"]["files"]), expected)
        self.assertTrue(all(value > 0 for value in policy["floors"]["files"].values()))

    def test_policy_rejects_zero_floors_and_ambiguous_runtime(self) -> None:
        source = json.loads((ROOT / "tools" / "coverage-policy.json").read_text(encoding="utf-8"))
        mutations = (
            ("python_runtime", "3.14"),
            ("measurement_model", "trace"),
            ("floors.overall", 0),
        )
        for key, value in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                candidate = json.loads(json.dumps(source))
                if key == "floors.overall":
                    candidate["floors"]["overall"] = value
                else:
                    candidate[key] = value
                path = Path(tmp) / "policy.json"
                path.write_text(json.dumps(candidate), encoding="utf-8")
                with self.assertRaises(coverage.CoveragePolicyError):
                    coverage.load_policy(path)

    def test_floor_failure_is_reported_by_the_cli_contract(self) -> None:
        rows = [coverage.FileCoverage("src/a.py", 49, 100)]
        policy = {
            "floors": {
                "overall": 50,
                "roots": {"src": 50},
                "files": {"src/a.py": 50},
            }
        }
        failures = coverage.evaluate_floors(rows, policy)
        self.assertEqual(
            failures,
            [
                "overall 49.00% is below 50.00%",
                "src 49.00% is below 50.00%",
                "src/a.py 49.00% is below 50.00%",
            ],
        )

    def test_ci_contains_a_pinned_coverage_job_required_by_the_aggregate_gate(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("coverage:", workflow)
        self.assertIn("name: Supported-code coverage", workflow)
        self.assertIn('python-version: "3.14.7"', workflow)
        self.assertIn("python -I -S -B tools/check_coverage.py", workflow)
        required = workflow.split("  required:", 1)[1]
        self.assertIn("- coverage", required)
        self.assertIn("COVERAGE_RESULT:", required)
        self.assertIn('test "$COVERAGE_RESULT" = "success"', required)


if __name__ == "__main__":
    unittest.main()
