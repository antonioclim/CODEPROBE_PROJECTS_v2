from __future__ import annotations

import json
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
