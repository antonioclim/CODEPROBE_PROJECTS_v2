from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402


class PhaseTwoReportSchemaTests(unittest.TestCase):
    def test_json_entrypoint_report_contains_stable_phase_two_fields(self) -> None:
        payload = {
            "code": "def add(left, right):\n    return left + right\n",
            "filename": "sample.py",
            "language_hint": "python",
            "profile": "default",
        }
        bundle = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
        self.assertIn("report", bundle)
        self.assertIn("text", bundle)
        report = bundle["report"]
        for key in [
            "app_name",
            "app_version",
            "schema_version",
            "filename",
            "language",
            "loc",
            "sloc",
            "overall_score",
            "overall_percent",
            "overall_applicable",
            "confidence",
            "verdict",
            "verdict_class",
            "profile",
            "duration_seconds",
            "notes",
            "warnings",
            "metrics",
        ]:
            self.assertIn(key, report)
        self.assertEqual(report["app_name"], engine.APP_NAME)
        self.assertEqual(report["app_version"], engine.APP_VERSION)
        self.assertEqual(report["schema_version"], "2.2.0")
        self.assertIsInstance(report["metrics"], list)
        self.assertTrue(report["metrics"])
        for metric in report["metrics"]:
            self.assertIn("group", metric)
            self.assertIn("contributes_to_overall", metric)
            self.assertIn(metric["group"], {"stylometry", "context", "quality", "documentation"})

    def test_invalid_override_surfaces_as_error(self) -> None:
        payload = {
            "code": "def add(a, b):\n    return a + b\n",
            "filename": "sample.py",
            "language_hint": "python",
            "profile": "default",
            "config_override": {"comment_density": {"group": "invalid"}},
        }
        with self.assertRaises(ValueError):
            engine.codeprobe_analyze(json.dumps(payload))

class IntakeProvenanceSchemaTests(unittest.TestCase):
    provenance = {"encoding": "latin-1", "normalisation": "newlines", "warnings": ["Decoded as latin-1; review the file encoding."]}

    def test_file_provenance_survives_json_and_text_as_a_caller_declaration(self):
        bundle = json.loads(engine.codeprobe_analyze(json.dumps({"code": "print('café')\n", "filename": "cafe.py", "intake_provenance": self.provenance})))
        self.assertEqual(bundle["report"]["intake_provenance"], {**self.provenance, "source": "caller-reported"})
        self.assertIn(self.provenance["warnings"][0], bundle["text"])
        self.assertIn("cafe.py: caller-reported", bundle["text"])

    def test_project_provenance_retains_paths_included_children_and_text(self):
        report = engine.analyse_project_payload({"files": [{"path": "src/cafe.py", "content": "print('café')\n", "intake_provenance": self.provenance}]})
        self.assertEqual(report["intake_provenance"], [{"path": "src/cafe.py", **self.provenance, "source": "caller-reported"}])
        self.assertEqual(report["files"][0]["intake_provenance"]["source"], "caller-reported")
        self.assertIn(self.provenance["warnings"][0], report["files"][0]["warnings"][-1])
        self.assertIn(self.provenance["warnings"][0], engine.format_project_report_text(report))

    def test_native_and_caller_provenance_are_distinct_and_utf8_gets_no_false_warning(self):
        valid = {"encoding": "utf-8", "normalisation": "none", "warnings": []}
        native = engine._NativeProjectFile(path="main.py", content="print(1)\n", size_bytes=9, intake_provenance=valid)
        report = engine.analyse_project_payload({"files": engine._NativeProjectFiles([native], unexpanded_directories=["node_modules"])})
        self.assertEqual(report["files"][0]["intake_provenance"]["source"], "native-intake")
        self.assertEqual(report["input_packaging"]["unexpanded_directories"], ["node_modules"])
        self.assertFalse(any("intake:" in warning for warning in report["warnings"]))
        empty = engine.analyse_project_payload({"files": engine._NativeProjectFiles(unexpanded_directories=["node_modules"])})
        self.assertEqual(empty["input_packaging"]["source"], "native-folder")

    def test_invalid_provenance_fails_before_file_or_project_collection(self):
        cases = [None, [], {}, {**self.provenance, "source": "native-intake"}, {**self.provenance, "encoding": []},
                 {**self.provenance, "normalisation": "unknown"}, {**self.provenance, "warnings": "text"},
                 {**self.provenance, "warnings": ["x"] * 9}, {**self.provenance, "warnings": ["x" * 513]},
                 {**self.provenance, "warnings": ["😀" * 513]}, {**self.provenance, "warnings": ["bad\x00"]},
                 {**self.provenance, "warnings": ["bad\x85"]}, {**self.provenance, "warnings": ["\ud800"]}]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                engine.validate_analysis_payload({"code": "print(1)", "intake_provenance": raw})
            with self.subTest(project_raw=raw), self.assertRaises(ValueError):
                engine.validate_analysis_payload({"files": [{"path": "main.py", "content": "print(1)", "intake_provenance": raw}]}, "project")

    def test_markup_is_retained_as_text_and_metadata_does_not_relax_content_limits(self):
        boundary = {**self.provenance, "warnings": ["😀" * 512]}
        self.assertEqual(engine.validate_intake_provenance(boundary), boundary)
        provenance = {**self.provenance, "warnings": ["<img src=x onerror=alert(1)>"]}
        bundle = json.loads(engine.codeprobe_analyze(json.dumps({"code": "print(1)\n", "filename": "main.py", "intake_provenance": provenance})))
        self.assertEqual(bundle["report"]["intake_provenance"]["warnings"], provenance["warnings"])
        report = engine.analyse_project_payload({"max_file_bytes": 1, "files": [{"path": "main.py", "content": "print(1)\n", "size_bytes": 0, "intake_provenance": provenance}]})
        self.assertEqual(report["excluded_files"][0]["reason"], "file_too_large")
        self.assertEqual(report["excluded_files"][0]["size_bytes"], 9)


if __name__ == "__main__":
    unittest.main()
