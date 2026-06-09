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


if __name__ == "__main__":
    unittest.main()
