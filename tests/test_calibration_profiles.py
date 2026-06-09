from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import calibrate_corpus  # noqa: E402
import calibrate_profile  # noqa: E402
import codeprobe_runtime as engine  # noqa: E402


SAMPLE_CODE = """
def add(left, right):
    return left + right


def subtract(left, right):
    return left - right


def multiply(left, right):
    value = left * right
    return value


def main():
    total = add(1, 2)
    return multiply(total, 3)
""".strip() + "\n"


class PhaseFourCalibrationTests(unittest.TestCase):
    def test_file_report_records_calibration_profile_and_trigger_status(self) -> None:
        calibration = {
            "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
            "profile_id": "unit-test-profile",
            "label": "Unit test calibration",
            "review_policy": {
                "file": {"low_max": 0.10, "moderate_max": 0.20, "elevated_max": 0.30, "review_trigger": 0.01},
                "project": {"low_max": 0.10, "moderate_max": 0.20, "elevated_max": 0.30, "review_trigger": 0.01},
            },
        }
        result = json.loads(engine.codeprobe_analyze(json.dumps({
            "filename": "sample.py",
            "code": SAMPLE_CODE,
            "calibration_profile": calibration,
        })))
        report = result["report"]
        self.assertEqual(report["app_version"], "2.2.0")
        self.assertEqual(report["schema_version"], "2.2.0")
        self.assertEqual(report["calibration_profile_id"], "unit-test-profile")
        self.assertEqual(report["review_trigger_percent"], 1.0)
        self.assertTrue(report["review_triggered"])
        self.assertIn(report["verdict_class"], {"low", "moderate", "elevated", "high"})

    def test_project_report_records_calibration_profile(self) -> None:
        calibration = {
            "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
            "profile_id": "project-test-profile",
            "review_policy": {
                "file": {"low_max": 0.28, "moderate_max": 0.48, "elevated_max": 0.68, "review_trigger": 0.50},
                "project": {"low_max": 0.28, "moderate_max": 0.48, "elevated_max": 0.68, "review_trigger": 0.50},
            },
        }
        result = json.loads(engine.codeprobe_analyze_project(json.dumps({
            "project_name": "calibrated-project",
            "files": [{"path": "src/app.py", "content": SAMPLE_CODE}],
            "calibration_profile": calibration,
        })))
        report = result["project_report"]
        self.assertEqual(report["schema_version"], "2.2.0-project")
        self.assertEqual(report["calibration_profile_id"], "project-test-profile")
        self.assertEqual(report["review_trigger_percent"], 50.0)
        self.assertIn("calibration_profile", report)
        self.assertIn("review_policy", report)
        self.assertEqual(report["project"]["calibration_profile_id"], "project-test-profile")

    def test_calibration_corpus_cli_generates_profile_usable_by_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "human").mkdir()
            (root / "ai").mkdir()
            (root / "human" / "student_1.py").write_text(SAMPLE_CODE, encoding="utf-8")
            (root / "ai" / "llm_1.py").write_text(
                SAMPLE_CODE.replace("return left + right", "# Return the computed addition\n    return left + right"),
                encoding="utf-8",
            )
            profile_path = root / "profile.json"
            summary_path = root / "summary.md"
            scores_path = root / "scores.csv"
            rc = calibrate_corpus.main([
                "--corpus-root", str(root),
                "--course", "unit-course",
                "--assignment", "unit-assignment",
                "--json-out", str(profile_path),
                "--markdown-out", str(summary_path),
                "--scores-out", str(scores_path),
            ])
            self.assertEqual(rc, 0)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["schema_version"], engine.CALIBRATION_PROFILE_SCHEMA)
            self.assertIn("review_policy", profile)
            self.assertTrue(summary_path.exists())
            self.assertTrue(scores_path.exists())
            report = json.loads(engine.codeprobe_analyze(json.dumps({
                "filename": "sample.py",
                "code": SAMPLE_CODE,
                "calibration_profile": profile,
            })))["report"]
            self.assertEqual(report["calibration_profile_id"], profile["profile_id"])

    def test_manifest_calibration_cli_generates_sensitivity_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "student.py").write_text(SAMPLE_CODE, encoding="utf-8")
            (root / "llm.py").write_text(
                SAMPLE_CODE.replace("def add", "# Generated helper\ndef add"),
                encoding="utf-8",
            )
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "profile_id": "manifest-unit-profile",
                "label": "Manifest unit profile",
                "course": "unit-course",
                "assignment": "unit-assignment",
                "samples": [
                    {"path": "student.py", "label": "human", "language_hint": "python"},
                    {"path": "llm.py", "label": "ai", "language_hint": "python"},
                ],
            }), encoding="utf-8")
            profile_path = root / "profile_manifest.json"
            summary_path = root / "summary_manifest.md"
            observations_path = root / "observations.csv"
            sensitivity_path = root / "sensitivity.csv"
            rc = calibrate_profile.main([
                "--manifest", str(manifest),
                "--profile-out", str(profile_path),
                "--summary-out", str(summary_path),
                "--csv-out", str(observations_path),
                "--sensitivity-out", str(sensitivity_path),
                "--target-fpr", "10",
            ])
            self.assertEqual(rc, 0)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["profile_id"], "manifest-unit-profile")
            self.assertIn("review_policy", profile)
            self.assertIn("Suggested local review trigger", summary_path.read_text(encoding="utf-8"))
            self.assertTrue(observations_path.exists())
            self.assertTrue(sensitivity_path.exists())


if __name__ == "__main__":
    unittest.main()
