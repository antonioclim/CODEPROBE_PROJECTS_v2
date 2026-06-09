import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
SRC = ROOT / "src"
APP = ROOT / "app"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import codeprobe_runtime as engine
from codeprobe_engine import api as cp_api
from codeprobe_engine.metrics import metric_inventory
from codeprobe_engine.release import build_release_manifest, verify_manifest, write_manifest


class ReleaseMetadataTests(unittest.TestCase):
    def test_file_report_contains_release_metadata(self):
        result = json.loads(engine.codeprobe_analyze(json.dumps({
            "code": "def add(left: int, right: int) -> int:\n    return left + right\n\nprint(add(1, 2))\n",
            "filename": "calculator.py",
            "engine_fingerprint": "0" * 64,
        })))
        report = result["report"]
        self.assertEqual(report["app_version"], "2.2.0")
        self.assertEqual(report["schema_version"], engine.FILE_REPORT_SCHEMA_VERSION)
        self.assertIn("metric_config_digest", report)
        self.assertIn("metric_role_summary", report)
        self.assertIn("tool_metadata", report)
        self.assertEqual(report["engine_fingerprint"]["value"], "0" * 64)
        self.assertFalse(engine.validate_report_shape(report, "file"))

    def test_project_report_contains_release_metadata(self):
        result = cp_api.analyse_project({
            "project_name": "phase5",
            "engine_fingerprint": "1" * 64,
            "files": [
                {"path": "src/main.py", "content": "def main():\n    return 0\n\nprint(main())\n", "size_bytes": 40},
                {"path": "README.md", "content": "# notes\n", "size_bytes": 8},
            ],
        })
        report = result["project_report"]
        self.assertEqual(report["schema_version"], engine.PROJECT_REPORT_SCHEMA_VERSION)
        self.assertEqual(report["included_file_count"], 1)
        self.assertIn("tool_metadata", report)
        self.assertEqual(report["engine_fingerprint"]["value"], "1" * 64)
        self.assertFalse(engine.validate_report_shape(report, "project"))

    def test_metric_inventory_and_role_summary_are_consistent(self):
        inventory = metric_inventory()
        summary = engine.metric_role_summary()
        self.assertEqual(len(inventory), summary["total_metrics"])
        self.assertGreater(summary["authorship_signal_metrics"], 0)
        self.assertGreater(summary["quality_only_metrics"], 0)
        self.assertGreater(summary["context_only_metrics"], 0)

    def test_release_manifest_can_be_built_and_verified(self):
        manifest = build_release_manifest(ROOT, app_version=engine.APP_VERSION)
        self.assertEqual(manifest["app_version"], "2.2.0")
        self.assertGreater(manifest["file_count"], 10)
        with tempfile.TemporaryDirectory() as tmp:
            # verification is meaningful only against the actual tree, so write
            # the manifest temporarily into the project root and then remove it.
            manifest_path = ROOT / "release/release-manifest.json"
            old = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else None
            try:
                write_manifest(ROOT, engine.APP_VERSION)
                self.assertFalse(verify_manifest(ROOT))
            finally:
                if old is None:
                    manifest_path.unlink(missing_ok=True)
                else:
                    manifest_path.write_text(old, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
