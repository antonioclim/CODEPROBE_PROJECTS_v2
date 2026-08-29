import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
SRC = ROOT / "src"
APP = ROOT / "app"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import codeprobe_runtime as engine
from codeprobe_engine import api as cp_api
from codeprobe_engine import release
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
            fixture_root = Path(tmp) / "kit"
            shutil.copytree(
                ROOT,
                fixture_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"),
            )
            write_manifest(fixture_root, engine.APP_VERSION)
            self.assertFalse(verify_manifest(fixture_root))

    def test_atomic_write_cleans_up_after_sync_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            target = directory / "evidence.json"
            target.write_bytes(b"original\n")
            before = {path.name for path in directory.iterdir()}
            with mock.patch.object(release.os, "fsync", side_effect=OSError("forced sync failure")):
                with self.assertRaisesRegex(OSError, "forced sync failure"):
                    release.atomic_write_bytes(target, b"replacement\n")
            self.assertEqual(target.read_bytes(), b"original\n")
            self.assertEqual({path.name for path in directory.iterdir()}, before)


if __name__ == "__main__":
    unittest.main()
