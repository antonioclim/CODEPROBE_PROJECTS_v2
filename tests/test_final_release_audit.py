from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
SRC = ROOT / "src"
for path in (TOOLS, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import check_file_references  # noqa: E402
import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine.release import MANIFEST_NAME  # noqa: E402


class FinalReleaseAuditTests(unittest.TestCase):
    def test_final_release_files_exist(self) -> None:
        expected = [
            "00-kit-index.md",
            "docs/15-final-release-audit.md",
            "docs/history/13-final-audit.md",
            "release/file-rename-map.csv",
            "release/release-manifest.json",
            "tools/check_file_references.py",
        ]
        for relative in expected:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_current_version_is_stable_release(self) -> None:
        self.assertEqual(engine.APP_VERSION, "2.2.0")
        self.assertEqual(engine.FILE_REPORT_SCHEMA_VERSION, "2.2.0")
        self.assertEqual(engine.PROJECT_REPORT_SCHEMA_VERSION, "2.2.0-project")
        self.assertEqual(MANIFEST_NAME, "release/release-manifest.json")

    def test_reference_checker_includes_legacy_path_audit(self) -> None:
        self.assertEqual(check_file_references.run_checks(ROOT), [])

    def test_file_rename_map_records_phase_13_files(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            rows = {row["current_path"]: row for row in csv.DictReader(handle)}
        self.assertEqual(rows["docs/15-final-release-audit.md"]["action"], "added_phase13")
        self.assertEqual(rows["docs/history/13-final-audit.md"]["phase"], "13")


if __name__ == "__main__":
    unittest.main()
