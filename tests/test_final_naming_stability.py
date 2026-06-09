from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import check_file_references  # noqa: E402
from codeprobe_engine.release import MANIFEST_NAME, iter_release_files  # noqa: E402


class FinalNamingStabilityTests(unittest.TestCase):
    def test_release_manifest_lives_under_release_directory(self) -> None:
        self.assertEqual(MANIFEST_NAME, "release/release-manifest.json")
        self.assertFalse((ROOT / "RELEASE_MANIFEST.json").exists())
        self.assertTrue((ROOT / MANIFEST_NAME).is_file())

    def test_no_retired_runtime_or_ui_paths_exist(self) -> None:
        retired = [
            "src/index.html",
            "src/project_index.html",
            "src/index.js",
            "src/project_index.js",
            "src/engine.py",
            "src/run_local_server.py",
            "src/analyze_project.py",
            "src/runtime_config.json",
            "src/RESOURCE_INTEGRITY_MANIFEST.json",
            "KIT_INDEX.md",
            "release/rename-map.csv",
        ]
        for relative in retired:
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_file_catalogue_and_rename_map_cover_release_files(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            mapped = {row["current_path"] for row in csv.DictReader(handle)}
        release_files = {path.relative_to(ROOT).as_posix() for path in iter_release_files(ROOT)}
        release_files.add(MANIFEST_NAME)
        self.assertTrue(release_files <= mapped)
        catalogue = (ROOT / "docs" / "00-file-catalogue.md").read_text(encoding="utf-8")
        for relative in ["00-kit-index.md", "release/release-manifest.json", "docs/15-final-release-audit.md"]:
            self.assertIn(relative, catalogue)

    def test_reference_audit_has_no_errors(self) -> None:
        self.assertEqual(check_file_references.run_checks(ROOT), [])


if __name__ == "__main__":
    unittest.main()
