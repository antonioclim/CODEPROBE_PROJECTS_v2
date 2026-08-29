from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import check_naming  # noqa: E402


class FinalNamingReleaseTests(unittest.TestCase):
    def test_naming_audit_passes(self) -> None:
        self.assertEqual(check_naming.run_checks(ROOT), [])

    def test_vcs_metadata_is_ignored_without_hiding_unknown_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            for name in check_naming.STANDARD_ROOT_FILES:
                (fixture_root / name).write_text("", encoding="utf-8")
            for name in check_naming.EXPECTED_DIRS:
                (fixture_root / name).mkdir()
            (fixture_root / ".git").mkdir()
            (fixture_root / ".git" / "Bad Name.py").write_text("# ignored VCS metadata\n", encoding="utf-8")
            self.assertEqual(check_naming.run_checks(fixture_root), [])
            (fixture_root / ".unexpected-hidden").mkdir()
            self.assertEqual(
                check_naming.check_root_layout(fixture_root),
                ["unexpected top-level directory: .unexpected-hidden"],
            )

    def test_phase13_documents_exist(self) -> None:
        for relative in [
            "docs/15-final-release-audit.md",
            "docs/history/13-final-audit.md",
            "tools/check_naming.py",
        ]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_rename_map_records_phase13_paths(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            rows = {row["current_path"]: row for row in csv.DictReader(handle)}
        self.assertEqual(rows["00-kit-index.md"]["previous_path"], "KIT_INDEX.md")
        self.assertEqual(rows["release/release-manifest.json"]["previous_path"], "RELEASE_MANIFEST.json")
        self.assertEqual(rows["release/file-rename-map.csv"]["previous_path"], "release/rename-map.csv")
        self.assertEqual(rows["tools/check_file_references.py"]["previous_path"], "tools/check_references.py")
        self.assertEqual(rows["docs/15-final-release-audit.md"]["action"], "added_phase13")


if __name__ == "__main__":
    unittest.main()
