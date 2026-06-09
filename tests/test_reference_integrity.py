from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
TOOLS = ROOT / "tools"
SRC = ROOT / "src"
APP = ROOT / "app"
for path in (TOOLS, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import check_file_references  # noqa: E402
from codeprobe_engine.release import iter_release_files  # noqa: E402


class ReferenceIntegrityTests(unittest.TestCase):
    def test_reference_checker_passes(self) -> None:
        self.assertEqual(check_file_references.run_checks(ROOT), [])

    def test_rename_map_covers_current_release_files(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            mapped = {row["current_path"] for row in csv.DictReader(handle)}
        current = {path.relative_to(ROOT).as_posix() for path in iter_release_files(ROOT)}
        current.add("release/release-manifest.json")
        self.assertTrue(current <= mapped)

    def test_key_phase10_documents_are_listed(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            mapped = {row["current_path"]: row for row in csv.DictReader(handle)}
        for relative in [
            "docs/00-file-catalogue.md",
            "docs/01-naming-policy.md",
            "docs/history/10-naming-governance.md",
            "tools/check_file_references.py",
        ]:
            self.assertIn(relative, mapped)
            self.assertTrue(mapped[relative]["proposed_final_path"])


if __name__ == "__main__":
    unittest.main()
