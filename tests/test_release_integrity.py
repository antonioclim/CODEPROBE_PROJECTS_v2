import tempfile
import unittest
import zipfile
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
APP = ROOT / "app"
for pth in (SRC, TOOLS):
    if str(pth) not in sys.path:
        sys.path.insert(0, str(pth))

from codeprobe_engine.release import build_release_manifest, zip_summary
import compare_releases as release_compare


class ReleaseIntegrityTests(unittest.TestCase):
    def _zip_with(self, path: Path, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)

    def test_source_manifest_records_total_source_size(self):
        manifest = build_release_manifest(ROOT, app_version="test")
        self.assertIn("total_source_size_bytes", manifest)
        self.assertGreater(manifest["total_source_size_bytes"], 0)
        self.assertEqual(manifest["total_source_size_bytes"], sum(item["size_bytes"] for item in manifest["files"]))

    def test_zip_summary_reports_container_and_member_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.zip"
            self._zip_with(path, {"root/a.txt": b"alpha", "root/b.txt": b"beta" * 20})
            summary = zip_summary(path)
            self.assertEqual(summary["file_count"], 2)
            self.assertEqual(summary["total_uncompressed_member_bytes"], 85)
            self.assertEqual(summary["zip_container_overhead_bytes"], summary["zip_size_bytes"] - summary["total_compressed_member_bytes"])
            self.assertEqual(len(summary["zip_sha256"]), 64)

    def test_release_comparison_normalises_top_level_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_zip = Path(tmp) / "old.zip"
            new_zip = Path(tmp) / "new.zip"
            self._zip_with(old_zip, {"oldroot/src/main.py": b"print(1)\n"})
            self._zip_with(new_zip, {"newroot/src/main.py": b"print(1)\n", "newroot/docs/new.md": b"new\n"})
            comparison = release_compare.compare_zip_packages(old_zip, new_zip)
            self.assertIn("docs/new.md", comparison["added_paths"])
            self.assertEqual(comparison["removed_paths"], [])
            self.assertEqual(comparison["deltas"]["file_count"], 1)


if __name__ == "__main__":
    unittest.main()
