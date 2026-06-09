from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import final_audit  # noqa: E402

class FinalPackageAuditTests(unittest.TestCase):
    def test_final_audit_passes(self) -> None:
        report = final_audit.build_audit(ROOT)
        self.assertEqual(report["status"], "pass", report)
        self.assertFalse(report["missing_required_paths"])
        self.assertFalse(report["forbidden_paths_present"])

    def test_final_audit_files_are_written(self) -> None:
        report = final_audit.write_reports(ROOT)
        self.assertEqual(report["status"], "pass")
        payload = json.loads((ROOT / "release" / "final-audit-report.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "codeprobe-final-package-audit/v1")
        self.assertTrue((ROOT / "release" / "final-audit-summary.md").is_file())

    def test_root_legacy_release_files_are_absent(self) -> None:
        self.assertFalse((ROOT / "RELEASE_MANIFEST.json").exists())
        self.assertFalse((ROOT / "release-manifest.json").exists())
        self.assertFalse((ROOT / "file-rename-map.csv").exists())
        self.assertFalse((ROOT / "KIT_INDEX.md").exists())

if __name__ == "__main__":
    unittest.main()
