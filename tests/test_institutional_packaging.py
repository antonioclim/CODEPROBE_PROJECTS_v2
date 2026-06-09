import json
import sys
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
import audit_institutional_pack
from codeprobe_engine import api as cp_api


class PhaseSevenInstitutionalPackagingTests(unittest.TestCase):
    def test_institutional_audit_passes(self):
        self.assertFalse(audit_institutional_pack.run_audit(ROOT))

    def test_final_resource_documents_exist(self):
        required = [
            "00-kit-index.md",
            "educator/01-student-quick-start.md",
            "educator/04-instructor-checklist.md",
            "educator/08-deployment-one-page.md",
            "educator/05-review-protocol.md",
            "educator/06-evidence-rubric.md",
            "docs/13-signed-release-workflow.md",
            "docs/12-release-hash-sheet.md",
            "docs/history/08-dynamic-ui-and-review.md",
            "docs/07-ui-extension-guide.md",
        ]
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_file_report_contains_reading_aliases(self):
        result = json.loads(engine.codeprobe_analyze(json.dumps({
            "code": "def add(left, right):\n    return left + right\n",
            "filename": "student.py",
            "language_hint": "python",
        })))
        report = result["report"]
        self.assertEqual(report["schema_version"], "2.2.0")
        self.assertEqual(report["reading"], report["verdict"])
        self.assertEqual(report["reading_class"], report["verdict_class"])

    def test_project_report_contains_reading_aliases(self):
        result = cp_api.analyse_project({
            "project_name": "phase8-project",
            "files": [
                {"path": "src/main.py", "content": "def main():\n    return 0\n", "size_bytes": 24},
                {"path": "README.md", "content": "# notes\n", "size_bytes": 8},
            ],
        })
        report = result["project_report"]
        self.assertEqual(report["schema_version"], "2.2.0-project")
        self.assertEqual(report["reading"], report["verdict"])
        self.assertEqual(report["reading_class"], report["verdict_class"])
        self.assertEqual(report["included_files"][0]["reading"], report["included_files"][0]["verdict"])


if __name__ == "__main__":
    unittest.main()
