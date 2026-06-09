from __future__ import annotations

import base64
import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
SRC = ROOT / "src"
APP = ROOT / "app"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import codeprobe_runtime as engine  # noqa: E402


class PhaseNineGithubZipRootTests(unittest.TestCase):
    def _project_zip(self, members: dict[str, str | bytes]) -> str:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, payload in members.items():
                archive.writestr(path, payload)
        return base64.b64encode(buffer.getvalue()).decode("ascii")

    def test_github_export_root_is_stripped_before_codeprobeignore(self) -> None:
        payload = {
            "project_name": "github-export",
            "zip_base64": self._project_zip({
                "student-project-main/.codeprobeignore": "generated/\n/docs/\n",
                "student-project-main/src/main.py": "def main():\n    return 0\n\nprint(main())\n",
                "student-project-main/generated/auto.py": "def auto():\n    return 1\n",
                "student-project-main/docs/notes.md": "# Notes\n",
            }),
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertTrue(report["input_packaging"]["common_root_stripped"])
        self.assertEqual(report["input_packaging"]["common_root_detected"], "student-project-main")
        self.assertEqual({item["path"] for item in report["included_files"]}, {"src/main.py"})
        excluded = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(excluded.get("generated/auto.py"), "ignored_by_codeprobeignore")
        self.assertIn("docs/notes.md", excluded)
        self.assertTrue(any(zone.get("scope") == "input_packaging" for zone in report["risk_zones"]))

    def test_source_directory_is_not_mistaken_for_hosted_export_root(self) -> None:
        payload = {
            "project_name": "src-only",
            "files": [
                {"path": "src/main.py", "content": "def main():\n    return 0\n"},
                {"path": "src/util.py", "content": "def util():\n    return 1\n"},
            ],
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertFalse(report["input_packaging"]["common_root_stripped"])
        self.assertEqual({item["path"] for item in report["included_files"]}, {"src/main.py", "src/util.py"})


if __name__ == "__main__":
    unittest.main()
