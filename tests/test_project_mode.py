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

import codeprobe_runtime as engine  # noqa: E402


class PhaseThreeProjectModeTests(unittest.TestCase):
    def test_codeprobeignore_excludes_generated_and_documentation_files(self) -> None:
        payload = {
            "project_name": "student-project",
            "files": [
                {"path": ".codeprobeignore", "content": "generated/\n*.min.js\n"},
                {"path": "src/main.py", "content": "def add(left, right):\n    return left + right\n\nprint(add(1, 2))\n"},
                {"path": "generated/client.py", "content": "def generated():\n    return 42\n"},
                {"path": "web/app.min.js", "content": "function x(){return 1}\n"},
                {"path": "docs/README.md", "content": "# Notes\n\nDocumentation must not enter the aggregate.\n"},
            ],
            "profile": "default",
        }
        result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
        report = result["project_report"]
        included = {item["path"] for item in report["files"]}
        self.assertEqual(included, {"src/main.py"})
        excluded = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertIn("generated/client.py", excluded)
        self.assertIn("web/app.min.js", excluded)
        self.assertIn("docs/README.md", excluded)
        self.assertEqual(report["report_kind"], "project")
        self.assertEqual(report["schema_version"], "2.2.0-project")

    def test_zip_project_payload_is_supported_and_rejects_unsafe_paths(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("src/app.py", "def main():\n    return 0\n\nmain()\n")
            archive.writestr("../escape.py", "print('bad')\n")
            archive.writestr("assets/logo.png", b"\x00\x01\x02")
        payload = {
            "project_name": "zip-project",
            "zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii"),
            "profile": "default",
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/app.py"})
        reasons = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertIn("../escape.py", reasons)
        self.assertIn("unsafe", reasons["../escape.py"])
        self.assertIn("assets/logo.png", reasons)

    def test_project_score_uses_sloc_weighting_and_cap(self) -> None:
        payload = {
            "project_name": "weighted",
            "files": [
                {"path": "a.py", "content": "# comment\ndef a():\n    return 1\n\n"},
                {"path": "b.js", "content": "function b() {\n  return 2;\n}\n"},
            ],
            "profile": "default",
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual(report["included_file_count"], 2)
        self.assertIn("aggregation", report)
        self.assertEqual(report["aggregation"]["per_file_sloc_cap"], engine.PROJECT_WEIGHT_CAP_SLOC)
        self.assertIn(report["verdict_class"], {"low", "moderate", "elevated", "high", "insufficient"})

    def test_markdown_is_excluded_from_project_aggregate_by_default(self) -> None:
        payload = {
            "project_name": "docs-only",
            "files": [
                {"path": "README.md", "content": "# Project\n\nThis is a document.\n"},
            ],
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual(report["included_file_count"], 0)
        self.assertFalse(report["overall_applicable"])
        self.assertEqual(report["verdict_class"], "insufficient")

    def test_negated_codeprobeignore_rule_can_reinclude_authored_source(self) -> None:
        payload = {
            "project_name": "negation",
            "files": [
                {"path": ".codeprobeignore", "content": "src/generated/\n!src/generated/handwritten.py\n"},
                {"path": "src/generated/client.py", "content": "def generated():\n    return 1\n"},
                {"path": "src/generated/handwritten.py", "content": "def handwritten():\n    return 2\n\nprint(handwritten())\n"},
            ],
            "profile": "default",
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/generated/handwritten.py"})
        excluded = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(excluded.get("src/generated/client.py"), "ignored_by_codeprobeignore")

    def test_unsafe_embedded_ignore_file_is_not_loaded(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../.codeprobeignore", "src/\n")
            archive.writestr("src/app.py", "def main():\n    return 0\n\nmain()\n")
        payload = {
            "project_name": "unsafe-ignore",
            "zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii"),
            "profile": "default",
        }
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/app.py"})
        reasons = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(reasons.get("../.codeprobeignore"), "unsafe_path")

    def test_project_text_report_lists_included_and_excluded_files(self) -> None:
        payload = {
            "project_name": "text-report",
            "files": [
                {"path": "src/app.py", "content": "def main():\n    return 0\n\nmain()\n"},
                {"path": "README.md", "content": "# Documentation\n"},
            ],
        }
        result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
        text = result["text"]
        self.assertIn("Analysed files:", text)
        self.assertIn("src/app.py", text)
        self.assertIn("Excluded files:", text)
        self.assertIn("README.md", text)


if __name__ == "__main__":
    unittest.main()
