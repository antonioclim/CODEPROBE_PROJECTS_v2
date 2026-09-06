import json
import re
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
from codeprobe_engine import api as cp_api


class PhaseEightDynamicUiAndReviewGuidanceTests(unittest.TestCase):
    def test_file_report_contains_manual_review_guidance(self):
        code = """
def parse_items(items):
    # process items
    # validate input
    # return result
    result = []
    for item in items:
        if item is None:
            continue
        result.append(str(item).strip())
    return result
""".strip() + "\n"
        payload = {"code": code, "filename": "student.py", "language_hint": "python"}
        result = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
        report = result["report"]
        self.assertEqual(report["schema_version"], "2.2.0")
        self.assertIn("manual_review_guidance", report)
        self.assertIn("risk_zones", report)
        self.assertIn("manual_review_recommendations", report)
        guidance = report["manual_review_guidance"]
        self.assertIn("recommended_manual_steps", guidance)
        self.assertIn("evidence_to_request", guidance)
        self.assertIn("Manual review guidance", result["text"])

    def test_project_report_contains_project_review_guidance(self):
        result = cp_api.analyse_project({
            "project_name": "phase8-project",
            "files": [
                {"path": "repo-main/src/main.py", "content": "def main():\n    return 0\n", "size_bytes": 25},
                {"path": "repo-main/README.md", "content": "# notes\n", "size_bytes": 8},
            ],
        })
        report = result["project_report"]
        self.assertEqual(report["schema_version"], "2.2.0-project")
        self.assertIn("manual_review_guidance", report)
        self.assertIn("risk_zones", report)
        guidance = report["manual_review_guidance"]
        self.assertEqual(guidance["scope"], "project")
        self.assertTrue(any(zone.get("scope") in {"calibration", "sample_size", "project_filtering"} for zone in guidance["risk_zones"]))
        self.assertIn("Manual review guidance", result["text"])

    def test_main_interface_has_dynamic_review_tab_and_global_drop(self):
        html = (APP / "index.html").read_text(encoding="utf-8")
        script = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        self.assertIn('data-tab="tab-review"', html)
        self.assertIn('id="manualReviewPanel"', html)
        self.assertIn('id="globalDropOverlay"', html)
        self.assertIn("renderManualReview", script)
        self.assertIn("collectDroppedFiles", script)
        self.assertIn("CodeProbeRuntime.collectDroppedFiles", script)
        self.assertIn("webkitGetAsEntry", (ROOT / "app" / "pyodide-loader.js").read_text(encoding="utf-8"))
        self.assertRegex(script, r"document\.addEventListener\(\"drop\"")

    def test_project_interface_accepts_drop_and_renders_guidance(self):
        html = (APP / "project.html").read_text(encoding="utf-8")
        script = (APP / "project-ui.js").read_text(encoding="utf-8")
        self.assertIn('id="reviewPanel"', html)
        self.assertIn('id="dropOverlay"', html)
        self.assertIn("renderReview", script)
        self.assertIn("handleDroppedProject", script)
        self.assertIn("CodeProbeRuntime.collectDroppedFiles", script)
        self.assertIn("webkitGetAsEntry", (ROOT / "app" / "pyodide-loader.js").read_text(encoding="utf-8"))


class BrowserInputBudgetTests(unittest.TestCase):
    def test_main_zip_limit_precedes_array_buffer(self):
        script = (ROOT / "app" / "codeprobe-ui.js").read_text(encoding="utf-8")
        start = script.index("async function handleProjectZip")
        section = script[start:script.index("function projectTextCandidate", start)]
        self.assertLess(section.index("MAX_BROWSER_PROJECT_ZIP_BYTES"), section.index("file.arrayBuffer"))

    def test_project_zip_limit_precedes_array_buffer(self):
        script = (ROOT / "app" / "project-ui.js").read_text(encoding="utf-8")
        start = script.index("async function loadZip")
        section = script[start:script.index("async function loadFolder", start)]
        self.assertLess(section.index("MAX_BROWSER_PROJECT_ZIP_BYTES"), section.index("file.arrayBuffer"))

    def test_browser_folder_budget_is_present_in_both_interfaces(self):
        for name in ("codeprobe-ui.js", "project-ui.js"):
            self.assertIn("MAX_BROWSER_PROJECT_TOTAL_BYTES", (ROOT / "app" / name).read_text(encoding="utf-8"))

    def test_browser_payload_forwards_engine_limits(self):
        for name in ("codeprobe-ui.js", "project-ui.js"):
            script = (ROOT / "app" / name).read_text(encoding="utf-8")
            for token in ("max_zip_bytes", "max_zip_entries", "max_file_bytes", "max_total_bytes"):
                self.assertIn(token, script)


if __name__ == "__main__":
    unittest.main()
