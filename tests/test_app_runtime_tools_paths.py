from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RuntimeUiCliNamingTests(unittest.TestCase):
    def test_phase12_runtime_ui_and_tools_paths_exist(self) -> None:
        for relative in [
            "app/index.html",
            "app/project.html",
            "app/codeprobe-ui.js",
            "app/project-ui.js",
            "app/pyodide-loader.js",
            "app/runtime-config.json",
            "app/resource-integrity.json",
            "src/codeprobe_runtime.py",
            "tools/analyze_project.py",
            "tools/check_release.py",
            "tools/build_release.py",
        ]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_phase12_retired_runtime_paths_are_absent(self) -> None:
        for relative in [
            "src/index.html",
            "src/project_index.html",
            "src/index.js",
            "src/project_index.js",
            "src/engine.py",
            "src/release_check.py",
            "src/analyze_project.py",
            "src/runtime_config.json",
            "src/RESOURCE_INTEGRITY_MANIFEST.json",
        ]:
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_resource_integrity_mentions_runtime_path(self) -> None:
        manifest = json.loads((ROOT / "app" / "resource-integrity.json").read_text(encoding="utf-8"))
        paths = {item["path"] for item in manifest["assets"]}
        self.assertIn("../src/codeprobe_runtime.py", paths)


if __name__ == "__main__":
    unittest.main()
