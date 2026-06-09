import base64
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
APP = ROOT / "app"


def sri_for(path: Path) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(path.read_bytes()).digest()).decode("ascii")


class BrowserSecurityTests(unittest.TestCase):
    def test_html_has_no_inline_code_or_unsafe_inline(self):
        for name in ["index.html", "project.html"]:
            html = (APP / name).read_text(encoding="utf-8")
            self.assertNotIn("unsafe-inline", html)
            self.assertNotRegex(html, r"<style\b")
            self.assertNotRegex(html, r"\sstyle\s*=")
            for match in re.finditer(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", html, re.S | re.I):
                attrs = match.group("attrs") or ""
                body = match.group("body").strip()
                self.assertIn("src=", attrs)
                self.assertEqual(body, "")

    def test_local_browser_resources_have_matching_sri(self):
        for html_name in ["index.html", "project.html"]:
            html = (APP / html_name).read_text(encoding="utf-8")
            for tag in re.finditer(r"<(?:script|link)\b(?P<attrs>[^>]*)>", html, re.I):
                attrs = tag.group("attrs") or ""
                target_match = re.search(r"\b(?:src|href)\s*=\s*[\"'](?P<target>[^\"']+)[\"']", attrs, re.I)
                if not target_match:
                    continue
                target = target_match.group("target")
                if target.startswith(("http://", "https://", "//")):
                    continue
                if not target.endswith((".js", ".css")):
                    continue
                integrity_match = re.search(r"\bintegrity\s*=\s*[\"'](?P<integrity>[^\"']+)[\"']", attrs, re.I)
                self.assertIsNotNone(integrity_match, f"{html_name}: {target} lacks SRI")
                self.assertEqual(integrity_match.group("integrity"), sri_for(APP / target))

    def test_resource_integrity_manifest_matches_files(self):
        manifest = json.loads((APP / "resource-integrity.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("schema"), "codeprobe-browser-resource-integrity/v1")
        seen = {item["path"] for item in manifest["assets"]}
        self.assertIn("codeprobe-ui.js", seen)
        self.assertIn("project-ui.js", seen)
        self.assertIn("pyodide-loader.js", seen)
        for item in manifest["assets"]:
            path = (APP / item["path"]).resolve()
            self.assertTrue(path.exists(), item["path"])
            self.assertEqual(item["sha256_hex"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(item["sri_sha256"], sri_for(path))

    def test_runtime_config_documents_cdn_and_local_modes(self):
        config = json.loads((APP / "runtime-config.json").read_text(encoding="utf-8"))
        self.assertEqual(config.get("schema"), "codeprobe-runtime-config/v1")
        pyodide = config["pyodide"]
        self.assertIn(pyodide["mode"], {"cdn", "local"})
        self.assertIn("loader_url", pyodide)
        self.assertIn("local_loader_url", pyodide)
        loader = (APP / "pyodide-loader.js").read_text(encoding="utf-8")
        self.assertIn("require_integrity", loader)
        self.assertIn("expected_loader_sha256", loader)


if __name__ == "__main__":
    unittest.main()
