import base64
import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
APP = ROOT / "app"
EXPECTED_RESOURCE_ASSETS = {
    "codeprobe.css",
    "project.css",
    "pyodide-loader.js",
    "codeprobe-ui.js",
    "project-ui.js",
    "runtime-config.json",
    "../src/codeprobe_runtime.py",
}
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import check_release  # noqa: E402
from codeprobe_engine.release import ReleaseSetError  # noqa: E402


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

    def test_canonical_resource_check_rejects_size_and_path_forgery(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp).resolve() / "kit"
            fixture_app = fixture_root / "app"
            fixture_src = fixture_root / "src"
            fixture_app.mkdir(parents=True)
            fixture_src.mkdir()
            assets = []
            self.assertEqual(check_release.REQUIRED_RESOURCE_ASSETS, EXPECTED_RESOURCE_ASSETS)
            for index, relative in enumerate(sorted(EXPECTED_RESOURCE_ASSETS)):
                path = (fixture_app / relative).resolve()
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"asset-{index}\n".encode("ascii")
                path.write_bytes(content)
                digest = hashlib.sha256(content).digest()
                assets.append({
                    "path": relative,
                    "size_bytes": len(content),
                    "sha256_hex": hashlib.sha256(content).hexdigest(),
                    "sri_sha256": "sha256-" + base64.b64encode(digest).decode("ascii"),
                })
            manifest = {
                "schema": check_release.RESOURCE_INTEGRITY_SCHEMA,
                "note": "fixture",
                "assets": assets,
            }
            manifest_path = fixture_app / "resource-integrity.json"

            with mock.patch.object(check_release, "ROOT", fixture_root):
                with mock.patch.object(check_release, "APP", fixture_app):
                    with mock.patch.object(check_release, "SRC", fixture_src):
                        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                        self.assertTrue(check_release.check_resource_integrity().ok)

                        assets[0]["size_bytes"] += 1
                        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                        size_result = check_release.check_resource_integrity()
                        self.assertFalse(size_result.ok)
                        self.assertIn("size mismatch", size_result.detail)

                        assets[0]["size_bytes"] -= 1
                        assets[0]["path"] = "../../outside.js"
                        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                        path_result = check_release.check_resource_integrity()
                        self.assertFalse(path_result.ok)
                        self.assertIn("unapproved path", path_result.detail)

                        manifest_path.write_text(
                            '{"schema":"one","schema":"two","note":"fixture","assets":[]}',
                            encoding="utf-8",
                        )
                        duplicate_result = check_release.check_resource_integrity()
                        self.assertFalse(duplicate_result.ok)
                        self.assertIn("duplicate JSON key", duplicate_result.detail)

    def test_browser_script_inventory_rejects_out_of_app_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / "kit"
            fixture_app = fixture_root / "app"
            fixture_app.mkdir(parents=True)
            (fixture_root / "outside.js").write_text("const value = 1;\n", encoding="utf-8")
            for name in ("index.html", "project.html"):
                (fixture_app / name).write_text(
                    '<script src="../outside.js"></script>\n',
                    encoding="utf-8",
                )
            with mock.patch.object(check_release, "APP", fixture_app):
                with self.assertRaisesRegex(ReleaseSetError, "outside app"):
                    check_release.browser_script_files()

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
