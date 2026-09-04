import base64
import hashlib
import json
import re
import sys
import tempfile
import unittest
from html.parser import HTMLParser
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
    "pyodide-provenance.json",
    "../src/codeprobe_runtime.py",
}
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import check_release  # noqa: E402
from codeprobe_engine.release import ReleaseSetError  # noqa: E402


class HtmlAccessibilityInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.by_id: dict[str, tuple[str, dict[str, str | None]]] = {}
        self.labels_for: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        identifier = attributes.get("id")
        if identifier:
            self.by_id[identifier] = (tag, attributes)
        if tag == "label" and attributes.get("for"):
            self.labels_for.add(str(attributes["for"]))


def accessibility_inventory(path: Path) -> HtmlAccessibilityInventory:
    parser = HtmlAccessibilityInventory()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


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


class BrowserAccessibilityContractTests(unittest.TestCase):
    def test_main_tabs_have_complete_aria_and_keyboard_contract(self) -> None:
        inventory = accessibility_inventory(APP / "index.html")
        expected = (
            ("result-tab-summary", "tab-summary", "true", "0"),
            ("result-tab-review", "tab-review", "false", "-1"),
            ("result-tab-metrics", "tab-metrics", "false", "-1"),
            ("result-tab-text", "tab-text", "false", "-1"),
            ("result-tab-json", "tab-json", "false", "-1"),
            ("result-tab-history", "tab-history", "false", "-1"),
        )
        for tab_id, panel_id, selected, tab_index in expected:
            tag, tab = inventory.by_id[tab_id]
            self.assertEqual(tag, "button")
            self.assertEqual(tab.get("role"), "tab")
            self.assertEqual(tab.get("aria-controls"), panel_id)
            self.assertEqual(tab.get("aria-selected"), selected)
            self.assertEqual(tab.get("tabindex"), tab_index)
            panel_tag, panel = inventory.by_id[panel_id]
            self.assertEqual(panel_tag, "section")
            self.assertEqual(panel.get("role"), "tabpanel")
            self.assertEqual(panel.get("aria-labelledby"), tab_id)
            self.assertEqual("hidden" in panel, selected != "true")
        script = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
            self.assertIn(f'event.key === "{key}"', script)
        self.assertIn('button.setAttribute("aria-selected"', script)
        self.assertIn("panel.hidden = !selected", script)
        self.assertIn("button.addEventListener(\"keydown\", handleTabKeydown)", script)

    def test_textareas_and_selects_have_programmatic_names(self) -> None:
        required = {
            "index.html": {
                "editor",
                "languageSelect",
                "profileSelect",
                "configOverride",
                "calibrationProfile",
                "textReport",
                "jsonReport",
            },
            "project.html": {
                "profileSelect",
                "calibrationProfile",
                "textReport",
                "jsonReport",
            },
        }
        for html_name, identifiers in required.items():
            with self.subTest(html=html_name):
                inventory = accessibility_inventory(APP / html_name)
                for identifier in identifiers:
                    tag, attrs = inventory.by_id[identifier]
                    self.assertIn(tag, {"select", "textarea"})
                    labelled = identifier in inventory.labels_for
                    labelled = labelled or bool(attrs.get("aria-label"))
                    references = str(attrs.get("aria-labelledby") or "").split()
                    labelled = labelled or bool(references and all(item in inventory.by_id for item in references))
                    self.assertTrue(labelled, f"{html_name}: {identifier} lacks an accessible name")

    def test_live_regions_progressbars_and_skip_links_are_explicit(self) -> None:
        for html_name, status_id, progress_ids in (
            ("index.html", "statusText", ("scoreProgress", "lowLevelQualityProgress")),
            ("project.html", "status", ("projectScoreProgress",)),
        ):
            with self.subTest(html=html_name):
                inventory = accessibility_inventory(APP / html_name)
                _, status = inventory.by_id[status_id]
                self.assertEqual(status.get("role"), "status")
                self.assertEqual(status.get("aria-live"), "polite")
                self.assertEqual(status.get("aria-atomic"), "true")
                skip_links = [attrs for tag, attrs in inventory.elements if tag == "a" and attrs.get("class") == "skip-link"]
                self.assertEqual(len(skip_links), 1)
                self.assertEqual(skip_links[0].get("href"), "#mainContent")
                self.assertIn("mainContent", inventory.by_id)
                for progress_id in progress_ids:
                    _, progress = inventory.by_id[progress_id]
                    self.assertEqual(progress.get("role"), "progressbar")
                    self.assertEqual(progress.get("aria-valuemin"), "0")
                    self.assertEqual(progress.get("aria-valuemax"), "100")
                    self.assertTrue(progress.get("aria-valuetext"))
                    self.assertIn(str(progress.get("aria-labelledby")), inventory.by_id)

    def test_focus_visible_rules_replace_outline_suppression(self) -> None:
        for css_name in ("codeprobe.css", "project.css"):
            css = (APP / css_name).read_text(encoding="utf-8")
            self.assertIn(":focus-visible", css)
            self.assertIn("outline: 3px solid", css)
            self.assertNotRegex(css, r"outline\s*:\s*(?:0|none)\s*;")

    def test_required_ci_includes_real_accessibility_and_functional_browser_gates(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("browser_accessibility:", workflow)
        self.assertIn("name: Browser accessibility (Chromium)", workflow)
        self.assertIn('CODEPROBE_REQUIRE_HTTP_NAVIGATION: "1"', workflow)
        self.assertIn("run: node tools/check_browser_accessibility.js", workflow)
        self.assertIn("browser_functional:", workflow)
        self.assertIn("name: Browser functional integrity (Chromium)", workflow)
        self.assertIn("run: node tools/check_browser_functional.js", workflow)
        self.assertIn("tools/prepare_pyodide_fixture.py", workflow)
        self.assertIn("- browser_accessibility", workflow)
        self.assertIn("- browser_functional", workflow)
        self.assertIn("BROWSER_ACCESSIBILITY_RESULT", workflow)
        self.assertIn("BROWSER_FUNCTIONAL_RESULT", workflow)
        self.assertIn('test "$BROWSER_ACCESSIBILITY_RESULT" = "success"', workflow)
        self.assertIn('test "$BROWSER_FUNCTIONAL_RESULT" = "success"', workflow)
        harness = (ROOT / "tools" / "check_browser_functional.js").read_text(encoding="utf-8")
        self.assertIn("testTamperedCoreFailsClosedAndReloadRetries", harness)
        self.assertIn("testTamperedEngineFailsClosed", harness)
        self.assertIn("assertSingleVerifiedRequests", harness)

    def test_browser_inputs_share_decoding_and_unicode_path_boundaries(self) -> None:
        loader = (APP / "pyodide-loader.js").read_text(encoding="utf-8")
        main_script = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        project_script = (APP / "project-ui.js").read_text(encoding="utf-8")
        self.assertIn("function decodeSourceBytes", loader)
        self.assertIn("function decodeLatin1", loader)
        self.assertIn('new TextDecoder("utf-8", { fatal: true })', loader)
        self.assertIn('rawPart.normalize("NFC")', loader)
        for script in (main_script, project_script):
            self.assertIn("CodeProbeRuntime.decodeSourceBytes", script)
            self.assertIn("CodeProbeRuntime.normaliseProjectPath", script)
            self.assertNotIn('new TextDecoder("utf-8", { fatal: false })', script)

    def test_manual_engine_override_is_explicitly_unverified(self) -> None:
        html = (APP / "index.html").read_text(encoding="utf-8")
        script = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        self.assertIn("Load unverified engine file", html)
        self.assertIn("window.confirm", script)
        self.assertIn("manual-unverified", script)
        self.assertIn("bypasses the packaged Python-engine integrity check", script)

    def test_progress_updates_keep_visual_and_accessibility_state_together(self) -> None:
        main_script = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        project_script = (APP / "project-ui.js").read_text(encoding="utf-8")
        self.assertIn("function setProgressBar(container, fill, value", main_script)
        self.assertIn('container.setAttribute("aria-valuenow"', main_script)
        self.assertIn('container.removeAttribute("aria-valuenow")', main_script)
        self.assertIn("function setProgressBar(value", project_script)
        self.assertIn('els.scoreProgress.setAttribute("aria-valuenow"', project_script)
        self.assertIn('els.scoreProgress.removeAttribute("aria-valuenow")', project_script)


if __name__ == "__main__":
    unittest.main()
