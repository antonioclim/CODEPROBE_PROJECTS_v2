from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import unittest
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
SRC = ROOT / "src"
TOOLS = ROOT / "tools"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


engine = load_module("codeprobe_runtime_phase4f1_test", SRC / "codeprobe_runtime.py")
fixture_tool = load_module(
    "prepare_pyodide_fixture_phase4f1_test",
    TOOLS / "prepare_pyodide_fixture.py",
)


class RuntimeByteIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.loader = (APP / "pyodide-loader.js").read_text(encoding="utf-8")
        cls.main_ui = (APP / "codeprobe-ui.js").read_text(encoding="utf-8")
        cls.project_ui = (APP / "project-ui.js").read_text(encoding="utf-8")
        cls.integrity = json.loads(
            (APP / "resource-integrity.json").read_text(encoding="utf-8")
        )

    def test_verified_buffers_are_bound_to_pyodide_inputs(self) -> None:
        for fragment in (
            "lockFileURL: lockURL",
            "stdLibURL: stdlibURL",
            'appendVerifiedClassicScript(verified.get("pyodide.asm.js")',
            "new Response(",
            'verified.get("pyodide.asm.wasm")',
            "Pyodide attempted to re-fetch verified startup artefact",
            "Verified Pyodide WASM was expected exactly once",
            "verified-and-consumed",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.loader)

    def test_engine_is_verified_before_import_on_both_pages(self) -> None:
        for name, source in (("main", self.main_ui), ("project", self.project_ui)):
            with self.subTest(interface=name):
                self.assertIn("CodeProbeRuntime.loadVerifiedEngineSource", source)

    def test_integrity_manifest_contains_current_engine_record(self) -> None:
        records = {item["path"]: item for item in self.integrity.get("assets", [])}
        record = records["../src/codeprobe_runtime.py"]
        content = (SRC / "codeprobe_runtime.py").read_bytes()
        self.assertEqual(record["size_bytes"], len(content))
        self.assertEqual(record["sha256_hex"], hashlib.sha256(content).hexdigest())

    def test_browser_decoder_declares_utf8_then_exact_latin1(self) -> None:
        self.assertIn('new TextDecoder("utf-8", { fatal: true })', self.loader)
        self.assertIn("function decodeLatin1Exact", self.loader)
        self.assertIn("String.fromCharCode", self.loader)
        self.assertIn('encoding: "latin-1"', self.loader)
        self.assertNotIn('new TextDecoder("iso-8859-1"', self.loader)

    def test_project_path_identity_is_nfc(self) -> None:
        decomposed = "src/cafe\u0301.py"
        composed = unicodedata.normalize("NFC", decomposed)
        self.assertEqual(engine.normalise_project_path(decomposed), composed)
        self.assertEqual(
            engine.normalise_project_path(decomposed),
            engine.normalise_project_path(composed),
        )

    def test_nfc_equivalent_project_paths_collide(self) -> None:
        warnings: list[str] = []
        files, source = engine.collect_project_files(
            {
                "files": [
                    {"path": "root/cafe\u0301.py", "content": "print(1)\n"},
                    {"path": "root/café.py", "content": "print(2)\n"},
                ]
            },
            warnings,
        )
        self.assertEqual(source, "file-list")
        self.assertIn("duplicate_path", [item.pre_exclusion_reason for item in files])

    def test_fixture_reader_is_bounded(self) -> None:
        with self.assertRaises(fixture_tool.FixtureError):
            fixture_tool.read_bounded(io.BytesIO(b"x" * 11), 10)
        self.assertEqual(fixture_tool.read_bounded(io.BytesIO(b"abc"), 10), b"abc")

    def test_fixture_member_paths_are_rejected_when_unsafe(self) -> None:
        for value in ("../pyodide.js", "/absolute/pyodide.js", "a//b"):
            with self.subTest(value=value):
                with self.assertRaises(fixture_tool.FixtureError):
                    fixture_tool.canonical_member_name(value)

    def test_functional_browser_gate_is_present(self) -> None:
        functional = (TOOLS / "check_browser_functional.js").read_text(encoding="utf-8")
        for fragment in (
            "testIntegrityFailureAndRetry",
            "testTamperedEngine",
            "testFileAnalysisAndExports",
            "testProjectAnalysis",
            "expectedFixtureCounts",
            "CODEPROBE_PYODIDE_FIXTURE_DIR",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, functional)


if __name__ == "__main__":
    unittest.main()
