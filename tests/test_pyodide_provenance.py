from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import check_pyodide_provenance as provenance  # noqa: E402


class PyodideProvenanceTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        target = root / "app"
        target.mkdir(parents=True)
        for name in (
            "runtime-config.json",
            "pyodide-provenance.json",
            "pyodide-loader.js",
            "codeprobe-ui.js",
            "project-ui.js",
        ):
            shutil.copyfile(ROOT / "app" / name, target / name)
        return root

    def test_repository_provenance_boundary_passes(self) -> None:
        self.assertEqual(provenance.audit_pyodide_provenance(ROOT), [])

    def test_production_configuration_cannot_disable_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            path = root / "app" / "runtime-config.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["pyodide"]["require_integrity"] = False
            path.write_text(json.dumps(data), encoding="utf-8")
            errors = provenance.audit_pyodide_provenance(root)
        self.assertTrue(any("must require integrity" in error for error in errors))

    def test_loader_digest_must_match_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            path = root / "app" / "pyodide-provenance.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["startup_artifacts"][0]["sha256_hex"] = "0" * 64
            data["startup_artifacts"][0]["sri_sha256"] = provenance._sri_for_hex("0" * 64)
            path.write_text(json.dumps(data), encoding="utf-8")
            errors = provenance.audit_pyodide_provenance(root)
        self.assertTrue(any("configured loader digest differs" in error for error in errors))

    def test_duplicate_startup_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            path = root / "app" / "pyodide-provenance.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["startup_artifacts"].append(dict(data["startup_artifacts"][0]))
            path.write_text(json.dumps(data), encoding="utf-8")
            errors = provenance.audit_pyodide_provenance(root)
        self.assertTrue(any("duplicate startup artefact" in error for error in errors))

    def test_ui_cannot_bypass_verified_runtime_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            path = root / "app" / "project-ui.js"
            path.write_text(
                path.read_text(encoding="utf-8") + "\nwindow.loadPyodide({});\n",
                encoding="utf-8",
            )
            errors = provenance.audit_pyodide_provenance(root)
        self.assertTrue(any("bypasses the verified" in error for error in errors))

    def test_duplicate_json_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(provenance.PyodideProvenanceError, "duplicate JSON key"):
                provenance.load_unique_json(path)


if __name__ == "__main__":
    unittest.main()
