from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import prepare_pyodide_fixture as fixture  # noqa: E402


NAMES = (
    "pyodide.js",
    "pyodide-lock.json",
    "python_stdlib.zip",
    "pyodide.asm.js",
    "pyodide.asm.wasm",
)


class PyodideFixtureTests(unittest.TestCase):
    def synthetic_fixture(self, root: Path) -> tuple[Path, Path]:
        source = root / "source"
        source.mkdir()
        records = []
        for index, name in enumerate(NAMES, start=1):
            content = (f"fixture-{index}-{name}\n").encode("utf-8")
            (source / name).write_bytes(content)
            records.append({
                "name": name,
                "size_bytes": len(content),
                "sha256_hex": hashlib.sha256(content).hexdigest(),
            })
        provenance = root / "provenance.json"
        provenance.write_text(
            json.dumps({
                "schema": "codeprobe-pyodide-provenance/v1",
                "version": "0.25.0",
                "distribution_base_url": "https://fixtures.invalid/pyodide/",
                "startup_artifacts": records,
            }),
            encoding="utf-8",
        )
        return source, provenance

    def test_local_fixture_is_copied_only_after_exact_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            target = root / "target"
            summary = fixture.prepare_fixture(
                target,
                source_dir=source,
                provenance_path=provenance,
            )
            self.assertEqual(summary["schema"], "codeprobe-pyodide-functional-fixture/v1")
            self.assertEqual(summary["version"], "0.25.0")
            self.assertEqual(len(summary["artifacts"]), 5)
            self.assertEqual({item["source"] for item in summary["artifacts"]}, {"local"})
            self.assertEqual({path.name for path in target.iterdir()}, set(NAMES))

    def test_tampered_fixture_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            path = source / "pyodide.js"
            path.write_bytes(path.read_bytes() + b"x")
            with self.assertRaisesRegex(fixture.FixtureError, "size mismatch|bounded regular"):
                fixture.prepare_fixture(
                    root / "target",
                    source_dir=source,
                    provenance_path=provenance,
                )

    def test_duplicate_provenance_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "provenance.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(fixture.FixtureError, "duplicate JSON key"):
                fixture.load_provenance(path)

    def test_cli_writes_a_machine_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            target = root / "target"
            summary = root / "summary.json"
            result = fixture.main([
                "--output-dir", str(target),
                "--source-dir", str(source),
                "--provenance", str(provenance),
                "--json-out", str(summary),
            ])
            self.assertEqual(result, 0)
            payload = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["artifacts"]), 5)

    def test_output_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(fixture.FixtureError, "must not be a symbolic link"):
                fixture.prepare_fixture(
                    alias,
                    source_dir=source,
                    provenance_path=provenance,
                )


if __name__ == "__main__":
    unittest.main()
