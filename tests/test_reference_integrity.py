from __future__ import annotations

import csv
import errno
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
TOOLS = ROOT / "tools"
SRC = ROOT / "src"
APP = ROOT / "app"
for path in (TOOLS, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import check_file_references  # noqa: E402
from codeprobe_engine.release import iter_release_files  # noqa: E402


class ReferenceIntegrityTests(unittest.TestCase):
    @staticmethod
    def _output_fixture(parent: Path):
        root = parent / "kit"
        (root / "app").mkdir(parents=True)
        (root / "release").mkdir()
        (root / "dist").mkdir()
        files = {
            "README.md": b"# Fixture\n[Archive](dist/archive.bin)\n",
            "app/resource-integrity.json": b'{"assets": [{"path": "asset.bin"}]}\n',
            "app/asset.bin": b"asset bytes\n",
            "dist/archive.bin": b"linked archive bytes\n",
        }
        for relative, content in files.items():
            (root / relative).write_bytes(content)
        paths = [*files, "release/file-rename-map.csv"]
        header = "current_path,proposed_final_path,role,action,phase,area,risk_level,rationale\n"
        (root / "release/file-rename-map.csv").write_text(header + "".join(
            f"{path},{path},fixture,keep,I04,test,low,fixture\n" for path in paths), encoding="utf-8")
        return root, [root / path for path in paths]

    def _check_output_aliases(self, kind: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs = self._output_fixture(parent)
            self.assertEqual(check_file_references.run_checks(root), [])
            before = {path: path.read_bytes() for path in inputs}
            for index, source in enumerate(inputs):
                with self.subTest(input=source.name, kind=kind):
                    output = parent / f"alias-{index}.json"
                    if kind == "same":
                        output = source
                    elif kind == "resolved":
                        (source.parent / "unused").mkdir(exist_ok=True)
                        output = source.parent / "unused" / ".." / source.name
                    else:
                        try:
                            if kind == "hardlink":
                                os.link(source, output)
                            else:
                                output.symlink_to(source)
                        except OSError as exc:
                            if exc.errno in {errno.EACCES, errno.EPERM, errno.ENOTSUP}:
                                self.skipTest(f"{kind} unavailable: {exc}")
                            raise
                    with mock.patch.object(check_file_references, "run_checks", wraps=check_file_references.run_checks) as checks, \
                            mock.patch.object(sys, "stdout", io.StringIO()):
                        status = check_file_references.main(["--root", str(root), "--json-out", str(output)])
                    self.assertEqual(status, 1)
                    checks.assert_not_called()
                    self.assertEqual(before, {path: path.read_bytes() for path in inputs})
                    if kind == "resolved":
                        self.assertEqual(list((source.parent / "unused").iterdir()), [])

    def test_output_rejects_same_and_resolved_verified_input_paths(self) -> None:
        self._check_output_aliases("same")
        self._check_output_aliases("resolved")

    def test_output_rejects_hardlinks_to_every_verified_input_kind(self) -> None:
        self._check_output_aliases("hardlink")

    def test_output_rejects_symlinks_to_every_verified_input_kind(self) -> None:
        self._check_output_aliases("symlink")

    def test_distinct_repeat_report_and_encoding_failure_preserve_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, inputs = self._output_fixture(Path(tmp))
            before = {path: path.read_bytes() for path in inputs}
            output = root / "dist" / "references.json"
            with mock.patch.object(sys, "stdout", io.StringIO()):
                for _ in range(2):
                    self.assertEqual(check_file_references.main(["--root", str(root), "--json-out", str(output)]), 0)
                    self.assertEqual(json.loads(output.read_bytes()), {"ok": True, "errors": []})
                valid = output.read_bytes()
                with mock.patch.object(check_file_references, "run_checks", return_value=["\ud800"]):
                    self.assertEqual(check_file_references.main(["--root", str(root), "--json-out", str(output)]), 1)
            self.assertEqual(output.read_bytes(), valid)
            self.assertEqual(before, {path: path.read_bytes() for path in inputs})

    def test_reference_checker_passes(self) -> None:
        self.assertEqual(check_file_references.run_checks(ROOT), [])

    def test_document_link_checker_ignores_vcs_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / ".git"
            metadata.mkdir()
            (metadata / "host-note.md").write_text("[missing](does-not-exist.md)\n", encoding="utf-8")
            self.assertEqual(check_file_references.check_document_links(root), [])

    def test_resource_manifest_cannot_reference_outside_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "kit"
            app = root / "app"
            app.mkdir(parents=True)
            outside = parent / "outside.js"
            outside.write_text("const outside = true;\n", encoding="utf-8")
            (app / "resource-integrity.json").write_text(
                json.dumps({"assets": [{"path": "../../outside.js"}]}),
                encoding="utf-8",
            )
            problems = check_file_references.check_resource_integrity_manifest(root)
            self.assertEqual(len(problems), 1)
            self.assertIn("outside package root", problems[0].message)

    def test_rename_map_covers_current_release_files(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            mapped = {row["current_path"] for row in csv.DictReader(handle)}
        current = {path.relative_to(ROOT).as_posix() for path in iter_release_files(ROOT)}
        current.add("release/release-manifest.json")
        self.assertTrue(current <= mapped)

    def test_key_phase10_documents_are_listed(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            mapped = {row["current_path"]: row for row in csv.DictReader(handle)}
        for relative in [
            "docs/00-file-catalogue.md",
            "docs/01-naming-policy.md",
            "docs/history/10-naming-governance.md",
            "tools/check_file_references.py",
        ]:
            self.assertIn(relative, mapped)
            self.assertTrue(mapped[relative]["proposed_final_path"])


if __name__ == "__main__":
    unittest.main()
