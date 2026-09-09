from __future__ import annotations

import hashlib
import json
import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import prepare_pyodide_fixture as fixture  # noqa: E402
from codeprobe_engine import release  # noqa: E402


NAMES = (
    "pyodide.js",
    "pyodide-lock.json",
    "python_stdlib.zip",
    "pyodide.asm.js",
    "pyodide.asm.wasm",
)


class PyodideFixtureTests(unittest.TestCase):
    def snapshot(self, root: Path) -> dict[str, bytes | None]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes() if path.is_file() else None
            for path in root.rglob("*")
        }

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

    def test_complete_metadata_is_required_before_creating_outputs(self) -> None:
        mutations = [
            ("version missing", lambda data: data.pop("version")),
            *[(f"version {value!r}", lambda data, value=value: data.update(version=value))
              for value in (None, True, 25, [], "", "0.25", "0.25.0\ud800", "01.2.3")],
            ("schema", lambda data: data.update(schema=1)),
            *[(f"URL {value!r}", lambda data, value=value: data.update(distribution_base_url=value))
              for value in (None, 1, [], "http://fixture.invalid/", "https://user@fixture.invalid/",
                            "https://fixture.invalid/?x/", "https://fixture.invalid/#x/",
                            "https://fixture.invalid:bad/", "https://fixture.invalid/\n",
                            "https://fixture.invalid/\ud800/")],
            ("missing member", lambda data: data["startup_artifacts"].pop()),
            ("extra member", lambda data: data["startup_artifacts"].append(dict(data["startup_artifacts"][0]))),
            ("duplicate member", lambda data: data["startup_artifacts"][1].update(name=NAMES[0])),
            ("unknown member", lambda data: data["startup_artifacts"][0].update(name="extra.js")),
            ("non-string member", lambda data: data["startup_artifacts"][0].update(name=[])),
            ("non-object member", lambda data: data["startup_artifacts"].__setitem__(0, [])),
            ("non-list inventory", lambda data: data.update(startup_artifacts={})),
            *[(f"size {value!r}", lambda data, value=value: data["startup_artifacts"][0].update(size_bytes=value))
              for value in (True, 0, -1, 1.5, "4")],
            *[(f"digest {value!r}", lambda data, value=value: data["startup_artifacts"][0].update(sha256_hex=value))
              for value in (None, 1, [], "a" * 63, "A" * 64)],
        ]
        for label, mutate in mutations:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, provenance = self.synthetic_fixture(root)
                control = fixture.prepare_fixture(root / "control", source_dir=source, provenance_path=provenance)
                self.assertEqual(len(control["artifacts"]), 5)
                data = json.loads(provenance.read_text(encoding="utf-8"))
                mutate(data)
                provenance.write_text(json.dumps(data), encoding="utf-8")
                before = self.snapshot(root)
                with self.assertRaises(fixture.FixtureError):
                    fixture.prepare_fixture(root / "target", source_dir=source, provenance_path=provenance)
                self.assertEqual(self.snapshot(root), before)

    def test_ambiguous_json_is_rejected_before_output_creation(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity", "1e999"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, provenance = self.synthetic_fixture(root)
                fixture.prepare_fixture(root / "control", source_dir=source, provenance_path=provenance)
                original = provenance.read_text(encoding="utf-8")
                provenance.write_text(original[:-1] + ', "unused": ' + value + "}", encoding="utf-8")
                before = self.snapshot(root)
                with self.assertRaisesRegex(fixture.FixtureError, "non-finite JSON"):
                    fixture.prepare_fixture(root / "target", source_dir=source, provenance_path=provenance)
                self.assertEqual(self.snapshot(root), before)

    def test_excessive_json_nesting_is_a_controlled_preflight_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            fixture.prepare_fixture(root / "control", source_dir=source, provenance_path=provenance)
            provenance.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            before = self.snapshot(root)
            with self.assertRaises(fixture.FixtureError):
                fixture.prepare_fixture(root / "target", source_dir=source, provenance_path=provenance)
            self.assertEqual(self.snapshot(root), before)

    def make_alias(self, root: Path, protected: Path, form: str) -> Path:
        if form == "same":
            return protected
        if form == "resolved":
            via = root / "via"
            via.mkdir()
            return via / ".." / protected.relative_to(root)
        alias = root / "alias.json"
        try:
            if form == "symlink":
                alias.symlink_to(protected)
            else:
                os.link(protected, alias)
        except (OSError, NotImplementedError):
            self.skipTest(f"{form} is unavailable")
        return alias

    def test_cli_summary_aliases_preserve_every_input_and_fixture_member(self) -> None:
        roles = ("provenance", *[f"source/{name}" for name in NAMES], *[f"target/{name}" for name in NAMES])
        for role in roles:
            for form in ("same", "resolved", "symlink", "hardlink"):
                with self.subTest(role=role, form=form), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    source, provenance = self.synthetic_fixture(root)
                    target = root / "target"
                    target.mkdir()
                    for name in NAMES:
                        (target / name).write_bytes((source / name).read_bytes())
                    protected = provenance if role == "provenance" else root / role
                    output = self.make_alias(root, protected, form)
                    before = self.snapshot(root)
                    with contextlib.redirect_stdout(io.StringIO()) as printed:
                        result = fixture.main([
                            "--output-dir", str(target), "--source-dir", str(source),
                            "--provenance", str(provenance), "--json-out", str(output),
                        ])
                    self.assertEqual(result, 1)
                    self.assertIn("[FAIL] pyodide-fixture", printed.getvalue())
                    self.assertEqual(self.snapshot(root), before)

    def test_summary_cannot_replace_consumed_tool_or_engine_source(self) -> None:
        for directory in ("src", "tools"):
            for form in ("same", "resolved", "symlink", "hardlink"):
                with self.subTest(directory=directory, form=form), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    source, provenance = self.synthetic_fixture(root)
                    code_dir = root / directory
                    code_dir.mkdir()
                    protected = code_dir / "owned_input.py"
                    protected.write_bytes(b"# inert owned source sentinel\n")
                    output = self.make_alias(root, protected, form)
                    before = self.snapshot(root)
                    with mock.patch.object(fixture, "ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                        result = fixture.main([
                            "--output-dir", str(root / "target"), "--source-dir", str(source),
                            "--provenance", str(provenance), "--json-out", str(output),
                        ])
                    self.assertEqual(result, 1)
                    self.assertEqual(self.snapshot(root), before)

    def test_output_namespace_conflicts_are_rejected_before_creation(self) -> None:
        for relation in ("directory", "ancestor", "source directory"):
            with self.subTest(relation=relation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source, provenance = self.synthetic_fixture(root)
                target = root / "new" / "target"
                output = {"directory": target, "ancestor": target.parent, "source directory": source}[relation]
                before = self.snapshot(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    result = fixture.main([
                        "--output-dir", str(target), "--source-dir", str(source),
                        "--provenance", str(provenance), "--json-out", str(output),
                    ])
                self.assertEqual(result, 1)
                self.assertEqual(self.snapshot(root), before)

    def test_source_directory_cannot_be_its_own_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            before = self.snapshot(root)
            with self.assertRaisesRegex(fixture.FixtureError, "unsafe fixture output"):
                fixture.prepare_fixture(source, source_dir=source, provenance_path=provenance)
            self.assertEqual(self.snapshot(root), before)

    def test_existing_distinct_cache_can_be_refreshed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            target = root / "target"
            target.mkdir()
            for name in NAMES:
                (target / name).write_bytes(b"stale cache")
            inputs = {path: path.read_bytes() for path in [provenance, *source.iterdir()]}
            summary = fixture.prepare_fixture(target, source_dir=source, provenance_path=provenance)
            self.assertEqual(len(summary["artifacts"]), 5)
            for name in NAMES:
                self.assertEqual((target / name).read_bytes(), (source / name).read_bytes())
            self.assertEqual({path: path.read_bytes() for path in inputs}, inputs)

    def test_local_reader_accepts_stable_exact_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_bytes(b"12345678")
            self.assertEqual(fixture._read_local(path, expected_size=8), b"12345678")

    def test_local_reader_growth_stops_at_the_ceiling_plus_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_bytes(b"12345678")
            original_read = os.read
            observed = []
            def grow_then_read(descriptor: int, size: int) -> bytes:
                if not observed:
                    with path.open("ab") as handle:
                        handle.write(b"x" * 56)
                content = original_read(descriptor, size)
                observed.append((size, len(content)))
                return content
            with mock.patch.object(release.os, "read", side_effect=grow_then_read):
                with self.assertRaisesRegex(fixture.FixtureError, "size ceiling"):
                    fixture._read_local(path, expected_size=8)
            self.assertEqual(observed, [(9, 9)])

    def test_local_reader_rejects_identity_change_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            replacement = Path(tmp) / "replacement"
            path.write_bytes(b"12345678")
            replacement.write_bytes(b"12345678")
            original_read = os.read
            changed = False
            def swap_then_return(descriptor: int, size: int) -> bytes:
                nonlocal changed
                content = original_read(descriptor, size)
                if not changed:
                    changed = True
                    try:
                        os.replace(replacement, path)
                    except PermissionError:
                        self.skipTest("replacing an open file is unavailable")
                return content
            with mock.patch.object(release.os, "read", side_effect=swap_then_return):
                with self.assertRaisesRegex(fixture.FixtureError, "changed during read"):
                    fixture._read_local(path, expected_size=8)

    def test_local_reader_rejects_symlinks_and_nonregular_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "file"
            path.write_bytes(b"12345678")
            with mock.patch.object(release.os, "open", side_effect=AssertionError("must not open a directory")):
                with self.assertRaisesRegex(fixture.FixtureError, "not a regular file"):
                    fixture._read_local(root, expected_size=8)
            alias = root / "alias"
            try:
                alias.symlink_to(path)
            except (OSError, NotImplementedError):
                self.skipTest("file symlinks are unavailable")
            with self.assertRaisesRegex(fixture.FixtureError, "not a regular file"):
                fixture._read_local(alias, expected_size=8)

    @unittest.skipUnless(hasattr(os, "O_NONBLOCK"), "non-blocking open flags are unavailable")
    def test_local_reader_uses_nonblocking_descriptor_openings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_bytes(b"12345678")
            original_open = os.open
            flags_seen = []
            def inspect_open(filename: Path, flags: int, *args: object, **kwargs: object) -> int:
                flags_seen.append(flags)
                return original_open(filename, flags, *args, **kwargs)
            with mock.patch.object(release.os, "open", side_effect=inspect_open):
                self.assertEqual(fixture._read_local(path, expected_size=8), b"12345678")
            self.assertGreaterEqual(len(flags_seen), 1)
            self.assertTrue(all(flags & os.O_NONBLOCK for flags in flags_seen))

    def test_same_size_digest_failure_never_publishes_the_failed_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            path = source / NAMES[0]
            path.write_bytes(b"x" * path.stat().st_size)
            before = self.snapshot(root)
            with self.assertRaisesRegex(fixture.FixtureError, "SHA-256 mismatch"):
                fixture.prepare_fixture(root / "target", source_dir=source, provenance_path=provenance)
            self.assertEqual(self.snapshot(root), before)

    def test_later_failure_preserves_only_prior_authenticated_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            (source / NAMES[-1]).write_bytes(b"x" * (source / NAMES[-1]).stat().st_size)
            target = root / "target"
            report = root / "summary.json"
            report.write_bytes(b"existing report")
            with self.assertRaisesRegex(fixture.FixtureError, "SHA-256 mismatch"):
                fixture.prepare_fixture(target, source_dir=source, provenance_path=provenance, json_out=report)
            self.assertEqual({path.name for path in target.iterdir()}, set(NAMES[:-1]))
            for name in NAMES[:-1]:
                self.assertEqual((target / name).read_bytes(), (source / name).read_bytes())
            self.assertEqual(report.read_bytes(), b"existing report")

    def test_output_alias_introduced_during_read_is_rechecked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, provenance = self.synthetic_fixture(root)
            target = root / "target"
            report = root / "summary.json"
            original_read = fixture._read_local
            def create_alias_after_read(path: Path, *, expected_size: int) -> bytes:
                content = original_read(path, expected_size=expected_size)
                try:
                    os.link(path, report)
                except (OSError, NotImplementedError):
                    self.skipTest("hardlinks are unavailable")
                return content
            before = {path: path.read_bytes() for path in [provenance, *source.iterdir()]}
            with mock.patch.object(fixture, "_read_local", side_effect=create_alias_after_read):
                with self.assertRaisesRegex(fixture.FixtureError, "unsafe fixture output"):
                    fixture.prepare_fixture(target, source_dir=source, provenance_path=provenance, json_out=report)
            self.assertFalse(target.exists())
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            self.assertEqual(report.read_bytes(), (source / NAMES[0]).read_bytes())


if __name__ == "__main__":
    unittest.main()
