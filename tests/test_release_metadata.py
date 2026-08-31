import contextlib
import errno
import json
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
SRC = ROOT / "src"
APP = ROOT / "app"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import codeprobe_runtime as engine
import check_release
from codeprobe_engine import api as cp_api
from codeprobe_engine import release
from codeprobe_engine.metrics import metric_inventory
from codeprobe_engine.release import (
    MANIFEST_NAME,
    ReleaseSetError,
    build_release_manifest,
    read_verified_release_snapshot,
    validate_release_set,
    verify_manifest,
    write_manifest,
)


class ReleaseMetadataTests(unittest.TestCase):
    def symlink_or_skip(
        self,
        link: Path,
        target: Path,
        *,
        target_is_directory: bool = False,
    ) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except OSError as exc:
            if os.name == "nt" and (
                getattr(exc, "winerror", None) == 1314
                or exc.errno in {errno.EACCES, errno.EPERM}
            ):
                self.skipTest("symbolic-link privilege is unavailable on this Windows runner")
            raise

    @staticmethod
    def make_manifest_fixture(parent: Path, name: str = "kit") -> Path:
        root = parent / name
        (root / "docs").mkdir(parents=True)
        (root / "docs" / "alpha.txt").write_bytes(b"alpha\n")
        (root / "source.txt").write_bytes(b"source\n")
        write_manifest(root, engine.APP_VERSION)
        return root

    @staticmethod
    def write_payload(root: Path, payload: dict) -> None:
        unsigned = {key: value for key, value in payload.items() if key != "manifest_sha256"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
        (root / MANIFEST_NAME).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def test_file_report_contains_release_metadata(self):
        result = json.loads(engine.codeprobe_analyze(json.dumps({
            "code": "def add(left: int, right: int) -> int:\n    return left + right\n\nprint(add(1, 2))\n",
            "filename": "calculator.py",
            "engine_fingerprint": "0" * 64,
        })))
        report = result["report"]
        self.assertEqual(report["app_version"], "2.2.0")
        self.assertEqual(report["schema_version"], engine.FILE_REPORT_SCHEMA_VERSION)
        self.assertIn("metric_config_digest", report)
        self.assertIn("metric_role_summary", report)
        self.assertIn("tool_metadata", report)
        self.assertEqual(report["engine_fingerprint"]["value"], "0" * 64)
        self.assertFalse(engine.validate_report_shape(report, "file"))

    def test_project_report_contains_release_metadata(self):
        result = cp_api.analyse_project({
            "project_name": "phase5",
            "engine_fingerprint": "1" * 64,
            "files": [
                {"path": "src/main.py", "content": "def main():\n    return 0\n\nprint(main())\n", "size_bytes": 40},
                {"path": "README.md", "content": "# notes\n", "size_bytes": 8},
            ],
        })
        report = result["project_report"]
        self.assertEqual(report["schema_version"], engine.PROJECT_REPORT_SCHEMA_VERSION)
        self.assertEqual(report["included_file_count"], 1)
        self.assertIn("tool_metadata", report)
        self.assertEqual(report["engine_fingerprint"]["value"], "1" * 64)
        self.assertFalse(engine.validate_report_shape(report, "project"))

    def test_metric_inventory_and_role_summary_are_consistent(self):
        inventory = metric_inventory()
        summary = engine.metric_role_summary()
        self.assertEqual(len(inventory), summary["total_metrics"])
        self.assertGreater(summary["authorship_signal_metrics"], 0)
        self.assertGreater(summary["quality_only_metrics"], 0)
        self.assertGreater(summary["context_only_metrics"], 0)

    def test_release_manifest_can_be_built_and_verified(self):
        manifest = build_release_manifest(ROOT, app_version=engine.APP_VERSION)
        self.assertEqual(manifest["app_version"], "2.2.0")
        self.assertGreater(manifest["file_count"], 10)
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / "kit"
            shutil.copytree(
                ROOT,
                fixture_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"),
            )
            write_manifest(fixture_root, engine.APP_VERSION)
            self.assertFalse(verify_manifest(fixture_root, app_version=engine.APP_VERSION))

    def test_manifest_can_hash_prospective_evidence_without_mutating_live_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_manifest_fixture(Path(tmp))
            evidence = root / "docs" / "alpha.txt"
            before = evidence.read_bytes()
            prospective = b"prospective audit evidence\n"
            manifest = build_release_manifest(
                root,
                app_version=engine.APP_VERSION,
                content_overrides={"docs/alpha.txt": prospective},
            )
            entry = next(
                item for item in manifest["files"]
                if item["path"] == "docs/alpha.txt"
            )
            self.assertEqual(entry["size_bytes"], len(prospective))
            self.assertEqual(entry["sha256"], hashlib.sha256(prospective).hexdigest())
            self.assertEqual(evidence.read_bytes(), before)

    def test_manifest_rejects_unknown_or_nonbyte_content_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_manifest_fixture(Path(tmp))
            with self.assertRaisesRegex(ValueError, "existing release member"):
                build_release_manifest(
                    root,
                    app_version=engine.APP_VERSION,
                    content_overrides={"missing.txt": b"missing\n"},
                )
            with self.assertRaisesRegex(TypeError, "must be bytes"):
                build_release_manifest(
                    root,
                    app_version=engine.APP_VERSION,
                    content_overrides={"source.txt": "not bytes"},  # type: ignore[dict-item]
                )

    def test_atomic_write_cleans_up_after_sync_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            target = directory / "evidence.json"
            target.write_bytes(b"original\n")
            before = {path.name for path in directory.iterdir()}
            with mock.patch.object(release.os, "fsync", side_effect=OSError("forced sync failure")):
                with self.assertRaisesRegex(OSError, "forced sync failure"):
                    release.atomic_write_bytes(target, b"replacement\n")
            self.assertEqual(target.read_bytes(), b"original\n")
            self.assertEqual({path.name for path in directory.iterdir()}, before)

    def test_manifest_verifier_rejects_every_authoritative_metadata_tamper(self):
        mutations = {
            "schema": lambda value: value.__setitem__("schema_version", "forged/v1"),
            "app-name": lambda value: value.__setitem__("app_name", "Forged"),
            "app-version": lambda value: value.__setitem__("app_version", "0.0.0"),
            "file-count": lambda value: value.__setitem__("file_count", value["file_count"] + 1),
            "total-size": lambda value: value.__setitem__("total_source_size_bytes", value["total_source_size_bytes"] + 1),
            "entry-size": lambda value: value["files"][0].__setitem__("size_bytes", value["files"][0]["size_bytes"] + 1),
            "entry-hash": lambda value: value["files"][0].__setitem__("sha256", "0" * 64),
        }
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    root = self.make_manifest_fixture(parent, name)
                    payload = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
                    mutate(payload)
                    self.write_payload(root, payload)
                    self.assertTrue(verify_manifest(root, app_version=engine.APP_VERSION))

            root = self.make_manifest_fixture(parent, "self-hash")
            payload = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
            payload["manifest_sha256"] = "0" * 64
            (root / MANIFEST_NAME).write_text(json.dumps(payload), encoding="utf-8")
            self.assertIn(
                "manifest_sha256 does not match the canonical manifest payload",
                verify_manifest(root, app_version=engine.APP_VERSION),
            )

    def test_manifest_verifier_rejects_ambiguous_shapes_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_manifest_fixture(parent, "duplicate-key")
            manifest_text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
            duplicate = manifest_text.replace("{", '{\n  "app_name": "Duplicate",', 1)
            (root / MANIFEST_NAME).write_text(duplicate, encoding="utf-8")
            errors = verify_manifest(root, app_version=engine.APP_VERSION)
            self.assertTrue(any("duplicate JSON object key" in error for error in errors), errors)

            cases = {
                "duplicate-entry": lambda value: value["files"].append(dict(value["files"][-1])),
                "non-object-entry": lambda value: value["files"].append("not-an-object"),
                "traversal": lambda value: value["files"][0].__setitem__("path", "../external.txt"),
                "non-canonical": lambda value: value["files"][0].__setitem__("path", "docs//alpha.txt"),
                "manifest-self": lambda value: value["files"][0].__setitem__("path", MANIFEST_NAME),
            }
            for name, mutate in cases.items():
                with self.subTest(name=name):
                    case_root = self.make_manifest_fixture(parent, name)
                    payload = json.loads((case_root / MANIFEST_NAME).read_text(encoding="utf-8"))
                    mutate(payload)
                    payload["file_count"] = len(payload["files"])
                    payload["total_source_size_bytes"] = sum(
                        item.get("size_bytes", 0) for item in payload["files"] if isinstance(item, dict)
                    )
                    self.write_payload(case_root, payload)
                    self.assertTrue(verify_manifest(case_root, app_version=engine.APP_VERSION))

    def test_release_set_rejects_links_and_special_files_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            external = parent / "external.txt"
            external.write_bytes(b"must not be packaged\n")
            root = self.make_manifest_fixture(parent)
            self.symlink_or_skip(root / "linked.txt", external)
            with self.assertRaisesRegex(ReleaseSetError, "symbolic links are forbidden"):
                validate_release_set(root)

            (root / "linked.txt").unlink()
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "special.fifo")
                with self.assertRaisesRegex(ReleaseSetError, "non-regular release entry"):
                    validate_release_set(root)

    def test_verified_snapshot_is_immutable_and_manifest_is_an_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_manifest_fixture(parent)
            snapshot = read_verified_release_snapshot(root, app_version=engine.APP_VERSION)
            captured = {entry.path: entry.content for entry in snapshot}
            (root / "source.txt").write_bytes(b"changed after capture\n")
            (root / "late.txt").write_bytes(b"late\n")
            self.assertEqual(captured["source.txt"], b"source\n")
            errors = verify_manifest(root, app_version=engine.APP_VERSION)
            self.assertTrue(any("current file missing from manifest: late.txt" in error for error in errors), errors)

    def test_manifest_reports_missing_size_and_hash_mismatches_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            missing_root = self.make_manifest_fixture(parent, "missing")
            (missing_root / "source.txt").unlink()
            self.assertIn(
                "recorded file missing from current release set: source.txt",
                verify_manifest(missing_root, app_version=engine.APP_VERSION),
            )

            changed_root = self.make_manifest_fixture(parent, "changed")
            (changed_root / "source.txt").write_bytes(b"change\n")
            errors = verify_manifest(changed_root, app_version=engine.APP_VERSION)
            self.assertIn("hash mismatch: source.txt", errors)
            self.assertNotIn("size mismatch: source.txt", errors)

            (changed_root / "source.txt").write_bytes(b"longer content\n")
            errors = verify_manifest(changed_root, app_version=engine.APP_VERSION)
            self.assertIn("size mismatch: source.txt", errors)

    def test_manifest_uses_global_lexical_path_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "kit"
            (root / "a").mkdir(parents=True)
            (root / "a" / "z.txt").write_bytes(b"nested\n")
            (root / "a!.txt").write_bytes(b"sibling\n")
            write_manifest(root, engine.APP_VERSION)
            payload = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual([item["path"] for item in payload["files"]], ["a!.txt", "a/z.txt"])
            self.assertEqual(verify_manifest(root, app_version=engine.APP_VERSION), [])

    def test_manifest_lone_surrogate_is_a_controlled_validation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_manifest_fixture(Path(tmp))
            raw = (root / MANIFEST_NAME).read_text(encoding="utf-8")
            raw = raw.replace('"app_name": "CodeProbe"', '"app_name": "\\ud800"')
            (root / MANIFEST_NAME).write_text(raw, encoding="utf-8")
            errors = verify_manifest(root, app_version=engine.APP_VERSION)
            self.assertTrue(errors)
            self.assertTrue(any("canonicalised" in error or "app_name" in error for error in errors), errors)

    def test_manifest_deep_nesting_and_read_errors_fail_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_manifest_fixture(Path(tmp))
            depth = 10_000
            (root / MANIFEST_NAME).write_text("[" * depth + "0" + "]" * depth, encoding="utf-8")
            errors = verify_manifest(root, app_version=engine.APP_VERSION)
            self.assertTrue(
                any(
                    "not valid unambiguous JSON" in error
                    or "top level must be an object" in error
                    for error in errors
                ),
                errors,
            )

            write_manifest(root, engine.APP_VERSION)
            with mock.patch.object(release.os, "read", side_effect=OSError("forced read failure")):
                errors = verify_manifest(root, app_version=engine.APP_VERSION)
            self.assertTrue(any("I/O failure while reading" in error for error in errors), errors)

    def test_untrusted_manifest_diagnostics_are_utf8_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_manifest_fixture(Path(tmp))
            raw = (root / MANIFEST_NAME).read_text(encoding="utf-8")
            raw = raw.replace("{", '{\n  "\\ud800": 1,', 1)
            (root / MANIFEST_NAME).write_text(raw, encoding="utf-8")
            result = check_release.check_manifest(root)
            self.assertFalse(result.ok)
            result.detail.encode("utf-8")

    def test_actual_release_paths_must_be_portable_and_not_collide(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            if os.name != "nt":
                root = self.make_manifest_fixture(parent, "invalid")
                (root / "bad\\name.txt").write_bytes(b"bad\n")
                with self.assertRaisesRegex(ReleaseSetError, "unsafe release path"):
                    validate_release_set(root)

            root = self.make_manifest_fixture(parent, "collision").resolve()
            upper_source = root / "SOURCE.TXT"
            try:
                with upper_source.open("xb") as handle:
                    handle.write(b"collision\n")
            except FileExistsError:
                collision_context = mock.patch.object(
                    release,
                    "_walk_release_files",
                    return_value=(root / "source.txt", upper_source),
                )
            else:
                collision_context = contextlib.nullcontext()
            with collision_context:
                with self.assertRaisesRegex(ReleaseSetError, "collide on a portable filesystem"):
                    validate_release_set(root)

            root = self.make_manifest_fixture(parent, "manifest-collision").resolve()
            with mock.patch.object(
                release,
                "_walk_release_files",
                return_value=(root / "release" / "RELEASE-MANIFEST.JSON",),
            ):
                with self.assertRaisesRegex(ReleaseSetError, "collide on a portable filesystem"):
                    tuple(release.iter_release_files(root))

    def test_directory_swap_to_symlink_is_detected_before_paths_are_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_manifest_fixture(parent).resolve()
            nested = root / "docs"
            saved = parent / "saved-docs"
            external = parent / "external"
            external.mkdir()
            (external / "secret.txt").write_bytes(b"external\n")
            real_scandir = release.os.scandir
            swapped = False

            def swap_before_scan(path: Path):
                nonlocal swapped
                if Path(path) == nested and not swapped:
                    swapped = True
                    nested.rename(saved)
                    self.symlink_or_skip(nested, external, target_is_directory=True)
                return real_scandir(path)

            with mock.patch.object(release.os, "scandir", side_effect=swap_before_scan):
                with self.assertRaisesRegex(ReleaseSetError, "changed during enumeration"):
                    validate_release_set(root)

    def test_root_anchored_reader_rejects_escape_and_symlink_before_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_manifest_fixture(parent).resolve()
            external = parent / "external.txt"
            external.write_bytes(b"external\n")
            with self.assertRaisesRegex(ReleaseSetError, "not canonical below its root"):
                release.read_regular_file(root / ".." / "external.txt", root=root)

            link = root / "linked.txt"
            self.symlink_or_skip(link, external)
            with mock.patch.object(release.os, "supports_dir_fd", set()):
                with mock.patch.object(release.os, "read", wraps=os.read) as reader:
                    with self.assertRaisesRegex(ReleaseSetError, "not a regular file"):
                        release.read_regular_file(link, root=root)
            reader.assert_not_called()

            source = root / "source.txt"
            saved = root / "source.saved"

            def swap_during_open(path: Path, selected_root: Path | None) -> int:
                source.rename(saved)
                self.symlink_or_skip(source, external)
                return os.open(external, os.O_RDONLY)

            with mock.patch.object(release, "_open_regular_for_read", side_effect=swap_during_open):
                with mock.patch.object(release.os, "read", wraps=os.read) as reader:
                    with self.assertRaisesRegex(ReleaseSetError, "not a regular file"):
                        release.read_regular_file(source, root=root)
            reader.assert_not_called()

    def test_deep_release_tree_is_enumerated_without_python_recursion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "kit"
            root.mkdir()
            current = root
            directories = [root]
            leaf = current / "leaf.txt"
            previous_recursion_limit = sys.getrecursionlimit()
            try:
                sys.setrecursionlimit(64)
                for _ in range(80):
                    current /= "d"
                    current.mkdir()
                    directories.append(current)
                leaf = current / "leaf.txt"
                leaf.write_bytes(b"leaf\n")
                write_manifest(root, engine.APP_VERSION)
                self.assertEqual(verify_manifest(root, app_version=engine.APP_VERSION), [])
            finally:
                sys.setrecursionlimit(previous_recursion_limit)
                leaf.unlink(missing_ok=True)
                (root / MANIFEST_NAME).unlink(missing_ok=True)
                release_directory = root / "release"
                if release_directory.is_dir():
                    release_directory.rmdir()
                for directory in reversed(directories):
                    directory.rmdir()

    def test_manifest_generation_rejects_late_membership_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_manifest_fixture(Path(tmp))
            real_iterator = release.iter_release_files
            calls = 0

            def inject_on_second_enumeration(selected_root: Path):
                nonlocal calls
                calls += 1
                if calls == 2:
                    (root / "late.txt").write_bytes(b"late\n")
                return real_iterator(selected_root)

            with mock.patch.object(release, "iter_release_files", side_effect=inject_on_second_enumeration):
                with self.assertRaisesRegex(ReleaseSetError, "membership changed"):
                    release.build_release_manifest(root, app_version=engine.APP_VERSION)

    def test_excluded_locations_are_matched_case_insensitively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "kit"
            (root / ".GIT").mkdir(parents=True)
            (root / ".GIT" / "secret.txt").write_bytes(b"excluded\n")
            (root / "Dist").mkdir()
            (root / "Dist" / "package.zip").write_bytes(b"excluded\n")
            (root / "source.txt").write_bytes(b"included\n")
            write_manifest(root, engine.APP_VERSION)
            payload = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual([item["path"] for item in payload["files"]], ["source.txt"])
            self.assertEqual(verify_manifest(root, app_version=engine.APP_VERSION), [])


if __name__ == "__main__":
    unittest.main()
