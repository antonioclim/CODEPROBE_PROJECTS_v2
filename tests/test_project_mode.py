from __future__ import annotations

import base64
import argparse
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine import api, project_io  # noqa: E402
import analyze_project  # noqa: E402


def zip_payload(entries, *, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for path, content in entries:
            archive.writestr(path, content)
    return base64.b64encode(buffer.getvalue()).decode("ascii"), buffer.getvalue()


class PhaseThreeProjectModeTests(unittest.TestCase):
    def test_codeprobeignore_excludes_generated_and_documentation_files(self) -> None:
        payload = {"project_name": "student-project", "files": [{"path": ".codeprobeignore", "content": "generated/\n*.min.js\n"}, {"path": "src/main.py", "content": "def add(left, right):\n    return left + right\n\nprint(add(1, 2))\n"}, {"path": "generated/client.py", "content": "def generated():\n    return 42\n"}, {"path": "web/app.min.js", "content": "function x(){return 1}\n"}, {"path": "docs/README.md", "content": "# Notes\n"}], "profile": "default"}
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})
        self.assertEqual(report["schema_version"], "2.2.0-project")

    def test_zip_project_payload_is_supported_and_rejects_unsafe_paths(self) -> None:
        encoded, _ = zip_payload([("src/app.py", "def main():\n    return 0\n\nmain()\n"), ("../escape.py", "print('bad')\n"), ("assets/logo.png", b"\x00\x01\x02")])
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "zip-project", "zip_base64": encoded})))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/app.py"})
        reasons = {item["path"]: item["reason"] for item in report["excluded_files"]}
        self.assertEqual(reasons.get("../escape.py"), "unsafe_path")

    def test_project_score_uses_sloc_weighting_and_cap(self) -> None:
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "weighted", "files": [{"path": "a.py", "content": "def a():\n    return 1\n"}, {"path": "b.js", "content": "function b() { return 2; }\n"}]})))["project_report"]
        self.assertEqual(report["included_file_count"], 2)
        self.assertEqual(report["aggregation"]["per_file_sloc_cap"], engine.PROJECT_WEIGHT_CAP_SLOC)

    def test_markdown_is_excluded_from_project_aggregate_by_default(self) -> None:
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "docs", "files": [{"path": "README.md", "content": "# Project\n"}]})))["project_report"]
        self.assertEqual(report["included_file_count"], 0)
        self.assertFalse(report["overall_applicable"])

    def test_negated_codeprobeignore_rule_can_reinclude_authored_source(self) -> None:
        payload = {"project_name": "negation", "files": [{"path": ".codeprobeignore", "content": "src/generated/\n!src/generated/handwritten.py\n"}, {"path": "src/generated/client.py", "content": "def generated():\n    return 1\n"}, {"path": "src/generated/handwritten.py", "content": "def handwritten():\n    return 2\n"}]}
        report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/generated/handwritten.py"})

    def test_unsafe_embedded_ignore_file_is_not_loaded(self) -> None:
        encoded, _ = zip_payload([("../.codeprobeignore", "src/\n"), ("src/app.py", "def main():\n    return 0\n")])
        report = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "unsafe-ignore", "zip_base64": encoded})))["project_report"]
        self.assertEqual({item["path"] for item in report["files"]}, {"src/app.py"})

    def test_project_text_report_lists_included_and_excluded_files(self) -> None:
        result = json.loads(engine.codeprobe_analyze_project(json.dumps({"project_name": "text-report", "files": [{"path": "src/app.py", "content": "def main():\n    return 0\n"}, {"path": "README.md", "content": "# Documentation\n"}]})))
        self.assertIn("Analysed files:", result["text"])
        self.assertIn("Excluded files:", result["text"])


class HostileProjectInputTests(unittest.TestCase):
    def _report(self, payload):
        return json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]

    def test_forged_file_size_metadata_is_not_trusted(self):
        report = self._report({"project_name": "forged", "max_file_bytes": 16, "files": [{"path": "main.py", "content": "x = '" + "a" * 100 + "'\n", "size_bytes": 1}]})
        self.assertEqual(report["excluded_files"][0]["reason"], "file_too_large")

    def test_invalid_file_limit_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "max_file_bytes"):
            engine.analyse_project_payload({"files": [], "max_file_bytes": 0})

    def test_invalid_total_limit_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "max_total_bytes"):
            engine.analyse_project_payload({"files": [], "max_total_bytes": -1})

    def test_zip_compressed_size_limit_is_checked_before_decode(self):
        encoded, raw = zip_payload([("main.py", "print('x')\n")])
        with self.assertRaisesRegex(ValueError, "compressed ZIP limit"):
            engine.analyse_project_payload({"zip_base64": encoded, "max_zip_bytes": len(raw) - 1})

    def test_zip_entry_count_limit_is_checked_from_eocd(self):
        encoded, _ = zip_payload([(f"f{i}.py", "print(1)\n") for i in range(3)])
        with self.assertRaisesRegex(ValueError, "entry limit"):
            engine.analyse_project_payload({"zip_base64": encoded, "max_zip_entries": 2})

    def test_zip_compression_ratio_bomb_is_not_decompressed(self):
        encoded, _ = zip_payload([("bomb.py", "#" + "0" * 200000)])
        report = self._report({"zip_base64": encoded, "max_file_bytes": 300000, "max_compression_ratio": 5})
        self.assertEqual(report["excluded_files"][0]["reason"], "compression_ratio_exceeded")

    def test_zip_member_size_limit_prevents_read(self):
        encoded, _ = zip_payload([("large.py", "x" * 1000)])
        report = self._report({"zip_base64": encoded, "max_file_bytes": 100})
        self.assertEqual(report["excluded_files"][0]["reason"], "file_too_large")

    def test_zip_total_budget_excludes_later_members(self):
        encoded, _ = zip_payload([("a.py", "a = 1\n" * 5), ("b.py", "b = 2\n" * 5)])
        report = self._report({"zip_base64": encoded, "max_total_bytes": 45})
        self.assertIn("project_total_byte_limit", {item["reason"] for item in report["excluded_files"]})

    def test_zip_unsupported_compression_is_not_opened(self):
        if not hasattr(zipfile, "ZIP_BZIP2"):
            self.skipTest("BZIP2 not available")
        encoded, _ = zip_payload([("main.py", "print(1)\n")], compression=zipfile.ZIP_BZIP2)
        report = self._report({"zip_base64": encoded})
        self.assertEqual(report["excluded_files"][0]["reason"], "unsupported_compression_method")

    def test_zip_encrypted_flag_is_rejected_before_member_read(self):
        encoded, raw = zip_payload([("main.py", "print(1)\n")])
        altered = bytearray(raw)
        local = altered.find(b"PK\x03\x04")
        central = altered.find(b"PK\x01\x02")
        altered[local + 6:local + 8] = (1).to_bytes(2, "little")
        altered[central + 8:central + 10] = (1).to_bytes(2, "little")
        report = self._report({"zip_base64": base64.b64encode(altered).decode("ascii")})
        self.assertEqual(report["excluded_files"][0]["reason"], "encrypted_zip_entry")

    def test_portable_duplicate_paths_are_excluded(self):
        encoded, _ = zip_payload([("A.py", "print(1)\n"), ("a.py", "print(2)\n")])
        report = self._report({"zip_base64": encoded})
        self.assertIn("duplicate_path", {item["reason"] for item in report["excluded_files"]})

    def test_unicode_equivalent_file_list_paths_collide_after_nfc_normalisation(self):
        decomposed = "cafe\u0301.py"
        report = self._report({
            "files": [
                {"path": "caf\u00e9.py", "content": "print(1)\n"},
                {"path": decomposed, "content": "print(2)\n"},
            ]
        })
        self.assertIn("duplicate_path", {item["reason"] for item in report["excluded_files"]})
        self.assertEqual({item["path"] for item in report["files"]}, {"caf\u00e9.py"})

    def test_unicode_equivalent_zip_paths_collide_after_nfc_normalisation(self):
        decomposed = "cafe\u0301.py"
        encoded, _ = zip_payload([
            ("caf\u00e9.py", "print(1)\n"),
            (decomposed, "print(2)\n"),
        ])
        report = self._report({"zip_base64": encoded})
        self.assertIn("duplicate_path", {item["reason"] for item in report["excluded_files"]})
        self.assertEqual({item["path"] for item in report["files"]}, {"caf\u00e9.py"})

    def test_folder_path_is_returned_in_nfc_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "cafe\u0301.py"
            target.write_text("print(1)\n", encoding="utf-8")
            files = project_io.read_folder_files(root)
            self.assertEqual([item["path"] for item in files], ["caf\u00e9.py"])

    def test_folder_unicode_equivalent_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            composed = root / "caf\u00e9.py"
            decomposed = root / "cafe\u0301.py"
            composed.write_text("print(1)\n", encoding="utf-8")
            decomposed.write_text("print(2)\n", encoding="utf-8")
            if composed.samefile(decomposed):
                self.skipTest("filesystem canonicalises Unicode-equivalent names")
            with self.assertRaisesRegex(project_io.ProjectInputError, "Unicode/case-equivalent"):
                project_io.read_folder_files(root)

    def test_ignore_file_below_ignored_directory_cannot_control_project(self):
        payload = {"files": [{"path": "node_modules/.codeprobeignore", "content": "src/\n"}, {"path": "src/main.py", "content": "print(1)\n"}]}
        report = self._report(payload)
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})

    def test_zip_symlink_ignore_file_cannot_control_project(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            info = zipfile.ZipInfo(".codeprobeignore")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "src/")
            archive.writestr("src/main.py", "print(1)\n")
        report = self._report({
            "zip_base64": base64.b64encode(buffer.getvalue()).decode("ascii")
        })
        excluded = [
            item
            for item in report["excluded_files"]
            if item["path"] == ".codeprobeignore"
        ]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]["reason"], "special_zip_entry")
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})

    def test_explicit_ignore_text_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "ignore_text"):
            engine.analyse_project_payload({"files": [], "ignore_text": "x" * 20, "max_ignore_bytes": 10})

    def test_explicit_ignore_rule_count_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "ignore rule"):
            engine.analyse_project_payload({"files": [], "ignore_text": "a\nb\nc\n", "max_ignore_rules": 2})

    def test_common_export_root_is_stripped_before_root_ignore(self):
        encoded, _ = zip_payload([("repo-main/.codeprobeignore", "generated/\n"), ("repo-main/generated/a.py", "print(1)\n"), ("repo-main/src/main.py", "print(2)\n")])
        report = self._report({"zip_base64": encoded})
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})

    def test_zip64_marker_is_rejected(self):
        encoded, raw = zip_payload([("main.py", "print(1)\n")])
        altered = bytearray(raw)
        eocd = altered.rfind(b"PK\x05\x06")
        altered[eocd + 10:eocd + 12] = (0xFFFF).to_bytes(2, "little")
        with self.assertRaisesRegex(ValueError, "ZIP64"):
            engine.analyse_project_payload({"zip_base64": base64.b64encode(altered).decode("ascii")})

    def test_multidisk_marker_is_rejected(self):
        encoded, raw = zip_payload([("main.py", "print(1)\n")])
        altered = bytearray(raw)
        eocd = altered.rfind(b"PK\x05\x06")
        altered[eocd + 4:eocd + 6] = (1).to_bytes(2, "little")
        with self.assertRaisesRegex(ValueError, "multi-disk"):
            engine.analyse_project_payload({"zip_base64": base64.b64encode(altered).decode("ascii")})

    def test_folder_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"; root.mkdir()
            outside = Path(tmp) / "outside.py"; outside.write_text("print('secret')\n")
            try:
                (root / "link.py").symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(project_io.ProjectInputError, "links"):
                project_io.read_folder_files(root)

    @unittest.skipIf(os.name == "nt", "POSIX special-file test")
    def test_folder_special_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); os.mkfifo(root / "pipe")
            with self.assertRaisesRegex(project_io.ProjectInputError, "special"):
                project_io.read_folder_files(root)

    @unittest.skipIf(os.name == "nt", "permission semantics differ")
    def test_ignored_unreadable_directory_is_not_traversed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); ignored = root / "node_modules"; ignored.mkdir(); (ignored / "large.py").write_text("x" * 10000)
            ignored.chmod(0)
            try:
                (root / "main.py").write_text("print(1)\n")
                files = project_io.read_folder_files(root)
                self.assertEqual({item["path"] for item in files}, {"main.py"})
            finally:
                ignored.chmod(stat.S_IRWXU)

    def test_folder_hard_link_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.py"
            alias = root / "alias.py"
            original.write_text("print(1)\n", encoding="utf-8")
            try:
                os.link(original, alias)
            except OSError:
                self.skipTest("hard-link creation unavailable")
            with self.assertRaisesRegex(project_io.ProjectInputError, "hard-linked"):
                project_io.read_folder_files(root)

    def test_oversized_zip_root_ignore_is_recorded_once_with_exact_reason(self):
        encoded, _ = zip_payload([
            (".codeprobeignore", "generated/\n" * 8),
            ("src/main.py", "print(1)\n"),
        ])
        report = self._report({"zip_base64": encoded, "max_ignore_bytes": 16})
        excluded = [
            item for item in report["excluded_files"]
            if item["path"] == ".codeprobeignore"
        ]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]["reason"], "ignore_file_too_large")
        self.assertEqual({item["path"] for item in report["files"]}, {"src/main.py"})

    def test_folder_total_budget_avoids_second_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "a.py").write_text("a = 1\n" * 5); (root / "b.py").write_text("b = 2\n" * 5)
            files = project_io.read_folder_files(root, max_total_bytes=40)
            self.assertEqual(len([item for item in files if item["content"]]), 1)

    def test_folder_inventory_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(3): (root / f"{index}.py").write_text("print(1)\n")
            with self.assertRaisesRegex(project_io.ProjectInputError, "inventory"):
                project_io.read_folder_files(root, max_entries=2)

    def test_directory_only_inventory_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(3):
                (root / f"directory-{index}").mkdir()
            with self.assertRaisesRegex(project_io.ProjectInputError, "inventory"):
                project_io.read_folder_files(root, max_entries=2)

    def test_inventory_limit_stops_scandir_before_unbounded_materialisation(self):
        class GuardedScandir:
            def __init__(self, directory):
                self.directory = Path(directory)
                self.position = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                self.position += 1
                if self.position <= 3:
                    return type(
                        "Entry",
                        (),
                        {
                            "name": f"entry-{self.position}.py",
                            "path": str(self.directory / f"entry-{self.position}.py"),
                        },
                    )()
                raise AssertionError("scandir was consumed beyond the first over-limit entry")

        with tempfile.TemporaryDirectory() as tmp:
            guarded = GuardedScandir(tmp)
            with mock.patch.object(project_io.os, "scandir", return_value=guarded):
                with self.assertRaisesRegex(project_io.ProjectInputError, "inventory"):
                    project_io.list_bounded_regular_files(Path(tmp), max_entries=2)
            self.assertEqual(guarded.position, 3)

    def test_file_growth_cannot_cross_remaining_total_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "main.py"
            target.write_text("x = 1\n", encoding="utf-8")
            original = project_io.read_bounded_regular_file

            def grow_before_read(path, *, root, max_bytes):
                Path(path).write_text("x" * 100, encoding="utf-8")
                return original(Path(path), root=Path(root), max_bytes=max_bytes)

            with mock.patch.object(
                project_io,
                "read_bounded_regular_file",
                side_effect=grow_before_read,
            ):
                with self.assertRaisesRegex(
                    project_io.ProjectInputError, "byte limit|input limit"
                ):
                    project_io.read_folder_files(
                        root, max_file_bytes=200, max_total_bytes=20
                    )

    def test_folder_limits_reject_boolean_and_non_positive_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for kwargs in (
                {"max_entries": 0},
                {"max_files": False},
                {"max_file_bytes": -1},
                {"max_total_bytes": 0},
                {"max_ignore_bytes": 0},
                {"max_ignore_rules": 0},
            ):
                with self.subTest(kwargs=kwargs):
                    with self.assertRaises(project_io.ProjectInputError):
                        project_io.read_folder_files(root, **kwargs)


class BoundedProjectControlTests(unittest.TestCase):
    @staticmethod
    def _args(root, **changes):
        values = dict(
            folder=str(root / "project"), zip=None, project_name="owned fixture",
            profile=None, include_documentation=False, config=None,
            calibration_profile=None, ignore_file=None, max_file_bytes=1000,
            max_total_bytes=10000, max_entries=20, max_files=10,
            max_archive_bytes=10000, max_ignore_bytes=1000, max_ignore_rules=100,
            max_compression_ratio=100.0, json_out=str(root / "report.json"),
            text_out=str(root / "report.txt"),
        )
        values.update(changes)
        return argparse.Namespace(**values)

    def test_integer_forms_and_zero_exact_read_limits_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input"
            for content, limits in ((b"", (0, 0.0, "0")), (b"x", (1, 1.0, " +1 "))):
                path.write_bytes(content)
                for limit in limits:
                    with self.subTest(content=content, limit=limit):
                        self.assertEqual(project_io.read_bounded_regular_file(
                            path, root=root, max_bytes=limit,
                        ), content)
            for value in (1, 1.0, "1", " +1 ", "1_0", "\u0661"):
                with self.subTest(value=value):
                    native = project_io._bounded_positive_int("max_entries", value, maximum=20)
                    runtime = engine._project_limit({"max_entries": value}, "max_entries", 2, minimum=1, maximum=20)
                    self.assertEqual(native, runtime)
                    self.assertEqual(native, int(value))

    def test_invalid_integer_forms_are_refused_before_filesystem_access(self):
        for value in (True, False, 1.9, "1.9", float("nan"), float("inf"), -float("inf"), "NaN", "Infinity", b"1", None, []):
            with self.subTest(value=repr(value)):
                with mock.patch.object(project_io, "_inspect_no_redirects") as inspect:
                    with self.assertRaises(project_io.ProjectInputError):
                        project_io.read_bounded_regular_file(Path("unused"), root=Path("."), max_bytes=value)
                    inspect.assert_not_called()
                with mock.patch.object(project_io, "_walk_metadata") as walk:
                    with self.assertRaises(project_io.ProjectInputError):
                        project_io.read_folder_files(Path("unused"), max_entries=value)
                    walk.assert_not_called()

    def test_both_opens_request_available_nonblocking_and_nofollow_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input"
            path.write_bytes(b"owned")
            real_open = os.open
            flags_seen = []
            def open_owned(path, flags):
                flags_seen.append(flags)
                return real_open(path, flags)
            with mock.patch.object(project_io.os, "open", side_effect=open_owned):
                self.assertEqual(project_io.read_bounded_regular_file(path, root=root, max_bytes=5), b"owned")
            self.assertEqual(len(flags_seen), 2)
            available_flags = (
                getattr(os, "O_NONBLOCK", 0), getattr(os, "O_NOFOLLOW", 0),
                getattr(os, "O_CLOEXEC", 0), getattr(os, "O_BINARY", 0),
            )
            for flags in flags_seen:
                for expected in available_flags:
                    self.assertEqual(flags & expected, expected)

    def test_each_open_rejects_a_simulated_special_descriptor_before_use(self):
        for selected_open in (1, 2):
            with self.subTest(selected_open=selected_open), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "input"
                path.write_bytes(b"owned")
                real_open, real_fstat, real_read = os.open, os.fstat, os.read
                opened, events = [], []
                def open_owned(path, flags):
                    if hasattr(os, "O_NONBLOCK"):
                        self.assertTrue(flags & os.O_NONBLOCK)
                    descriptor = real_open(path, flags)
                    opened.append(descriptor)
                    events.append(("open", len(opened)))
                    return descriptor
                def inspect(descriptor):
                    metadata = real_fstat(descriptor)
                    if len(opened) == selected_open and descriptor == opened[-1]:
                        events.append(("special", selected_open))
                        return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
                    return metadata
                def read(descriptor, count):
                    events.append(("read", count))
                    return real_read(descriptor, count)
                with mock.patch.object(project_io.os, "open", side_effect=open_owned), mock.patch.object(project_io.os, "fstat", side_effect=inspect), mock.patch.object(project_io.os, "read", side_effect=read), mock.patch.object(project_io.os.path, "sameopenfile") as same:
                    with self.assertRaisesRegex(project_io.ProjectInputError, "regular file"):
                        project_io.read_bounded_regular_file(path, root=root, max_bytes=5)
                    same.assert_not_called()
                self.assertEqual(len(opened), selected_open)
                self.assertIn(("special", selected_open), events)
                if selected_open == 1:
                    self.assertFalse(any(event[0] == "read" for event in events))
                for descriptor in opened:
                    with self.assertRaises(OSError):
                        real_fstat(descriptor)
                self.assertEqual(path.read_bytes(), b"owned")

    def test_verification_descriptor_identity_is_checked_before_sameopenfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "input"
            path.write_bytes(b"owned")
            real_open, real_fstat = os.open, os.fstat
            opened = []
            def open_owned(path, flags):
                descriptor = real_open(path, flags)
                opened.append(descriptor)
                return descriptor
            def inspect(descriptor):
                metadata = real_fstat(descriptor)
                if len(opened) == 2 and descriptor == opened[1]:
                    fields = {name: getattr(metadata, name) for name in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
                    fields["st_ino"] += 1
                    return SimpleNamespace(**fields)
                return metadata
            with mock.patch.object(project_io.os, "open", side_effect=open_owned), mock.patch.object(project_io.os, "fstat", side_effect=inspect), mock.patch.object(project_io.os.path, "sameopenfile") as same:
                with self.assertRaisesRegex(project_io.ProjectInputError, "changed during read"):
                    project_io.read_bounded_regular_file(path, root=root, max_bytes=5)
                same.assert_not_called()
            for descriptor in opened:
                with self.assertRaises(OSError):
                    real_fstat(descriptor)

    def test_control_inputs_use_their_declared_caps_before_body_read(self):
        for option, constant in (("config", "MAX_CONFIG_BYTES"), ("calibration_profile", "MAX_CALIBRATION_PROFILE_BYTES")):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "control.json"
                path.write_bytes(b" " * 33)
                args = self._args(root, **{option: str(path)})
                with mock.patch.object(analyze_project, constant, 32), mock.patch.object(project_io.os, "read") as read, mock.patch.object(analyze_project, "project_payload_from_path") as intake:
                    with self.assertRaisesRegex(ValueError, "32-byte input limit"):
                        analyze_project.build_payload(args)
                    read.assert_not_called()
                    intake.assert_not_called()
                self.assertEqual(path.read_bytes(), b" " * 33)

    def test_control_input_growth_reads_at_most_cap_plus_one(self):
        for option, constant in (("config", "MAX_CONFIG_BYTES"), ("calibration_profile", "MAX_CALIBRATION_PROFILE_BYTES")):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / "control.json"
                path.write_bytes(b"{}" + b" " * 30)
                real_read = os.read
                requested, received = [], []
                def grow_read(descriptor, count):
                    if not requested:
                        path.write_bytes(b"{}" + b" " * 62)
                    requested.append(count)
                    data = real_read(descriptor, count)
                    received.append(len(data))
                    return data
                with mock.patch.object(analyze_project, constant, 32), mock.patch.object(project_io.os, "read", side_effect=grow_read), mock.patch.object(analyze_project, "project_payload_from_path") as intake:
                    with self.assertRaisesRegex(ValueError, "32-byte limit while being read"):
                        analyze_project.build_payload(self._args(root, **{option: str(path)}))
                    intake.assert_not_called()
                self.assertEqual(requested, [33])
                self.assertEqual(sum(received), 33)
                self.assertEqual(path.read_bytes(), b"{}" + b" " * 62)

    def test_control_objects_at_exact_cap_are_accepted(self):
        for option, constant in (("config", "MAX_CONFIG_BYTES"), ("calibration_profile", "MAX_CALIBRATION_PROFILE_BYTES")):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "project").mkdir()
                path = root / "control.json"
                path.write_bytes(b"{}" + b" " * 30)
                with mock.patch.object(analyze_project, constant, 32):
                    payload = analyze_project.build_payload(self._args(root, **{option: str(path)}))
                key = "config_override" if option == "config" else option
                self.assertEqual(payload[key], {})
                self.assertEqual(payload["files"], [])
                self.assertEqual(path.read_bytes(), b"{}" + b" " * 30)

    def test_default_folder_and_zip_names_and_explicit_name_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "owned-project"
            project.mkdir()
            archive = root / "owned-export.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("main.py", "print(1)\n")
            for source, expected in (({"folder": str(project)}, "owned-project"), ({"folder": None, "zip": str(archive)}, "owned-export")):
                for requested in ("", "explicit name"):
                    with self.subTest(source=source, requested=requested):
                        payload = analyze_project.build_payload(self._args(root, project_name=requested, **source))
                        self.assertEqual(payload["project_name"], requested or expected)

    def test_invalid_control_json_preserves_inputs_and_output_sentinels(self):
        cases = (b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}', b"[]", b"null", b"true", b'"text"', b"", b"{", b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":"\xff"}')
        for option in ("--config", "--calibration-profile"):
            for data in cases:
                with self.subTest(option=option, data=data), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    project = root / "project"
                    project.mkdir()
                    source = project / "main.py"
                    source.write_bytes(b"print(1)\n")
                    control, jout, tout = (root / name for name in ("control.json", "report.json", "report.txt"))
                    control.write_bytes(data)
                    jout.write_bytes(b"previous JSON")
                    tout.write_bytes(b"previous text")
                    before = {p: p.read_bytes() for p in (source, control, jout, tout)}
                    with mock.patch.object(analyze_project, "project_payload_from_path") as intake, contextlib.redirect_stderr(io.StringIO()) as stderr:
                        result = analyze_project.main(["--folder", str(project), option, str(control), "--json-out", str(jout), "--text-out", str(tout)])
                        intake.assert_not_called()
                    self.assertEqual(result, 2)
                    self.assertIn("configuration" if option == "--config" else "calibration profile", stderr.getvalue())
                    self.assertEqual({p: p.read_bytes() for p in before}, before)
                    self.assertEqual(list(root.glob(".codeprobe-report-*")), [])

    def test_semantically_invalid_config_is_rejected_before_project_intake(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "config.json"
            for data in ({"unknown": {}}, {"line_length_uniformity": []}, {"line_length_uniformity": {"enabled": "true"}}):
                with self.subTest(data=data):
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with mock.patch.object(analyze_project, "project_payload_from_path") as intake:
                        with self.assertRaises(ValueError):
                            analyze_project.build_payload(self._args(root, config=str(path)))
                        intake.assert_not_called()

    def test_invalid_cli_limits_precede_control_open_and_project_intake(self):
        for changes in ({"max_entries": 1.9}, {"max_files": True}, {"max_compression_ratio": float("nan")}, {"max_compression_ratio": float("inf")}, {"max_compression_ratio": 0}, {"max_compression_ratio": 1001}):
            with self.subTest(changes=changes), mock.patch.object(analyze_project, "_read_json_input") as control, mock.patch.object(analyze_project, "project_payload_from_path") as intake:
                with self.assertRaises(ValueError):
                    analyze_project.build_payload(self._args(Path("unused"), config="unused.json", **changes))
                control.assert_not_called()
                intake.assert_not_called()

    def test_control_leaf_and_root_redirects_are_refused_without_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            path = real / "control.json"
            path.write_bytes(b"{}")
            leaf, parent = root / "leaf.json", root / "alias"
            try:
                leaf.symlink_to(path)
                parent.symlink_to(real, target_is_directory=True)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("symbolic-link privilege unavailable")
                raise
            for alias in (leaf, parent / "control.json"):
                with self.subTest(alias=alias), mock.patch.object(project_io.os, "read") as read:
                    with self.assertRaisesRegex(ValueError, "link|reparse"):
                        analyze_project._read_json_input(str(alias), "owned control", max_bytes=32)
                    read.assert_not_called()
            self.assertEqual(path.read_bytes(), b"{}")

    def test_valid_shipped_profile_and_config_preserve_effective_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            code = "def add(left, right):\n    return left + right\n"
            (project / "main.py").write_text(code, encoding="utf-8")
            override = {"line_length_uniformity": {"weight": 0.17}}
            config = root / "config.json"
            config.write_text(json.dumps(override), encoding="utf-8")
            profile_path = ROOT / "calibration/03-example-calibration-profile.json"
            args = self._args(root, config=str(config), calibration_profile=str(profile_path))
            actual = engine.analyse_project_payload(analyze_project.build_payload(args))
            expected_payload = project_io.project_payload_from_path(project, max_file_bytes=1000, max_total_bytes=10000, max_entries=20, max_files=10, max_archive_bytes=10000, max_ignore_bytes=1000, max_ignore_rules=100)
            expected_payload.update(project_name="owned fixture", config_override=override, calibration_profile=json.loads(profile_path.read_text(encoding="utf-8")))
            expected = engine.analyse_project_payload(expected_payload)
            for key in ("decision_score", "metric_config_digest", "calibration_profile", "included_file_count", "excluded_files"):
                self.assertEqual(actual[key], expected[key], key)

class CoherentProjectIntakeTests(unittest.TestCase):
    def test_duplicate_root_controls_are_inert_in_both_containers_and_orders(self):
        for names in ((".CODEPROBEIGNORE", ".codeprobeignore"), (".codeprobeignore", ".CODEPROBEIGNORE")):
            entries = [(name, "src/\n") for name in names] + [("src/main.py", "print(1)\n")]
            encoded, _ = zip_payload(entries)
            for payload in ({"files": [{"path": name, "content": text} for name, text in entries]}, {"zip_base64": encoded}):
                with self.subTest(names=names, container="zip" if "zip_base64" in payload else "files"):
                    opened = []
                    original = engine._read_zip_member_bounded
                    def read(archive, info, maximum):
                        opened.append(info.orig_filename)
                        return original(archive, info, maximum)
                    with mock.patch.object(engine, "_read_zip_member_bounded", side_effect=read):
                        report = engine.analyse_project_payload(payload)
                    self.assertEqual([item["path"] for item in report["files"]], ["src/main.py"])
                    self.assertEqual([item["reason"] for item in report["excluded_files"]], ["duplicate_path", "duplicate_path"])
                    self.assertFalse(any(name.casefold() == ".codeprobeignore" for name in opened))
                    self.assertNotIn("Loaded the project-root .codeprobeignore.", report["notes"])

    def test_zip_original_nul_names_are_rejected_without_reading_the_member(self):
        for path in ("Xbad.py", "badXname.py", "good.pyXbad"):
            encoded, raw = zip_payload([(path, "print(1)\n"), ("safe.py", "print(2)\n")])
            altered = raw.replace(path.encode(), path.replace("X", "\x00").encode())
            calls = []
            original = engine._read_zip_member_bounded
            def read(archive, info, maximum):
                calls.append(info.orig_filename)
                return original(archive, info, maximum)
            with self.subTest(path=path), mock.patch.object(engine, "_read_zip_member_bounded", side_effect=read):
                report = engine.analyse_project_payload({"zip_base64": base64.b64encode(altered).decode("ascii")})
            self.assertEqual([item["path"] for item in report["files"]], ["safe.py"])
            self.assertEqual(report["excluded_files"][0]["reason"], "unsafe_path")
            self.assertIn("\\x00", report["excluded_files"][0]["path"])
            self.assertEqual(calls, ["safe.py"])

    def test_nul_positions_share_one_disposition_and_never_contribute_a_score(self):
        for position in (0, 4095, 4096, 4100):
            text = "#" * position + "\x00" + "\n"
            encoded, _ = zip_payload([("main.py", text)], compression=zipfile.ZIP_STORED)
            for payload in ({"files": [{"path": "main.py", "content": text}]}, {"zip_base64": encoded}):
                with self.subTest(position=position, zip="zip_base64" in payload):
                    report = engine.analyse_project_payload(payload)
                    self.assertEqual(report["excluded_files"][0]["reason"], "undecodable_text")
                    self.assertEqual(report["excluded_files"][0]["size_bytes"], len(text))
                    self.assertFalse(report["overall_applicable"])
            self.assertIsNone(engine.decode_text_bytes(text.encode())[0])

    def test_content_exclusions_do_not_consume_the_single_analysis_slot(self):
        for first in ("", "const x='" + "a" * 1900 + "';"):
            entries = [("a.js", first), ("b.py", "print(1)\n"), ("c.py", "print(2)\n")]
            encoded, _ = zip_payload(entries, compression=zipfile.ZIP_STORED)
            for payload in ({"files": [{"path": path, "content": text} for path, text in entries]}, {"zip_base64": encoded}):
                with self.subTest(empty=not first, zip="zip_base64" in payload):
                    report = engine.analyse_project_payload({**payload, "max_files": 1})
                    self.assertEqual([item["path"] for item in report["files"]], ["b.py"])
                    self.assertEqual(report["excluded_files"][-1]["reason"], "project_file_limit")

    def test_content_exclusions_still_consume_the_independent_byte_budget(self):
        text = "const x='" + "a" * 1900 + "';"
        report = engine.analyse_project_payload({"max_files": 1, "max_total_bytes": len(text), "files": [
            {"path": "a.js", "content": text}, {"path": "b.py", "content": "print(1)\n"}]})
        self.assertEqual([item["reason"] for item in report["excluded_files"]], ["minified_or_bundled_asset", "project_total_byte_limit"])
        with self.assertRaisesRegex(ValueError, "entry limit"):
            engine.analyse_project_payload({"max_zip_entries": 2, "files": [{"path": f"{index}.py", "content": ""} for index in range(3)]})

    def test_root_control_compression_and_zero_size_are_checked_before_read(self):
        encoded, raw = zip_payload([(".codeprobeignore", "#" * 512), ("src/main.py", "print(1)\n")])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            info = archive.getinfo(".codeprobeignore")
            ratio = info.file_size / info.compress_size
        for maximum, expected in ((ratio, "ignore_file"), (ratio - 0.01, "compression_ratio_exceeded")):
            calls = []
            original = engine._read_zip_member_bounded
            def read(archive, info, maximum_bytes):
                calls.append(info.orig_filename)
                return original(archive, info, maximum_bytes)
            with mock.patch.object(engine, "_read_zip_member_bounded", side_effect=read):
                report = engine.analyse_project_payload({"zip_base64": encoded, "max_compression_ratio": maximum})
            self.assertEqual(report["excluded_files"][0]["reason"], expected)
            self.assertEqual(".codeprobeignore" in calls, expected == "ignore_file")
        altered = bytearray(raw)
        central = altered.index(b"PK\x01\x02")
        altered[central + 20:central + 24] = b"\0" * 4
        with mock.patch.object(engine, "_read_zip_member_bounded", wraps=engine._read_zip_member_bounded) as read:
            report = engine.analyse_project_payload({"zip_base64": base64.b64encode(altered).decode("ascii")})
        self.assertEqual(report["excluded_files"][0]["reason"], "compression_ratio_exceeded")
        self.assertFalse(any(call.args[1].orig_filename == ".codeprobeignore" for call in read.call_args_list))
        for invalid in (float("nan"), float("inf"), -float("inf")):
            with mock.patch.object(engine, "collect_project_files") as collect:
                with self.assertRaisesRegex(ValueError, "finite"):
                    engine.analyse_project_payload({"zip_base64": encoded, "max_compression_ratio": invalid})
                collect.assert_not_called()

    def test_exact_base64_limits_accept_every_padding_class_and_reject_one_byte_over(self):
        observed = set()
        for comment_size in range(3):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("main.py", "print(1)\n")
                archive.comment = b"x" * comment_size
            raw = buffer.getvalue()
            observed.add(len(raw) % 3)
            encoded = base64.b64encode(raw).decode("ascii")
            self.assertEqual(engine.analyse_project_payload({"zip_base64": encoded, "max_zip_bytes": len(raw)})["included_file_count"], 1)
            with self.assertRaisesRegex(ValueError, "compressed ZIP limit"):
                engine.analyse_project_payload({"zip_base64": encoded, "max_zip_bytes": len(raw) - 1})
        self.assertEqual(observed, {0, 1, 2})
        for encoded in ("A===", "AAAA!", "AAAA\n", "A" * 100):
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                engine.analyse_project_payload({"zip_base64": encoded, "max_zip_bytes": 10})

    def test_internal_native_exclusions_preserve_reason_size_and_lose_privilege_in_json(self):
        native = engine._NativeProjectFile(path="large.py", content="", size_bytes=101,
                                         pre_exclusion_reason="file_too_large", pre_exclusion_detail="Bounded native metadata.")
        report = engine.analyse_project_payload({"files": [native], "max_file_bytes": 100})
        self.assertEqual((report["excluded_files"][0]["reason"], report["excluded_files"][0]["size_bytes"]), ("file_too_large", 101))
        self.assertIn("101 selected bytes", engine.format_project_report_text(report))
        public = json.loads(json.dumps(native))
        public["native_pre_exclusion"] = ["file_too_large", "forged", 101]
        report = engine.analyse_project_payload({"files": [public], "max_file_bytes": 100})
        self.assertEqual((report["excluded_files"][0]["reason"], report["excluded_files"][0]["size_bytes"]), ("empty_file", 0))
        with self.assertRaises(ValueError):
            engine._NativeProjectFile(path="main.py", content="print(1)\n", size_bytes=1, pre_exclusion_reason="file_too_large")

    def test_slash_patterns_are_root_relative_and_basename_patterns_are_recursive(self):
        rules = engine.parse_ignore_patterns("generated/\n!generated/student_owned.py\n")
        self.assertFalse(engine.project_path_is_ignored("generated/student_owned.py", rules))
        self.assertTrue(engine.project_path_is_ignored("nested/generated/student_owned.py", rules))
        self.assertTrue(engine.project_path_is_ignored("nested/secret.py", engine.parse_ignore_patterns("secret.py")))

    def test_root_control_byte_limit_is_separate_from_source_limit(self):
        report = engine.analyse_project_payload({"max_file_bytes": 10, "max_ignore_bytes": 100, "files": [
            {"path": ".codeprobeignore", "content": "# a bounded root control\n"}, {"path": "main.py", "content": "print(1)\n"}]})
        self.assertEqual(report["excluded_files"][0]["reason"], "ignore_file")
        self.assertEqual(report["included_file_count"], 1)
        encoded, _ = zip_payload([(".codeprobeignore", b"#\xff\n"), ("main.py", "print(1)\n")], compression=zipfile.ZIP_STORED)
        report = engine.analyse_project_payload({"zip_base64": encoded, "max_ignore_bytes": 3})
        self.assertEqual(report["excluded_files"][0]["reason"], "ignore_file")
        self.assertEqual(report["excluded_files"][0]["size_bytes"], 3)
        self.assertEqual(report["included_file_count"], 1)

    def test_native_reinclusion_preserves_paths_and_does_not_expand_unrelated_dependencies(self):
        for external in (False, True):
            with self.subTest(external=external), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "generated").mkdir()
                (root / "generated/student_owned.py").write_text("print(1)\n", encoding="utf-8")
                (root / "generated/other.py").write_text("print(2)\n", encoding="utf-8")
                (root / "node_modules").mkdir()
                (root / "node_modules/dependency.py").write_text("print(3)\n", encoding="utf-8")
                ignore = "!generated/student_owned.py\n"
                if not external:
                    (root / ".codeprobeignore").write_text(ignore, encoding="utf-8")
                traversed = []
                original = project_io.os.scandir
                def scandir(path):
                    traversed.append(Path(path))
                    return original(path)
                with mock.patch.object(project_io.os, "scandir", side_effect=scandir):
                    payload = project_io.project_payload_from_path(root, ignore_text=ignore if external else "")
                report = engine.analyse_project_payload(payload)
                self.assertEqual([item["path"] for item in report["files"]], ["generated/student_owned.py"])
                self.assertNotIn(root / "node_modules", traversed)
                self.assertEqual(report["input_packaging"]["unexpanded_directories"], ["node_modules"])
                self.assertIn("Unexpanded directories (children were not inventoried):\n- node_modules", engine.format_project_report_text(report))
                self.assertFalse(report["input_packaging"]["common_root_stripped"])
                self.assertFalse(any(item["path"].startswith("node_modules/") for item in report["excluded_files"]))

    def test_native_filename_rule_does_not_prune_other_languages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src/a.py").write_text("print(1)\n", encoding="utf-8")
            (root / "src/b.js").write_text("const result = 2;\n", encoding="utf-8")
            report = engine.analyse_project_payload(project_io.project_payload_from_path(root, ignore_text="*.py\n"))
            self.assertEqual([item["path"] for item in report["files"]], ["src/b.js"])
            self.assertEqual(report["excluded_files"][0]["reason"], "ignored_by_codeprobeignore")

    def test_native_empty_and_minified_files_preserve_budget_and_single_slot(self):
        for first in (b"", b"const x='" + b"a" * 1900 + b"';"):
            with self.subTest(empty=not first), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "a.js").write_bytes(first)
                (root / "b.py").write_bytes(b"print(1)\n")
                payload = project_io.project_payload_from_path(root, max_files=1)
                report = engine.analyse_project_payload(payload)
                self.assertEqual([item["path"] for item in report["files"]], ["b.py"])
                self.assertEqual(report["excluded_files"][0]["size_bytes"], len(first))

    def test_native_preexclusions_have_exact_size_reason_and_no_forbidden_body_read(self):
        cases = ((b"x" * 101, {"max_file_bytes": 100}, "file_too_large", False),
                 (b"x" * 11, {"max_total_bytes": 10}, "project_total_byte_limit", False),
                 (b"x" * 4096 + b"\0", {}, "undecodable_text", True),
                 (b"", {}, "empty_file", True))
        for data, limits, expected, should_read in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "main.py").write_bytes(data)
                with mock.patch.object(project_io, "read_bounded_regular_file", wraps=project_io.read_bounded_regular_file) as read:
                    payload = project_io.project_payload_from_path(root, **limits)
                self.assertEqual(bool(read.call_count), should_read)
                report = engine.analyse_project_payload(payload)
                self.assertEqual((report["excluded_files"][0]["reason"], report["excluded_files"][0]["size_bytes"]), (expected, len(data)))
                self.assertIn(f"{len(data)} selected bytes", engine.format_project_report_text(report))
                self.assertEqual((root / "main.py").read_bytes(), data)

    def test_native_directory_depth_accepts_64_and_refuses_65_before_child_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root
            for _ in range(64):
                current /= "d"
                current.mkdir()
            (current / "main.py").write_text("print(1)\n", encoding="utf-8")
            report = engine.analyse_project_payload(project_io.project_payload_from_path(root, max_entries=100))
            self.assertEqual(report["included_file_count"], 1)
            excessive = current / "d"
            excessive.mkdir()
            calls = []
            original = project_io.os.scandir
            def scandir(path):
                calls.append(Path(path))
                return original(path)
            with mock.patch.object(project_io.os, "scandir", side_effect=scandir):
                with self.assertRaisesRegex(project_io.ProjectInputError, "depth exceeds 64"):
                    project_io.project_payload_from_path(root, max_entries=100)
            self.assertNotIn(excessive, calls)

    def test_native_root_aliases_fail_before_control_body_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upper, lower = root / ".CODEPROBEIGNORE", root / ".codeprobeignore"
            upper.write_text("src/\n", encoding="utf-8")
            lower.write_text("src/\n", encoding="utf-8")
            if upper.samefile(lower):
                self.skipTest("filesystem canonicalises case-equivalent names")
            with mock.patch.object(project_io, "read_bounded_regular_file") as read:
                with self.assertRaisesRegex(project_io.ProjectInputError, "Unicode/case-equivalent"):
                    project_io.project_payload_from_path(root)
                read.assert_not_called()


class PythonProjectDiagnosticTests(unittest.TestCase):
    INVALID = "def broken():\n    if True:\n        return 1\n  return 0\n"
    VALID = "def add(left, right):\n    result = left + right\n    return result\n\ndef subtract(left, right):\n    return left - right\n"

    def test_member_diagnostics_reach_project_json_text_and_python_api(self):
        payload = {"project_name": "parser-fixture", "files": [
            {"path": "broken.py", "content": self.INVALID},
            {"path": "valid.py", "content": self.VALID},
        ]}
        for entry in (api.analyse_project, lambda item: json.loads(engine.codeprobe_analyze_project(json.dumps(item)))):
            result = entry(payload)
            report = result["project_report"]
            self.assertEqual(result["report"], report)
            self.assertEqual([item["path"] for item in report["files"]], ["broken.py", "valid.py"])
            broken = next(item for item in report["files"] if item["path"] == "broken.py")
            warnings = broken["warnings"]
            self.assertTrue(any("IndentationError at line 4," in item for item in warnings))
            qualified = [item for item in report["warnings"] if "broken.py" in item and "IndentationError at line 4," in item]
            self.assertTrue(qualified)
            for diagnostic in qualified:
                self.assertIn(diagnostic, result["text"])
            self.assertEqual(report["included_file_count"], 2)
            with self.assertRaisesRegex(ValueError, "requires a successful AST parse"):
                entry({**payload, "require_python_ast": True})

    def test_project_cli_reports_unbound_errors_and_preserves_outputs_on_bound_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "broken.py"
            source.write_text(self.INVALID, encoding="utf-8")
            json_out, text_out = root / "report.json", root / "report.txt"
            args = ["--folder", str(project), "--json-out", str(json_out), "--text-out", str(text_out)]
            self.assertEqual(analyze_project.main(args), 0)
            report = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertTrue(any("broken.py" in item and "IndentationError" in item for item in report["warnings"]))
            self.assertIn("IndentationError", text_out.read_text(encoding="utf-8"))
            profile_path = root / "bound-profile.json"
            profile = {"profile_id": "owned-parser-contract", "scoring_contract": engine.scoring_contract("default", engine.merged_metric_config("default"))}
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            before = {path: path.read_bytes() for path in (source, profile_path, json_out, text_out)}
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                status = analyze_project.main([*args, "--calibration-profile", str(profile_path)])
            self.assertEqual(status, 2)
            self.assertIn("requires a successful AST parse", stderr.getvalue())
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            self.assertEqual(list(root.glob(".codeprobe-report-*")), [])


if __name__ == "__main__":
    unittest.main()
