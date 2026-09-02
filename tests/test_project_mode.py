from __future__ import annotations

import base64
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine import project_io  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
