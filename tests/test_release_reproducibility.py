from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import check_release_reproducibility as reproducibility  # noqa: E402


class ReleaseReproducibilityUnitTests(unittest.TestCase):
    @staticmethod
    def snapshot(files: dict[str, bytes]) -> reproducibility.GitSnapshot:
        entries: dict[str, reproducibility.TreeEntry] = {}
        for directory in reproducibility._derived_directories(list(files)):
            entries[directory] = reproducibility.TreeEntry("directory")
        for path, content in files.items():
            entries[path] = reproducibility.TreeEntry(
                "file",
                len(content),
                hashlib.sha256(content).hexdigest(),
                "100644",
            )
        return reproducibility.GitSnapshot(dict(sorted(entries.items())), dict(sorted(files.items())))

    @staticmethod
    def write_tar(path: Path, members: list[tuple[str, str, bytes]]) -> None:
        with tarfile.open(path, "w") as archive:
            for name, kind, content in members:
                info = tarfile.TarInfo(name)
                if kind == "directory":
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                elif kind == "file":
                    info.type = tarfile.REGTYPE
                    info.mode = 0o644
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
                elif kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "target"
                    archive.addfile(info)
                else:  # pragma: no cover - test helper guard
                    raise AssertionError(kind)

    def test_parse_ls_tree_z_preserves_spaces_and_accepts_long_object_ids(self) -> None:
        first_id = b"a" * 40
        second_id = b"b" * 64
        payload = (
            b"100644 blob " + first_id + b"\tdocs/guide one.md\0"
            b"100644 blob " + second_id + b"\tsource.py\0"
        )
        leaves = reproducibility.parse_ls_tree_z(payload)
        self.assertEqual([leaf.path for leaf in leaves], ["docs/guide one.md", "source.py"])
        self.assertEqual(leaves[1].object_id, "b" * 64)

    def test_parse_ls_tree_z_rejects_noncanonical_and_colliding_paths(self) -> None:
        object_id = b"a" * 40
        with self.assertRaisesRegex(reproducibility.ReproducibilityError, "not canonical"):
            reproducibility.parse_ls_tree_z(b"100644 blob " + object_id + b"\tdocs/../escape.txt\0")
        with self.assertRaisesRegex(reproducibility.ReproducibilityError, "case-insensitive"):
            reproducibility.parse_ls_tree_z(
                b"100644 blob " + object_id + b"\tReadme.md\0"
                b"100644 blob " + object_id + b"\tREADME.md\0"
            )

    def test_safe_archive_extraction_materialises_exact_regular_files(self) -> None:
        expected = self.snapshot({"docs/guide.md": b"guide\n", "source.py": b"print(1)\n"})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "source.tar"
            destination = root / "export"
            self.write_tar(
                archive_path,
                [
                    ("docs", "directory", b""),
                    ("docs/guide.md", "file", b"guide\n"),
                    ("source.py", "file", b"print(1)\n"),
                ],
            )
            reproducibility.extract_git_archive_safely(archive_path, destination, expected)
            self.assertEqual((destination / "docs" / "guide.md").read_bytes(), b"guide\n")
            self.assertEqual((destination / "source.py").read_bytes(), b"print(1)\n")

    def test_safe_archive_extraction_rejects_traversal_and_links(self) -> None:
        expected = self.snapshot({"safe.txt": b"safe\n"})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            traversal = root / "traversal.tar"
            self.write_tar(traversal, [("../escape.txt", "file", b"safe\n")])
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "not canonical"):
                reproducibility.extract_git_archive_safely(traversal, root / "traversal-export", expected)
            self.assertFalse((root / "escape.txt").exists())

            linked = root / "linked.tar"
            self.write_tar(linked, [("safe.txt", "symlink", b"")])
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "forbidden"):
                reproducibility.extract_git_archive_safely(linked, root / "linked-export", expected)

    def test_safe_archive_extraction_rejects_duplicates_and_content_changes(self) -> None:
        expected = self.snapshot({"safe.txt": b"safe\n"})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate = root / "duplicate.tar"
            self.write_tar(
                duplicate,
                [("safe.txt", "file", b"safe\n"), ("safe.txt", "file", b"safe\n")],
            )
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "duplicate"):
                reproducibility.extract_git_archive_safely(duplicate, root / "duplicate-export", expected)

            changed = root / "changed.tar"
            self.write_tar(changed, [("safe.txt", "file", b"evil\n")])
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "first difference"):
                reproducibility.extract_git_archive_safely(changed, root / "changed-export", expected)

    def test_archive_inventory_does_not_hide_a_generated_dot_git_entry(self) -> None:
        expected = self.snapshot({"safe.txt": b"safe\n"})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.txt").write_bytes(b"safe\n")
            (root / ".git").mkdir()
            (root / ".git" / "unexpected").write_bytes(b"generated\n")
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "unexpected '.git'"):
                reproducibility.require_matching_tree(
                    expected,
                    root,
                    label="archive fixture",
                    exclude_git=False,
                )

    def test_packet_verification_rejects_stored_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            packet = reproducibility.PacketPaths(
                root / reproducibility.PACKET_BASENAME,
                root / (reproducibility.PACKET_BASENAME + ".sha256.txt"),
                root / (reproducibility.PACKET_BASENAME + ".package_audit.json"),
            )
            member_name = "CodeProbe_Project_Kit_v1.0/source.py"
            info = zipfile.ZipInfo(member_name, reproducibility.DETERMINISTIC_ZIP_DATETIME)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_STORED
            with zipfile.ZipFile(packet.zip_path, "x") as archive:
                archive.writestr(info, b"print(1)\n")
            content = packet.zip_path.read_bytes()
            packet.checksum_path.write_text(
                f"{hashlib.sha256(content).hexdigest()}  {reproducibility.PACKET_BASENAME}\n",
                encoding="ascii",
            )
            packet.audit_path.write_text(
                json.dumps(reproducibility.summarise_zip(packet.zip_path), indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "metadata is not canonical"):
                reproducibility.verify_packet(
                    packet,
                    {"source.py": b"print(1)\n"},
                    "1.0",
                    label="stored fixture",
                )

    def test_git_environment_removes_ambient_git_controls(self) -> None:
        poisoned = {
            "GIT_DIR": "/tmp/elsewhere",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.autocrlf",
            "GIT_CONFIG_VALUE_0": "input",
            "GIT_WORK_TREE": "/tmp/worktree",
        }
        with mock.patch.dict(os.environ, poisoned, clear=False):
            environment = reproducibility._git_environment()
        for name in poisoned:
            self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")

    def test_forced_crlf_state_is_rejected(self) -> None:
        record = b"i/lf w/crlf attr/text eol=lf\tchanged.txt\0"
        with mock.patch.object(reproducibility, "run_git", return_value=record):
            with self.assertRaisesRegex(reproducibility.ReproducibilityError, "non-LF text state"):
                reproducibility.require_normalised_eol(Path("."), label="fixture")

    def test_recursive_invocation_is_rejected_before_workspace_creation(self) -> None:
        error = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {reproducibility.ACTIVE_ENVIRONMENT_VARIABLE: "1"},
            clear=False,
        ):
            with mock.patch.object(reproducibility.tempfile, "mkdtemp") as creator:
                with contextlib.redirect_stderr(error):
                    exit_code = reproducibility.main([])
        self.assertEqual(exit_code, 1)
        creator.assert_not_called()
        self.assertIn("recursive invocation rejected", error.getvalue())

    def test_byte_difference_and_tree_diagnostics_are_bounded(self) -> None:
        diagnostic = reproducibility.describe_byte_difference(b"abcd", b"abXd", label="fixture")
        self.assertIn("byte offset 2", diagnostic)
        self.assertIn(hashlib.sha256(b"abcd").hexdigest(), diagnostic)
        self.assertNotIn("abcd", diagnostic)
        self.assertNotIn(b"abcd".hex(), diagnostic)

        expected = {f"expected-{index}": reproducibility.TreeEntry("file", 1, "a") for index in range(8)}
        actual = {f"actual-{index}": reproducibility.TreeEntry("file", 1, "b") for index in range(8)}
        messages = reproducibility.tree_mismatch_diagnostics(expected, actual, label="fixture", limit=3)
        self.assertEqual(len(messages), 4)
        self.assertIn("additional", messages[-1])


if __name__ == "__main__":
    unittest.main()
