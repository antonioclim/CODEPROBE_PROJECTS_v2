import errno
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
APP = ROOT / "app"
for pth in (SRC, TOOLS):
    if str(pth) not in sys.path:
        sys.path.insert(0, str(pth))

import build_release
import codeprobe_runtime as engine
from codeprobe_engine.release import (
    ReleaseSetError, build_release_manifest, validate_diagnostic_outputs,
    write_manifest, write_zip_summary, zip_summary,
)
import compare_releases as release_compare


class ReleaseIntegrityTests(unittest.TestCase):
    def _comparison_fixture(self, parent: Path):
        old_zip, new_zip = parent / "old.zip", parent / "new.zip"
        self._zip_with(old_zip, {"oldroot/a.txt": b"alpha"})
        self._zip_with(new_zip, {"newroot/a.txt": b"omega", "newroot/b.txt": b"beta"})
        root = parent / "kit"
        (root / "tools").mkdir(parents=True)
        (root / "release").mkdir()
        source = root / "tools" / "compare_releases.py"
        source.write_bytes(b"# inert source fixture\n")
        metadata = root / "release" / "release-manifest.json"
        metadata.write_bytes(b"{}\n")
        return root, (old_zip, new_zip, source, metadata)

    def _check_comparison_aliases(self, kind: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs = self._comparison_fixture(parent)
            before = {path: path.read_bytes() for path in inputs}
            for index, source in enumerate(inputs):
                for flag in ("--json-out", "--md-out"):
                    with self.subTest(input=source.name, kind=kind, flag=flag):
                        output = parent / f"alias-{index}-{flag[2:]}.txt"
                        if kind == "same":
                            output = source
                        elif kind == "resolved":
                            (source.parent / "unused").mkdir(exist_ok=True)
                            output = source.parent / "unused" / ".." / source.name
                        elif kind == "symlink":
                            self.symlink_or_skip(output, source)
                        else:
                            try:
                                os.link(source, output)
                            except OSError as exc:
                                if exc.errno in {errno.EACCES, errno.EPERM, errno.ENOTSUP}:
                                    self.skipTest(f"hard links are unavailable: {exc}")
                                raise
                        other = parent / "not-created" / "other.txt"
                        other_flag = "--md-out" if flag == "--json-out" else "--json-out"
                        with mock.patch.object(release_compare, "ROOT", root), \
                                mock.patch.object(release_compare, "compare_zip_packages", wraps=release_compare.compare_zip_packages) as compare, \
                                mock.patch.object(sys, "stdout", io.StringIO()):
                            status = release_compare.main([str(inputs[0]), str(inputs[1]), flag, str(output), other_flag, str(other)])
                        self.assertEqual(status, 1)
                        compare.assert_not_called()
                        self.assertFalse(other.parent.exists())
                        self.assertEqual(before, {path: path.read_bytes() for path in inputs})

    def test_comparison_rejects_same_and_resolved_input_paths_before_work(self) -> None:
        self._check_comparison_aliases("same")
        self._check_comparison_aliases("resolved")

    def test_comparison_rejects_hardlink_input_aliases_before_either_report(self) -> None:
        self._check_comparison_aliases("hardlink")

    def test_comparison_rejects_symlink_input_aliases_before_either_report(self) -> None:
        self._check_comparison_aliases("symlink")

    def test_comparison_rejects_same_resolved_and_hardlinked_sibling_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs = self._comparison_fixture(parent)
            for kind in ("same", "resolved", "hardlink"):
                with self.subTest(kind=kind):
                    first = parent / (kind + ".json")
                    first.write_bytes(b"report sentinel\n")
                    second = first
                    if kind == "resolved":
                        (parent / "unused").mkdir()
                        second = parent / "unused" / ".." / first.name
                    elif kind == "hardlink":
                        second = parent / (kind + ".md")
                        os.link(first, second)
                    with mock.patch.object(release_compare, "ROOT", root), \
                            mock.patch.object(sys, "stdout", io.StringIO()):
                        self.assertEqual(release_compare.main([str(inputs[0]), str(inputs[1]), "--json-out", str(first), "--md-out", str(second)]), 1)
                    self.assertEqual(first.read_bytes(), b"report sentinel\n")
                    self.assertEqual(second.read_bytes(), b"report sentinel\n")

    def test_comparison_rejects_symlinked_sibling_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs = self._comparison_fixture(parent)
            first, second = parent / "report.json", parent / "report.md"
            first.write_bytes(b"report sentinel\n")
            self.symlink_or_skip(second, first)
            with mock.patch.object(release_compare, "ROOT", root), mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(release_compare.main([str(inputs[0]), str(inputs[1]), "--json-out", str(first), "--md-out", str(second)]), 1)
            self.assertEqual(first.read_bytes(), b"report sentinel\n")

    def test_comparison_renders_both_reports_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs = self._comparison_fixture(parent)
            before = {path: path.read_bytes() for path in inputs}
            first, second = parent / "report.json", parent / "report.md"
            with mock.patch.object(release_compare, "ROOT", root), mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertEqual(release_compare.main([str(inputs[0]), str(inputs[1]), "--json-out", str(first), "--md-out", str(second)]), 0)
                report = json.loads(first.read_bytes())
                self.assertEqual(report["added_paths"], ["b.txt"])
                self.assertEqual([item["path"] for item in report["changed_paths"]], ["a.txt"])
                self.assertIn("`b.txt`", second.read_text(encoding="utf-8"))
                valid = {path: path.read_bytes() for path in (first, second)}
                with mock.patch.object(release_compare, "render_markdown", return_value="\ud800"):
                    self.assertEqual(release_compare.main([str(inputs[0]), str(inputs[1]), "--json-out", str(first), "--md-out", str(second)]), 1)
            self.assertEqual(valid, {path: path.read_bytes() for path in (first, second)})
            self.assertEqual(before, {path: path.read_bytes() for path in inputs})

    def test_diagnostic_output_ancestor_collision_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            first = parent / "new" / "report.json"
            second = first / "report.md"
            with self.assertRaises(ReleaseSetError):
                validate_diagnostic_outputs((first, second), inputs=())
            self.assertFalse((parent / "new").exists())

    def test_comparison_reports_partial_publication_without_claiming_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root, inputs = self._comparison_fixture(parent)
            first, second = parent / "report.json", parent / "report.md"
            first.write_bytes(b"old JSON sentinel\n")
            second.write_bytes(b"old Markdown sentinel\n")
            publish = release_compare.atomic_write_bytes
            output = io.StringIO()

            def fail_second(path, content):
                if path == second:
                    raise OSError("controlled second-report failure")
                return publish(path, content)

            with mock.patch.object(release_compare, "ROOT", root), \
                    mock.patch.object(release_compare, "atomic_write_bytes", side_effect=fail_second), \
                    mock.patch.object(sys, "stdout", output):
                self.assertEqual(release_compare.main([str(inputs[0]), str(inputs[1]), "--json-out", str(first), "--md-out", str(second)]), 1)
            self.assertEqual(json.loads(first.read_bytes())["added_paths"], ["b.txt"])
            self.assertEqual(second.read_bytes(), b"old Markdown sentinel\n")
            self.assertIn("publication may be partial", output.getvalue())

    def test_zip_summary_rejects_same_resolved_and_hardlinked_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source = parent / "source.zip"
            self._zip_with(source, {"root/a.txt": b"alpha"})
            before = source.read_bytes()
            (parent / "unused").mkdir()
            alias = parent / "hardlink.json"
            os.link(source, alias)
            for output in (source, parent / "unused" / ".." / source.name, alias):
                with self.subTest(output=output):
                    with self.assertRaises(ReleaseSetError):
                        write_zip_summary(source, output)
                    self.assertEqual(source.read_bytes(), before)
            output = parent / "reports" / "summary.json"
            result = write_zip_summary(source, output)
            self.assertEqual(json.loads(output.read_bytes()), result)
            self.assertEqual(result["zip_sha256"], hashlib.sha256(before).hexdigest())
            self.assertEqual(source.read_bytes(), before)

    def test_zip_summary_rejects_symlink_to_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source, output = parent / "source.zip", parent / "report.json"
            self._zip_with(source, {"root/a.txt": b"alpha"})
            before = source.read_bytes()
            self.symlink_or_skip(output, source)
            with self.assertRaises(ReleaseSetError):
                write_zip_summary(source, output)
            self.assertEqual(source.read_bytes(), before)

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
    def make_release_fixture(parent: Path, name: str) -> Path:
        root = parent / name
        (root / "docs").mkdir(parents=True)
        (root / "docs" / "guide.md").write_bytes(b"# Guide\n")
        (root / "source.py").write_bytes(b"print('stable')\n")
        write_manifest(root, engine.APP_VERSION)
        return root

    def test_host_mode_comparison_respects_windows_capabilities(self):
        self.assertTrue(
            build_release._host_mode_matches(0o666, 0o644, platform_name="nt")
        )
        self.assertFalse(
            build_release._host_mode_matches(0o444, 0o644, platform_name="nt")
        )
        self.assertTrue(
            build_release._host_mode_matches(0o644, 0o644, platform_name="posix")
        )
        self.assertFalse(
            build_release._host_mode_matches(0o666, 0o644, platform_name="posix")
        )

    def test_windows_file_metadata_sync_does_not_hide_io_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.zip"
            path.write_bytes(b"packet")
            failure = OSError(errno.EIO, "simulated storage failure")
            with mock.patch.object(build_release.os, "name", "nt"):
                with mock.patch.object(build_release.os, "fsync", side_effect=failure):
                    with self.assertRaises(OSError) as captured:
                        build_release._fsync_file_metadata(path)
            self.assertEqual(captured.exception.errno, errno.EIO)

    def test_windows_file_metadata_sync_ignores_only_unsupported_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packet.zip"
            path.write_bytes(b"packet")
            unsupported = OSError(errno.EINVAL, "metadata flush unsupported")
            with mock.patch.object(build_release.os, "name", "nt"):
                with mock.patch.object(build_release.os, "fsync", side_effect=unsupported):
                    build_release._fsync_file_metadata(path)

    def _zip_with(self, path: Path, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in members.items():
                archive.writestr(name, payload)

    def test_source_manifest_records_total_source_size(self):
        manifest = build_release_manifest(ROOT, app_version="test")
        self.assertIn("total_source_size_bytes", manifest)
        self.assertGreater(manifest["total_source_size_bytes"], 0)
        self.assertEqual(manifest["total_source_size_bytes"], sum(item["size_bytes"] for item in manifest["files"]))

    def test_zip_summary_reports_container_and_member_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.zip"
            self._zip_with(path, {"root/a.txt": b"alpha", "root/b.txt": b"beta" * 20})
            summary = zip_summary(path)
            self.assertEqual(summary["file_count"], 2)
            self.assertEqual(summary["total_uncompressed_member_bytes"], 85)
            self.assertEqual(summary["zip_container_overhead_bytes"], summary["zip_size_bytes"] - summary["total_compressed_member_bytes"])
            self.assertEqual(len(summary["zip_sha256"]), 64)

    def test_release_comparison_normalises_top_level_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_zip = Path(tmp) / "old.zip"
            new_zip = Path(tmp) / "new.zip"
            self._zip_with(old_zip, {"oldroot/src/main.py": b"print(1)\n"})
            self._zip_with(new_zip, {"newroot/src/main.py": b"print(1)\n", "newroot/docs/new.md": b"new\n"})
            comparison = release_compare.compare_zip_packages(old_zip, new_zip)
            self.assertIn("docs/new.md", comparison["added_paths"])
            self.assertEqual(comparison["removed_paths"], [])
            self.assertEqual(comparison["deltas"]["file_count"], 1)

    def test_package_bytes_and_member_root_do_not_depend_on_checkout_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            first_root = self.make_release_fixture(parent, "alpha-checkout")
            second_root = self.make_release_fixture(parent, "renamed-checkout")
            first = build_release.publish_release(
                first_root,
                parent / "one" / "release.zip",
                app_version=engine.APP_VERSION,
            )
            second = build_release.publish_release(
                second_root,
                parent / "two" / "release.zip",
                app_version=engine.APP_VERSION,
            )
            for first_path, second_path in zip(first.all(), second.all()):
                self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            with zipfile.ZipFile(first.zip_path) as archive:
                self.assertTrue(archive.namelist())
                self.assertTrue(all(name.startswith(f"CodeProbe_Project_Kit_v{engine.APP_VERSION}/") for name in archive.namelist()))
                for info in archive.infolist():
                    self.assertEqual(info.date_time, build_release.DETERMINISTIC_ZIP_DATETIME)
                    self.assertEqual(info.create_system, 3)
                    self.assertTrue(stat.S_ISREG(info.external_attr >> 16))
                    self.assertEqual(stat.S_IMODE(info.external_attr >> 16), 0o644)

    def test_output_inside_release_set_and_source_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            with self.assertRaisesRegex(build_release.PublicationError, "must be under dist"):
                build_release.plan_release_targets(root, root / "package.zip")

            alias = root / "dist" / "package.zip"
            alias.parent.mkdir()
            os.link(root / "source.py", alias)
            with self.assertRaisesRegex(build_release.PublicationError, "aliases a source file"):
                build_release.publish_release(root, alias, app_version=engine.APP_VERSION)

    def test_output_and_member_root_names_must_be_portable(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            with self.assertRaisesRegex(build_release.PublicationError, "reserved device name"):
                build_release.plan_release_targets(root, parent / "CON.zip")
            with self.assertRaisesRegex(build_release.PublicationError, "too long"):
                build_release.plan_release_targets(root, parent / ("a" * 240 + ".zip"))
            for member_root in ("CON", "NUL.txt", "kit.", "a" * 256):
                with self.subTest(member_root=member_root):
                    with self.assertRaisesRegex(build_release.PublicationError, "portable path segment"):
                        build_release.publish_release(
                            root,
                            parent / f"{hashlib.sha256(member_root.encode()).hexdigest()}.zip",
                            app_version=engine.APP_VERSION,
                            package_root=member_root,
                        )

    def test_existing_output_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            external = parent / "external.bin"
            external.write_bytes(b"preserve me")
            output = parent / "release.zip"
            self.symlink_or_skip(output, external)
            with self.assertRaisesRegex(build_release.PublicationError, "symbolic link"):
                build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            self.assertEqual(external.read_bytes(), b"preserve me")

    def test_in_checkout_output_parent_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit").resolve()
            external = parent / "external-output"
            external.mkdir()
            self.symlink_or_skip(root / "dist", external, target_is_directory=True)
            with self.assertRaisesRegex(build_release.PublicationError, "traverses a symbolic link"):
                build_release.plan_release_targets(root, root / "dist" / "release.zip")

            alias = parent / "checkout-alias"
            self.symlink_or_skip(alias, root, target_is_directory=True)
            with self.assertRaisesRegex(build_release.PublicationError, "traverses a symbolic link"):
                build_release.plan_release_targets(
                    alias,
                    root / "dist" / "release.zip",
                )
            self.assertEqual(list(external.iterdir()), [])

    def test_root_alias_is_bound_once_during_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            first = self.make_release_fixture(parent, "first").resolve()
            second = self.make_release_fixture(parent, "second").resolve()
            (second / "source.py").write_bytes(b"print('second')\n")
            write_manifest(second, engine.APP_VERSION)
            alias = parent / "checkout-alias"
            self.symlink_or_skip(alias, first, target_is_directory=True)
            requested_output = alias / "dist" / "release.zip"
            output = first / "dist" / "release.zip"
            real_planner = build_release._plan_release_targets

            def swap_before_planning(
                lexical_root: Path,
                resolved_root: Path,
                selected_output: Path,
            ):
                alias.unlink()
                self.symlink_or_skip(alias, second, target_is_directory=True)
                return real_planner(lexical_root, resolved_root, selected_output)

            with mock.patch.object(
                build_release,
                "_plan_release_targets",
                side_effect=swap_before_planning,
            ):
                targets = build_release.publish_release(
                    alias,
                    requested_output,
                    app_version=engine.APP_VERSION,
                )

            self.assertEqual(targets.zip_path, output)
            with zipfile.ZipFile(output) as archive:
                member = f"CodeProbe_Project_Kit_v{engine.APP_VERSION}/source.py"
                self.assertEqual(archive.read(member), b"print('stable')\n")
            self.assertFalse((second / "dist").exists())

    def test_staging_failure_leaves_existing_release_packet_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "release.zip"
            targets = build_release.plan_release_targets(root, output)
            old = {}
            for index, target in enumerate(targets.all()):
                target.write_bytes(f"old-{index}\n".encode("ascii"))
                old[target] = target.read_bytes()
            with mock.patch.object(build_release, "build_staged_zip", side_effect=OSError("forced staging failure")):
                with self.assertRaisesRegex(OSError, "forced staging failure"):
                    build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            self.assertEqual(old, {target: target.read_bytes() for target in targets.all()})
            self.assertFalse(
                any(
                    ".staging-" in path.name
                    or ".transaction-" in path.name
                    or path.name.endswith(".publish.lock")
                    for path in parent.iterdir()
                )
            )

    def test_packet_fingerprint_uses_coherent_descriptor_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "release.zip"
            content = b"packet\n"
            target.write_bytes(content)
            path_metadata = target.lstat()
            descriptor_metadata = mock.Mock(
                st_dev=path_metadata.st_dev + 1,
                st_ino=path_metadata.st_ino + 1,
                st_size=len(content),
                st_mtime_ns=path_metadata.st_mtime_ns,
                st_mode=path_metadata.st_mode,
            )

            with mock.patch.object(
                build_release,
                "read_regular_file_with_metadata",
                return_value=(content, descriptor_metadata),
            ):
                fingerprint = build_release._fingerprint(target)

            self.assertEqual(
                fingerprint,
                (
                    descriptor_metadata.st_dev,
                    descriptor_metadata.st_ino,
                    len(content),
                    descriptor_metadata.st_mtime_ns,
                    stat.S_IMODE(descriptor_metadata.st_mode),
                    hashlib.sha256(content).hexdigest(),
                ),
            )

    def test_commit_failure_restores_complete_prior_packet(self):
        for failure_position in (1, 2, 3):
            with self.subTest(failure_position=failure_position), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                parent = Path(tmp)
                root = self.make_release_fixture(parent, "kit")
                output = parent / "release.zip"
                targets = build_release.plan_release_targets(root, output)
                old = {}
                fixed_mtime = 1_700_000_000_000_000_000
                for index, target in enumerate(targets.all()):
                    target.write_bytes(f"old-{index}\n".encode("ascii"))
                    if os.name != "nt":
                        # Windows does not implement arbitrary POSIX permission bits.
                        os.chmod(target, 0o640)
                        os.utime(target, ns=(fixed_mtime, fixed_mtime))
                    old[target] = (target.read_bytes(), stat.S_IMODE(target.stat().st_mode), target.stat().st_mtime_ns)

                real_replace = os.replace
                calls = 0

                def fail_selected_commit(source: Path, destination: Path) -> None:
                    nonlocal calls
                    calls += 1
                    if calls == failure_position:
                        raise OSError(f"forced replacement failure {failure_position}")
                    real_replace(source, destination)

                with mock.patch.object(
                    build_release,
                    "_commit_staged_target",
                    side_effect=fail_selected_commit,
                ):
                    with self.assertRaisesRegex(build_release.PublicationError, "prior outputs were restored"):
                        build_release.publish_release(root, output, app_version=engine.APP_VERSION)
                for target, (expected_content, expected_mode, expected_mtime) in old.items():
                    metadata = target.stat()
                    self.assertEqual(target.read_bytes(), expected_content)
                    self.assertTrue(
                        build_release._host_mode_matches(
                            stat.S_IMODE(metadata.st_mode),
                            expected_mode,
                        )
                    )
                    self.assertEqual(metadata.st_mtime_ns, expected_mtime)
                self.assertFalse(
                any(
                    ".staging-" in path.name
                    or ".transaction-" in path.name
                    or path.name.endswith(".publish.lock")
                    for path in parent.iterdir()
                )
            )

    def test_successful_publication_is_consistent_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "release.zip"
            targets = build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            before = {target: (target.read_bytes(), target.stat().st_mtime_ns) for target in targets.all()}
            checksum = targets.checksum_path.read_text(encoding="utf-8")
            self.assertEqual(checksum, f"{hashlib.sha256(targets.zip_path.read_bytes()).hexdigest()}  release.zip\n")
            audit = json.loads(targets.audit_path.read_text(encoding="utf-8"))
            self.assertEqual(audit["zip_sha256"], hashlib.sha256(targets.zip_path.read_bytes()).hexdigest())
            build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            self.assertEqual(before, {target: (target.read_bytes(), target.stat().st_mtime_ns) for target in targets.all()})

    @unittest.skipIf(
        os.name == "nt",
        "POSIX fault-injection ordering; Windows rollback is covered by complete restoration",
    )
    def test_incomplete_rollback_retains_recovery_directory_and_lock(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "release.zip"
            targets = build_release.plan_release_targets(root, output)
            for index, target in enumerate(targets.all()):
                target.write_bytes(f"old-{index}\n".encode("ascii"))

            real_replace = os.replace
            calls = 0

            def fail_commit_and_restore(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls in {2, 3}:
                    raise OSError(f"forced replacement failure {calls}")
                real_replace(source, destination)

            with mock.patch.object(
                build_release,
                "_commit_staged_target",
                side_effect=fail_commit_and_restore,
            ):
                with self.assertRaisesRegex(build_release.PublicationError, "rollback is incomplete") as caught:
                    build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            self.assertIsNotNone(caught.exception.recovery_path)
            self.assertTrue(caught.exception.recovery_path.is_dir())
            lock = parent / ".release.zip.publish.lock"
            self.assertTrue(lock.is_file())

    @unittest.skipIf(
        os.name == "nt",
        "POSIX fault-injection ordering; Windows rollback is covered by complete restoration",
    )
    def test_rollback_does_not_overwrite_concurrently_changed_untouched_target(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "release.zip"
            targets = build_release.plan_release_targets(root, output)
            for index, target in enumerate(targets.all()):
                target.write_bytes(f"old-{index}\n".encode("ascii"))

            real_replace = os.replace
            calls = 0

            def change_checksum_then_fail(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    targets.checksum_path.write_bytes(b"concurrent owner update\n")
                    raise OSError("forced commit failure")
                real_replace(source, destination)

            with mock.patch.object(
                build_release,
                "_commit_staged_target",
                side_effect=change_checksum_then_fail,
            ):
                with self.assertRaisesRegex(
                    build_release.PublicationError,
                    "not attributable|rollback is incomplete",
                ) as caught:
                    build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            self.assertEqual(targets.checksum_path.read_bytes(), b"concurrent owner update\n")
            self.assertTrue(caught.exception.recovery_path.is_dir())

    def test_source_change_after_snapshot_cannot_enter_staged_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "release.zip"
            real_builder = build_release.build_staged_zip

            def inject_after_snapshot(snapshot, staged_output, *, package_root):
                (root / "late.txt").write_bytes(b"late and unverified\n")
                return real_builder(snapshot, staged_output, package_root=package_root)

            with mock.patch.object(build_release, "build_staged_zip", side_effect=inject_after_snapshot):
                targets = build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            with zipfile.ZipFile(targets.zip_path) as archive:
                self.assertFalse(any(name.endswith("/late.txt") for name in archive.namelist()))


if __name__ == "__main__":
    unittest.main()
