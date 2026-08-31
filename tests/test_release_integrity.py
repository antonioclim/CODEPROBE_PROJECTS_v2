import errno
import hashlib
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
from codeprobe_engine.release import build_release_manifest, write_manifest, zip_summary
import compare_releases as release_compare


class ReleaseIntegrityTests(unittest.TestCase):
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
            self.assertFalse(any(".staging-" in path.name or path.name.endswith(".publish.lock") for path in parent.iterdir()))

    def test_commit_failure_restores_complete_prior_packet(self):
        for failure_position in (1, 2, 3):
            with self.subTest(failure_position=failure_position), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root = self.make_release_fixture(parent, "kit")
                output = parent / "release.zip"
                targets = build_release.plan_release_targets(root, output)
                old = {}
                fixed_mtime = 1_700_000_000_000_000_000
                for index, target in enumerate(targets.all()):
                    target.write_bytes(f"old-{index}\n".encode("ascii"))
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

                with mock.patch.object(build_release.os, "replace", side_effect=fail_selected_commit):
                    with self.assertRaisesRegex(build_release.PublicationError, "prior outputs were restored"):
                        build_release.publish_release(root, output, app_version=engine.APP_VERSION)
                restored = {
                    target: (target.read_bytes(), stat.S_IMODE(target.stat().st_mode), target.stat().st_mtime_ns)
                    for target in targets.all()
                }
                self.assertEqual(restored, old)
                self.assertFalse(any(".staging-" in path.name or path.name.endswith(".publish.lock") for path in parent.iterdir()))

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

    def test_incomplete_rollback_retains_recovery_directory_and_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
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

            with mock.patch.object(build_release.os, "replace", side_effect=fail_commit_and_restore):
                with mock.patch.object(build_release, "_verify_prior_state", side_effect=PermissionError("forced verification failure")):
                    with self.assertRaisesRegex(build_release.PublicationError, "rollback is incomplete") as caught:
                        build_release.publish_release(root, output, app_version=engine.APP_VERSION)
            self.assertIsNotNone(caught.exception.recovery_path)
            self.assertTrue(caught.exception.recovery_path.is_dir())
            self.assertTrue((parent / ".release.zip.publish.lock").is_file())

    def test_rollback_does_not_overwrite_concurrently_changed_untouched_target(self):
        with tempfile.TemporaryDirectory() as tmp:
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

            with mock.patch.object(build_release.os, "replace", side_effect=change_checksum_then_fail):
                with self.assertRaisesRegex(build_release.PublicationError, "rollback is incomplete") as caught:
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
