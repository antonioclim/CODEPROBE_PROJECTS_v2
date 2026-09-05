from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for path in (SRC, TOOLS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import build_release
import codeprobe_runtime as engine
from codeprobe_engine.release import write_manifest


DRIVER = ROOT / "tests" / "test_release_crash_driver.py"
VERSION = engine.APP_VERSION


class ReleaseRecoveryTests(unittest.TestCase):
    @staticmethod
    def make_release_fixture(parent: Path, name: str, content: bytes = b"print('old')\n") -> Path:
        root = parent / name
        (root / "docs").mkdir(parents=True)
        (root / "docs" / "guide.md").write_bytes(b"# Guide\n")
        (root / "source.py").write_bytes(content)
        write_manifest(root, VERSION)
        return root

    @staticmethod
    def packet_bytes(targets: build_release.ReleaseTargets) -> dict[str, bytes | None]:
        return {
            key: path.read_bytes() if path.exists() else None
            for key, path in build_release._target_mapping(targets).items()
        }

    def run_driver(
        self,
        action: str,
        root: Path,
        output: Path,
        fault: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                os.fspath(DRIVER),
                action,
                "--root",
                os.fspath(root),
                "--out",
                os.fspath(output),
                "--version",
                VERSION,
                "--fault",
                fault,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )

    def prepare_old_and_new(self, parent: Path):
        root = self.make_release_fixture(parent, "kit")
        output = parent / "public" / "release.zip"
        old_targets = build_release.publish_release(root, output, app_version=VERSION)
        old_bytes = self.packet_bytes(old_targets)
        (root / "source.py").write_bytes(b"print('new')\n")
        write_manifest(root, VERSION)
        expected = build_release.publish_release(
            root,
            parent / "expected" / "release.zip",
            app_version=VERSION,
        )
        new_bytes = self.packet_bytes(expected)
        return root, output, old_targets, old_bytes, new_bytes

    def assert_no_recovery_state(self, output: Path) -> None:
        parent = output.parent
        self.assertFalse(build_release._lock_path(parent, output.name).exists())
        self.assertEqual(
            list(parent.glob(build_release._transaction_prefix(output.name) + "*")),
            [],
        )

    def crash_and_recover_prior(self, fault: str) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, old_bytes, _new_bytes = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, fault)
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            if fault in {"readiness_withdrawn", "zip_installed", "audit_installed"}:
                self.assertFalse(targets.checksum_path.exists(), "mixed packet exposed a readiness marker")
            result = build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue(result.recovered)
            self.assertEqual(self.packet_bytes(targets), old_bytes)
            self.assert_no_recovery_state(output)

    def crash_and_recover_new(self, fault: str) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, _old_bytes, new_bytes = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, fault)
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            self.assertTrue(targets.checksum_path.is_file(), "complete packet lacked its readiness marker")
            result = build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(result.status, "new-packet-committed")
            self.assertEqual(self.packet_bytes(targets), new_bytes)
            self.assert_no_recovery_state(output)

    def test_crash_after_lock_is_cleaned_without_public_change(self):
        self.crash_and_recover_prior("lock_acquired")

    def test_crash_during_private_staging_is_cleaned_before_public_mutation(self):
        self.crash_and_recover_prior("transaction_created")

    def test_crash_after_mutation_authorisation_restores_prior_packet(self):
        self.crash_and_recover_prior("mutation_authorised")

    def test_crash_after_prepared_journal_restores_prior_packet(self):
        self.crash_and_recover_prior("prepared")

    def test_crash_after_readiness_withdrawal_restores_prior_packet(self):
        self.crash_and_recover_prior("readiness_withdrawn")

    def test_crash_after_zip_install_restores_prior_packet(self):
        self.crash_and_recover_prior("zip_installed")

    def test_crash_after_audit_install_restores_prior_packet(self):
        self.crash_and_recover_prior("audit_installed")

    def test_crash_after_checksum_install_retains_complete_new_packet(self):
        self.crash_and_recover_new("checksum_installed")

    def test_crash_after_commit_record_retains_complete_new_packet(self):
        self.crash_and_recover_new("committed")

    def test_partial_first_publication_recovers_to_absence(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            result = build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(result.status, "prior-packet-restored")
            targets = build_release.plan_release_targets(root, output)
            self.assertTrue(all(not path.exists() for path in targets.all()))
            self.assert_no_recovery_state(output)

    def test_recovery_is_repeatable_after_abrupt_rollback_interruption(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, old_bytes, _new_bytes = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            interrupted = self.run_driver("recover", root, output, "rollback_zip_restored")
            self.assertEqual(interrupted.returncode, 97, interrupted.stdout)
            result = build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(result.status, "prior-packet-restored")
            self.assertEqual(self.packet_bytes(targets), old_bytes)
            self.assert_no_recovery_state(output)

    def valid_lock_payload(self, targets: build_release.ReleaseTargets, transaction_id: str) -> dict:
        return {
            "schema": build_release.LOCK_SCHEMA,
            "transaction_id": transaction_id,
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "app_version": VERSION,
            "basename": targets.zip_path.name,
            "transaction_dir": build_release._transaction_dir(
                targets.zip_path.parent,
                targets.zip_path.name,
                transaction_id,
            ).name,
            "created_at_utc": build_release._utc_now(),
        }

    def test_live_lock_blocks_recovery_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            targets = build_release.plan_release_targets(root, output)
            output.parent.mkdir(parents=True)
            transaction_id = "1" * 32
            lock = build_release._lock_path(output.parent, output.name)
            build_release._create_lock(lock, self.valid_lock_payload(targets, transaction_id))
            with self.assertRaisesRegex(build_release.PublicationError, "live local process"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue(lock.is_file())

    def test_stale_lock_without_transaction_retains_only_a_complete_packet(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            targets = build_release.publish_release(root, output, app_version=VERSION)
            transaction_id = "a" * 32
            payload = self.valid_lock_payload(targets, transaction_id)
            payload["pid"] = 99999999
            lock = build_release._lock_path(output.parent, output.name)
            build_release._create_lock(lock, payload)
            result = build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(result.status, "stale-lock-removed")
            self.assertIn("complete verified", result.detail)
            self.assertFalse(lock.exists())
            build_release._verify_public_packet(targets)

    def test_stale_lock_without_transaction_rejects_a_partial_packet(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            targets = build_release.publish_release(root, output, app_version=VERSION)
            targets.checksum_path.unlink()
            transaction_id = "b" * 32
            payload = self.valid_lock_payload(targets, transaction_id)
            payload["pid"] = 99999999
            lock = build_release._lock_path(output.parent, output.name)
            build_release._create_lock(lock, payload)
            with self.assertRaisesRegex(build_release.PublicationError, "not provably complete or absent"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue(lock.exists())
            self.assertTrue(targets.zip_path.exists())
            self.assertFalse(targets.checksum_path.exists())

    def test_public_state_revalidation_blocks_a_late_concurrent_change(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, _old, _new = self.prepare_old_and_new(parent)
            original = build_release._copy_for_install
            changed = False

            def concurrent_change(source, destination, install_dir, *, mode, mtime_ns=None):
                nonlocal changed
                if not changed and destination == targets.zip_path:
                    targets.audit_path.write_bytes(b"late concurrent owner data\n")
                    changed = True
                return original(source, destination, install_dir, mode=mode, mtime_ns=mtime_ns)

            with unittest.mock.patch.object(build_release, "_copy_for_install", side_effect=concurrent_change):
                with self.assertRaisesRegex(build_release.PublicationError, "changed outside the transaction|not attributable"):
                    build_release.publish_release(root, output, app_version=VERSION)
            self.assertEqual(targets.audit_path.read_bytes(), b"late concurrent owner data\n")
            self.assertTrue(build_release._lock_path(output.parent, output.name).exists())

    def test_foreign_host_lock_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            targets = build_release.plan_release_targets(root, output)
            output.parent.mkdir(parents=True)
            transaction_id = "2" * 32
            payload = self.valid_lock_payload(targets, transaction_id)
            payload["hostname"] = socket.gethostname() + ".foreign"
            payload["pid"] = 999999
            lock = build_release._lock_path(output.parent, output.name)
            build_release._create_lock(lock, payload)
            with self.assertRaisesRegex(build_release.PublicationError, "another host"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue(lock.is_file())

    def test_duplicate_key_lock_is_rejected_and_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            output.parent.mkdir(parents=True)
            lock = build_release._lock_path(output.parent, output.name)
            lock.write_text(
                '{"schema":"one","schema":"two"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(build_release.PublicationError, "duplicate JSON key"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue(lock.is_file())

    def test_missing_journal_after_mutation_marker_is_fail_closed(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, _targets, _old, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "mutation_authorised")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            lock = build_release._read_control_json(build_release._lock_path(output.parent, output.name))
            transaction_dir = output.parent / lock["transaction_dir"]
            (transaction_dir / "journal.json").unlink()
            with self.assertRaisesRegex(build_release.PublicationError, "journal is missing after public mutation"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue((transaction_dir / "public-mutation.started").is_file())

    def test_orphan_transaction_without_lock_is_preserved_and_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            output.parent.mkdir(parents=True)
            orphan = output.parent / (build_release._transaction_prefix(output.name) + "3" * 32)
            orphan.mkdir()
            (orphan / "unknown.bin").write_bytes(b"preserve")
            with self.assertRaisesRegex(build_release.PublicationError, "orphaned publication transaction"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual((orphan / "unknown.bin").read_bytes(), b"preserve")

    def test_recovery_precedes_current_source_manifest_validation(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, old_bytes, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            (root / "release" / "release-manifest.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(Exception):
                build_release.publish_release(root, output, app_version=VERSION)
            self.assertEqual(self.packet_bytes(targets), old_bytes)
            self.assert_no_recovery_state(output)

    def test_normal_cli_recovers_before_current_checkout_validation(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, old_bytes, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            (root / "release" / "release-manifest.json").write_text("{}\n", encoding="utf-8")

            def invalid_current_checkout(*, skip_tests):
                self.assertFalse(skip_tests)
                self.assertEqual(self.packet_bytes(targets), old_bytes)
                self.assert_no_recovery_state(output)
                return [build_release.check_release.CheckResult("release-manifest", False, "invalid current manifest")]

            with unittest.mock.patch.object(build_release, "ROOT", root):
                with unittest.mock.patch.object(build_release.check_release, "run_checks", side_effect=invalid_current_checkout) as gate:
                    with unittest.mock.patch.object(build_release, "publish_release") as publisher:
                        self.assertEqual(build_release.main(["--out", os.fspath(output)]), 1)
            gate.assert_called_once_with(skip_tests=False)
            publisher.assert_not_called()
            self.assertEqual(self.packet_bytes(targets), old_bytes)
            self.assert_no_recovery_state(output)

    def test_normal_cli_refuses_unknown_state_before_validation_or_publication(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, _old, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            targets.audit_path.write_bytes(b"concurrent owner data\n")
            with unittest.mock.patch.object(build_release, "ROOT", root):
                with unittest.mock.patch.object(build_release.check_release, "run_checks") as gate:
                    with unittest.mock.patch.object(build_release, "publish_release") as publisher:
                        self.assertEqual(build_release.main(["--out", os.fspath(output)]), 1)
            gate.assert_not_called()
            publisher.assert_not_called()
            self.assertEqual(targets.audit_path.read_bytes(), b"concurrent owner data\n")
            self.assertTrue(build_release._lock_path(output.parent, output.name).is_file())

    def test_recovery_rejects_a_different_application_version(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, _targets, _old, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "prepared")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            lock = build_release._read_control_json(build_release._lock_path(output.parent, output.name))
            transaction_dir = output.parent / lock["transaction_dir"]
            journal_path = transaction_dir / "journal.json"
            journal = build_release._read_control_json(journal_path)
            journal["app_version"] = "999.0.0"
            build_release._atomic_write_control_json(journal_path, journal)
            with self.assertRaisesRegex(build_release.PublicationError, "another application version"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue(transaction_dir.is_dir())

    def test_unknown_concurrent_public_change_is_preserved_and_blocks(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, _old, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            targets.audit_path.write_bytes(b"concurrent owner data\n")
            with self.assertRaisesRegex(build_release.PublicationError, "not attributable"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(targets.audit_path.read_bytes(), b"concurrent owner data\n")
            self.assertTrue(build_release._lock_path(output.parent, output.name).is_file())

    def test_orphan_staging_is_cleaned_only_when_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = self.make_release_fixture(parent, "kit")
            output = parent / "public" / "release.zip"
            output.parent.mkdir(parents=True)
            empty = output.parent / (build_release._legacy_stage_prefix(output.name) + "empty")
            empty.mkdir()
            result = build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(result.status, "clean")
            self.assertFalse(empty.exists())
            nonempty = output.parent / (build_release._legacy_stage_prefix(output.name) + "nonempty")
            nonempty.mkdir()
            (nonempty / "unknown.bin").write_bytes(b"unknown")
            with self.assertRaisesRegex(build_release.PublicationError, "non-empty legacy staging"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertTrue((nonempty / "unknown.bin").is_file())

    def test_control_creation_selects_binary_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            marker = parent / "public-mutation.started"
            lock = parent / "packet.publish.lock"
            real_open = os.open
            binary_flag = getattr(os, "O_BINARY", 1 << 28)
            observed = []

            def inspect_open(path, flags, mode=0o777, **kwargs):
                if Path(path) in {marker, lock} and flags & os.O_CREAT:
                    observed.append((Path(path), flags))
                native_flags = flags if os.name == "nt" else flags & ~binary_flag
                return real_open(path, native_flags, mode, **kwargs)

            with unittest.mock.patch.object(os, "O_BINARY", binary_flag, create=True):
                with unittest.mock.patch.object(os, "open", side_effect=inspect_open):
                    build_release._create_mutation_marker(marker, "a" * 32)
                    build_release._create_lock(lock, {"sample": "line one\nline two"})
            self.assertEqual(len(observed), 2)
            for path, flags in observed:
                self.assertTrue(flags & binary_flag, path.name)
                self.assertTrue(flags & os.O_EXCL, path.name)
            self.assertEqual(marker.read_bytes(), b"transaction_id=" + b"a" * 32 + b"\n")
            self.assertNotIn(b"\r", lock.read_bytes())

    def test_failed_control_write_closes_before_unlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "packet.publish.lock"
            real_unlink = Path.unlink
            descriptors = []

            def fail_write(descriptor, content):
                descriptors.append(descriptor)
                raise OSError("controlled incomplete write")

            def require_closed(path, *args, **kwargs):
                if path == lock:
                    with self.assertRaises(OSError):
                        os.fstat(descriptors[-1])
                return real_unlink(path, *args, **kwargs)

            with unittest.mock.patch.object(build_release, "_write_all", side_effect=fail_write):
                with unittest.mock.patch.object(Path, "unlink", require_closed):
                    with self.assertRaisesRegex(OSError, "controlled incomplete write"):
                        build_release._create_lock(lock, {"sample": "value"})
            self.assertFalse(lock.exists())

    def test_windows_liveness_declares_pointer_sized_handles(self):
        import ctypes
        from ctypes import wintypes

        wide_handle = (1 << 40) + 17
        kernel = unittest.mock.Mock()
        kernel.OpenProcess.return_value = wide_handle

        def report_exit(handle, pointer):
            self.assertEqual(handle, wide_handle)
            ctypes.cast(pointer, ctypes.POINTER(wintypes.DWORD)).contents.value = 259
            return True

        kernel.GetExitCodeProcess.side_effect = report_exit
        with unittest.mock.patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            self.assertTrue(build_release._windows_process_alive(12345))
        self.assertIs(kernel.OpenProcess.restype, wintypes.HANDLE)
        self.assertEqual(kernel.OpenProcess.argtypes, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
        self.assertEqual(kernel.GetExitCodeProcess.argtypes, [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)])
        self.assertIs(kernel.GetExitCodeProcess.restype, wintypes.BOOL)
        self.assertEqual(kernel.CloseHandle.argtypes, [wintypes.HANDLE])
        self.assertIs(kernel.CloseHandle.restype, wintypes.BOOL)
        kernel.CloseHandle.assert_called_once_with(wide_handle)

    def test_recover_only_cli_and_recipient_command(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            parent = Path(tmp)
            root, output, targets, old_bytes, _new = self.prepare_old_and_new(parent)
            crashed = self.run_driver("publish", root, output, "audit_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    os.fspath(TOOLS / "build_release.py"),
                    "--out",
                    os.fspath(output),
                    "--recover-only",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("[PASS] release-recovery", completed.stdout)
            self.assertEqual(self.packet_bytes(targets), old_bytes)
            guide = (ROOT / "docs" / "13-signed-release-workflow.md").read_text(encoding="utf-8")
            self.assertIn(
                "python3 -I -S -B tools/validate_release.py --skip-tests",
                guide,
            )

    def test_invalid_lock_fields_retain_prior_packet(self):
        changes = (
            ("extra", True), ("schema", "unsupported"),
            ("transaction_id", "../unknown"), ("app_version", "999.0.0"),
            ("basename", "other.zip"), ("transaction_dir", "../other"),
            ("hostname", ""), ("pid", True), ("pid", 0),
            ("created_at_utc", "not-a-timeZ"), ("created_at_utc", "2026-09-05"),
        )
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, output, targets, old_bytes, _new = self.prepare_old_and_new(Path(tmp))
            crashed = self.run_driver("publish", root, output, "prepared")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            lock_path = build_release._lock_path(output.parent, output.name)
            original = build_release._read_control_json(lock_path)
            for field, value in changes:
                with self.subTest(field=field, value=value):
                    altered = dict(original)
                    altered[field] = value
                    build_release._atomic_write_control_json(lock_path, altered)
                    with self.assertRaises(build_release.PublicationError):
                        build_release.recover_release(root, output, app_version=VERSION)
                    self.assertEqual(self.packet_bytes(targets), old_bytes)
                    self.assertEqual(build_release._read_control_json(lock_path), altered)
            build_release._atomic_write_control_json(lock_path, original)
            build_release.recover_release(root, output, app_version=VERSION)
            self.assert_no_recovery_state(output)

    def test_invalid_journal_fields_retain_prior_packet(self):
        changes = (
            (("extra",), True), (("schema",), "unsupported"),
            (("transaction_id",), "0" * 32), (("basename",), "other.zip"),
            (("package_root",), "../outside"), (("state",), "unknown"),
            (("sequence",), 0), (("created_at_utc",), "badZ"),
            (("updated_at_utc",), "2026-09-05"), (("targets",), {}),
            (("new",), []), (("prior",), []),
            (("new", "zip"), []), (("new", "zip"), {}),
            (("new", "zip", "path"), "../outside"),
            (("new", "zip", "path"), "backup/0"),
            (("new", "zip", "size_bytes"), -1),
            (("new", "zip", "sha256"), "invalid"),
            (("new", "zip", "mode"), True),
            (("new", "zip", "mtime_ns"), -1),
            (("prior", "zip"), []),
            (("prior", "zip", "existed"), "yes"),
            (("prior", "zip", "path"), "backup/9"),
            (("prior", "zip", "sha256"), "0" * 64),
        )
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, output, targets, old_bytes, _new = self.prepare_old_and_new(Path(tmp))
            crashed = self.run_driver("publish", root, output, "prepared")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            lock_path = build_release._lock_path(output.parent, output.name)
            lock = build_release._read_control_json(lock_path)
            transaction = output.parent / lock["transaction_dir"]
            journal_path = transaction / "journal.json"
            original = build_release._read_control_json(journal_path)
            for field_path, value in changes:
                with self.subTest(field_path=field_path):
                    altered = json.loads(json.dumps(original))
                    record = altered
                    for field in field_path[:-1]:
                        record = record[field]
                    record[field_path[-1]] = value
                    build_release._atomic_write_control_json(journal_path, altered)
                    with self.assertRaises(build_release.PublicationError):
                        build_release.recover_release(root, output, app_version=VERSION)
                    self.assertEqual(self.packet_bytes(targets), old_bytes)
                    self.assertTrue(lock_path.is_file())
                    self.assertEqual(build_release._read_control_json(journal_path), altered)
            build_release._atomic_write_control_json(journal_path, original)
            build_release.recover_release(root, output, app_version=VERSION)
            self.assert_no_recovery_state(output)

    def test_modified_new_member_retains_recovery_evidence(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, output, targets, _old, _new = self.prepare_old_and_new(Path(tmp))
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            lock_path = build_release._lock_path(output.parent, output.name)
            lock = build_release._read_control_json(lock_path)
            transaction = output.parent / lock["transaction_dir"]
            journal = build_release._read_control_json(transaction / "journal.json")
            member = transaction / journal["new"]["zip"]["path"]
            member.write_bytes(b"unrecognised replacement\n")
            before = self.packet_bytes(targets)
            with self.assertRaisesRegex(build_release.PublicationError, "new zip transaction bytes"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(self.packet_bytes(targets), before)
            self.assertEqual(member.read_bytes(), b"unrecognised replacement\n")
            self.assertTrue(lock_path.is_file())

    def test_modified_backup_retains_recovery_evidence(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root, output, targets, _old, _new = self.prepare_old_and_new(Path(tmp))
            crashed = self.run_driver("publish", root, output, "zip_installed")
            self.assertEqual(crashed.returncode, 97, crashed.stdout)
            lock_path = build_release._lock_path(output.parent, output.name)
            lock = build_release._read_control_json(lock_path)
            transaction = output.parent / lock["transaction_dir"]
            journal = build_release._read_control_json(transaction / "journal.json")
            backup = transaction / journal["prior"]["zip"]["path"]
            backup.write_bytes(b"unrecognised backup\n")
            before = self.packet_bytes(targets)
            with self.assertRaisesRegex(build_release.PublicationError, "prior zip backup"):
                build_release.recover_release(root, output, app_version=VERSION)
            self.assertEqual(self.packet_bytes(targets), before)
            self.assertEqual(backup.read_bytes(), b"unrecognised backup\n")
            self.assertTrue(lock_path.is_file())

    def test_non_object_and_oversized_control_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "control.json"
            for content in (b"[]\n", b"null\n", b"x" * (build_release.CONTROL_FILE_LIMIT_BYTES + 1)):
                with self.subTest(size=len(content)):
                    path.write_bytes(content)
                    with self.assertRaises(build_release.PublicationError):
                        build_release._read_control_json(path)
                    self.assertEqual(path.read_bytes(), content)
            path.write_bytes(b"{}\n")
            with self.assertRaises(build_release.PublicationError):
                build_release._atomic_write_control_json(
                    path, {"payload": "x" * build_release.CONTROL_FILE_LIMIT_BYTES}
                )
            self.assertEqual(path.read_bytes(), b"{}\n")
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_failed_lock_write_removes_only_its_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            lock = parent / "packet.publish.lock"
            retained = parent / "unrelated.txt"
            retained.write_bytes(b"retain\n")
            with unittest.mock.patch.object(build_release.os, "write", return_value=0):
                with self.assertRaisesRegex(OSError, "short write"):
                    build_release._create_lock(lock, {"transaction_id": "1" * 32})
            self.assertFalse(lock.exists())
            self.assertEqual(retained.read_bytes(), b"retain\n")

    def test_existing_lock_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "packet.publish.lock"
            lock.write_bytes(b"existing owner\n")
            with self.assertRaisesRegex(build_release.PublicationError, "lock exists"):
                build_release._create_lock(lock, {"transaction_id": "1" * 32})
            self.assertEqual(lock.read_bytes(), b"existing owner\n")



if __name__ == "__main__":
    unittest.main()
