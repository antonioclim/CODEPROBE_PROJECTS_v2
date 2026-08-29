from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import build_release  # noqa: E402
import check_release  # noqa: E402
import final_audit  # noqa: E402
from codeprobe_engine.release import ReleaseSetError  # noqa: E402


class FinalPackageAuditTests(unittest.TestCase):
    @staticmethod
    def snapshot_tree(root: Path) -> dict[str, tuple[object, ...]]:
        snapshot: dict[str, tuple[object, ...]] = {}
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if ".git" in relative.parts:
                continue
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            key = relative.as_posix()
            if path.is_symlink():
                snapshot[key] = ("symlink", mode, metadata.st_mtime_ns, path.readlink().as_posix())
            elif path.is_file():
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                snapshot[key] = ("file", mode, metadata.st_size, metadata.st_mtime_ns, digest)
            elif path.is_dir():
                snapshot[key] = ("directory", mode, metadata.st_mtime_ns)
            else:
                snapshot[key] = ("other", mode, metadata.st_mtime_ns)
        return snapshot

    def test_final_audit_passes(self) -> None:
        report = final_audit.build_audit(ROOT)
        self.assertEqual(report["status"], "pass", report)
        self.assertFalse(report["missing_required_paths"])
        self.assertFalse(report["forbidden_paths_present"])

    def test_final_audit_files_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            output_dir = fixture_root / "release"
            root_evidence = [ROOT / relative for relative in check_release.EVIDENCE_PATHS]
            before = {path: path.read_bytes() for path in root_evidence}
            expected = final_audit.build_audit(ROOT)
            report = final_audit.write_reports(ROOT, expected, output_dir=output_dir)
            self.assertEqual(report["status"], "pass")
            payload = json.loads((output_dir / "final-audit-report.json").read_text(encoding="utf-8"))
            self.assertEqual(payload, expected)
            self.assertTrue((output_dir / "final-audit-summary.md").is_file())
            self.assertEqual(final_audit.verify_reports(fixture_root, expected), [])
            self.assertEqual(before, {path: path.read_bytes() for path in root_evidence})

    def test_failed_audit_is_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "release"
            failed = dict(final_audit.build_audit(ROOT), status="fail")
            with self.assertRaisesRegex(ValueError, "failed audit"):
                final_audit.write_reports(ROOT, failed, output_dir=output_dir)
            self.assertFalse(output_dir.exists())

    def test_audit_report_verification_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            output_dir = fixture_root / "release"
            report = final_audit.build_audit(ROOT)
            final_audit.write_reports(ROOT, report, output_dir=output_dir)
            self.assertEqual(final_audit.verify_reports(fixture_root, report), [])
            (output_dir / "final-audit-summary.md").write_text("tampered\n", encoding="utf-8")
            self.assertEqual(
                final_audit.verify_reports(fixture_root, report),
                ["stale audit artefact: release/final-audit-summary.md"],
            )
            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(final_audit.main(["--root", str(fixture_root)]), 1)

    def test_audit_report_verification_handles_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            report = final_audit.build_audit(ROOT)
            final_audit.write_reports(ROOT, report, output_dir=fixture_root / "release")
            (fixture_root / "release" / "final-audit-report.json").write_bytes(b"\xff")
            self.assertEqual(
                final_audit.verify_reports(fixture_root, report),
                ["invalid or unreadable audit artefact: release/final-audit-report.json"],
            )

    def test_check_only_paths_do_not_write_release_evidence(self) -> None:
        evidence = [ROOT / relative for relative in check_release.EVIDENCE_PATHS]
        before = {path: path.read_bytes() for path in evidence}
        with mock.patch.object(final_audit, "write_reports") as writer:
            result = check_release.check_final_audit(verify_persisted=False)
        self.assertTrue(result.ok, result.detail)
        writer.assert_not_called()
        self.assertEqual(before, {path: path.read_bytes() for path in evidence})

    def test_fast_release_checks_leave_release_evidence_unchanged(self) -> None:
        evidence = [ROOT / relative for relative in check_release.EVIDENCE_PATHS]
        before = {path: path.read_bytes() for path in evidence}
        results = check_release.run_checks(
            skip_tests=True,
            verify_manifest_file=False,
            verify_persisted_evidence=False,
        )
        self.assertTrue(all(result.ok for result in results), results)
        self.assertEqual(before, {path: path.read_bytes() for path in evidence})

    def test_failed_validation_does_not_refresh_release_evidence(self) -> None:
        forced_failure = check_release.CheckResult("smoke-reports", False, "forced regression failure")
        with mock.patch.object(check_release, "check_smoke_reports", return_value=forced_failure):
            with mock.patch.object(check_release, "refresh_release_evidence") as refresh:
                results = check_release.run_checks(
                    skip_tests=True,
                    write_manifest_file=True,
                    verify_manifest_file=False,
                )
        refresh.assert_not_called()
        self.assertTrue(any(not result.ok for result in results))

    def test_unsafe_release_set_stops_the_gate_before_other_readers(self) -> None:
        with mock.patch.object(
            check_release,
            "validate_release_set",
            side_effect=ReleaseSetError("symbolic links are forbidden"),
        ):
            with mock.patch.object(check_release, "check_python_compile") as compiler:
                results = check_release.run_checks(skip_tests=True, write_manifest_file=True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "release-set-safety")
        self.assertFalse(results[0].ok)
        compiler.assert_not_called()

    def test_final_audit_cli_does_not_read_symlinked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / "kit"
            shutil.copytree(
                ROOT,
                fixture_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"),
            )
            evidence = fixture_root / "release" / "final-audit-report.json"
            external = Path(tmp) / "external.json"
            external.write_text('{"external": true}\n', encoding="utf-8")
            evidence.unlink()
            evidence.symlink_to(external)
            with mock.patch.object(final_audit, "read_regular_file") as reader:
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = final_audit.main(["--root", str(fixture_root)])
            self.assertEqual(exit_code, 1)
            reader.assert_not_called()

    def test_unreadable_evidence_prevents_refresh_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            for relative in check_release.EVIDENCE_PATHS:
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"existing\n")
            report = final_audit.build_audit(ROOT)
            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(check_release, "read_regular_file", side_effect=OSError("forced read failure")):
                    with mock.patch.object(final_audit, "write_reports") as report_writer:
                        with mock.patch.object(check_release, "write_manifest") as manifest_writer:
                            result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("existing evidence could not be read", result.detail)
            report_writer.assert_not_called()
            manifest_writer.assert_not_called()

    def test_missing_evidence_is_not_bootstrapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            for relative in check_release.EVIDENCE_PATHS[1:]:
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"existing\n")
            with mock.patch.object(final_audit, "build_audit") as auditor:
                with mock.patch.object(final_audit, "write_reports") as report_writer:
                    result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("tracked evidence is missing", result.detail)
            auditor.assert_not_called()
            report_writer.assert_not_called()

    def test_refresh_reports_incomplete_rollback_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            for relative in check_release.EVIDENCE_PATHS:
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"existing\n")
            report = final_audit.build_audit(ROOT)
            real_atomic_write = check_release.atomic_write_bytes
            calls = 0

            def fail_second_restore(path: Path, content: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("forced rollback failure")
                real_atomic_write(path, content)

            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(final_audit, "write_reports", side_effect=OSError("forced refresh failure")):
                    with mock.patch.object(check_release, "atomic_write_bytes", side_effect=fail_second_restore):
                        result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("rollback incomplete", result.detail)
            self.assertEqual(calls, len(check_release.EVIDENCE_PATHS))

    def test_final_audit_cli_is_check_only_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            report = final_audit.build_audit(ROOT)
            final_audit.write_reports(ROOT, report, output_dir=fixture_root / "release")
            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(final_audit, "write_reports") as writer:
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = final_audit.main(["--root", str(fixture_root)])
            self.assertEqual(exit_code, 0)
            writer.assert_not_called()

    def test_json_output_inside_release_set_is_rejected_before_checks(self) -> None:
        target = ROOT / "release" / "check-results.json"
        with mock.patch.object(check_release, "run_checks") as runner:
            with mock.patch.object(check_release, "atomic_write_text") as writer:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        check_release.main(["--json-out", str(target)])
        runner.assert_not_called()
        writer.assert_not_called()

    def test_default_gate_leaves_complete_source_tree_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / "kit"
            shutil.copytree(
                ROOT,
                fixture_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"),
            )
            refresh = subprocess.run(
                [sys.executable, "tools/check_release.py", "--skip-tests", "--write-release-evidence"],
                cwd=fixture_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(refresh.returncode, 0, refresh.stdout + refresh.stderr)
            before = self.snapshot_tree(fixture_root)
            gate = subprocess.run(
                [sys.executable, "tools/check_release.py", "--skip-tests"],
                cwd=fixture_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(gate.returncode, 0, gate.stdout + gate.stderr)
            self.assertEqual(self.snapshot_tree(fixture_root), before)

    def test_failed_build_validation_does_not_create_a_package(self) -> None:
        failure = check_release.CheckResult("forced", False, "forced regression failure")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "release.zip"
            with mock.patch.object(check_release, "run_checks", return_value=[failure]):
                with mock.patch.object(build_release, "publish_release") as publisher:
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = build_release.main(["--out", str(output)])
        self.assertEqual(exit_code, 1)
        publisher.assert_not_called()

    def test_root_legacy_release_files_are_absent(self) -> None:
        self.assertFalse((ROOT / "RELEASE_MANIFEST.json").exists())
        self.assertFalse((ROOT / "release-manifest.json").exists())
        self.assertFalse((ROOT / "file-rename-map.csv").exists())
        self.assertFalse((ROOT / "KIT_INDEX.md").exists())

if __name__ == "__main__":
    unittest.main()
