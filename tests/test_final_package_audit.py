from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
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

NESTED_GATE_ENV = "CODEPROBE_NESTED_CANONICAL_GATE"


class FinalPackageAuditTests(unittest.TestCase):
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
            with mock.patch.object(
                check_release,
                "check_unittest_suite",
                return_value=check_release.CheckResult("unit-tests", True, "247 test(s) passed"),
            ):
                with mock.patch.object(check_release, "refresh_release_evidence") as refresh:
                    results = check_release.run_checks(
                        write_manifest_file=True,
                        verify_manifest_file=False,
                    )
        refresh.assert_not_called()
        self.assertTrue(any(not result.ok for result in results))

    def test_skipped_tests_cannot_authorise_evidence_refresh(self) -> None:
        with mock.patch.object(check_release, "refresh_release_evidence") as refresh:
            results = check_release.run_checks(
                skip_tests=True,
                write_manifest_file=True,
                verify_manifest_file=False,
                verify_persisted_evidence=False,
            )
        refresh.assert_not_called()
        evidence = next(result for result in results if result.name == "release-evidence")
        self.assertFalse(evidence.ok)
        self.assertFalse(evidence.skipped)
        self.assertIn("mandatory check was skipped", evidence.detail)

    def test_dependency_boundary_failure_is_part_of_the_canonical_gate(self) -> None:
        with mock.patch.object(
            check_release.check_dependency_boundary,
            "audit_dependency_boundary",
            return_value=["unapproved dependency fixture"],
        ):
            results = check_release.run_checks(
                skip_tests=True,
                verify_manifest_file=False,
                verify_persisted_evidence=False,
            )
        dependency_result = next(
            result for result in results if result.name == "dependency-boundary"
        )
        self.assertFalse(dependency_result.ok)
        self.assertIn("unapproved dependency fixture", dependency_result.detail)

    def test_dependency_boundary_failure_skips_untrusted_unittests(self) -> None:
        forced_failure = check_release.CheckResult(
            "dependency-boundary",
            False,
            "forced dependency failure",
        )
        with mock.patch.object(
            check_release,
            "check_dependency_policy",
            return_value=forced_failure,
        ):
            with mock.patch.object(check_release, "check_unittest_suite") as suite:
                results = check_release.run_checks(
                    verify_manifest_file=False,
                    verify_persisted_evidence=False,
                )
        suite.assert_not_called()
        names = [result.name for result in results]
        self.assertLess(
            names.index("dependency-boundary"),
            names.index("python-compile"),
        )
        unit_tests = next(result for result in results if result.name == "unit-tests")
        self.assertTrue(unit_tests.ok)
        self.assertTrue(unit_tests.skipped)
        self.assertIn("dependency boundary failed", unit_tests.detail)

    def test_canonical_cli_ignores_ambient_site_and_shadow_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ambient = Path(tmp)
            marker = ambient / "sitecustomize-loaded.txt"
            (ambient / "sitecustomize.py").write_text(
                f"open({str(marker)!r}, 'w', encoding='utf-8').write('loaded\\n')\n",
                encoding="utf-8",
            )
            (ambient / "json.py").write_text(
                "raise RuntimeError('ambient json shadow imported')\n",
                encoding="utf-8",
            )
            encodings = ambient / "encodings"
            encodings.mkdir()
            (encodings / "__init__.py").write_text(
                "import _io\n"
                f"_io.open({str(marker)!r}, 'w').write('pre-bootstrap loaded\\n')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(ambient)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(ROOT / "tools" / "check_release.py"),
                    "--help",
                ],
                cwd=ambient,
                env=environment,
                text=True,
                capture_output=True,
            )
            output = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 0, output)
            self.assertFalse(marker.exists())
            self.assertNotIn("ambient json shadow imported", output)

    def test_release_cli_refuses_nonisolated_invocation(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-S",
                "-B",
                str(ROOT / "tools" / "check_release.py"),
                "--help",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("requires isolated, site-free Python", completed.stderr)

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
            fixture_root = (Path(tmp) / "kit").resolve()
            shutil.copytree(
                ROOT,
                fixture_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"),
            )
            evidence = fixture_root / "release" / "final-audit-report.json"
            external = Path(tmp) / "external.json"
            external.write_text('{"external": true}\n', encoding="utf-8")
            evidence.unlink()
            self.symlink_or_skip(evidence, external)
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
                with mock.patch.object(
                    check_release,
                    "read_regular_file_with_metadata",
                    side_effect=OSError("forced read failure"),
                ):
                    with mock.patch.object(check_release, "atomic_write_bytes") as writer:
                        result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("existing evidence could not be read", result.detail)
            writer.assert_not_called()

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

    def test_refresh_refuses_source_mutation_after_validation_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / "kit"
            source = fixture_root / "source.txt"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"validated\n")
            for relative in check_release.EVIDENCE_PATHS[:2]:
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"existing\n")
            from codeprobe_engine.release import write_manifest

            write_manifest(fixture_root, "2.2.0")
            expected = check_release.capture_release_tree(
                fixture_root,
                exclude_evidence=True,
            )
            source.write_bytes(b"changed after validation\n")
            report = final_audit.build_audit(ROOT)
            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(check_release, "atomic_write_bytes") as writer:
                    result = check_release.refresh_release_evidence(
                        fixture_root,
                        expected_source=expected,
                    )
            self.assertFalse(result.ok)
            self.assertIn("changed during validation", result.detail)
            writer.assert_not_called()

    def test_evidence_snapshot_uses_coherent_reader_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp).resolve()
            path = fixture_root / "evidence.json"
            path.write_bytes(b"coherent\n")
            metadata = path.stat()
            with mock.patch.object(
                check_release,
                "read_regular_file_with_metadata",
                return_value=(b"coherent\n", metadata),
            ) as reader:
                with mock.patch.object(
                    Path,
                    "lstat",
                    side_effect=AssertionError("a second pathname stat is not coherent"),
                ):
                    snapshot = check_release._capture_evidence(path, root=fixture_root)
            self.assertEqual(snapshot.content, b"coherent\n")
            self.assertEqual(snapshot.mtime_ns, metadata.st_mtime_ns)
            reader.assert_called_once_with(path, root=fixture_root)

    def test_partial_refresh_restores_all_evidence_bytes_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            original: dict[Path, tuple[bytes, int, int]] = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"existing-{index}\n".encode("ascii"))
                if os.name != "nt":
                    os.chmod(path, 0o600)
                    timestamp = 1_700_000_000_000_000_000 + index * 1_000_000_000
                    os.utime(path, ns=(timestamp, timestamp))
                metadata = path.stat()
                original[relative] = (
                    path.read_bytes(),
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_mtime_ns,
                )
            report = final_audit.build_audit(ROOT)
            real_atomic_write = check_release.atomic_write_bytes
            original_contents = {value[0] for value in original.values()}

            for failure_position in (2, 3):
                with self.subTest(failure_position=failure_position):
                    generated_calls = 0

                    def fail_selected_commit(
                        path: Path,
                        content: bytes,
                        **write_options: object,
                    ):
                        nonlocal generated_calls
                        if content not in original_contents:
                            generated_calls += 1
                            if generated_calls == failure_position:
                                raise OSError("forced evidence commit failure")
                        return real_atomic_write(path, content, **write_options)

                    with mock.patch.object(final_audit, "build_audit", return_value=report):
                        with mock.patch.object(
                            check_release,
                            "atomic_write_bytes",
                            side_effect=fail_selected_commit,
                        ):
                            result = check_release.refresh_release_evidence(fixture_root)
                    self.assertFalse(result.ok)
                    self.assertIn("was rolled back", result.detail)
                    for relative, (expected_content, expected_mode, expected_mtime) in original.items():
                        path = fixture_root / relative
                        metadata = path.stat()
                        self.assertEqual(path.read_bytes(), expected_content)
                        self.assertTrue(
                            check_release._mode_matches(
                                stat.S_IMODE(metadata.st_mode),
                                expected_mode,
                            )
                        )
                        self.assertEqual(metadata.st_mtime_ns, expected_mtime)

    def test_silent_restore_failure_is_reported_as_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp).resolve()
            originals: dict[Path, bytes] = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"existing-{index}\n".encode("ascii")
                path.write_bytes(content)
                originals[relative] = content
            report = final_audit.build_audit(ROOT)
            real_atomic_write = check_release.atomic_write_bytes
            generated_calls = 0

            def fail_commit_and_ignore_restore(
                path: Path,
                content: bytes,
                **write_options: object,
            ):
                nonlocal generated_calls
                relative = path.relative_to(fixture_root)
                if content == originals[relative]:
                    return
                generated_calls += 1
                if generated_calls == 2:
                    raise OSError("forced evidence commit failure")
                return real_atomic_write(path, content, **write_options)

            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(
                    check_release,
                    "atomic_write_bytes",
                    side_effect=fail_commit_and_ignore_restore,
                ):
                    result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("rollback incomplete", result.detail)

    def test_completed_replace_is_owned_before_post_write_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp).resolve()
            originals: dict[Path, bytes] = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"existing-{index}\n".encode("ascii")
                path.write_bytes(content)
                originals[relative] = content
            report = final_audit.build_audit(ROOT)
            first_relative = check_release.EVIDENCE_PATHS[0]
            first_path = fixture_root / first_relative
            real_fingerprint = check_release._evidence_fingerprint
            failed = False

            def fail_first_post_write_fingerprint(path: Path, *, root: Path):
                nonlocal failed
                if (
                    not failed
                    and path == first_path
                    and path.read_bytes() != originals[first_relative]
                ):
                    failed = True
                    raise OSError("forced post-replace fingerprint failure")
                return real_fingerprint(path, root=root)

            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(
                    check_release,
                    "_evidence_fingerprint",
                    side_effect=fail_first_post_write_fingerprint,
                ):
                    result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("was rolled back", result.detail)
            self.assertEqual(
                originals,
                {
                    relative: (fixture_root / relative).read_bytes()
                    for relative in check_release.EVIDENCE_PATHS
                },
            )

        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp).resolve()
            originals = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"reoccupied-{index}\n".encode("ascii")
                path.write_bytes(content)
                originals[relative] = content
            report = final_audit.build_audit(ROOT)
            real_replace = Path.replace
            actor_paths: list[Path] = []
            raised = False

            def replace_reoccupy_and_raise(source: Path, destination: Path):
                nonlocal raised
                result = real_replace(source, destination)
                if not raised:
                    raised = True
                    source.write_bytes(b"concurrent writer\n")
                    actor_paths.append(source)
                    raise OSError("forced ambiguous replacement with reoccupation")
                return result

            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(
                    Path,
                    "replace",
                    new=replace_reoccupy_and_raise,
                ):
                    result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("rollback incomplete", result.detail)
            self.assertEqual(
                originals,
                {
                    relative: (fixture_root / relative).read_bytes()
                    for relative in check_release.EVIDENCE_PATHS
                },
            )
            self.assertEqual(actor_paths[0].read_bytes(), b"concurrent writer\n")
            actor_paths[0].unlink()

        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp).resolve()
            originals = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"ambiguous-{index}\n".encode("ascii")
                path.write_bytes(content)
                originals[relative] = content
            report = final_audit.build_audit(ROOT)
            first_path = fixture_root / check_release.EVIDENCE_PATHS[0]
            real_replace = Path.replace
            raised = False

            def replace_then_raise(source: Path, destination: Path):
                nonlocal raised
                result = real_replace(source, destination)
                if not raised and destination == first_path:
                    raised = True
                    raise OSError("forced ambiguous replacement result")
                return result

            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(Path, "replace", new=replace_then_raise):
                    result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("was rolled back", result.detail)
            self.assertEqual(
                originals,
                {
                    relative: (fixture_root / relative).read_bytes()
                    for relative in check_release.EVIDENCE_PATHS
                },
            )

    def test_post_write_verification_failure_restores_complete_evidence_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            originals: dict[Path, bytes] = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"existing-{index}\n".encode("ascii")
                path.write_bytes(content)
                originals[relative] = content
            report = final_audit.build_audit(ROOT)
            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(
                    final_audit,
                    "verify_reports",
                    return_value=["forced post-write mismatch"],
                ):
                    result = check_release.refresh_release_evidence(fixture_root)
            self.assertFalse(result.ok)
            self.assertIn("was rolled back", result.detail)
            self.assertEqual(
                originals,
                {
                    relative: (fixture_root / relative).read_bytes()
                    for relative in check_release.EVIDENCE_PATHS
                },
            )

    def test_interrupt_after_partial_refresh_restores_then_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            originals: dict[Path, bytes] = {}
            for index, relative in enumerate(check_release.EVIDENCE_PATHS):
                path = fixture_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                content = f"existing-{index}\n".encode("ascii")
                path.write_bytes(content)
                originals[relative] = content
            report = final_audit.build_audit(ROOT)
            real_atomic_write = check_release.atomic_write_bytes
            generated_calls = 0

            def interrupt_second_commit(
                path: Path,
                content: bytes,
                **write_options: object,
            ):
                nonlocal generated_calls
                if content not in originals.values():
                    generated_calls += 1
                    if generated_calls == 2:
                        raise KeyboardInterrupt
                return real_atomic_write(path, content, **write_options)

            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(
                    check_release,
                    "atomic_write_bytes",
                    side_effect=interrupt_second_commit,
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        check_release.refresh_release_evidence(fixture_root)
            self.assertEqual(
                originals,
                {
                    relative: (fixture_root / relative).read_bytes()
                    for relative in check_release.EVIDENCE_PATHS
                },
            )

    def test_final_audit_cli_is_check_only_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp)
            report = final_audit.build_audit(ROOT)
            final_audit.write_reports(ROOT, report, output_dir=fixture_root / "release")
            with mock.patch.object(final_audit, "build_audit", return_value=report):
                with mock.patch.object(final_audit, "verify_manifest", return_value=[]):
                    with mock.patch.object(final_audit, "write_reports") as writer:
                        with contextlib.redirect_stdout(io.StringIO()):
                            exit_code = final_audit.main(["--root", str(fixture_root)])
            self.assertEqual(exit_code, 0)
            writer.assert_not_called()

    def test_final_audit_cli_rejects_a_stale_manifest(self) -> None:
        report = final_audit.build_audit(ROOT)
        with mock.patch.object(final_audit, "build_audit", return_value=report):
            with mock.patch.object(final_audit, "verify_reports", return_value=[]):
                with mock.patch.object(
                    final_audit,
                    "verify_manifest",
                    return_value=["hash mismatch: docs/example.md"],
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = final_audit.main(["--root", str(ROOT)])
        self.assertEqual(exit_code, 1)

    def test_release_tree_snapshot_detects_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / "kit"
            (fixture_root / "docs").mkdir(parents=True)
            source = fixture_root / "docs" / "source.txt"
            source.write_bytes(b"before\n")
            from codeprobe_engine.release import write_manifest

            write_manifest(fixture_root, "2.2.0")
            snapshot = check_release.capture_release_tree(fixture_root)
            source.write_bytes(b"after\n")
            result = check_release.check_release_tree_stability(snapshot, fixture_root)
        self.assertFalse(result.ok)
        self.assertIn("docs/source.txt", result.detail)

    def test_json_output_inside_release_set_is_rejected_before_checks(self) -> None:
        target = ROOT / "release" / "check-results.json"
        with mock.patch.object(check_release, "run_checks") as runner:
            with mock.patch.object(check_release, "atomic_write_text") as writer:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        check_release.main(["--json-out", str(target)])
        runner.assert_not_called()
        writer.assert_not_called()

        with tempfile.TemporaryDirectory() as tmp:
            external_output = Path(tmp).resolve() / "checks.json"
            with mock.patch.object(check_release, "run_checks", return_value=[]):
                with mock.patch.object(
                    check_release,
                    "atomic_write_text",
                    side_effect=ReleaseSetError("diagnostic target is not regular"),
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = check_release.main(
                            ["--json-out", str(external_output)]
                        )
        self.assertEqual(exit_code, 1)

    def test_node_can_be_mandatory_in_ci_without_changing_local_default(self) -> None:
        with mock.patch.object(check_release.shutil, "which", return_value=None):
            local_result = check_release.check_javascript_syntax()
            ci_result = check_release.check_javascript_syntax(require_node=True)
        self.assertTrue(local_result.ok)
        self.assertTrue(local_result.skipped)
        self.assertFalse(ci_result.ok)
        self.assertFalse(ci_result.skipped)
        self.assertIn("required", ci_result.detail)

    def test_unit_test_result_reports_the_discovered_count(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="-----\nRan 247 tests in 1.250s\n\nOK\n",
        )
        with mock.patch.object(check_release.subprocess, "run", return_value=completed):
            result = check_release.check_unittest_suite()
        self.assertTrue(result.ok)
        self.assertEqual(result.detail, "247 test(s) passed")

    def test_empty_or_fully_skipped_suite_cannot_pass(self) -> None:
        cases = (
            "Ran 0 tests in 0.001s\n\nOK\n",
            "Ran 247 tests in 0.001s\n\nOK (skipped=247)\n",
        )
        for stderr in cases:
            with self.subTest(stderr=stderr):
                completed = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="",
                    stderr=stderr,
                )
                with mock.patch.object(check_release.subprocess, "run", return_value=completed):
                    result = check_release.check_unittest_suite()
                self.assertFalse(result.ok)
                self.assertIn("execution floor not met", result.detail)

    def test_unit_test_failure_reports_bounded_identifiers_without_traceback(self) -> None:
        headers = "".join(
            f"ERROR: test_{index} (test_example.ExampleTests.test_{index})\n"
            for index in range(7)
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="SECRET-STDOUT\n",
            stderr=(
                f"{headers}"
                f"ERROR: test_long (test_example.{'a' * 2_000})\n"
                "Traceback: SECRET-TRACEBACK\n"
                "FAILED (token=123456)\n"
            ),
        )
        with mock.patch.object(check_release.subprocess, "run", return_value=completed):
            result = check_release.check_unittest_suite()
        self.assertFalse(result.ok)
        self.assertIn("unittest exited with code 1", result.detail)
        self.assertIn("test_example.ExampleTests.test_0", result.detail)
        self.assertIn("test_example.ExampleTests.test_4", result.detail)
        self.assertNotIn("test_example.ExampleTests.test_5", result.detail)
        self.assertNotIn("token", result.detail)
        self.assertNotIn("SECRET", result.detail)
        self.assertLessEqual(
            len(result.detail),
            check_release.MAX_UNITTEST_DETAIL_CHARACTERS,
        )

    def test_unit_test_failure_extracts_identifier_from_subtest_header_only(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr=(
                "ERROR: test_case (test_example.ExampleTests.test_case) "
                "(secret='must-not-leak')\n"
                "Traceback: SECRET-TRACEBACK\n"
                "FAILED (errors=1)\n"
            ),
        )
        with mock.patch.object(check_release.subprocess, "run", return_value=completed):
            result = check_release.check_unittest_suite()
        self.assertIn("test_example.ExampleTests.test_case", result.detail)
        self.assertNotIn("must-not-leak", result.detail)
        self.assertNotIn("SECRET", result.detail)

    def test_unit_test_success_requires_a_recognised_terminal_summary(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="Ran 999 tests in 0.001s\nOK\n",
            stderr="OK\n",
        )
        with mock.patch.object(check_release.subprocess, "run", return_value=completed):
            result = check_release.check_unittest_suite()
        self.assertFalse(result.ok)
        self.assertIn("not a recognised successful run", result.detail)

    def test_unittest_child_removes_all_ambient_python_controls(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="Ran 247 tests in 0.001s\n\nOK\n",
        )
        ambient = {
            "PYTHONHASHSEED": "314159",
            "PYTHONHOME": "/ambient/python-home",
            "PYTHONPATH": "/ambient/python-path",
            "PYTHONUTF8": "1",
        }
        with mock.patch.dict(check_release.os.environ, ambient, clear=False):
            with mock.patch.object(
                check_release.subprocess,
                "run",
                return_value=completed,
            ) as runner:
                result = check_release.check_unittest_suite()
        self.assertTrue(result.ok, result.detail)
        environment = runner.call_args.kwargs["env"]
        self.assertFalse(
            any(key.upper().startswith("PYTHON") for key in environment),
            environment,
        )

    @unittest.skipIf(os.environ.get(NESTED_GATE_ENV) == "1", "outer canonical-gate regression")
    def test_default_gate_leaves_complete_source_tree_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = (Path(tmp) / "kit").resolve()
            shutil.copytree(
                ROOT,
                fixture_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".mypy_cache", "dist"),
            )
            (fixture_root / "release" / "release-manifest.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            prepared = check_release.refresh_release_evidence(fixture_root)
            self.assertTrue(prepared.ok, prepared.detail)
            before = self.snapshot_tree(fixture_root)
            environment = os.environ.copy()
            environment[NESTED_GATE_ENV] = "1"
            gate = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "tools/check_release.py"],
                cwd=fixture_root,
                env=environment,
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
