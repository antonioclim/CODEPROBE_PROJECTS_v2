from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codeprobe_engine import release_recovery
from codeprobe_engine.release_recovery import (
    ReleaseRecoveryError,
    crash_safe_replace,
    finalise_current_process_transactions,
    recover_pending_transaction,
)


class ReleaseRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        release_recovery._ACTIVE_OUTPUTS.clear()

    def tearDown(self) -> None:
        release_recovery._ACTIVE_OUTPUTS.clear()

    @staticmethod
    def _packet(directory: Path, prefix: str, payload: bytes) -> dict[str, Path]:
        digest = hashlib.sha256(payload).hexdigest()
        paths = {
            "zip": directory / f"{prefix}.zip",
            "checksum": directory / f"{prefix}.zip.sha256",
            "audit": directory / f"{prefix}.package-audit.json",
        }
        paths["zip"].write_bytes(payload)
        paths["checksum"].write_text(
            f"{digest}  {paths['zip'].name}\n", encoding="utf-8"
        )
        paths["audit"].write_text(
            json.dumps(
                {
                    "schema": "test-package-audit/v1",
                    "zip_sha256": digest,
                    "zip_name": paths["zip"].name,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return paths

    @staticmethod
    def _staged_packet(directory: Path, prefix: str, payload: bytes) -> dict[str, Path]:
        stage = directory / "staging"
        stage.mkdir()
        return ReleaseRecoveryTests._packet(stage, prefix, payload)

    def test_no_journal_is_a_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(recover_pending_transaction(temporary), "none")

    def test_normal_completion_commits_consistent_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            old = self._packet(output, "CodeProbe", b"old packet")
            staged = self._staged_packet(output, "CodeProbe", b"new packet")
            for key in ("zip", "checksum", "audit"):
                crash_safe_replace(staged[key], old[key])
            finalise_current_process_transactions()
            self.assertEqual(old["zip"].read_bytes(), b"new packet")
            self.assertFalse((output / release_recovery.RECOVERY_DIR_NAME).exists())

    def test_inconsistent_normal_completion_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            old = self._packet(output, "CodeProbe", b"old packet")
            staged = self._staged_packet(output, "CodeProbe", b"new packet")
            crash_safe_replace(staged["zip"], old["zip"])
            finalise_current_process_transactions()
            self.assertEqual(old["zip"].read_bytes(), b"old packet")
            self.assertFalse((output / release_recovery.RECOVERY_DIR_NAME).exists())

    def _crash_process(
        self,
        output: Path,
        crash_key: str | None,
        *,
        exit_after_all: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        script = r'''
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
src = Path(sys.argv[2])
out = Path(sys.argv[3])
crash_name = sys.argv[4]
exit_after_all = sys.argv[5] == "1"
sys.path.insert(0, str(src))
from codeprobe_engine import release_recovery as rr

original = rr._REAL_REPLACE

def killer(source, destination):
    original(source, destination)
    if crash_name and Path(destination).name == crash_name:
        os._exit(87)

rr._REAL_REPLACE = killer
for name in ("CodeProbe.zip", "CodeProbe.zip.sha256", "CodeProbe.package-audit.json"):
    rr.crash_safe_replace(root / "staging" / name, out / name)
if exit_after_all:
    os._exit(87)
rr.finalise_current_process_transactions()
'''
        crash_name = {
            "zip": "CodeProbe.zip",
            "checksum": "CodeProbe.zip.sha256",
            "audit": "CodeProbe.package-audit.json",
            None: "",
        }[crash_key]
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                script,
                str(output),
                str(SRC),
                str(output),
                crash_name,
                "1" if exit_after_all else "0",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )

    def test_forced_death_after_each_public_replace_rolls_back(self) -> None:
        for crash_key in ("zip", "checksum", "audit"):
            with self.subTest(crash_key=crash_key), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                old = self._packet(output, "CodeProbe", b"old packet")
                self._staged_packet(output, "CodeProbe", b"new packet")
                result = self._crash_process(output, crash_key)
                self.assertEqual(result.returncode, 87, result.stdout)
                self.assertEqual(recover_pending_transaction(output), "rolled-back")
                self.assertEqual(old["zip"].read_bytes(), b"old packet")
                self.assertIn(
                    hashlib.sha256(b"old packet").hexdigest(),
                    old["checksum"].read_text(encoding="utf-8"),
                )
                self.assertFalse(
                    (output / release_recovery.RECOVERY_DIR_NAME).exists()
                )

    def test_death_after_complete_consistent_packet_retains_new_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            old = self._packet(output, "CodeProbe", b"old packet")
            self._staged_packet(output, "CodeProbe", b"new packet")
            result = self._crash_process(output, None, exit_after_all=True)
            self.assertEqual(result.returncode, 87, result.stdout)
            self.assertEqual(recover_pending_transaction(output), "committed")
            self.assertEqual(old["zip"].read_bytes(), b"new packet")
            self.assertFalse((output / release_recovery.RECOVERY_DIR_NAME).exists())

    def test_prior_absent_targets_are_removed_during_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            staged = self._staged_packet(output, "CodeProbe", b"new packet")
            crash_safe_replace(staged["zip"], output / "CodeProbe.zip")
            finalise_current_process_transactions()
            self.assertFalse((output / "CodeProbe.zip").exists())

    def test_corrupt_journal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            recovery = output / release_recovery.RECOVERY_DIR_NAME
            recovery.mkdir()
            (recovery / release_recovery.JOURNAL_NAME).write_text(
                "{not-json", encoding="utf-8"
            )
            with self.assertRaises(ReleaseRecoveryError):
                recover_pending_transaction(output)
            self.assertTrue(recovery.exists())

    def test_escaping_journal_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            recovery = output / release_recovery.RECOVERY_DIR_NAME
            recovery.mkdir()
            payload = {
                "schema": release_recovery.RECOVERY_SCHEMA,
                "transaction_id": "a" * 32,
                "process_nonce": "dead-process",
                "records": [
                    {
                        "target": "../outside.zip",
                        "backup": None,
                        "existed": False,
                        "state": "prepared",
                    }
                ],
            }
            (recovery / release_recovery.JOURNAL_NAME).write_text(
                json.dumps(payload), encoding="utf-8"
            )
            with self.assertRaises(ReleaseRecoveryError):
                recover_pending_transaction(output)

    def test_non_packet_replace_delegates_without_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source.tmp"
            destination = directory / "destination.txt"
            source.write_text("value", encoding="utf-8")
            crash_safe_replace(source, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), "value")
            self.assertFalse(
                (directory / release_recovery.RECOVERY_DIR_NAME).exists()
            )


if __name__ == "__main__":
    unittest.main()
