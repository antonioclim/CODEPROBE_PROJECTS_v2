from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "check_pyodide_lifecycle.py"
POLICY = ROOT / "app" / "pyodide-support-policy.json"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "check_pyodide_lifecycle_phase4f2_test", TOOL
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load check_pyodide_lifecycle.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lifecycle = load_module()


class PyodideLifecycleTests(unittest.TestCase):
    def test_repository_policy_is_current_but_not_release_approved(self) -> None:
        result = lifecycle.check_policy(
            POLICY,
            today=dt.date(2026, 9, 4),
        )
        self.assertEqual(result["pinned_version"], "0.25.0")
        self.assertEqual(
            result["public_release_status"],
            "blocked-until-measured-upgrade",
        )
        self.assertTrue(result["upgrade_required_before_public_release"])
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.check_policy(
                POLICY,
                today=dt.date(2026, 9, 4),
                require_release_approval=True,
            )

    def test_policy_expires_after_next_review_date(self) -> None:
        with self.assertRaisesRegex(lifecycle.LifecycleError, "review expired"):
            lifecycle.check_policy(
                POLICY,
                today=dt.date(2026, 10, 16),
            )

    def test_review_interval_ceiling_is_enforced(self) -> None:
        payload = json.loads(POLICY.read_text(encoding="utf-8"))
        payload["next_review_by"] = "2027-01-01"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "interval"):
            lifecycle.validate_policy(
                payload,
                today=dt.date(2026, 9, 4),
            )

    def test_provenance_version_must_match_policy(self) -> None:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        provenance = json.loads(
            (POLICY.parent / "pyodide-provenance.json").read_text(
                encoding="utf-8"
            )
        )
        provenance["version"] = "0.24.1"
        with self.assertRaisesRegex(lifecycle.LifecycleError, "does not match"):
            lifecycle.validate_policy(
                policy,
                today=dt.date(2026, 9, 4),
                provenance=provenance,
            )

    def test_assurance_boundary_cannot_claim_unverified_scope(self) -> None:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        policy["assurance_boundary"]["current_advisory_absence_claimed"] = True
        with self.assertRaisesRegex(
            lifecycle.LifecycleError,
            "current_advisory_absence_claimed",
        ):
            lifecycle.validate_policy(
                policy,
                today=dt.date(2026, 9, 4),
            )

    def test_cli_returns_failure_for_expired_fixture(self) -> None:
        payload = json.loads(POLICY.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            policy_path = temporary_path / "pyodide-support-policy.json"
            provenance_path = temporary_path / "pyodide-provenance.json"
            policy_path.write_text(
                json.dumps(payload), encoding="utf-8"
            )
            provenance_path.write_text(
                (POLICY.parent / "pyodide-provenance.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            original_argv = sys.argv
            try:
                sys.argv = [
                    str(TOOL),
                    "--policy",
                    str(policy_path),
                    "--today",
                    "2026-10-16",
                ]
                self.assertEqual(lifecycle.main(), 1)
            finally:
                sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
