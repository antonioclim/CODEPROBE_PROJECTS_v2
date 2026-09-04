from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Phase4F2GovernanceTests(unittest.TestCase):
    def test_security_policy_uses_private_reporting_and_scope_limits(self) -> None:
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("Do not disclose", text)
        self.assertIn("Report a vulnerability", text)
        self.assertIn("not an authorship determination", text)
        self.assertNotIn("TODO", text)

    def test_codeowners_covers_high_risk_boundaries(self) -> None:
        text = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        for required in (
            "/.github/workflows/",
            "/app/pyodide-loader.js",
            "/app/analysis-watchdog.js",
            "/src/codeprobe_engine/release_recovery.py",
            "/release/",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertIn("@antonioclim", text)

    def test_citation_metadata_is_specific_without_invented_identifier(self) -> None:
        text = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        self.assertIn("family-names: Clim", text)
        self.assertIn("given-names: Antonio", text)
        self.assertIn("version: 2.2.0", text)
        self.assertNotIn("doi:", text.lower())
        self.assertNotIn("orcid", text.lower())

    def test_runtime_policy_is_explicitly_not_public_release_approved(self) -> None:
        payload = json.loads(
            (ROOT / "app" / "pyodide-support-policy.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(payload["upgrade_required_before_public_release"])
        self.assertEqual(
            payload["public_release_status"],
            "blocked-until-measured-upgrade",
        )
        self.assertFalse(
            payload["assurance_boundary"]["current_advisory_absence_claimed"]
        )


if __name__ == "__main__":
    unittest.main()
