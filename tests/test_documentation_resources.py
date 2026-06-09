from __future__ import annotations

import csv
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PhaseElevenDocumentationResourceTests(unittest.TestCase):
    def test_phase11_public_documentation_paths_exist(self) -> None:
        for relative in [
            "docs/02-architecture.md",
            "docs/03-report-schema.md",
            "docs/04-browser-security.md",
            "docs/05-offline-deployment.md",
            "docs/06-calibration-guide.md",
            "docs/07-ui-extension-guide.md",
            "docs/08-release-process.md",
            "docs/09-release-integrity.md",
            "docs/10-provenance.md",
            "docs/11-design-decisions.md",
            "docs/12-release-hash-sheet.md",
            "docs/13-signed-release-workflow.md",
            "docs/14-optimisation-roadmap.md",
            "docs/history/11-documentation-resources.md",
            "docs/assets/interface-preview.png",
        ]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_phase11_educator_and_calibration_paths_exist(self) -> None:
        for relative in [
            "educator/01-student-quick-start.md",
            "educator/02-student-announcement.md",
            "educator/02-student-announcement.docx",
            "educator/03-student-disclosure-template.md",
            "educator/04-instructor-checklist.md",
            "educator/05-review-protocol.md",
            "educator/06-evidence-rubric.md",
            "educator/07-course-integration.md",
            "educator/08-deployment-one-page.md",
            "educator/09-project-kit-notice.md",
            "calibration/01-corpus-manifest-template.csv",
            "calibration/01-corpus-manifest-template.json",
            "calibration/02-calibration-profile-template.json",
            "calibration/03-example-calibration-profile.json",
            "calibration/04-validation-summary-template.md",
            "calibration/profiles/README.md",
            "calibration/reports/.gitkeep",
        ]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_retired_phase11_directories_are_absent(self) -> None:
        self.assertFalse((ROOT / "educator_resources").exists())
        self.assertFalse((ROOT / "calibration" / "local_profiles").exists())
        self.assertFalse((ROOT / "calibration" / "validation_reports").exists())

    def test_rename_map_records_previous_paths_for_phase11_moves(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            rows = {row["current_path"]: row for row in csv.DictReader(handle)}
        self.assertEqual(rows["docs/10-provenance.md"]["previous_path"], "AI_ASSISTANCE_AND_PROVENANCE.md")
        self.assertEqual(rows["educator/02-student-announcement.md"]["previous_path"], "educator_resources/AI_FINGERPRINT_SELF_CHECK_ANNOUNCEMENT_REVISED.md")
        self.assertEqual(rows["calibration/01-corpus-manifest-template.csv"]["previous_path"], "calibration/manifest_template.csv")


if __name__ == "__main__":
    unittest.main()
