from __future__ import annotations

import csv
import json
import re
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


class AuthorshipAndLineageDocumentationTests(unittest.TestCase):
    """Maintain explicit citation identity without a runtime YAML dependency."""

    def text(self, relative: str) -> str:
        path = ROOT / relative
        self.assertTrue(path.is_file(), relative)
        return path.read_text(encoding="utf-8")

    def citation(self) -> dict:
        # JSON is the deliberately selected YAML-compatible CFF representation.
        try:
            citation = json.loads(self.text("CITATION.cff"))
        except (ValueError, TypeError) as exc:
            self.fail(f"CITATION.cff must use the maintained JSON representation: {exc}")
        self.assertIsInstance(citation, dict)
        return citation

    def test_citation_has_named_author_and_explicit_software_release(self) -> None:
        citation = self.citation()
        self.assertEqual(citation["cff-version"], "1.2.0")
        self.assertEqual(citation["authors"], [{"family-names": "Clim", "given-names": "Antonio"}])
        self.assertEqual(citation["type"], "software")
        self.assertEqual(citation["license"], "MIT")
        self.assertEqual(citation["version"], "2.2.0")
        self.assertEqual(citation["date-released"], "2026-09-06")
        self.assertEqual(citation["commit"], "2d38fbd3772a9f415dfcc52ab2840aadd15575e3")
        repository = "https://github.com/antonioclim/CODEPROBE_PROJECTS_v2"
        self.assertEqual(citation["repository-code"], repository)
        self.assertEqual(citation["url"], repository + "/releases/tag/v2.2.0")
        self.assertTrue(citation["title"] and citation["message"])
        self.assertFalse({"doi", "identifiers", "preferred-citation", "references"} & citation.keys())

    def test_readme_and_bibtex_use_the_cff_citation_identity(self) -> None:
        citation = self.citation()
        readme = self.text("README.md")
        bibtex = self.text("CITATION.bib")
        self.assertIn("## Cite this repository", readme)
        self.assertIn("Clim, A. (2026).", readme)
        self.assertIn(citation["title"], readme)
        self.assertIn("author = {Clim, Antonio}", bibtex)
        self.assertIn("version = {" + citation["version"] + "}", bibtex)
        self.assertIn("date = {" + citation["date-released"] + "}", bibtex)
        for text in (readme, bibtex):
            self.assertIn(citation["url"], text)
        self.assertIn("[CITATION.cff](CITATION.cff)", readme)
        self.assertIn("[CITATION.bib](CITATION.bib)", readme)
        self.assertIn("development checkout", readme)
        self.assertIn("later documentation changes", readme)

    def test_contributor_guide_names_the_maintainer_and_keeps_the_full_gates(self) -> None:
        guide = self.text("CONTRIBUTING.md")
        self.assertIn("**Antonio Clim**", guide)
        self.assertIn("https://github.com/antonioclim", guide)
        self.assertIn("python3 -I -S -B tools/check_release.py --require-node", guide)
        self.assertIn("--write-release-evidence", guide)
        self.assertIn("python3 -I -S -B tools/check_release_reproducibility.py", guide)
        self.assertIn("MIT", guide)
        self.assertIn("Synthetic labels do not become observations", guide)
        self.assertNotIn("python3 -m py_compile", guide)

    def test_legacy_observation_is_attributed_and_not_a_validated_error_rate(self) -> None:
        readme = self.text("README.md")
        section = readme.split("## Relationship to the legacy repository", 1)
        self.assertEqual(len(section), 2)
        notice = section[1].split("\n## ", 1)[0]
        for phrase in ("Antonio Clim", "30%", "author-reported operational observation",
                       "not an independently reproduced benchmark", "false-positive rate",
                       "denominator", "does not assert that public access has already been removed"):
            self.assertIn(phrase, notice)
        self.assertIn("engineering improvements", notice)
        self.assertIn("do not establish detector accuracy", notice)
        self.assertIn("[legacy comparison](docs/history/14-legacy-lineage.md)", notice)

    def test_legacy_comparison_uses_fixed_source_snapshots(self) -> None:
        comparison = self.text("docs/history/14-legacy-lineage.md")
        refs = {
            "CODEPROBE_PROJECTS_v1": "e7a1778b789c98c6c2029d8cfa85184757731ecf",
            "CODEPROBE_PROJECTS_v2": "3fe84e86d72876f674f37c152bc0cefe23500e29",
        }
        for repository, commit in refs.items():
            urls = re.findall(r"https://github\.com/antonioclim/" + repository + r"/(?:blob|tree)/[^\s)]+", comparison)
            self.assertTrue(urls, repository)
            self.assertTrue(all("/" + commit in url for url in urls), urls)
        self.assertIn("not a newly completed exhaustive", comparison)
        self.assertIn("cannot be converted", comparison)
        self.assertIn("does not perform or certify", comparison)
        self.assertIn("no new legacy real-browser execution", comparison)

    def test_authorship_addition_preserves_the_expanded_format_guide(self) -> None:
        readme = self.text("README.md")
        self.assertIn("**Author and maintainer: Antonio Clim**", readme)
        self.assertIn("![CodeProbe interface preview](docs/assets/interface-preview.png)", readme)
        for heading in ("Supported languages and source extensions", "Documents, databases and other file types",
                        "Input routes, folders and Git archives", "Command-line use", "Reports and exports",
                        "Input limits and exclusions"):
            self.assertIn("## " + heading, readme)
        for token in (".tsx", ".zsh", ".docx", "PDF", ".sqlite3", "git archive", "No PDF/OCR"):
            self.assertIn(token, readme)


if __name__ == "__main__":
    unittest.main()
