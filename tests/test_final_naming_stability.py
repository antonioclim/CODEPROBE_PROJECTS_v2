from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import check_file_references  # noqa: E402
from codeprobe_engine.release import MANIFEST_NAME, iter_release_files  # noqa: E402


class FinalNamingStabilityTests(unittest.TestCase):
    def test_release_manifest_lives_under_release_directory(self) -> None:
        self.assertEqual(MANIFEST_NAME, "release/release-manifest.json")
        self.assertFalse((ROOT / "RELEASE_MANIFEST.json").exists())
        self.assertTrue((ROOT / MANIFEST_NAME).is_file())

    def test_no_retired_runtime_or_ui_paths_exist(self) -> None:
        retired = [
            "src/index.html",
            "src/project_index.html",
            "src/index.js",
            "src/project_index.js",
            "src/engine.py",
            "src/run_local_server.py",
            "src/analyze_project.py",
            "src/runtime_config.json",
            "src/RESOURCE_INTEGRITY_MANIFEST.json",
            "KIT_INDEX.md",
            "release/rename-map.csv",
        ]
        for relative in retired:
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_file_catalogue_and_rename_map_cover_release_files(self) -> None:
        with (ROOT / "release" / "file-rename-map.csv").open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        mapped = {row["current_path"] for row in rows}
        self.assertEqual(len(rows), len(mapped), "file-rename map contains duplicate current paths")
        release_files = {path.relative_to(ROOT).as_posix() for path in iter_release_files(ROOT)}
        release_files.add(MANIFEST_NAME)
        self.assertEqual(mapped, release_files)
        catalogue = (ROOT / "docs" / "00-file-catalogue.md").read_text(encoding="utf-8")
        for relative in sorted(release_files):
            self.assertIn(f"| `{relative}` |", catalogue, relative)

    def test_checkout_policy_fixes_text_to_lf_and_marks_binary_assets(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("* text=auto eol=lf", attributes)
        self.assertIn("-filter", attributes)
        self.assertIn("-export-subst", attributes)
        for pattern in ("*.docx binary !eol", "*.png binary !eol", "*.wasm binary !eol"):
            self.assertIn(pattern, attributes)
        self.assertNotIn(b"\r", (ROOT / "release" / "file-rename-map.csv").read_bytes())

    def test_ci_preserves_exact_run_evidence_and_uses_native_macos_arm64(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "github.event.pull_request.number || github.run_id",
            workflow,
        )
        self.assertIn(
            '- os: macos-15\n            python: "3.14.7"\n'
            "            architecture: arm64\n"
            "            python_machine: arm64\n"
            "            node_arch: arm64",
            workflow,
        )
        self.assertEqual(workflow.count("architecture: ${{ matrix.architecture }}"), 2)
        self.assertIn("EXPECTED_PYTHON_MACHINE", workflow)
        self.assertIn("EXPECTED_NODE_ARCH", workflow)
        self.assertNotIn("--write-release-evidence", workflow)

    def test_reference_audit_has_no_errors(self) -> None:
        self.assertEqual(check_file_references.run_checks(ROOT), [])


if __name__ == "__main__":
    unittest.main()
