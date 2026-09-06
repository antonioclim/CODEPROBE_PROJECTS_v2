"""Static boundaries and hermetic races complement the real Chromium gate."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))
import calibrate_profile
import check_dependency_boundary
import check_pyodide_provenance


class WorkerContractTests(unittest.TestCase):
    def test_neither_interface_can_execute_python_on_the_page(self):
        for name in ("codeprobe-ui.js", "project-ui.js"):
            source = (ROOT / "app" / name).read_text(encoding="utf-8")
            self.assertNotIn(".runPython(", source)
            self.assertIn("CodeProbeRuntime.createAnalysisSession", source)
            self.assertIn("cancelAnalysis", source)
            self.assertIn("generation !==", source)

    def test_worker_has_fixed_entry_points_and_clears_payload(self):
        source = (ROOT / "app" / "analysis-worker.js").read_text(encoding="utf-8")
        self.assertIn('runtime.globals.delete("payload_json")', source)
        self.assertIn("codeprobe_runtime.codeprobe_analyze_project(payload_json)", source)
        self.assertIn("codeprobe_runtime.codeprobe_analyze(payload_json)", source)
        self.assertNotIn("runPython(message", source)
        self.assertNotIn("error.message", source)

    def test_worker_record_matches_bytes_before_any_remote_execution(self):
        source = (ROOT / "app" / "pyodide-loader.js").read_text(encoding="utf-8")
        data = (ROOT / "app" / "analysis-worker.js").read_bytes()
        record = re.search(r"const PACKAGED_WORKER_RECORD = Object.freeze\(\{(.*?)\}\);", source, re.S).group(1)
        self.assertIn(hashlib.sha256(data).hexdigest(), record)
        self.assertIn(f"size_bytes: {len(data)}", record)
        self.assertIn("integrity: script.integrity", source)
        self.assertIn("worker.terminate()", source)

    def test_worker_entry_is_not_allowed_to_install_packages(self):
        source = 'self.importScripts("https://example.invalid/untrusted.js");'
        self.assertTrue(any(pattern.search(source) for pattern, _ in check_dependency_boundary.DYNAMIC_JAVASCRIPT_LOADERS))

    def test_cancel_controls_exist_on_both_pages(self):
        for name in ("index.html", "project.html"):
            source = (ROOT / "app" / name).read_text(encoding="utf-8")
            self.assertIn('id="cancelBtn" type="button" disabled', source)
            self.assertIn("worker-src 'self' blob:", source)

    def test_large_input_highlighting_is_bounded(self):
        source = (ROOT / "app" / "codeprobe-ui.js").read_text(encoding="utf-8")
        self.assertIn("if (code.length > 50000) return escapeHtml(code);", source)

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable on this runner")
    def test_hermetic_worker_protocol_races(self):
        completed = subprocess.run(
            [shutil.which("node"), str(ROOT / "tools" / "check_worker_protocol.js")],
            cwd=ROOT, capture_output=True, text=True, timeout=45, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("21 hermetic scenarios", completed.stdout)

    def test_an_extra_worker_import_is_rejected_by_the_actual_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "app", root / "app")
            path = root / "app" / "pyodide-loader.js"
            with path.open("a", encoding="utf-8") as stream:
                stream.write('\nself.importScripts("unreviewed.js");\n')
            errors = check_dependency_boundary.check_javascript_package_loading(root)
            self.assertTrue(any("dynamic worker import" in error for error in errors), errors)

    def test_worker_size_cannot_pass_as_a_decimal_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "app", root / "app")
            shutil.copytree(ROOT / "src", root / "src")
            path = root / "app" / "pyodide-loader.js"
            source = path.read_text(encoding="utf-8")
            size = len((root / "app" / "analysis-worker.js").read_bytes())
            source = source.replace(f"size_bytes: {size},", f"size_bytes: {size}0,")
            path.write_text(source, encoding="utf-8")
            errors = check_pyodide_provenance.audit_pyodide_provenance(root)
            self.assertTrue(any("worker integrity record differs" in error for error in errors), errors)

    def test_real_browser_gate_covers_both_pages_without_a_worker_double(self):
        source = (ROOT / "tools" / "check_browser_functional.js").read_text(encoding="utf-8")
        self.assertIn("testWorkerResponsiveness(cdp, baseUrl, state, false)", source)
        self.assertIn("testWorkerResponsiveness(cdp, baseUrl, state, true)", source)
        self.assertIn("testTamperedWorkerBootstrap", source)
        self.assertIn("LEGAL_BUSY_SOURCE", source)
        self.assertNotIn("class Worker", source)

    def test_governance_metadata_does_not_invent_authorship_or_enforcement(self):
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        owners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        self.assertEqual(json.loads(citation)["authors"], [{"family-names": "Clim", "given-names": "Antonio"}])
        self.assertIn("CodeProbe contributors", licence)
        self.assertNotIn("doi", json.loads(citation))
        self.assertTrue(all("orcid" not in author for author in json.loads(citation)["authors"]))
        self.assertIn("* @antonioclim", owners)
        self.assertIn("does not establish", owners)
        self.assertTrue((ROOT / "SECURITY.md").is_file())
        self.assertTrue((ROOT / "docs" / "21-runtime-lifecycle.md").is_file())


class OpaqueCalibrationIdentifierTests(unittest.TestCase):
    @staticmethod
    def observations():
        return [
            calibrate_profile.SampleResult(
                path=f"alice-{index}.py", label="human" if index % 2 == 0 else "ai",
                kind="file", language="python", score=.2 if index % 2 == 0 else .8,
                applicable=True, sloc=20, verdict_class="low", sample_id=f"private-name-{index}",
                split="fit" if index < 4 else "evaluation", group_id=f"group-person-{index // 2}-{index % 2}",
            ) for index in range(8)
        ]

    def test_tokens_are_fresh_and_contain_no_source_or_declared_identifiers(self):
        rows = self.observations()
        first = calibrate_profile.build_profile({}, rows, .1)
        second = calibrate_profile.build_profile({}, rows, .1)
        left = first["validation"]["sample_results"]
        right = second["validation"]["sample_results"]
        self.assertTrue({row["sample_id"] for row in left}.isdisjoint(row["sample_id"] for row in right))
        self.assertTrue({row["group_id"] for row in left}.isdisjoint(row["group_id"] for row in right))
        serialised = json.dumps(first)
        self.assertNotIn("alice", serialised)
        self.assertNotIn("private-name", serialised)
        self.assertNotIn("group-person", serialised)
        self.assertEqual(first["review_policy"], second["review_policy"])
        self.assertFalse(first["validation"]["identifier_policy"]["mapping_exported"])

    def test_estimation_and_partition_assignment_do_not_depend_on_export_tokens(self):
        rows = self.observations()
        first = calibrate_profile.build_profile({}, rows, .1)
        second = calibrate_profile.build_profile({}, rows, .1)
        for field in ("evaluation_design", "fit_at_selected_trigger", "evaluation_at_selected_trigger", "sensitivity"):
            self.assertEqual(first["validation"][field], second["validation"][field])
        for left, right in zip(first["validation"]["sample_results"], second["validation"]["sample_results"]):
            for field in ("split", "score", "label", "language", "sloc"):
                self.assertEqual(left[field], right[field])

    def test_group_equality_is_retained_within_one_export(self):
        rows = self.observations()
        rows[2].group_id = rows[0].group_id
        output = calibrate_profile._opaque_sample_results(rows)
        self.assertEqual(output[0]["group_id"], output[2]["group_id"])
        self.assertNotEqual(output[0]["sample_id"], output[2]["sample_id"])
        for row in output:
            self.assertEqual(row["path"], row["sample_id"])
            self.assertRegex(row["sample_id"], r"^sample-[0-9a-f]{32}$")
        self.assertEqual(rows[0].path, "alice-0.py")

    def test_explicit_split_leakage_is_still_rejected_before_tokenisation(self):
        rows = self.observations()
        rows[4].group_id = rows[0].group_id
        with self.assertRaisesRegex(ValueError, "one partition"):
            calibrate_profile.build_profile({}, rows, .1)


if __name__ == "__main__":
    unittest.main()
