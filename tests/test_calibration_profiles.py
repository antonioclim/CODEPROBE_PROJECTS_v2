from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import calibrate_corpus  # noqa: E402
import calibrate_profile  # noqa: E402
import codeprobe_runtime as engine  # noqa: E402


SAMPLE_CODE = """
def add(left, right):
    return left + right


def subtract(left, right):
    return left - right


def multiply(left, right):
    value = left * right
    return value


def main():
    total = add(1, 2)
    return multiply(total, 3)
""".strip() + "\n"


class PhaseFourCalibrationTests(unittest.TestCase):
    def test_file_report_records_calibration_profile_and_trigger_status(self) -> None:
        calibration = {
            "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
            "profile_id": "unit-test-profile",
            "label": "Unit test calibration",
            "review_policy": {
                "file": {"low_max": 0.10, "moderate_max": 0.20, "elevated_max": 0.30, "review_trigger": 0.01},
                "project": {"low_max": 0.10, "moderate_max": 0.20, "elevated_max": 0.30, "review_trigger": 0.01},
            },
        }
        result = json.loads(engine.codeprobe_analyze(json.dumps({
            "filename": "sample.py",
            "code": SAMPLE_CODE,
            "calibration_profile": calibration,
        })))
        report = result["report"]
        self.assertEqual(report["app_version"], "2.2.0")
        self.assertEqual(report["schema_version"], "2.2.0")
        self.assertEqual(report["calibration_profile_id"], "unit-test-profile")
        self.assertEqual(report["review_trigger_percent"], 1.0)
        self.assertTrue(report["review_triggered"])
        self.assertIn(report["verdict_class"], {"low", "moderate", "elevated", "high"})

    def test_project_report_records_calibration_profile(self) -> None:
        calibration = {
            "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
            "profile_id": "project-test-profile",
            "review_policy": {
                "file": {"low_max": 0.28, "moderate_max": 0.48, "elevated_max": 0.68, "review_trigger": 0.50},
                "project": {"low_max": 0.28, "moderate_max": 0.48, "elevated_max": 0.68, "review_trigger": 0.50},
            },
        }
        result = json.loads(engine.codeprobe_analyze_project(json.dumps({
            "project_name": "calibrated-project",
            "files": [{"path": "src/app.py", "content": SAMPLE_CODE}],
            "calibration_profile": calibration,
        })))
        report = result["project_report"]
        self.assertEqual(report["schema_version"], "2.2.0-project")
        self.assertEqual(report["calibration_profile_id"], "project-test-profile")
        self.assertEqual(report["review_trigger_percent"], 50.0)
        self.assertIn("calibration_profile", report)
        self.assertIn("review_policy", report)
        self.assertEqual(report["project"]["calibration_profile_id"], "project-test-profile")

    def test_calibration_corpus_cli_generates_profile_usable_by_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "human").mkdir()
            (root / "ai").mkdir()
            (root / "human" / "student_1.py").write_text(SAMPLE_CODE, encoding="utf-8")
            (root / "human" / "student_2.py").write_text(
                SAMPLE_CODE.replace("total = add(1, 2)", "total = subtract(4, 1)"),
                encoding="utf-8",
            )
            (root / "ai" / "llm_1.py").write_text(
                SAMPLE_CODE.replace("return left + right", "# Return the computed addition\n    return left + right"),
                encoding="utf-8",
            )
            (root / "ai" / "llm_2.py").write_text(
                SAMPLE_CODE.replace("def multiply", "# Generated multiplication helper\ndef multiply"),
                encoding="utf-8",
            )
            profile_path = root / "profile.json"
            summary_path = root / "summary.md"
            scores_path = root / "scores.csv"
            rc = calibrate_corpus.main([
                "--corpus-root", str(root),
                "--course", "unit-course",
                "--assignment", "unit-assignment",
                "--json-out", str(profile_path),
                "--markdown-out", str(summary_path),
                "--scores-out", str(scores_path),
            ])
            self.assertEqual(rc, 0)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["schema_version"], engine.CALIBRATION_PROFILE_SCHEMA)
            self.assertIn("review_policy", profile)
            self.assertTrue(summary_path.exists())
            self.assertTrue(scores_path.exists())
            report = json.loads(engine.codeprobe_analyze(json.dumps({
                "filename": "sample.py",
                "code": SAMPLE_CODE,
                "calibration_profile": profile,
            })))["report"]
            self.assertEqual(report["calibration_profile_id"], profile["profile_id"])

    def test_manifest_calibration_cli_generates_sensitivity_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "student_1.py").write_text(SAMPLE_CODE, encoding="utf-8")
            (root / "student_2.py").write_text(
                SAMPLE_CODE.replace("total = add(1, 2)", "total = subtract(4, 1)"),
                encoding="utf-8",
            )
            (root / "llm_1.py").write_text(
                SAMPLE_CODE.replace("def add", "# Generated helper\ndef add"),
                encoding="utf-8",
            )
            (root / "llm_2.py").write_text(
                SAMPLE_CODE.replace("def multiply", "# Generated multiplication helper\ndef multiply"),
                encoding="utf-8",
            )
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "profile_id": "manifest-unit-profile",
                "label": "Manifest unit profile",
                "course": "unit-course",
                "assignment": "unit-assignment",
                "samples": [
                    {"path": "student_1.py", "label": "human", "language_hint": "python"},
                    {"path": "student_2.py", "label": "human", "language_hint": "python"},
                    {"path": "llm_1.py", "label": "ai", "language_hint": "python"},
                    {"path": "llm_2.py", "label": "ai", "language_hint": "python"},
                ],
            }), encoding="utf-8")
            profile_path = root / "profile_manifest.json"
            summary_path = root / "summary_manifest.md"
            observations_path = root / "observations.csv"
            sensitivity_path = root / "sensitivity.csv"
            rc = calibrate_profile.main([
                "--manifest", str(manifest),
                "--profile-out", str(profile_path),
                "--summary-out", str(summary_path),
                "--csv-out", str(observations_path),
                "--sensitivity-out", str(sensitivity_path),
                "--target-fpr", "10",
            ])
            self.assertEqual(rc, 0)
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            self.assertEqual(profile["profile_id"], "manifest-unit-profile")
            self.assertIn("review_policy", profile)
            self.assertIn("Suggested local review trigger", summary_path.read_text(encoding="utf-8"))
            self.assertTrue(observations_path.exists())
            self.assertTrue(sensitivity_path.exists())


class IndependentCalibrationBoundaryTests(unittest.TestCase):
    def _result(self, name, label, score, *, split="", language="python", kind="file", group=""):
        return calibrate_profile.SampleResult(name, label, kind, "project" if kind == "project" else language, score, True, 20, "low", "", name, split, group or f"group-{name}")

    def _balanced(self):
        return [
            self._result("h-fit.py", "human", 0.20, split="fit"),
            self._result("a-fit.py", "ai_generated", 0.80, split="fit"),
            self._result("h-eval.py", "human", 0.25, split="evaluation"),
            self._result("a-eval.py", "ai_generated", 0.75, split="evaluation"),
        ]

    def test_profile_records_independent_holdout(self):
        profile = calibrate_profile.build_profile({"profile_id": "p"}, self._balanced(), 0.10)
        design = profile["validation"]["evaluation_design"]
        self.assertTrue(design["independent_holdout"])
        self.assertIn("physical filesystem identity", design["independence_basis"])
        self.assertIn("not inferred", design["independence_limitation"])

    def test_trigger_is_selected_from_fit_partition(self):
        first = calibrate_profile.build_profile({"profile_id": "p"}, self._balanced(), 0.10)
        changed = self._balanced(); changed[2].score = 0.99; changed[3].score = 0.01
        second = calibrate_profile.build_profile({"profile_id": "p"}, changed, 0.10)
        self.assertEqual(first["review_policy"], second["review_policy"])

    def test_absolute_paths_are_pseudonymised(self):
        rows = self._balanced(); rows[0].path = "/home/alice/private/h.py"; rows[0].sample_id = ""
        profile = calibrate_profile.build_profile({"profile_id": "p"}, rows, 0.10)
        serialised = json.dumps(profile)
        self.assertNotIn("/home/alice", serialised)

    def test_mixed_file_languages_are_rejected(self):
        rows = self._balanced(); rows[-1].language = "javascript"
        with self.assertRaisesRegex(ValueError, "mix languages"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, 0.10)

    def test_mixed_report_kinds_are_rejected(self):
        rows = self._balanced(); rows[-1].kind = "project"; rows[-1].language = "project"
        with self.assertRaisesRegex(ValueError, "mix file and project"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, 0.10)

    def test_project_profile_is_scoped_to_project_only(self):
        rows = [self._result("hf", "human", .2, split="fit", kind="project"), self._result("af", "ai_generated", .8, split="fit", kind="project"), self._result("he", "human", .2, split="evaluation", kind="project"), self._result("ae", "ai_generated", .8, split="evaluation", kind="project")]
        profile = calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)
        self.assertEqual(profile["scope"]["report_kinds"], ["project"])
        self.assertEqual(profile["calibrated_policy_kind"], "project")

    def test_file_profile_records_language_scope(self):
        profile = calibrate_profile.build_profile({"profile_id": "p"}, self._balanced(), .1)
        self.assertEqual(profile["scope"]["languages"], ["python"])

    def test_failed_sample_aborts_profile(self):
        rows = self._balanced(); rows[0].verdict_class = "error"; rows[0].warning = "read failed"
        with self.assertRaisesRegex(ValueError, "sample analysis failed"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_partial_explicit_splits_are_rejected(self):
        rows = self._balanced(); rows[-1].split = ""
        with self.assertRaisesRegex(ValueError, "every sample"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_automatic_split_is_reproducible(self):
        rows = [self._result(f"h{i}", "human", .2 + i/100) for i in range(4)] + [self._result(f"a{i}", "ai_generated", .7 + i/100) for i in range(4)]
        left = calibrate_profile.build_profile({"profile_id": "p", "split_seed": "s"}, rows, .1)
        right = calibrate_profile.build_profile({"profile_id": "p", "split_seed": "s"}, rows, .1)
        self.assertEqual([item["split"] for item in left["validation"]["sample_results"]], [item["split"] for item in right["validation"]["sample_results"]])

    def test_groups_do_not_cross_partitions(self):
        rows = [self._result("h1a", "human", .2, group="g-h1"), self._result("h1b", "human", .21, group="g-h1"), self._result("h2", "human", .22, group="g-h2"), self._result("a1", "ai_generated", .8, group="g-a1"), self._result("a2", "ai_generated", .82, group="g-a2")]
        profile = calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)
        observed = {}
        for item in profile["validation"]["sample_results"]:
            observed.setdefault(item["group_id"], set()).add(item["split"])
        self.assertTrue(all(len(value) == 1 for value in observed.values()))

    def test_explicit_group_cannot_mix_label_strata(self):
        rows = self._balanced()
        rows[0].group_id = "group-shared"
        rows[1].group_id = "group-shared"
        with self.assertRaisesRegex(ValueError, "cannot mix"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_insufficient_groups_fail_closed(self):
        rows = [self._result("h1", "human", .2, group="same-h"), self._result("h2", "human", .22, group="same-h"), self._result("a1", "ai_generated", .8, group="same-a"), self._result("a2", "ai_generated", .82, group="same-a")]
        with self.assertRaisesRegex(ValueError, "at least two"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_observation_csv_has_no_absolute_path(self):
        import tempfile
        rows = self._balanced(); rows[0].path = "C:/Users/Alice/private.py"; rows[0].sample_id = ""
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "observations.csv"
            calibrate_profile.write_observations_csv(output, rows)
            self.assertNotIn("Users/Alice", output.read_text())

    def test_runtime_scope_rejects_language_mismatch(self):
        profile = {"scope": {"report_kinds": ["file"], "languages": ["python"]}}
        allowed, message = engine.calibration_scope_decision(profile, "file", "javascript")
        self.assertFalse(allowed)
        self.assertIn("javascript", message)

    def test_non_applicable_sample_aborts_profile(self):
        rows = self._balanced()
        rows[0].applicable = False
        rows[0].score = None
        with self.assertRaisesRegex(ValueError, "every sample must yield"):
            calibrate_profile.build_profile({"profile_id": "p"}, rows, .1)

    def test_manifest_rejects_duplicate_sample_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.py"
            sample.write_text(SAMPLE_CODE, encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "samples": [
                    {"path": "sample.py", "label": "human", "split": "fit"},
                    {"path": "./sample.py", "label": "human", "split": "evaluation"},
                ]
            }), encoding="utf-8")
            args = type("Args", (), {
                "manifest": str(manifest), "profile_id": "", "label": "",
                "profile_version": "", "config": None,
                "evaluation_fraction": None, "split_seed": "",
                "root": "", "target_fpr": .1, "profile": "default",
                "out_dir": str(root / "out"), "profile_out": None,
                "summary_out": None, "json_out": None, "md_out": None,
                "csv_out": None, "sensitivity_out": None,
            })()
            with self.assertRaisesRegex(ValueError, "duplicate calibration sample"):
                calibrate_profile.run_calibration(args)

    def test_manifest_rejects_non_object_sample_record(self):
        with self.assertRaisesRegex(ValueError, "every calibration sample"):
            calibrate_profile._manifest_records({"samples": [{}, "bad"]})

    def test_output_cannot_overwrite_sample(self):
        sample = Path("/tmp/sample.py")
        with self.assertRaisesRegex(ValueError, "must not overwrite"):
            calibrate_profile._validate_output_paths(
                {
                    "profile_path": sample,
                    "summary_path": Path("/tmp/summary.md"),
                    "observations_path": Path("/tmp/observations.csv"),
                    "sensitivity_path": Path("/tmp/sensitivity.csv"),
                },
                manifest_path=Path("/tmp/manifest.json"),
                sample_paths=[(sample, "file")],
            )

    def test_output_parent_alias_is_canonicalised(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlink creation unavailable")
            outputs = {
                "profile_path": alias / "profile.json",
                "summary_path": alias / "summary.md",
                "observations_path": alias / "observations.csv",
                "sensitivity_path": alias / "sensitivity.csv",
            }
            calibrate_profile._validate_output_paths(
                outputs,
                manifest_path=root / "manifest.json",
                sample_paths=[],
            )
            self.assertEqual(outputs["profile_path"], real.resolve() / "profile.json")
            self.assertEqual(outputs["summary_path"], real.resolve() / "summary.md")

    def test_output_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "profile.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "link or reparse point"):
                calibrate_profile._validate_output_destination(
                    "profile_path", link
                )

    def test_folder_corpus_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "human").mkdir()
            (root / "ai").mkdir()
            outside = root / "outside.py"
            outside.write_text(SAMPLE_CODE, encoding="utf-8")
            try:
                (root / "human" / "linked.py").symlink_to(outside)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "links"):
                calibrate_corpus.build_manifest_from_corpus(
                    root, "course", "assignment", "p", "label"
                )

    def test_exported_profile_preserves_scope(self):
        profile = calibrate_profile.build_profile(
            {"profile_id": "p"}, self._balanced(), .1
        )
        normalised = engine.normalise_calibration_profile(profile)
        public = engine.calibration_profile_public(normalised)
        self.assertEqual(public["scope"]["languages"], ["python"])
        self.assertEqual(public["calibrated_policy_kind"], "file")

    def test_public_report_metadata_excludes_sample_level_validation(self):
        profile = calibrate_profile.build_profile(
            {"profile_id": "p"}, self._balanced(), .1
        )
        public = engine.calibration_profile_public(
            engine.normalise_calibration_profile(profile)
        )
        self.assertNotIn("sample_results", public["validation"])
        self.assertNotIn("sensitivity", public["validation"])
        self.assertIn("evaluation_design", public["validation"])

    def test_csv_manifest_rejects_duplicate_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.csv"
            path.write_text("path,label,LABEL\na.py,human,human\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate column"):
                calibrate_profile.load_manifest(path)

    def test_metric_override_json_uses_bounded_unambiguous_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate = root / "override.json"
            duplicate.write_text(
                '{"comment_to_code_ratio":{"weight":0.1,"weight":0.2}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                calibrate_profile._load_json_object_file(
                    duplicate, "metric override configuration"
                )

            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "links"):
                calibrate_profile._load_json_object_file(
                    link, "metric override configuration"
                )

    def test_hard_linked_samples_are_rejected_as_one_physical_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.py"
            alias = root / "alias.py"
            original.write_text(SAMPLE_CODE, encoding="utf-8")
            try:
                os.link(original, alias)
            except OSError:
                self.skipTest("hard-link creation unavailable")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "samples": [
                    {"path": original.name, "label": "human"},
                    {"path": alias.name, "label": "human"},
                ]
            }), encoding="utf-8")
            args = type("Args", (), {
                "manifest": str(manifest), "profile_id": "", "label": "",
                "profile_version": "", "config": None,
                "evaluation_fraction": None, "split_seed": "",
                "root": "", "target_fpr": .1, "profile": "default",
                "out_dir": str(root / "out"), "profile_out": None,
                "summary_out": None, "json_out": None, "md_out": None,
                "csv_out": None, "sensitivity_out": None,
            })()
            with self.assertRaisesRegex(ValueError, "physical source"):
                calibrate_profile.run_calibration(args)

    def test_generated_profile_uses_pseudonymous_sample_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            names = ("alice.py", "bob.py", "model_one.py", "model_two.py")
            for name in names:
                (root / name).write_text(SAMPLE_CODE, encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "samples": [
                    {"path": names[0], "label": "human", "split": "fit"},
                    {"path": names[1], "label": "human", "split": "evaluation"},
                    {"path": names[2], "label": "ai", "split": "fit"},
                    {"path": names[3], "label": "ai", "split": "evaluation"},
                ]
            }), encoding="utf-8")
            args = type("Args", (), {
                "manifest": str(manifest), "profile_id": "", "label": "",
                "profile_version": "", "config": None,
                "evaluation_fraction": None, "split_seed": "",
                "root": "", "target_fpr": .1, "profile": "default",
                "out_dir": str(root / "out"), "profile_out": None,
                "summary_out": None, "json_out": None, "md_out": None,
                "csv_out": None, "sensitivity_out": None,
            })()
            result = calibrate_profile.run_calibration(args)
            serialised = json.dumps(result["profile"])
            for name in names:
                self.assertNotIn(name, serialised)
            self.assertRegex(serialised, r"sample-[0-9a-f]{32}")


if __name__ == "__main__":
    unittest.main()
