from __future__ import annotations

import argparse
import contextlib
import csv
import errno
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import calibrate_corpus  # noqa: E402
import calibrate_profile  # noqa: E402
import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine import api, project_io  # noqa: E402


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


class CalibrationPublicationTests(unittest.TestCase):
    """Owned filesystem fixtures; source text is analysed, never executed."""

    def _fixture(self, root, *, kind="file", wrapper=False):
        corpus = root / "corpus"
        corpus.mkdir()
        inputs, records = [], []
        for index, (label, split) in enumerate((
            ("human", "fit"), ("ai", "fit"),
            ("human", "evaluation"), ("ai", "evaluation"),
        )):
            parent = corpus / label if wrapper else corpus
            parent.mkdir(exist_ok=True)
            if kind == "project":
                sample = parent / f"project-{index}"
                sample.mkdir()
                source = sample / "main.py"
                source.write_text(SAMPLE_CODE, encoding="utf-8")
                ignore = sample / ".codeprobeignore"
                ignore.write_text("# owned calibration fixture\n", encoding="utf-8")
                inputs.extend((source, ignore))
            elif kind == "zip":
                sample = parent / f"project-{index}.zip"
                with zipfile.ZipFile(sample, "w") as archive:
                    archive.writestr("main.py", SAMPLE_CODE)
                inputs.append(sample)
            else:
                sample = parent / f"sample-{index}.py"
                sample.write_text(SAMPLE_CODE, encoding="utf-8")
                inputs.append(sample)
            records.append({"path": sample.relative_to(corpus).as_posix(),
                            "kind": "project" if kind in {"project", "zip"} else "file",
                            "label": label, "split": split, "group": f"group-{index}"})
        manifest = {"profile_id": "publication-fixture", "label": "Publication fixture",
                    "samples": records,
                    "metric_overrides": {"line_length_uniformity": {"weight": .1}}}
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        config = root / "config.json"
        config.write_text(json.dumps({"line_length_uniformity": {"weight": 1.0}}), encoding="utf-8")
        inputs.extend((manifest_path, config))
        out = root / "output"
        out.mkdir()
        outputs = {"profile_path": out / "calibration_profile.json",
                   "summary_path": out / "validation_summary.md",
                   "observations_path": out / "calibration_observations.csv",
                   "sensitivity_path": out / "threshold_sensitivity.csv"}
        if wrapper:
            outputs["generated_manifest_path"] = out / "generated_manifest.json"
        for name, path in outputs.items():
            path.write_bytes(f"previous complete {name}\n".encode("ascii"))
        args = argparse.Namespace(manifest=str(manifest_path), root=str(corpus),
                                  profile="default", target_fpr=1.0,
                                  config=str(config), out_dir=str(out))
        return args, inputs, outputs, manifest

    @staticmethod
    def _bytes(paths):
        return {path: path.read_bytes() for path in paths}

    def _no_staging(self, root):
        self.assertEqual(list(root.rglob(".codeprobe-calibration-*")), [])

    def _hardlink(self, target, destination):
        destination.unlink(missing_ok=True)
        try:
            os.link(target, destination)
        except OSError as exc:
            self.skipTest(f"hard-link creation unavailable: {exc}")

    def _wrapper(self, args, outputs, **overrides):
        options = ["--corpus-root", args.root, "--out-dir", args.out_dir,
                   "--config", args.config, "--profile-id", "publication-fixture",
                   "--label", getattr(args, "label", "Publication fixture"), "--target-fpr", "1"]
        flags = {"profile_path": "--profile-out", "summary_path": "--summary-out",
                 "observations_path": "--csv-out", "sensitivity_path": "--sensitivity-out",
                 "generated_manifest_path": "--manifest-out"}
        for name, path in {**outputs, **overrides}.items():
            options.extend((flags[name], str(path)))
        messages = io.StringIO()
        with contextlib.redirect_stdout(messages):
            result = calibrate_corpus.main(options)
        return result, messages.getvalue()

    def _assert_coherent(self, outputs, *, generated=False, project=False):
        profile = json.loads(outputs["profile_path"].read_text(encoding="utf-8"))
        with outputs["observations_path"].open(encoding="utf-8", newline="") as handle:
            observations = list(csv.DictReader(handle))
        with outputs["sensitivity_path"].open(encoding="utf-8", newline="") as handle:
            sensitivity = list(csv.DictReader(handle))
        rows = profile["validation"]["sample_results"]
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row["applicable"] for row in rows))
        self.assertEqual([row["sample_id"] for row in rows],
                         [row["sample_id"] for row in observations])
        self.assertEqual([row["group_id"] for row in rows],
                         [row["group_id"] for row in observations])
        for actual, exported in zip(rows, observations):
            self.assertEqual(float(exported["score"]), actual["score"])
            self.assertEqual(float(exported["decision_score"]), actual["decision_score"])
            self.assertEqual(actual["scoring_contract"], profile["scoring_contract"])
            self.assertRegex(actual["sample_id"], r"^sample-[0-9a-f]{12}4[0-9a-f]{19}$")
        self.assertEqual([float(row["threshold"]) for row in sensitivity],
                         [row["threshold"] for row in profile["validation"]["sensitivity"]])
        summary = outputs["summary_path"].read_text(encoding="utf-8")
        self.assertIn(profile["label"], summary)
        trigger = profile["review_policy"][profile["calibrated_policy_kind"]]["review_trigger"]
        self.assertIn(f"{trigger * 100:.1f}%", summary)
        payload = {"calibration_profile": profile}
        if project:
            payload["files"] = [{"path": "main.py", "content": SAMPLE_CODE}]
            report = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        else:
            payload.update(filename="sample.py", code=SAMPLE_CODE)
            report = json.loads(engine.codeprobe_analyze(json.dumps(payload)))["report"]
        self.assertTrue(profile["operational"])
        self.assertEqual(profile["metric_overrides"]["line_length_uniformity"]["weight"], 1.0)
        self.assertEqual(report["metric_config_digest"], profile["scoring_contract"]["metric_config_digest"])
        self.assertEqual(report["overall_score"], rows[0]["score"])
        self.assertNotIn(str(outputs["profile_path"].parent.parent), json.dumps(profile))
        if generated:
            manifest = json.loads(outputs["generated_manifest_path"].read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["samples"]), 4)
            corpus = outputs["profile_path"].parent.parent / "corpus"
            self.assertTrue(all((corpus / row["path"]).is_file() for row in manifest["samples"]))

    def test_direct_hardlinked_inputs_and_outputs_preserve_all_bytes(self):
        for case in ("sample", "manifest", "config", "output", "zip"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, kind="zip" if case == "zip" else "file")
                target = {"sample": inputs[0], "zip": inputs[0], "manifest": Path(args.manifest),
                          "config": Path(args.config), "output": outputs["summary_path"]}[case]
                self._hardlink(target, outputs["profile_path"])
                before = self._bytes([*inputs, *outputs.values()])
                with self.assertRaisesRegex(ValueError, "overwrite|collide|inside"):
                    calibrate_profile.run_calibration(args)
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

    def test_configuration_and_portable_output_names_are_refused(self):
        for case in ("config", "casefold", "unicode-nfc"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root)
                if case == "config":
                    args.profile_out = args.config
                else:
                    first, second = (("Report.json", "report.json") if case == "casefold"
                                     else ("r\u00e9port.json", "re\u0301port.json"))
                    args.profile_out = str(root / "output" / first)
                    args.summary_out = str(root / "output" / second)
                before = self._bytes([*inputs, *outputs.values()])
                with self.assertRaisesRegex(ValueError, "overwrite|collide|inside"):
                    calibrate_profile.run_calibration(args)
                self.assertEqual(self._bytes(before), before)
                self.assertFalse(Path(getattr(args, "summary_out", root / "absent")).exists())
                self._no_staging(root)

    def test_wrapper_manifest_collisions_preserve_all_bytes(self):
        for case in ("config", "output", "output-hardlink", "sample-hardlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, wrapper=True)
                if case == "config":
                    outputs["generated_manifest_path"] = Path(args.config)
                elif case == "output":
                    outputs["generated_manifest_path"] = outputs["profile_path"]
                else:
                    target = outputs["profile_path"] if case == "output-hardlink" else inputs[0]
                    self._hardlink(target, outputs["generated_manifest_path"])
                before = self._bytes([*inputs, *outputs.values()])
                result, message = self._wrapper(args, outputs)
                self.assertEqual(result, 2, message)
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

    def test_external_project_child_and_ignore_aliases_are_protected(self):
        # Qualify both project forms with real applicable analysis before relying
        # on an identity rejection in either folder or ZIP negative fixtures.
        for kind in ("project", "zip"):
            with self.subTest(positive_kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, kind=kind)
                before = self._bytes(inputs)
                calibrate_profile.run_calibration(args)
                self._assert_coherent(outputs, project=True)
                self.assertEqual(self._bytes(inputs), before)
                self._no_staging(root)
        for child in ("main.py", ".codeprobeignore"):
            for generated in (False, True):
                with self.subTest(child=child, generated=generated), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    args, inputs, outputs, manifest = self._fixture(root, kind="project")
                    target = root / "corpus" / "project-0" / child
                    destination = (root / "external-manifest.json" if generated else outputs["profile_path"])
                    self._hardlink(target, destination)
                    before = self._bytes([*inputs, *outputs.values(), destination])
                    with self.assertRaisesRegex(ValueError, "physical calibration input"):
                        if generated:
                            calibrate_profile.prepare_calibration(
                                args, manifest=manifest, manifest_path=destination,
                                generated_manifest_path=destination,
                            )
                        else:
                            calibrate_profile.run_calibration(args)
                    self.assertEqual(self._bytes(before), before)
                    self._no_staging(root)

    def test_project_tree_outputs_are_refused_without_creating_a_leaf(self):
        for leaf in ("main.py", "new-result.json"):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, kind="project")
                args.profile_out = str(root / "corpus" / "project-0" / leaf)
                before = self._bytes([*inputs, *outputs.values()])
                with self.assertRaisesRegex(ValueError, "overwrite|collide|inside"):
                    calibrate_profile.run_calibration(args)
                self.assertEqual(self._bytes(before), before)
                if leaf == "new-result.json":
                    self.assertFalse(Path(args.profile_out).exists())
                self._no_staging(root)

    def test_output_symlink_preserves_target_and_other_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, inputs, outputs, _ = self._fixture(root)
            destination = outputs["profile_path"]
            destination.unlink()
            try:
                destination.symlink_to(inputs[0])
            except OSError as exc:
                self.skipTest(f"symbolic-link creation unavailable: {exc}")
            before = self._bytes([*inputs, *outputs.values()])
            with self.assertRaisesRegex(ValueError, "link|reparse"):
                calibrate_profile.run_calibration(args)
            self.assertEqual(self._bytes(before), before)
            self.assertTrue(destination.is_symlink())
            self._no_staging(root)

    def test_special_output_is_refused_before_opening_it(self):
        for case in ("directory", "fifo"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                if case == "fifo" and not hasattr(os, "mkfifo"):
                    self.skipTest("FIFO creation is unavailable on this platform")
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root)
                destination = outputs.pop("profile_path")
                destination.unlink()
                destination.mkdir() if case == "directory" else os.mkfifo(destination)
                before = self._bytes([*inputs, *outputs.values()])
                with mock.patch.object(calibrate_profile, "publish_calibration") as publish:
                    with self.assertRaisesRegex(ValueError, "regular file"):
                        calibrate_profile.run_calibration(args)
                publish.assert_not_called()
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

    def test_destination_metadata_doubles_fail_closed(self):
        for case in ("reparse", "missing-identity"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp).resolve() / "output.json"
                destination.write_bytes(b"previous complete output")
                real_lstat = Path.lstat
                actual = destination.lstat()
                def metadata(path, *args, **kwargs):
                    if path == destination:
                        return argparse.Namespace(
                            st_mode=stat.S_IFREG | 0o600,
                            st_file_attributes=0x400 if case == "reparse" else 0,
                            st_dev=actual.st_dev, st_ino=0, st_size=actual.st_size,
                            st_mtime_ns=actual.st_mtime_ns, st_ctime_ns=actual.st_ctime_ns,
                        )
                    return real_lstat(path, *args, **kwargs)
                with mock.patch.object(Path, "lstat", metadata):
                    with self.assertRaisesRegex(ValueError, "reparse|identity"):
                        calibrate_profile._validate_output_paths(
                            {"profile_path": destination}, manifest_path=None, sample_paths=[],
                        )
                self.assertEqual(destination.read_bytes(), b"previous complete output")

    def test_detectable_destination_substitution_prevents_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, inputs, outputs, _ = self._fixture(root)
            prepared = calibrate_profile.prepare_calibration(args)
            self._hardlink(inputs[0], outputs["profile_path"])
            # The fixture deliberately changes this name; publication must preserve
            # the substituted bytes and every other pre-existing destination.
            before = self._bytes([*inputs, *outputs.values()])
            with self.assertRaises(calibrate_profile.CalibrationPublicationError) as raised:
                calibrate_profile.publish_calibration(prepared)
            self.assertEqual(raised.exception.published_paths, ())
            self.assertIsInstance(raised.exception.__cause__, ValueError)
            self.assertEqual(self._bytes(before), before)
            self._no_staging(root)

    def test_detectable_consumed_input_change_prevents_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, inputs, outputs, _ = self._fixture(root, kind="project")
            prepared = calibrate_profile.prepare_calibration(args)
            inputs[1].write_text("# changed owned ignore policy\n", encoding="utf-8")
            before = self._bytes([*inputs, *outputs.values()])
            with self.assertRaises(calibrate_profile.CalibrationPublicationError) as raised:
                calibrate_profile.publish_calibration(prepared)
            self.assertEqual(raised.exception.published_paths, ())
            self.assertIsInstance(raised.exception.__cause__, ValueError)
            self.assertEqual(self._bytes(before), before)
            self._no_staging(root)

    def test_ordinary_direct_and_wrapper_outputs_are_coherent(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, wrapper=wrapper)
                before = self._bytes(inputs)
                if wrapper:
                    result, message = self._wrapper(args, outputs)
                    self.assertEqual(result, 0, message)
                else:
                    calibrate_profile.run_calibration(args)
                self.assertEqual(self._bytes(inputs), before)
                self._assert_coherent(outputs, generated=wrapper)
                self._no_staging(root)

    def test_canonical_parent_alias_allows_distinct_regular_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, inputs, outputs, _ = self._fixture(root)
            alias = root / "output-alias"
            try:
                alias.symlink_to(root / "output", target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symbolic-link creation unavailable: {exc}")
            args.out_dir = str(alias)
            before = self._bytes(inputs)
            calibrate_profile.run_calibration(args)
            self._assert_coherent(outputs)
            self.assertEqual(self._bytes(inputs), before)
            self._no_staging(root)

    def test_real_surrogate_metadata_preserves_every_destination(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, manifest = self._fixture(root, wrapper=wrapper)
                manifest["label"] = "invalid scalar \ud800"
                Path(args.manifest).write_text(json.dumps(manifest, ensure_ascii=True), encoding="utf-8")
                before = self._bytes([*inputs, *outputs.values()])
                if wrapper:
                    # The wrapper receives metadata as an argument, while the direct
                    # CLI reads the same invalid scalar from escaped valid JSON.
                    args.label = manifest["label"]
                    result, message = self._wrapper(args, outputs)
                    self.assertEqual(result, 2, message)
                    self.assertRegex(message, "UTF-8|Unicode")
                else:
                    with self.assertRaisesRegex(ValueError, "UTF-8|Unicode"):
                        calibrate_profile.run_calibration(args)
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

    def test_each_non_json_renderer_encodes_before_any_publication(self):
        for renderer in ("render_summary", "render_observations_csv", "render_sensitivity_csv"):
            with self.subTest(renderer=renderer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, wrapper=True)
                before = self._bytes([*inputs, *outputs.values()])
                with mock.patch.object(calibrate_profile, renderer, return_value="invalid \ud800") as render:
                    result, message = self._wrapper(args, outputs)
                self.assertEqual(result, 2, message)
                self.assertRegex(message, "UTF-8|Unicode")
                render.assert_called_once()
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

        # An otherwise ignored manifest field reaches the fifth encoding slot
        # without first invalidating profile JSON or the three rendered reports.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, inputs, outputs, manifest = self._fixture(root, wrapper=True)
            manifest["opaque_fixture_metadata"] = "invalid scalar \ud800"
            before = self._bytes([*inputs, *outputs.values()])
            with self.assertRaisesRegex(ValueError, "manifest_path.*invalid Unicode"):
                calibrate_profile.prepare_calibration(
                    args, manifest=manifest, manifest_path=outputs["generated_manifest_path"],
                    generated_manifest_path=outputs["generated_manifest_path"],
                )
            self.assertEqual(self._bytes(before), before)
            self._no_staging(root)

    def test_staging_creation_failure_preserves_direct_and_wrapper_outputs(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, wrapper=wrapper)
                before = self._bytes([*inputs, *outputs.values()])
                original = calibrate_profile.tempfile.mkstemp
                calls = []
                def creation(*call_args, **kwargs):
                    calls.append(kwargs)
                    if len(calls) == 2:
                        raise OSError("owned second-stage creation failure")
                    return original(*call_args, **kwargs)
                with mock.patch.object(calibrate_profile.tempfile, "mkstemp", side_effect=creation):
                    if wrapper:
                        result, message = self._wrapper(args, outputs)
                        self.assertEqual(result, 2, message)
                    else:
                        with self.assertRaises(calibrate_profile.CalibrationPublicationError) as raised:
                            calibrate_profile.run_calibration(args)
                        self.assertEqual(raised.exception.published_paths, ())
                        self.assertIsInstance(raised.exception.__cause__, OSError)
                self.assertEqual(len(calls), 2)
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

    def test_staging_identity_acquisition_failure_closes_its_descriptor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args, inputs, outputs, _ = self._fixture(root)
            before = self._bytes([*inputs, *outputs.values()])
            real_mkstemp, real_fstat = tempfile.mkstemp, os.fstat
            acquired = []
            fault = OSError("owned staging identity acquisition failure")
            def acquire(*call_args, **kwargs):
                descriptor, path = real_mkstemp(*call_args, **kwargs)
                acquired.append(descriptor)
                return descriptor, path
            def inspect(descriptor):
                if acquired and descriptor == acquired[0]:
                    raise fault
                return real_fstat(descriptor)
            with mock.patch.object(calibrate_profile.tempfile, "mkstemp", side_effect=acquire):
                with mock.patch.object(calibrate_profile.os, "fstat", side_effect=inspect):
                    with self.assertRaises(calibrate_profile.CalibrationPublicationError) as raised:
                        calibrate_profile.run_calibration(args)
            self.assertIs(raised.exception.__cause__, fault)
            self.assertEqual(raised.exception.published_paths, ())
            self.assertEqual(len(acquired), 1)
            with self.assertRaises(OSError) as closed:
                real_fstat(acquired[0])
            self.assertEqual(closed.exception.errno, errno.EBADF)
            self.assertEqual(self._bytes(before), before)
            self._no_staging(root)

    def test_consumed_file_collector_rejects_changed_repeat_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.py"
            source.write_bytes(b"first owned input")
            consumed = {}
            self.assertEqual(project_io.read_bounded_regular_file(
                source, root=root, max_bytes=100, consumed_files=consumed,
            ), b"first owned input")
            recorded = dict(consumed)
            source.write_bytes(b"different owned input")
            with self.assertRaisesRegex(ValueError, "changed"):
                project_io.read_bounded_regular_file(
                    source, root=root, max_bytes=100, consumed_files=consumed,
                )
            self.assertEqual(consumed, recorded)
            self.assertEqual(source.read_bytes(), b"different owned input")

    def test_staging_write_and_flush_failures_preserve_all_outputs(self):
        for stage in ("write", "flush"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, _ = self._fixture(root, wrapper=True)
                before = self._bytes([*inputs, *outputs.values()])
                real_fdopen = os.fdopen
                opened, faults = [], []
                class FaultedFile:
                    def __init__(self, handle):
                        self.handle = handle
                    def __enter__(self):
                        return self
                    def __exit__(self, *exc):
                        self.handle.close()
                    def write(self, data):
                        if stage == "write":
                            faults.append(stage)
                            raise OSError("owned staging write failure")
                        return self.handle.write(data)
                    def flush(self):
                        if stage == "flush":
                            faults.append(stage)
                            raise OSError("owned staging flush failure")
                        return self.handle.flush()
                    def fileno(self):
                        return self.handle.fileno()
                def faulted_open(*call_args, **kwargs):
                    handle = real_fdopen(*call_args, **kwargs)
                    opened.append(handle)
                    return FaultedFile(handle) if len(opened) == 2 else handle
                with mock.patch.object(calibrate_profile.os, "fdopen", side_effect=faulted_open):
                    result, message = self._wrapper(args, outputs)
                self.assertEqual(result, 2, message)
                self.assertEqual(faults, [stage])
                self.assertTrue(all(handle.closed for handle in opened))
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)

    def test_failure_between_replacements_reports_complete_partial_publication(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                args, inputs, outputs, _ = self._fixture(root, wrapper=wrapper)
                before = self._bytes([*inputs, *outputs.values()])
                real_replace = os.replace
                installed, attempted = {}, []
                def replace(source, destination, *call_args, **kwargs):
                    destination = Path(destination)
                    attempted.append(destination)
                    if len(attempted) == 2:
                        raise OSError("owned second replacement failure")
                    complete = Path(source).read_bytes()
                    real_replace(source, destination, *call_args, **kwargs)
                    installed[destination] = complete
                with mock.patch.object(calibrate_profile.os, "replace", side_effect=replace):
                    if wrapper:
                        result, message = self._wrapper(args, outputs)
                        self.assertEqual(result, 2, message)
                        self.assertIn("partial", message.lower())
                    else:
                        with self.assertRaisesRegex(calibrate_profile.CalibrationPublicationError, "partial") as raised:
                            calibrate_profile.run_calibration(args)
                        self.assertEqual(raised.exception.published_paths, tuple(str(path) for path in installed))
                        self.assertIsInstance(raised.exception.__cause__, OSError)
                self.assertEqual(len(attempted), 2)
                self.assertEqual(len(installed), 1)
                for path, old in before.items():
                    self.assertEqual(path.read_bytes(), installed.get(path, old))
                for path, content in installed.items():
                    if path.suffix == ".json":
                        self.assertIsInstance(json.loads(content.decode("utf-8")), dict)
                    elif path.suffix == ".csv":
                        self.assertTrue(list(csv.DictReader(io.StringIO(content.decode("utf-8")))))
                    else:
                        self.assertIn("CodeProbe calibration summary", content.decode("utf-8"))
                self._no_staging(root)

    def test_invalid_python_calibration_samples_preserve_every_existing_output(self):
        invalid = "def broken():\n    if True:\n        return 1\n  return 0\n"
        for kind in ("file", "project", "zip"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, inputs, outputs, manifest = self._fixture(root, kind=kind)
                if kind == "zip":
                    with zipfile.ZipFile(inputs[0], "w") as archive:
                        archive.writestr("broken.py", invalid)
                else:
                    inputs[0].write_text(invalid, encoding="utf-8")
                before = self._bytes([*inputs, *outputs.values()])
                record = manifest["samples"][0]
                sample = Path(args.root) / record["path"]
                result = calibrate_profile.analyse_sample(sample, record, "default", base_dir=Path(args.root))
                self.assertEqual(result.verdict_class, "error")
                self.assertFalse(result.applicable)
                self.assertIsNone(result.score)
                self.assertIsNone(result.scoring_contract)
                self.assertIn("requires a successful AST parse", result.warning)
                with self.assertRaisesRegex(ValueError, "sample analysis failed"):
                    calibrate_profile.run_calibration(args)
                self.assertEqual(self._bytes(before), before)
                self._no_staging(root)


class BoundPythonParserTests(unittest.TestCase):
    def test_current_engine_bound_profiles_refuse_invalid_ast_at_each_public_entry(self):
        profile = {"profile_id": "owned-python-binding",
                   "scoring_contract": engine.scoring_contract("default", engine.merged_metric_config("default"))}
        invalid_sources = (
            "def broken():\n    if True:\n        return 1\n  return 0\n",
            "if True:\n\tpass\n        pass\n",
            "value = (\n    1,\n",
        )
        entries = (
            (api.analyse_file, lambda source: {"filename": "sample.py", "code": source}),
            (api.analyse_project, lambda source: {"files": [{"path": "sample.py", "content": source}]}),
            (lambda payload: json.loads(engine.codeprobe_analyze(json.dumps(payload))), lambda source: {"filename": "sample.py", "code": source}),
            (lambda payload: json.loads(engine.codeprobe_analyze_project(json.dumps(payload))), lambda source: {"files": [{"path": "sample.py", "content": source}]}),
        )
        for entry, payload_for in entries:
            valid = entry({**payload_for(SAMPLE_CODE), "calibration_profile": profile})["report"]
            self.assertEqual(valid["calibration_profile_id"], "owned-python-binding")
            self.assertTrue(valid["overall_applicable"])
            for source in invalid_sources:
                with self.subTest(entry=entry, source=source), self.assertRaisesRegex(ValueError, "requires a successful AST parse"):
                    entry({**payload_for(source), "calibration_profile": profile})
            incompatible = json.loads(json.dumps(profile))
            incompatible["scoring_contract"]["engine_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "engine identity.*recalibrate"):
                entry({**payload_for(SAMPLE_CODE), "calibration_profile": incompatible})


if __name__ == "__main__":
    unittest.main()
