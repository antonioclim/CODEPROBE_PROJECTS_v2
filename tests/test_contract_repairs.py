"""Regression contracts for scoring replay, input provenance and packet repair.

All labelled examples below are synthetic program fixtures, not observations
about authorship. Browser-double tests are separate from the real Pyodide gate.
"""
from __future__ import annotations

import argparse
import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tools")]
import build_release
import calibrate_profile
import codeprobe_runtime as engine
from codeprobe_engine.release import write_manifest

CODE = """def add(left, right):
    return left + right


def subtract(left, right):
    return left - right


def multiply(left, right):
    value = left * right
    return value


def main():
    total = add(1, 2)
    return multiply(total, 3)
"""


class EngineFingerprintContractTests(unittest.TestCase):
    def test_contradictory_verified_labels_are_downgraded_on_both_apis(self):
        claim = {"value": "f" * 64, "source": "packaged-verified"}
        actual = engine.engine_source_fingerprint()["value"]
        for project in (False, True):
            payload = {"engine_fingerprint": claim}
            payload.update({"files": [{"path": "main.py", "content": CODE}]} if project else {"filename": "main.py", "code": CODE})
            with self.subTest(project=project):
                result = json.loads((engine.codeprobe_analyze_project if project else engine.codeprobe_analyze)(json.dumps(payload)))
                report = result["project_report" if project else "report"]
                value = report["engine_fingerprint"]
                self.assertEqual(value["source"], "caller-unverified")
                self.assertEqual(value["declared_source"], "packaged-verified")
                self.assertFalse(value["matches_loaded_source"])
                self.assertEqual(value["measured_sha256"], actual)
                self.assertEqual(report["tool_metadata"]["engine_fingerprint"], value)

    def test_matching_browser_provenance_is_preserved(self):
        actual = engine.engine_source_fingerprint()["value"]
        value = engine.effective_engine_fingerprint({"value": actual, "scope": "src/codeprobe_runtime.py", "source": "packaged-verified"})
        self.assertEqual(value["source"], "packaged-verified")
        self.assertIs(value["matches_loaded_source"], True)
        self.assertEqual(value["measured_sha256"], actual)

    def test_missing_source_cannot_authenticate_a_claim(self):
        with mock.patch.dict(engine.__dict__, {"__file__": None}):
            value = engine.effective_engine_fingerprint({"value": "f" * 64, "source": "packaged-verified"})
        self.assertEqual(value["source"], "caller-unverified")
        self.assertIsNone(value["matches_loaded_source"])
        self.assertEqual(value["measured_sha256"], "")

    def test_manual_source_is_not_promoted_by_digest_equality(self):
        actual = engine.engine_source_fingerprint()["value"]
        value = engine.effective_engine_fingerprint({"value": actual, "source": "manual-unverified"})
        self.assertEqual(value["source"], "manual-unverified")
        self.assertIs(value["matches_loaded_source"], True)

    def test_legacy_caller_value_is_retained_separately(self):
        value = engine.effective_engine_fingerprint("f" * 64)
        self.assertEqual(value["value"], "f" * 64)
        self.assertEqual(value["source"], "caller")
        self.assertEqual(value["measured_sha256"], engine.engine_source_fingerprint()["value"])
        self.assertFalse(value["matches_loaded_source"])

    def test_claimed_measurements_and_wrong_algorithms_or_scopes_are_not_trusted(self):
        actual = engine.engine_source_fingerprint()["value"]
        for extra in ({"value": "f" * 64}, {"algorithm": "sha512"}, {"scope": "another.py"}):
            claim = {"value": actual, "source": "packaged-verified", "matches_loaded_source": True,
                     "measured_sha256": "e" * 64, **extra}
            with self.subTest(extra=extra):
                value = engine.effective_engine_fingerprint(claim)
                self.assertEqual(value["source"], "caller-unverified")
                self.assertFalse(value["matches_loaded_source"])
                self.assertEqual(value["measured_sha256"], actual)

    def test_normalisation_is_idempotent_without_mutating_input(self):
        claim = {"value": "f" * 64, "source": "packaged-verified"}
        saved = copy.deepcopy(claim)
        value = engine.effective_engine_fingerprint(claim)
        self.assertEqual(engine.effective_engine_fingerprint(value), value)
        self.assertEqual(claim, saved)


class ScoringReplayTests(unittest.TestCase):
    def calibrate(self, root, *, mode="default", overrides=None, cli_config=False, kind="file", code=CODE):
        samples = []
        for index, (label, split) in enumerate((("human", "fit"), ("ai", "fit"), ("human", "evaluation"), ("ai", "evaluation"))):
            name = f"sample-{index}.py" if kind == "file" else f"project-{index}"
            path = root / name
            if kind == "project":
                path.mkdir()
                path = path / "main.py"
            path.write_text(code, encoding="utf-8")
            samples.append({"path": name, "label": label, "split": split, "group": f"g-{index}", "kind": kind})
        manifest = {"profile_id": "synthetic-replay", "samples": samples}
        config = None
        if overrides is not None:
            if cli_config:
                # --config replaces the manifest override, rather than merging it invisibly.
                manifest["metric_overrides"] = {"line_length_uniformity": {"weight": .1}}
                config = root / "config.json"
                config.write_text(json.dumps(overrides), encoding="utf-8")
            else:
                manifest["metric_overrides"] = overrides
        path = root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        args = argparse.Namespace(manifest=str(path), root=None, profile=mode, target_fpr=.1,
                                  config=str(config) if config else None, out_dir=str(root / "output"))
        return calibrate_profile.run_calibration(args)

    @staticmethod
    def replay(calibration, kind="file", **extra):
        payload = {"calibration_profile": calibration, **extra}
        if kind == "project":
            payload.update(project_name="synthetic", files=[{"path": "main.py", "content": CODE}])
            return json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))["project_report"]
        payload.update(filename="sample.py", code=CODE)
        return json.loads(engine.codeprobe_analyze(json.dumps(payload)))["report"]

    def check_replay(self, *, mode="default", cli_config=False, kind="file"):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.calibrate(Path(tmp), mode=mode, cli_config=cli_config, kind=kind,
                                    overrides={"line_length_uniformity": {"weight": 1.0}})
            profile = result["profile"]
            report = self.replay(profile, kind)
            self.assertTrue(profile["operational"])
            self.assertEqual(report["profile"], mode)
            for row in result["results"]:
                self.assertEqual(row["score"], report["overall_score"])
                self.assertEqual(row["decision_score"], report["decision_score"])
                self.assertEqual(row["scoring_contract"]["metric_config_digest"], report["metric_config_digest"])
                self.assertEqual(row["scoring_contract"], profile["scoring_contract"])
            rate = profile["validation"]["evaluation_at_selected_trigger"]["false_positive_rate"]
            self.assertEqual(rate, float(report["review_triggered"]))
            self.assertIn("Operational for replay", Path(result["summary_path"]).read_text(encoding="utf-8"))

    def test_bound_python_file_requires_ast_even_with_opt_out_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp))["profile"]
            payload = {"filename": "invalid.py", "code": "def broken(:\n", "calibration_profile": profile, "require_python_ast": False}
            with self.assertRaisesRegex(ValueError, "successful AST parse"):
                engine.codeprobe_analyze(json.dumps(payload))

    def test_bound_project_requires_ast_without_inventing_child_calibration(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp), kind="project")["profile"]
            payload = {"files": [{"path": "invalid.py", "content": "def broken(:\n"}], "calibration_profile": profile}
            with self.assertRaisesRegex(ValueError, "successful AST parse"):
                engine.codeprobe_analyze_project(json.dumps(payload))
            report = self.replay(profile, kind="project")
            self.assertFalse(report["included_files"][0]["calibration_profile_id"])

    def test_calibration_rejects_python_parse_fallback_before_fitting(self):
        for kind in ("file", "project"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    self.calibrate(Path(tmp), kind=kind, code="def broken(:\n" + CODE)

    def test_unbound_diagnostics_keep_ast_warning_and_runtime_metadata(self):
        result = json.loads(engine.codeprobe_analyze(json.dumps({"filename": "invalid.py", "code": "def broken(:\n" + CODE})))
        report = result["report"]
        self.assertTrue(any("AST warning" in item for item in report["warnings"]))
        self.assertFalse(report["calibration_profile_id"])
        runtime = report["tool_metadata"]["python_runtime"]
        self.assertEqual(runtime["version"], ".".join(map(str, sys.version_info[:3])))
        self.assertEqual(runtime["platform"], sys.platform)

    def test_manifest_overrides_replay_on_files(self):
        self.check_replay()

    def test_cli_config_replays_on_files(self):
        self.check_replay(cli_config=True)

    def test_manifest_overrides_replay_on_projects(self):
        self.check_replay(kind="project")

    def test_cli_config_replays_on_projects(self):
        self.check_replay(kind="project", cli_config=True)

    def test_strict_mode_is_selected_from_the_bound_profile(self):
        self.check_replay(mode="strict")

    def test_explicit_mode_conflict_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp), mode="strict")["profile"]
            with self.assertRaisesRegex(ValueError, "base profile conflicts"):
                self.replay(profile, profile="default")

    def test_different_override_is_rejected_but_an_identical_override_is_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp))["profile"]
            self.replay(profile, config_override={})
            with self.assertRaisesRegex(ValueError, "configuration does not match"):
                self.replay(profile, config_override={"line_length_uniformity": {"weight": 1.0}})

    def test_claimed_caller_fingerprint_cannot_override_the_actual_engine_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp))["profile"]
            profile["scoring_contract"]["engine_sha256"] = "a" * 64
            with self.assertRaisesRegex(ValueError, "engine identity"):
                self.replay(profile, engine_fingerprint="a" * 64)

    def test_contract_rejects_mutated_digest_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp))["profile"]
            for key, value in (("metric_config_digest", "a" * 64), ("extra", "unknown"), ("base_profile", "nonexistent")):
                changed = copy.deepcopy(profile)
                changed["scoring_contract"][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.replay(changed)

    def test_bound_profiles_refuse_wrong_report_kind_or_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp))["profile"]
            with self.assertRaisesRegex(ValueError, "incompatible with this input"):
                self.replay(profile, "project")
            changed = copy.deepcopy(profile)
            changed["scope"]["languages"] = ["javascript"]
            with self.assertRaisesRegex(ValueError, "incompatible with this input"):
                self.replay(changed)
            changed["scope"]["languages"] = "python"
            with self.assertRaisesRegex(ValueError, "incompatible with this input"):
                self.replay(changed)

    def test_non_operational_profile_cannot_be_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = self.calibrate(Path(tmp))["profile"]
            profile["operational"] = False
            profile["operational_reason"] = "fit-target-unmet"
            with self.assertRaisesRegex(ValueError, "non-operational"):
                self.replay(profile)
            public = engine.calibration_profile_public(engine.normalise_calibration_profile(profile))
            self.assertFalse(public["operational"])
            self.assertEqual(public["operational_reason"], "fit-target-unmet")

    def test_fit_target_failure_is_explicit_and_evaluation_never_changes_the_trigger(self):
        contract = engine.scoring_contract("default", engine.merged_metric_config("default"))
        rows = [calibrate_profile.SampleResult(
            f"synthetic-{index}", "human" if index % 2 == 0 else "ai", "file", "python",
            .95 if index % 2 == 0 else .99, True, 20, "high", sample_id=f"s-{index}",
            group_id=f"group-{index}", split="fit" if index < 2 else "evaluation", scoring_contract=contract,
        ) for index in range(4)]
        first = calibrate_profile.build_profile({}, rows, .1)
        self.assertFalse(first["operational"])
        self.assertFalse(first["validation"]["target_met"])
        self.assertFalse(first["validation"]["grid_feasible"])
        rows[2].score = .01
        second = calibrate_profile.build_profile({}, rows, .1)
        self.assertEqual(first["review_policy"], second["review_policy"])
        self.assertFalse(second["operational"])
        self.assertTrue(second["validation"]["evaluation_target_met"])
        with self.assertRaisesRegex(ValueError, "non-operational"):
            self.replay(first)

    def test_inconsistent_sample_scoring_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.calibrate(Path(tmp))
            rows = [calibrate_profile.SampleResult(**row) for row in result["results"]]
            rows[0].scoring_contract = {**rows[0].scoring_contract, "metric_config_digest": "b" * 64}
            with self.assertRaisesRegex(ValueError, "effective scoring contract"):
                calibrate_profile.build_profile({}, rows, .1)

    def test_threshold_selection_uses_unrounded_decision_scores(self):
        contract = engine.scoring_contract("default", engine.merged_metric_config("default"))
        rows = [calibrate_profile.SampleResult(
            f"s{index}", "human" if index % 2 == 0 else "ai", "file", "python",
            .6 if index % 2 == 0 else .8, True, 20, "high", sample_id=f"s{index}",
            group_id=f"group-{index}", split="fit" if index < 2 else "evaluation", scoring_contract=contract,
            decision_score=.59996 if index % 2 == 0 else .8,
        ) for index in range(4)]
        profile = calibrate_profile.build_profile({}, rows, 0)
        self.assertEqual(profile["review_policy"]["file"]["review_trigger"], .6)
        self.assertEqual(profile["validation"]["fit_at_selected_trigger"]["false_positive_rate"], 0)

    def test_rounded_rates_cannot_make_an_infeasible_grid_point_eligible(self):
        # 1/3 rounds to .3333 but still exceeds .33331.
        threshold, _, _ = calibrate_profile.choose_review_trigger([.2, .2, .6], [.8], [], .33331)
        self.assertGreater(threshold, .6)

    def test_report_file_reads_do_not_depend_on_the_host_locale(self):
        original = Path.read_text

        def legacy_read(path, encoding=None, errors=None, **options):
            return original(path, encoding=encoding or "cp1252", errors=errors, **options)

        # The generated files are UTF-8 even when the host default is not.
        with mock.patch.object(Path, "read_text", autospec=True, side_effect=legacy_read):
            self.check_replay()
            self.test_cli_omitted_mode_uses_project_contract()

    def test_cli_omitted_mode_uses_project_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.calibrate(root, mode="strict", kind="project")
            output = root / "replayed.json"
            completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(ROOT / "tools/analyze_project.py"),
                "--folder", str(root / "project-2"), "--calibration-profile", result["profile_path"],
                "--json-out", str(output)], capture_output=True, text=True, check=False, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["profile"], "strict")
            self.assertEqual(report["overall_score"], result["results"][2]["score"])


class IntakeProvenanceTests(unittest.TestCase):
    @staticmethod
    def report(files, **extra):
        return json.loads(engine.codeprobe_analyze_project(json.dumps({"files": files, **extra})))

    def test_absent_calibration_is_consistent_at_root_and_child(self):
        for value in (None, {}, "{}"):
            with self.subTest(value=value):
                result = self.report([{"path": "main.py", "content": CODE}], calibration_profile=value)
                report = result["project_report"]
                self.assertEqual(report["calibration_profile_id"], "")
                self.assertEqual(report["review_trigger_source"], "default-provisional")
                self.assertEqual(report["included_files"][0]["calibration_profile_id"], "")
                self.assertNotIn("Calibration profile active", json.dumps(result))
                self.assertIn("default provisional", result["text"])

    def test_project_policy_does_not_claim_per_file_calibration(self):
        profile = {"profile_id": "project-only", "scope": {"report_kinds": ["project"], "languages": ["project"]}, "review_policy": {"project": {"review_trigger": .1}}}
        report = self.report([{"path": "main.py", "content": CODE}], calibration_profile=profile)["project_report"]
        self.assertEqual(report["calibration_profile_id"], "project-only")
        self.assertEqual(report["included_files"][0]["calibration_profile_id"], "")
        self.assertTrue(report["review_triggered"])

    def test_rejected_entries_remain_in_the_same_root_normalisation_and_text(self):
        files = [{"path": "repo/main.py", "content": CODE},
                 {"path": "repo/oversized.py", "size_bytes": 1_000_001, "intake_rejection": {"reason": "file_too_large"}}]
        result = self.report(files)
        report = result["project_report"]
        self.assertEqual(report["included_file_count"], 1)
        self.assertEqual(report["excluded_file_count"], 1)
        excluded = report["excluded_files"][0]
        self.assertEqual(excluded["path"], "oversized.py")
        self.assertEqual(excluded["reason"], "browser_file_too_large")
        self.assertIn("Caller-reported", excluded["detail"])
        self.assertIn("oversized.py", result["text"])

    def test_metadata_rejections_cannot_supply_hidden_content_or_arbitrary_reasons(self):
        valid = {"path": "a.py", "size_bytes": 5, "intake_rejection": {"reason": "unreadable_file"}}
        variations = [{**valid, "content": "print(1)"}, {**valid, "size_bytes": -1},
                      {**valid, "size_bytes": True}, {**valid, "path": "a" * 4097},
                      {**valid, "intake_rejection": {"reason": []}},
                      {**valid, "intake_rejection": {"reason": "author_verified"}},
                      {**valid, "intake_rejection": {"reason": "unreadable_file", "content": "secret"}}]
        for entry in variations:
            with self.subTest(entry=str(entry)[:100]), self.assertRaises(ValueError):
                self.report([entry])

    def test_metadata_rejections_share_the_total_entry_limit(self):
        entry = {"path": "a.py", "size_bytes": 5, "intake_rejection": {"reason": "unreadable_file"}}
        with self.assertRaisesRegex(ValueError, "entry limit"):
            self.report([entry, entry], max_zip_entries=1)

    def test_unsafe_metadata_path_is_not_accepted_as_source(self):
        result = self.report([{"path": "../private.py", "size_bytes": 5, "intake_rejection": {"reason": "unreadable_file"}}])
        report = result["project_report"]
        self.assertEqual(report["included_file_count"], 0)
        self.assertEqual(report["excluded_files"][0]["reason"], "unsafe_path")

    def test_a_rejected_ignore_file_never_supplies_ignore_rules(self):
        result = self.report([{"path": ".codeprobeignore", "size_bytes": 1_000_001, "intake_rejection": {"reason": "file_too_large"}},
                              {"path": "main.py", "content": CODE}])
        self.assertEqual(result["project_report"]["included_file_count"], 1)
        self.assertEqual(result["project_report"]["excluded_file_count"], 1)


class PublicationOverlapTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "source"
        source.mkdir()
        (source / "main.py").write_text("print('synthetic')\n")
        write_manifest(source, engine.APP_VERSION)
        targets = build_release.publish_release(source, root / "public/release.zip", app_version=engine.APP_VERSION)
        return source, targets

    def test_every_partial_subset_is_repaired_without_stranding_a_lock(self):
        for bits in range(1, 8):
            with self.subTest(bits=bits), tempfile.TemporaryDirectory() as tmp:
                source, targets = self.fixture(Path(tmp))
                original = {path: path.read_bytes() for path in targets.all()}
                for index, path in enumerate(targets.all()):
                    if bits & (1 << index):
                        path.unlink()
                build_release.publish_release(source, targets.zip_path, app_version=engine.APP_VERSION)
                self.assertEqual({path: path.read_bytes() for path in targets.all()}, original)
                self.assertFalse(build_release._lock_path(targets.zip_path.parent, targets.zip_path.name).exists())
                self.assertEqual(list(targets.zip_path.parent.glob("*.transaction-*")), [])

    def test_interrupted_overlap_repairs_recover_to_a_recognised_state(self):
        for missing in ("zip", "audit", "checksum"):
            for fault in ("prepared", "readiness_withdrawn", "zip_installed", "audit_installed", "checksum_installed", "committed"):
                with self.subTest(missing=missing, fault=fault), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                    source, targets = self.fixture(Path(tmp))
                    mapping = build_release._target_mapping(targets)
                    mapping[missing].unlink()
                    prior = {key: path.read_bytes() if path.exists() else None for key, path in mapping.items()}
                    completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(ROOT / "tests/test_release_crash_driver.py"),
                        "publish", "--root", str(source), "--out", str(targets.zip_path), "--version", engine.APP_VERSION, "--fault", fault],
                        capture_output=True, text=True, timeout=30, check=False)
                    self.assertEqual(completed.returncode, 97, completed.stdout + completed.stderr)
                    recovered = build_release.recover_release(source, targets.zip_path, app_version=engine.APP_VERSION)
                    self.assertTrue(recovered.recovered)
                    if recovered.status == "new-packet-committed":
                        build_release._verify_public_packet(targets)
                    else:
                        self.assertEqual({key: path.read_bytes() if path.exists() else None for key, path in mapping.items()}, prior)
                    self.assertFalse(build_release._lock_path(targets.zip_path.parent, targets.zip_path.name).exists())

    def test_unknown_concurrent_bytes_remain_fail_closed_during_overlap(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            source, targets = self.fixture(Path(tmp))
            targets.checksum_path.unlink()
            def fault(point):
                if point == "zip_installed":
                    targets.audit_path.write_bytes(b"unknown concurrent modification")
            with self.assertRaisesRegex(build_release.PublicationError, "not attributable|changed outside"):
                build_release.publish_release(source, targets.zip_path, app_version=engine.APP_VERSION, _fault_hook=fault)
            self.assertEqual(targets.audit_path.read_bytes(), b"unknown concurrent modification")
            self.assertTrue(build_release._lock_path(targets.zip_path.parent, targets.zip_path.name).exists())

    @unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
    def test_browser_input_and_export_contracts(self):
        completed = subprocess.run([shutil.which("node"), str(ROOT / "tools/check_input_contracts.js")],
                                   capture_output=True, text=True, timeout=45, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("input-contracts:", completed.stdout)


if __name__ == "__main__":
    unittest.main()
