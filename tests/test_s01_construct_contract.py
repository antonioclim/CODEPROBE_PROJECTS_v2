from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_contract():
    path = ROOT / "src/codeprobe_review_contract.py"
    spec = importlib.util.spec_from_file_location("codeprobe_review_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load contract")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTRACT = load_contract()


def fixture(name: str):
    return json.loads((ROOT / "tests/fixtures/s01" / name).read_text(encoding="utf-8"))


class ReviewContractTests(unittest.TestCase):
    def test_valid_vector_report_passes_and_digest_is_deterministic(self):
        report = fixture("valid-review-report.json")
        CONTRACT.validate_review_report(report)
        rebuilt = dict(report)
        rebuilt["deterministic_digest"] = "0" * 64
        rebuilt = CONTRACT.finalise_report(rebuilt)
        self.assertEqual(report, rebuilt)
        self.assertEqual(report["deterministic_digest"], CONTRACT.finalise_report(rebuilt)["deterministic_digest"])

    def test_global_scalar_and_authorship_like_fields_fail_recursively(self):
        invalid = fixture("invalid-authorship-report.json")
        with self.assertRaisesRegex(ValueError, "prohibited identifier"):
            CONTRACT.validate_review_report(invalid)
        valid = fixture("valid-review-report.json")
        valid["review_evidence"]["overall_score"] = 0.9
        with self.assertRaisesRegex(ValueError, "unsupported shape|prohibited identifier"):
            CONTRACT.validate_review_report(valid)

    def test_typed_unavailable_observation_cannot_be_zero(self):
        report = fixture("valid-review-report.json")
        observation = dict(report["observations"][0])
        observation.update({"applicability": {"status": "unavailable", "reason": "parser scope"}, "value": 0})
        report["observations"] = [observation]
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unavailable but supplies a value"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_feedback_is_question_based_traceable_and_reversible(self):
        report = fixture("valid-review-report.json")
        action = dict(report["feedback_actions"][0])
        action["review_question"] = "Manual review required"
        with self.assertRaises(ValueError):
            CONTRACT.validate_feedback_action(action)
        action = dict(report["feedback_actions"][0])
        action["reversible"] = False
        with self.assertRaisesRegex(ValueError, "reversible"):
            CONTRACT.validate_feedback_action(action)

    def test_affirmative_provenance_claim_is_rejected_even_in_an_allowed_field(self):
        report = fixture("valid-review-report.json")
        report["review_evidence"]["dimensions"][0]["interpretation"] = (
            "This evidence estimates the probability of AI authorship."
        )
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "prohibited affirmative claim"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_camel_case_and_punctuated_prohibited_identifiers_are_rejected(self):
        report = fixture("valid-review-report.json")
        report["review_evidence"]["AuthorshipProbability"] = 0.8
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "prohibited identifier"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_acronym_camel_case_and_direct_provenance_assertions_are_rejected(self):
        report = fixture("valid-review-report.json")
        report["review_evidence"]["AIProbability"] = 0.8
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "prohibited identifier"):
            CONTRACT.validate_review_report(report, check_digest=False)
        report = fixture("valid-review-report.json")
        report["review_evidence"]["dimensions"][0]["interpretation"] = "The source appears to be AI-generated code."
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "prohibited affirmative claim"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_required_non_inferences_are_mandatory(self):
        report = fixture("valid-review-report.json")
        report["non_inferences"] = report["non_inferences"][:-1]
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "required non-inferences"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_vector_has_no_cross_dimension_compensation_operation(self):
        report = fixture("valid-review-report.json")
        evidence = report["review_evidence"]
        self.assertEqual(evidence["composition_rule"], "vector_only_non_compensatory")
        self.assertNotIn("score", evidence)
        self.assertNotIn("weights", evidence)
        self.assertFalse(any(callable(getattr(CONTRACT, name)) and "aggregate" in name for name in dir(CONTRACT)))


    def test_observation_value_is_atomic_and_measurement_scale_is_not_a_unit_category(self):
        report = fixture("valid-review-report.json")
        report["observations"][0]["value"] = {"nested": 4}
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "atomic JSON scalar"):
            CONTRACT.validate_review_report(report, check_digest=False)
        report = fixture("valid-review-report.json")
        report["observations"][0]["measurement_scale"] = "count"
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "measurement_scale"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_feedback_cannot_cross_dimension_or_invent_source_evidence(self):
        report = fixture("valid-review-report.json")
        second = json.loads(json.dumps(report["observations"][0]))
        second["observation_id"] = "python.function.other_observation"
        second["attribute"] = "other bounded observation"
        second["fingerprint"] = "b" * 64
        second["source_evidence"][0]["evidence_id"] = "evidence.example.other.lines"
        report["observations"].append(second)
        report["review_evidence"]["dimensions"].append({
            "dimension_id": "other_dimension",
            "spec_version": "0.1.0-prototype",
            "status": "evidence_available",
            "observation_refs": [second["observation_id"]],
            "interpretation": "A second bounded interpretation.",
            "limitations": ["Prototype only."]
        })
        action = report["feedback_actions"][0]
        action["dimension_id"] = "other_dimension"
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "outside its declared dimension"):
            CONTRACT.validate_review_report(report, check_digest=False)
        action["observation_refs"] = [second["observation_id"]]
        action["source_evidence_refs"] = ["evidence.ghost"]
        with self.assertRaisesRegex(ValueError, "source evidence not owned"):
            CONTRACT.validate_review_report(report, check_digest=False)

    def test_feedback_policy_rule_must_be_declared_and_response_state_is_external(self):
        report = fixture("valid-review-report.json")
        report["feedback_actions"][0]["policy_rule_id"] = "policy.undeclared"
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unknown policy rule"):
            CONTRACT.validate_review_report(report, check_digest=False)
        action_schema = json.loads((ROOT / "schemas/codeprobe-feedback-action-v1.schema.json").read_text(encoding="utf-8"))
        response_schema = json.loads((ROOT / "schemas/codeprobe-feedback-response-v1.schema.json").read_text(encoding="utf-8"))
        self.assertNotIn("acknowledgement_state", action_schema["properties"])
        self.assertEqual(response_schema["properties"]["schema"]["const"], "codeprobe-feedback-response/v1")

    def test_source_evidence_coordinate_system_is_bound_to_evidence_kind(self):
        report = fixture("valid-review-report.json")
        report["observations"][0]["source_evidence"][0]["coordinate_system"] = "utf8_byte_offsets_half_open"
        report["deterministic_digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "coordinate_system"):
            CONTRACT.validate_review_report(report, check_digest=False)


class LegacyMigrationTests(unittest.TestCase):
    def test_legacy_scalar_is_discarded_not_translated(self):
        legacy = fixture("legacy-file-report-v2.2.0.json")
        envelope = CONTRACT.migrate_legacy_report(legacy)
        self.assertTrue(envelope["non_equivalent"])
        self.assertEqual(envelope["schema"], CONTRACT.LEGACY_ENVELOPE_SCHEMA)
        self.assertIn("$.overall_score", envelope["discarded_semantics"])
        self.assertIn("$.verdict", envelope["discarded_semantics"])
        self.assertFalse(any(item["legacy_path"] in {"$.overall_score", "$.verdict"} for item in envelope["preserved_values"]))
        self.assertNotIn("review_evidence", envelope)

    def test_provenance_labelled_policy_is_refused(self):
        legacy = fixture("legacy-file-report-v2.2.0.json")
        policy = fixture("legacy-calibration-provenance-labels.json")
        with self.assertRaisesRegex(ValueError, "provenance label"):
            CONTRACT.migrate_legacy_report(legacy, policy_profile=policy)

    def test_ambiguous_unversioned_legacy_document_is_refused(self):
        with self.assertRaisesRegex(ValueError, "too ambiguous"):
            CONTRACT.migrate_legacy_report({"note": "unstructured"})

    def test_provenance_values_inside_legacy_report_are_archived_as_discarded_semantics(self):
        legacy = fixture("legacy-file-report-v2.2.0.json")
        legacy["training_label"] = "ai_generated"
        envelope = CONTRACT.migrate_legacy_report(legacy)
        self.assertIn("$.training_label", envelope["discarded_semantics"])
        self.assertFalse(any(item["legacy_path"] == "$.training_label" for item in envelope["preserved_values"]))

    def test_duplicate_and_nonfinite_json_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            CONTRACT.strict_json_loads('{"x":1,"x":2}', label="fixture")
        with self.assertRaises(ValueError):
            CONTRACT.canonical_json({"x": math.inf})

    def test_cli_preserves_source_and_refuses_alias(self):
        legacy_path = ROOT / "tests/fixtures/s01/legacy-file-report-v2.2.0.json"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "envelope.json"
            before = legacy_path.read_bytes()
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(ROOT / "tools/migrate_v2_report.py"), str(legacy_path), str(output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(legacy_path.read_bytes(), before)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(result["non_equivalent"])
            alias = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(ROOT / "tools/migrate_v2_report.py"), str(legacy_path), str(legacy_path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(alias.returncode, 0)
            self.assertEqual(legacy_path.read_bytes(), before)


class ContractArtefactTests(unittest.TestCase):
    def test_phase_checker_passes(self):
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(ROOT / "tools/check_s01_construct_contract.py"), "--root", str(ROOT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("PASS", completed.stdout)

    def test_construct_map_is_complete_and_explicitly_hypothetical(self):
        construct = json.loads((ROOT / "research/construct-map.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(len(construct["dimensions"]), 7)
        self.assertIn("working_hypotheses", construct["status"])
        for dimension in construct["dimensions"]:
            self.assertEqual(dimension["status"], "working_hypothesis")
            self.assertTrue(dimension["prohibited_inferences"])
            self.assertTrue(dimension["evidence_gate"])

    def test_schema_index_is_unique_and_policy_target_is_non_provenance(self):
        index = json.loads((ROOT / "research/schema-index.v1.json").read_text(encoding="utf-8"))
        paths = [item["path"] for item in index["schemas"]]
        identifiers = [item["id"] for item in index["schemas"]]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(len(identifiers), len(set(identifiers)))
        policy_schema = json.loads((ROOT / "schemas/codeprobe-policy-evaluation-profile-v1.schema.json").read_text(encoding="utf-8"))
        targets = set(policy_schema["properties"]["target"]["enum"])
        self.assertEqual(
            targets,
            {"action_correctness", "actionability", "revision_quality", "uptake", "burden", "false_prompting", "coverage"},
        )
        self.assertFalse(any("author" in target or target.startswith("ai") for target in targets))
        self.assertIn("schemas/codeprobe-feedback-response-v1.schema.json", paths)

    def test_report_schema_requires_each_non_inference(self):
        schema = json.loads((ROOT / "schemas/codeprobe-review-report-v3.schema.json").read_text(encoding="utf-8"))
        constraints = schema["properties"]["non_inferences"]["allOf"]
        required = {item["contains"]["const"] for item in constraints}
        self.assertEqual(required, set(CONTRACT.REQUIRED_NON_INFERENCES))

    def test_a01_f007_is_not_falsely_closed(self):
        acceptance = json.loads((ROOT / "research/s01-acceptance-contract.v1.json").read_text(encoding="utf-8"))
        finding = acceptance["historic_finding"]
        self.assertEqual(finding["finding_id"], "A01-F007")
        self.assertEqual(finding["s01_disposition"], "CONTRACT_REWRITTEN_IMPLEMENTATION_PENDING_S04")
        self.assertIn("Do not close", finding["closure_rule"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
