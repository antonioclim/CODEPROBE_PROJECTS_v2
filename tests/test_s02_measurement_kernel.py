
from __future__ import annotations

import csv
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

import codeprobe_measurement_kernel as kernel
import codeprobe_s01_observation_adapter as s01_adapter
from oracles.s02_reference_oracles import generic_reference, markdown_reference, python_ast_reference

FIXTURES = HERE / "fixtures" / "s02"
CATALOGUE_PATH = ROOT / "research" / "observation-catalogue.v1.json"
DISPOSITION_PATH = ROOT / "research" / "legacy-metric-disposition.v1.csv"
DIGEST_PATH = FIXTURES / "expected-digests.v1.json"


def values(result):
    grouped = {}
    for record in result["observations"]:
        grouped.setdefault(record["observation_id"], []).append(
            (record["entity"]["entity_id"], record["applicability"]["state"], record["value"])
        )
    for key in grouped:
        grouped[key].sort(key=lambda item: item[0])
    return grouped


def singleton_values(result):
    output = {}
    for record in result["observations"]:
        if record["entity"]["entity_id"] in {"source", "python_module", "markdown_document"}:
            output[record["observation_id"]] = record["value"]
    return output


def state_for(result, observation_id):
    records = [r for r in result["observations"] if r["observation_id"] == observation_id]
    if len(records) != 1:
        raise AssertionError(f"expected singleton {observation_id}, got {len(records)}")
    return records[0]["applicability"]["state"], records[0]["value"]


class CatalogueContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = json.loads(CATALOGUE_PATH.read_text(encoding="utf-8"))

    def test_exactly_forty_unique_atomic_specifications(self):
        observations = self.catalogue["observations"]
        self.assertEqual(40, self.catalogue["observation_count"])
        self.assertEqual(40, len(observations))
        self.assertEqual(40, len({item["observation_id"] for item in observations}))
        self.assertTrue(all(item["status"] == "reference_implementation_s02" for item in observations))

    def test_every_specification_is_complete_and_has_oracle_and_limits(self):
        required = {
            "specification_id", "observation_id", "entity", "attribute",
            "measurement_scale", "unit", "codomain", "counting_rule",
            "algorithm", "parser_scope", "applicability_states",
            "source_evidence_production", "nuisance_factors",
            "expected_metamorphic_relations", "admissible_interpretations",
            "prohibited_inferences", "oracle_ids", "residual_limitations",
            "dimension_ids", "legacy_sources", "instance_cardinality",
        }
        for item in self.catalogue["observations"]:
            self.assertTrue(required.issubset(item), item["observation_id"])
            self.assertGreaterEqual(len(item["expected_metamorphic_relations"]), 2)
            self.assertTrue(item["oracle_ids"])
            self.assertTrue(item["residual_limitations"])
            self.assertEqual(
                {"observed", "not_applicable", "insufficient_evidence", "unavailable"},
                {state["state"] for state in item["applicability_states"]},
            )

    def test_all_legacy_metrics_have_one_non_scalar_decision(self):
        with DISPOSITION_PATH.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(37, len(rows))
        self.assertEqual(37, len({row["legacy_metric"] for row in rows}))
        self.assertTrue(all(row["legacy_score_weight_preserved"] == "false" for row in rows))
        self.assertTrue(all(row["legacy_thresholds_preserved"] == "false" for row in rows))
        self.assertTrue(all(row["provenance_interpretation_preserved"] == "false" for row in rows))

    def test_adapter_has_no_unmapped_s01_required_property(self):
        self.assertEqual([], s01_adapter.UNMAPPED_REQUIRED_PROPERTIES)

    def test_catalogue_uses_canonical_s01_dimension_identifiers(self):
        construct = json.loads((ROOT / "research" / "construct-map.v1.json").read_text(encoding="utf-8"))
        dimensions = {item["dimension_id"] for item in construct["dimensions"]}
        referenced = {dimension for item in self.catalogue["observations"] for dimension in item["dimension_ids"]}
        self.assertTrue(referenced.issubset(dimensions), sorted(referenced - dimensions))


class GenericMeasurementTests(unittest.TestCase):
    def test_reference_oracle_for_all_generic_fixtures(self):
        names = [
            "empty.txt", "single_line.txt", "single_line_lf.txt",
            "line_endings_lf.txt", "line_endings_crlf.txt",
            "unicode_bom.txt", "layout.txt",
        ]
        for name in names:
            with self.subTest(name=name):
                raw = (FIXTURES / name).read_bytes()
                result = kernel.measure_bytes(raw, language="text", path=name)
                actual = singleton_values(result)
                expected = generic_reference(raw)
                for observation_id, expected_value in expected.items():
                    self.assertEqual(expected_value, actual[observation_id], observation_id)
                kernel.verify_result_against_catalogue(result, json.loads(CATALOGUE_PATH.read_text()))

    def test_lf_crlf_relation(self):
        lf = kernel.measure_bytes((FIXTURES / "line_endings_lf.txt").read_bytes(), language="text", path="x")
        crlf = kernel.measure_bytes((FIXTURES / "line_endings_crlf.txt").read_bytes(), language="text", path="x")
        left = singleton_values(lf)
        right = singleton_values(crlf)
        for key in left:
            if key == "source.byte_count":
                self.assertNotEqual(left[key], right[key])
            else:
                self.assertEqual(left[key], right[key], key)

    def test_evidence_identity_separates_artifact_and_callable_scope(self):
        result = kernel.measure_bytes((FIXTURES / "python_complexity.py").read_bytes(), language="python")
        evidence_ids = [item["evidence_id"] for item in result["source_evidence"]]
        self.assertEqual(len(evidence_ids), len(set(evidence_ids)))
        self.assertTrue(any(":whole_artifact:" in item for item in evidence_ids))
        self.assertTrue(any(":python_callable:" in item for item in evidence_ids))

    def test_path_rename_does_not_change_measurement_identity(self):
        raw = (FIXTURES / "python_normal.py").read_bytes()
        first = kernel.measure_bytes(raw, language="python", path="a/source.py")
        second = kernel.measure_bytes(raw, language="python", path="renamed/source.py")
        self.assertEqual(first["measurement_digest"], second["measurement_digest"])
        self.assertEqual(
            [item["evidence_id"] for item in first["source_evidence"]],
            [item["evidence_id"] for item in second["source_evidence"]],
        )
        self.assertEqual(
            [item["record_id"] for item in first["observations"]],
            [item["record_id"] for item in second["observations"]],
        )

    def test_seeded_randomised_generic_oracle(self):
        import random
        rng = random.Random(20260911)
        alphabet = "abcXYZ09 _\t"
        for case in range(250):
            line_count = rng.randrange(0, 18)
            lines = ["".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 40))) for _ in range(line_count)]
            terminal = rng.choice(["", "\n", "\r\n"])
            separator = rng.choice(["\n", "\r\n", "\r"])
            raw = (separator.join(lines) + terminal).encode("utf-8")
            result = kernel.measure_bytes(raw, language="text", path=f"case-{case}.txt")
            actual = singleton_values(result)
            expected = generic_reference(raw)
            for observation_id, expected_value in expected.items():
                self.assertEqual(expected_value, actual[observation_id], (case, observation_id, raw))

    def test_empty_dispersion_and_proportions_are_not_zero(self):
        result = kernel.measure_bytes(b"", language="python")
        for observation_id in (
            "source.max_line_length_codepoints",
            "source.mean_line_length_codepoints",
            "source.population_sd_line_length_codepoints",
            "source.line_length_cv",
            "python.comment_line_proportion",
            "python.docstring_coverage_proportion",
            "python.annotation_coverage_proportion",
        ):
            state, value = state_for(result, observation_id)
            self.assertEqual("insufficient_evidence", state, observation_id)
            self.assertIsNone(value)


class PythonMeasurementTests(unittest.TestCase):
    def test_shared_ast_reference_counts(self):
        for name in (
            "python_normal.py", "python_imports.py", "python_literals.py",
            "python_exceptions.py", "python_complexity.py", "python_nested.py",
        ):
            with self.subTest(name=name):
                raw = (FIXTURES / name).read_bytes()
                result = kernel.measure_bytes(raw, language="python", path=name)
                actual = singleton_values(result)
                expected = python_ast_reference(raw.decode("utf-8"))
                for observation_id, expected_value in expected.items():
                    self.assertEqual(expected_value, actual[observation_id], observation_id)

    def test_syntax_failure_is_typed_and_not_zero(self):
        result = kernel.measure_bytes((FIXTURES / "python_syntax_error.py").read_bytes(), language="python")
        self.assertEqual(("observed", "syntax_error"), state_for(result, "python.parse_status"))
        for observation_id in (
            "python.function_definition_count", "python.class_definition_count",
            "python.numeric_literal_count", "python.exception_handler_count",
        ):
            self.assertEqual(("unavailable", None), state_for(result, observation_id))

    def test_comment_oracle_and_hash_in_string(self):
        result = kernel.measure_bytes((FIXTURES / "python_comments.py").read_bytes(), language="python")
        actual = singleton_values(result)
        self.assertEqual(2, actual["python.comment_token_count"])
        self.assertEqual(2, actual["python.comment_physical_line_count"])
        self.assertEqual(round(2 / 3, 12), actual["python.comment_line_proportion"])

    def test_docstring_counts(self):
        result = kernel.measure_bytes((FIXTURES / "python_docstrings.py").read_bytes(), language="python")
        actual = singleton_values(result)
        self.assertEqual(4, actual["python.docstring_eligible_definition_count"])
        self.assertEqual(3, actual["python.docstring_present_definition_count"])
        self.assertEqual(0.75, actual["python.docstring_coverage_proportion"])

    def test_annotation_slot_counts(self):
        result = kernel.measure_bytes((FIXTURES / "python_annotations.py").read_bytes(), language="python")
        actual = singleton_values(result)
        self.assertEqual(10, actual["python.annotation_eligible_slot_count"])
        self.assertEqual(5, actual["python.annotation_present_slot_count"])
        self.assertEqual(0.5, actual["python.annotation_coverage_proportion"])

    def test_import_binding_counts(self):
        result = kernel.measure_bytes((FIXTURES / "python_imports.py").read_bytes(), language="python")
        actual = singleton_values(result)
        self.assertEqual(3, actual["python.import_statement_count"])
        self.assertEqual(4, actual["python.imported_binding_count"])
        self.assertEqual(1, actual["python.wildcard_import_count"])

    def test_literal_and_exception_counts(self):
        literals = singleton_values(kernel.measure_bytes((FIXTURES / "python_literals.py").read_bytes(), language="python"))
        self.assertEqual(4, literals["python.numeric_literal_count"])
        exceptions = singleton_values(kernel.measure_bytes((FIXTURES / "python_exceptions.py").read_bytes(), language="python"))
        self.assertEqual(2, exceptions["python.exception_handler_count"])
        self.assertEqual(2, exceptions["python.raise_statement_count"])

    def test_callable_worked_example(self):
        result = kernel.measure_bytes((FIXTURES / "python_complexity.py").read_bytes(), language="python")
        grouped = values(result)
        self.assertEqual([("python_callable:1:branchy:L1", "observed", 9)], grouped["python.callable.physical_span_lines"])
        self.assertEqual([("python_callable:1:branchy:L1", "observed", 5)], grouped["python.callable.decision_point_count"])
        self.assertEqual([("python_callable:1:branchy:L1", "observed", 6)], grouped["python.callable.mccabe_complexity"])
        self.assertEqual([("python_callable:1:branchy:L1", "observed", 3)], grouped["python.callable.max_control_nesting_depth"])

    def test_nested_callable_is_excluded_from_outer(self):
        result = kernel.measure_bytes((FIXTURES / "python_nested.py").read_bytes(), language="python")
        decisions = values(result)["python.callable.decision_point_count"]
        self.assertEqual(
            [
                ("python_callable:1:outer:L1", "observed", 1),
                ("python_callable:2:inner:L3", "observed", 1),
            ],
            decisions,
        )

    def test_alpha_renaming_preserves_value_multiset(self):
        left = kernel.measure_bytes((FIXTURES / "python_alpha_a.py").read_bytes(), language="python")
        right = kernel.measure_bytes((FIXTURES / "python_alpha_b.py").read_bytes(), language="python")
        def value_multiset(result):
            return sorted(
                (item["observation_id"], item["applicability"]["state"], json.dumps(item["value"], sort_keys=True))
                for item in result["observations"]
            )
        self.assertEqual(value_multiset(left), value_multiset(right))

    def test_comment_insertion_changes_only_declared_layout_comment_and_span_values(self):
        base = singleton_values(kernel.measure_bytes((FIXTURES / "python_comment_base.py").read_bytes(), language="python"))
        added = singleton_values(kernel.measure_bytes((FIXTURES / "python_comment_added.py").read_bytes(), language="python"))
        self.assertEqual(base["python.comment_token_count"] + 1, added["python.comment_token_count"])
        self.assertEqual(base["python.comment_physical_line_count"] + 1, added["python.comment_physical_line_count"])
        for key in (
            "python.function_definition_count", "python.async_function_definition_count",
            "python.class_definition_count", "python.import_statement_count",
            "python.numeric_literal_count", "python.exception_handler_count",
            "python.raise_statement_count",
        ):
            self.assertEqual(base[key], added[key], key)


class MarkdownMeasurementTests(unittest.TestCase):
    def test_reference_scanner(self):
        for name in ("markdown_normal.md", "markdown_fenced.md", "markdown_unclosed.md", "markdown_closed.md"):
            with self.subTest(name=name):
                raw = (FIXTURES / name).read_bytes()
                result = kernel.measure_bytes(raw, language="markdown", path=name)
                actual = singleton_values(result)
                expected = markdown_reference(raw.decode("utf-8"))
                for observation_id, expected_value in expected.items():
                    self.assertEqual(expected_value, actual[observation_id], observation_id)

    def test_headings_inside_fence_are_excluded(self):
        actual = singleton_values(kernel.measure_bytes((FIXTURES / "markdown_fenced.md").read_bytes(), language="markdown"))
        self.assertEqual(2, actual["markdown.atx_heading_count"])
        self.assertEqual(0, actual["markdown.setext_heading_count"])
        self.assertEqual(1, actual["markdown.fenced_code_block_count"])

    def test_unclosed_fence_relation(self):
        open_result = singleton_values(kernel.measure_bytes((FIXTURES / "markdown_unclosed.md").read_bytes(), language="markdown"))
        closed_result = singleton_values(kernel.measure_bytes((FIXTURES / "markdown_closed.md").read_bytes(), language="markdown"))
        self.assertEqual("unclosed_fence", open_result["markdown.parse_status"])
        self.assertEqual("complete", closed_result["markdown.parse_status"])
        self.assertEqual(open_result["markdown.fenced_code_block_count"], closed_result["markdown.fenced_code_block_count"])


class IntakeBoundaryTests(unittest.TestCase):
    def test_exact_and_exceeded_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "source.txt"
            p.write_bytes(b"abcd")
            self.assertEqual(4, singleton_values(kernel.measure_file(p, language="text", max_bytes=4))["source.byte_count"])
            with self.assertRaises(kernel.MeasurementError) as caught:
                kernel.measure_file(p, language="text", max_bytes=3)
            self.assertEqual("ME-002", caught.exception.code)

    def test_invalid_utf8_and_nul_are_rejected(self):
        with self.assertRaises(kernel.MeasurementError) as utf8_error:
            kernel.measure_bytes(b"\xff", language="text")
        self.assertEqual("ME-003", utf8_error.exception.code)
        with self.assertRaises(kernel.MeasurementError) as nul_error:
            kernel.measure_bytes(b"a\0b", language="text")
        self.assertEqual("ME-004", nul_error.exception.code)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support unavailable")
    def test_symlink_and_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("x", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(kernel.MeasurementError) as caught:
                kernel.measure_file(link, language="text")
            self.assertEqual("ME-001", caught.exception.code)
            with self.assertRaises(kernel.MeasurementError):
                kernel.measure_file(root, language="text")


class DeterminismAndNegativeContractTests(unittest.TestCase):
    def test_expected_fixture_digests(self):
        expected = json.loads(DIGEST_PATH.read_text(encoding="utf-8"))
        for record in expected["fixtures"]:
            raw = (FIXTURES / record["path"]).read_bytes()
            result = kernel.measure_bytes(raw, language=record["language"], path=record["path"])
            self.assertEqual(record["measurement_digest"], result["measurement_digest"], record["path"])

    def test_repeated_execution_is_identical(self):
        raw = (FIXTURES / "python_normal.py").read_bytes()
        first = kernel.measure_bytes(raw, language="python", path="same.py")
        second = kernel.measure_bytes(raw, language="python", path="same.py")
        self.assertEqual(first, second)

    def test_forbidden_identifier_is_rejected(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        record = dict(result["observations"][0])
        record["overall_score"] = 0
        with self.assertRaises(ValueError):
            kernel.validate_observation_record(record)

    def test_unavailable_cannot_be_numeric_zero(self):
        result = kernel.measure_bytes((FIXTURES / "python_syntax_error.py").read_bytes(), language="python")
        record = next(item for item in result["observations"] if item["observation_id"] == "python.function_definition_count")
        altered = json.loads(json.dumps(record))
        altered["value"] = 0
        with self.assertRaises(ValueError):
            kernel.validate_observation_record(altered)


    def test_normalised_forbidden_identifier_is_rejected(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        altered = json.loads(json.dumps(result))
        altered["overallScore"] = 0
        with self.assertRaises(ValueError):
            kernel.validate_kernel_result(altered)

    def test_non_finite_atomic_value_is_rejected(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        record = json.loads(json.dumps(result["observations"][0]))
        record["value"] = float("nan")
        with self.assertRaises(ValueError):
            kernel.validate_observation_record(record)

    def test_observed_value_cannot_carry_unavailability_reason(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        record = json.loads(json.dumps(next(item for item in result["observations"] if item["applicability"]["state"] == "observed")))
        record["applicability"]["reason_code"] = "ME-999"
        record["applicability"]["reason"] = "Injected reason"
        with self.assertRaises(ValueError):
            kernel.validate_observation_record(record)

    def test_duplicate_evidence_reference_is_rejected(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        record = json.loads(json.dumps(result["observations"][0]))
        record["source_evidence_ids"].append(record["source_evidence_ids"][0])
        with self.assertRaises(ValueError):
            kernel.validate_observation_record(record)

    def test_tampered_measurement_digest_is_rejected(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        altered = json.loads(json.dumps(result))
        altered["measurement_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            kernel.validate_kernel_result(altered)

    def test_s01_adapter_preserves_required_values(self):
        result = kernel.measure_bytes(b"x = 1\n", language="python")
        adapted = s01_adapter.adapt_observation(result["observations"][0])
        self.assertEqual(set(s01_adapter.REQUIRED_MAPPING) | set(s01_adapter.TEMPLATE_FALLBACK), set(adapted))
        for target, source in s01_adapter.REQUIRED_MAPPING.items():
            value = result["observations"][0]
            for component in source.split("."):
                value = value[component]
            self.assertEqual(value, adapted[target])


if __name__ == "__main__":
    unittest.main(verbosity=2)
