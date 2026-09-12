
#!/usr/bin/env python3
"""Fail-closed S02 measurement-kernel acceptance checker."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

REQUIRED_SPEC_FIELDS = {
    "specification_id", "observation_id", "title", "status", "entity",
    "attribute", "measurement_scale", "unit", "codomain", "counting_rule",
    "algorithm", "parser_scope", "applicability_states",
    "source_evidence_production", "nuisance_factors",
    "expected_metamorphic_relations", "admissible_interpretations",
    "prohibited_inferences", "oracle_ids", "residual_limitations",
    "dimension_ids", "legacy_sources", "instance_cardinality",
}
FORBIDDEN_IDS = {
    "overall_score", "review_trigger", "ai_probability", "authorship_probability",
    "human_likelihood", "misconduct_verdict", "sanction_trigger",
}
EXPECTED_PRINCIPLES = {
    "atomic_values_only": True,
    "canonical_s01_dimension_ids": True,
    "causal_attribution": False,
    "conformance_not_construct_validity": True,
    "global_scalar": False,
    "source_evidence_required": True,
    "typed_applicability": True,
    "unavailable_is_zero": False,
}
EXECUTABLE_PYTHON = (
    "src/codeprobe_measurement_kernel.py",
    "src/codeprobe_s01_observation_adapter.py",
    "tools/check_s02_measurement_kernel.py",
    "tests/oracles/s02_reference_oracles.py",
    "tests/test_s02_measurement_kernel.py",
)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def recursive_keys(value: Any):
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield str(key)
            yield from recursive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from recursive_keys(nested)


def resolve_pointer(document: Any, fragment: str) -> Any:
    if fragment in ("", "#"):
        return document
    if not fragment.startswith("#/"):
        raise ValueError(f"unsupported non-local fragment: {fragment}")
    value = document
    for token in fragment[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            value = value[int(token)]
        else:
            value = value[token]
    return value


def iter_refs(value: Any):
    if isinstance(value, Mapping):
        if "$ref" in value:
            yield value["$ref"]
        for nested in value.values():
            yield from iter_refs(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_refs(nested)


def check_schema_references(root: Path) -> None:
    schemas = {path.name: load_json(path) for path in sorted((root / "schemas").glob("*.schema.json"))}
    schemas_by_id = {
        document.get("$id"): document
        for document in schemas.values()
        if isinstance(document.get("$id"), str)
    }
    for name, document in schemas.items():
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SystemExit(f"{name}: not Draft 2020-12")
        for ref in iter_refs(document):
            if ref.startswith("#"):
                resolve_pointer(document, ref)
                continue
            file_part, marker, fragment = ref.partition("#")
            if file_part.startswith("https://json-schema.org/"):
                continue
            target = schemas_by_id.get(file_part)
            if target is None:
                target_name = Path(file_part).name
                target = schemas.get(target_name)
            if target is None:
                raise SystemExit(f"{name}: unresolved schema reference {ref}")
            if marker:
                resolve_pointer(target, "#" + fragment)


def check_schema_contract_shapes(root: Path) -> None:
    catalogue_schema = load_json(root / "schemas" / "codeprobe-observation-catalogue-v1.schema.json")
    result_schema = load_json(root / "schemas" / "codeprobe-measurement-kernel-result-v1.schema.json")
    specification = catalogue_schema.get("$defs", {}).get("specification", {})
    if specification.get("additionalProperties") is not False:
        raise SystemExit("catalogue specification schema is not closed")
    principles = catalogue_schema.get("properties", {}).get("principles", {})
    if principles.get("type") != "object" or principles.get("additionalProperties") is not False:
        raise SystemExit("catalogue principles schema is not a closed object")
    if catalogue_schema.get("properties", {}).get("observation_count", {}).get("const") != 40:
        raise SystemExit("catalogue schema does not pin the forty-observation contract")
    observation = result_schema.get("$defs", {}).get("observation", {})
    if observation.get("additionalProperties") is not False:
        raise SystemExit("kernel observation schema is not closed")
    applicability = observation.get("properties", {}).get("applicability", {})
    if applicability.get("additionalProperties") is not False:
        raise SystemExit("kernel applicability schema is not closed")
    instrumentation = observation.get("properties", {}).get("instrumentation", {})
    if instrumentation.get("additionalProperties") is not False:
        raise SystemExit("kernel instrumentation schema is not closed")
    if result_schema.get("properties", {}).get("kernel_version", {}).get("const") != "1.1.0":
        raise SystemExit("kernel-result schema version is not pinned")


def check_catalogue(root: Path) -> set[str]:
    catalogue = load_json(root / "research" / "observation-catalogue.v1.json")
    if catalogue.get("schema") != "codeprobe-observation-catalogue/v1" or catalogue.get("version") != "1.1.0":
        raise SystemExit("observation catalogue identity mismatch")
    if catalogue.get("status") != "reference_implementation_s02_candidate":
        raise SystemExit("observation catalogue status mismatch")
    if catalogue.get("principles") != EXPECTED_PRINCIPLES:
        raise SystemExit("observation catalogue principles differ from the S02 contract")
    observations = catalogue.get("observations")
    if catalogue.get("observation_count") != 40 or not isinstance(observations, list) or len(observations) != 40:
        raise SystemExit("S02 requires exactly forty retained observation specifications")
    ids = [item.get("observation_id") for item in observations]
    specification_ids = [item.get("specification_id") for item in observations]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate observation identifier")
    if len(specification_ids) != len(set(specification_ids)):
        raise SystemExit("duplicate observation specification identifier")
    construct = load_json(root / "research" / "construct-map.v1.json")
    canonical_dimensions = {item["dimension_id"] for item in construct.get("dimensions", [])}
    if set(ids) & FORBIDDEN_IDS:
        raise SystemExit("forbidden global scalar/provenance identifier in catalogue")
    for item in observations:
        missing = REQUIRED_SPEC_FIELDS - set(item)
        if missing:
            raise SystemExit(f"{item.get('observation_id')}: incomplete specification {sorted(missing)}")
        if item["status"] != "reference_implementation_s02":
            raise SystemExit(f"{item['observation_id']}: invalid implementation status")
        if item["specification_id"] != f"codeprobe-observation/{item['observation_id']}/1.1.0":
            raise SystemExit(f"{item['observation_id']}: specification identity mismatch")
        if item["instance_cardinality"] not in {"one_per_artifact", "zero_or_more_per_artifact"}:
            raise SystemExit(f"{item['observation_id']}: unsupported cardinality")
        if item["algorithm"].get("version") != "1.1.0" or item["algorithm"].get("deterministic_given_contract") is not True:
            raise SystemExit(f"{item['observation_id']}: algorithm identity mismatch")
        if {state["state"] for state in item["applicability_states"]} != {
            "observed", "not_applicable", "insufficient_evidence", "unavailable"
        }:
            raise SystemExit(f"{item['observation_id']}: applicability contract incomplete")
        if len(item["expected_metamorphic_relations"]) < 2:
            raise SystemExit(f"{item['observation_id']}: insufficient metamorphic specification")
        if not item["oracle_ids"] or not item["residual_limitations"]:
            raise SystemExit(f"{item['observation_id']}: oracle or residual limitation absent")
        unknown_dimensions = set(item["dimension_ids"]) - canonical_dimensions
        if unknown_dimensions:
            raise SystemExit(f"{item['observation_id']}: non-canonical S01 dimensions {sorted(unknown_dimensions)}")
    return set(ids)


def check_dispositions(root: Path, observation_ids: set[str]) -> None:
    with (root / "research" / "legacy-metric-disposition.v1.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 37 or len({row["legacy_metric"] for row in rows}) != 37:
        raise SystemExit("legacy metric disposition is not exactly thirty-seven unique decisions")
    for row in rows:
        if any(row[field] != "false" for field in (
            "legacy_score_weight_preserved", "legacy_thresholds_preserved",
            "provenance_interpretation_preserved",
        )):
            raise SystemExit(f"{row['legacy_metric']}: prohibited legacy semantics retained")
        replacements = {value for value in row["replacement_observation_ids"].split(";") if value}
        if not replacements.issubset(observation_ids):
            raise SystemExit(f"{row['legacy_metric']}: unknown replacement {sorted(replacements - observation_ids)}")
        if not row["decision"] or not row["rationale"] or not row["residual_validity_question"]:
            raise SystemExit(f"{row['legacy_metric']}: incomplete decision")


def check_oracles(root: Path, observation_ids: set[str]) -> None:
    hierarchy = load_json(root / "research" / "oracle-hierarchy.v1.json")
    records = hierarchy.get("oracles", [])
    ids = {record["oracle_id"] for record in records}
    if len(ids) != len(records):
        raise SystemExit("duplicate oracle identifier")
    catalogue = load_json(root / "research" / "observation-catalogue.v1.json")
    used = {oracle for item in catalogue["observations"] for oracle in item["oracle_ids"]}
    if not used.issubset(ids):
        raise SystemExit(f"unresolved oracle ids: {sorted(used - ids)}")
    covered = {obs for record in records for obs in record.get("covers", [])}
    if not observation_ids.issubset(covered):
        raise SystemExit(f"implemented observations lack oracle coverage: {sorted(observation_ids - covered)}")
    for record in records:
        if not record["residual_limitations"]:
            raise SystemExit(f"{record['oracle_id']}: residual limitations absent")


def check_graph_errors_hypotheses(root: Path) -> None:
    graph = load_json(root / "research" / "measurement-dependency-graph.v1.json")
    node_ids = {node["id"] for node in graph["nodes"]}
    if len(node_ids) != len(graph["nodes"]):
        raise SystemExit("duplicate dependency-graph node")
    for edge in graph["edges"]:
        if edge["from"] not in node_ids or edge["to"] not in node_ids:
            raise SystemExit(f"unresolved dependency edge: {edge}")
    errors = load_json(root / "research" / "measurement-error-register.v1.json")
    classes = {record["class"] for record in errors["errors"]}
    required_classes = {
        "intake_error", "decoding_error", "parser_error", "unsupported_syntax",
        "finite_budget", "environment_drift", "true_absence",
        "insufficient_evidence", "approximation", "instrumentation_error",
    }
    if not required_classes.issubset(classes):
        raise SystemExit(f"measurement-error classes missing: {sorted(required_classes - classes)}")
    hypotheses = load_json(root / "research" / "s02-robustness-hypotheses.v1.json")
    if not hypotheses["hypotheses"] or any(
        not item["status"].startswith("preregister_before") for item in hypotheses["hypotheses"]
    ):
        raise SystemExit("hypotheses are not explicitly prospective")


def check_conformance(root: Path) -> None:
    with (root / "research" / "conformance-matrix.v1.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) < 30 or len({row["case_id"] for row in rows}) != len(rows):
        raise SystemExit("conformance matrix is incomplete or has duplicate cases")
    categories = {row["category"] for row in rows}
    required = {"normal", "boundary", "malformed", "unsupported_syntax", "resource_exhaustion"}
    # Scope-boundary and malformed-but-bounded jointly satisfy the unsupported class.
    if "scope_boundary" in categories:
        categories.add("unsupported_syntax")
    if "malformed_but_bounded" in categories:
        categories.add("malformed")
    if not required.issubset(categories):
        raise SystemExit(f"conformance categories missing: {sorted(required - categories)}")


def check_fixture_manifest(root: Path) -> None:
    fixture_root = root / "tests" / "fixtures" / "s02"
    expected = load_json(fixture_root / "expected-digests.v1.json")
    if expected.get("fixture_count") != len(expected.get("fixtures", [])):
        raise SystemExit("fixture digest count mismatch")
    paths = [record["path"] for record in expected["fixtures"]]
    if len(paths) != len(set(paths)):
        raise SystemExit("duplicate fixture digest path")
    for record in expected["fixtures"]:
        path = fixture_root / record["path"]
        if not path.is_file() or sha256(path) != record["raw_sha256"]:
            raise SystemExit(f"fixture provenance mismatch: {record['path']}")


def load_kernel(root: Path):
    sys.path.insert(0, str(root / "src"))
    import codeprobe_measurement_kernel as kernel
    return kernel


def check_kernel_outputs(root: Path, observation_ids: set[str]) -> None:
    kernel = load_kernel(root)
    catalogue = load_json(root / "research" / "observation-catalogue.v1.json")
    emitted = set()
    fixture_root = root / "tests" / "fixtures" / "s02"
    expected = load_json(fixture_root / "expected-digests.v1.json")
    for record in expected["fixtures"]:
        result = kernel.measure_bytes(
            (fixture_root / record["path"]).read_bytes(),
            language=record["language"],
            path=record["path"],
        )
        kernel.validate_kernel_result(result)
        kernel.verify_result_against_catalogue(result, catalogue)
        if result["measurement_digest"] != record["measurement_digest"]:
            raise SystemExit(f"fixture output digest mismatch: {record['path']}")
        emitted.update(item["observation_id"] for item in result["observations"])
    if emitted != observation_ids:
        raise SystemExit(f"catalogue/kernel coverage mismatch: missing={sorted(observation_ids-emitted)} extra={sorted(emitted-observation_ids)}")
    if set(recursive_keys(result)) & FORBIDDEN_IDS:
        raise SystemExit("forbidden identifier emitted by kernel")


def check_s01_interface(root: Path) -> None:
    audit = load_json(root / "research" / "s02-s01-interface-audit.v1.json")
    if audit.get("unmapped_required_properties"):
        raise SystemExit("S01 observation adapter has unmapped required fields")
    sys.path.insert(0, str(root / "src"))
    import codeprobe_measurement_kernel as kernel
    import codeprobe_s01_observation_adapter as adapter
    sample = kernel.measure_bytes(b"x = 1\n", language="python")["observations"][0]
    adapted = adapter.adapt_observation(sample)
    expected_fields = set(adapter.REQUIRED_MAPPING) | set(adapter.TEMPLATE_FALLBACK)
    if set(adapted) != expected_fields:
        raise SystemExit("S01 adapter field mismatch")


def compile_executable_files(root: Path) -> None:
    for relative in EXECUTABLE_PYTHON:
        path = root / relative
        if not path.is_file():
            raise SystemExit(f"missing executable Python file: {relative}")
        py_compile.compile(str(path), doraise=True)


def run_tests(root: Path) -> None:
    command = [sys.executable, "-I", "-S", "-B", str(root / "tests" / "test_s02_measurement_kernel.py")]
    environment = dict(os.environ)
    environment["PYTHONWARNINGS"] = "error::ResourceWarning"
    completed = subprocess.run(command, cwd=root, text=True, env=environment)
    if completed.returncode:
        raise SystemExit("S02 test suite failed")


def run_s01_checker(root: Path) -> None:
    checker = root / "tools" / "check_s01_construct_contract.py"
    if not checker.is_file():
        raise SystemExit("S01 checker absent from assembled candidate")
    command = [sys.executable, "-I", "-S", "-B", str(checker), "--root", str(root)]
    completed = subprocess.run(command, cwd=root, text=True)
    if completed.returncode:
        raise SystemExit("S01 contract regression")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--skip-s01", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    observation_ids = check_catalogue(root)
    check_dispositions(root, observation_ids)
    check_oracles(root, observation_ids)
    check_graph_errors_hypotheses(root)
    check_conformance(root)
    check_schema_references(root)
    check_schema_contract_shapes(root)
    check_fixture_manifest(root)
    compile_executable_files(root)
    check_kernel_outputs(root, observation_ids)
    check_s01_interface(root)
    run_tests(root)
    if not args.skip_s01:
        run_s01_checker(root)
    print(json.dumps({
        "status": "PASS",
        "observation_specifications": len(observation_ids),
        "legacy_metric_decisions": 37,
        "conformance_cases": len(list(csv.DictReader((root / "research" / "conformance-matrix.v1.csv").open(encoding="utf-8", newline="")))),
        "python": sys.version.split()[0],
        "claim": "software conformance only; construct validity remains unestablished",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
