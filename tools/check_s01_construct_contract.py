#!/usr/bin/env python3
"""Fail-closed S01 contract verifier."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

REQUIRED_FILES = {
    ".github/workflows/s01-construct-contract.yml",
    "docs/research/README.md",
    "docs/research/01-construct-map.md",
    "docs/research/02-terminology-policy.md",
    "docs/research/03-report-schema-migration.md",
    "docs/research/04-scalar-and-aggregation-decision.md",
    "docs/research/05-formative-policy-evaluation.md",
    "docs/research/06-claim-boundary.md",
    "docs/research/07-a01-f007-acceptance-contract.md",
    "research/construct-map.v1.json",
    "research/terminology-registry.v1.json",
    "research/claim-policy.v1.json",
    "research/s01-acceptance-contract.v1.json",
    "research/schema-index.v1.json",
    "schemas/codeprobe-review-report-v3.schema.json",
    "schemas/codeprobe-feedback-action-v1.schema.json",
    "schemas/codeprobe-feedback-response-v1.schema.json",
    "schemas/codeprobe-legacy-migration-envelope-v1.schema.json",
    "schemas/codeprobe-policy-evaluation-profile-v1.schema.json",
    "schemas/codeprobe-process-evidence-v1.schema.json",
    "src/codeprobe_review_contract.py",
    "tools/check_s01_construct_contract.py",
    "tools/migrate_v2_report.py",
    "tests/test_s01_construct_contract.py",
    "tests/fixtures/s01/valid-review-report.json",
    "tests/fixtures/s01/legacy-file-report-v2.2.0.json",
    "tests/fixtures/s01/legacy-calibration-provenance-labels.json",
    "tests/fixtures/s01/invalid-authorship-report.json",
}

PUBLIC_CONTRACT_FILES = {
    "docs/research/README.md",
    "docs/research/01-construct-map.md",
    "docs/research/02-terminology-policy.md",
    "docs/research/03-report-schema-migration.md",
    "docs/research/04-scalar-and-aggregation-decision.md",
    "docs/research/05-formative-policy-evaluation.md",
    "docs/research/06-claim-boundary.md",
    "docs/research/07-a01-f007-acceptance-contract.md",
}


def load_contract(root: Path):
    path = root / "src/codeprobe_review_contract.py"
    spec = importlib.util.spec_from_file_location("codeprobe_review_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load S01 contract module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r} in {path}")
            result[key] = value
        return result
    with path.open(encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=unique)


def walk_keys(node, path="$" ):
    if isinstance(node, dict):
        for key, value in node.items():
            yield path, key
            yield from walk_keys(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk_keys(value, f"{path}[{index}]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    missing = sorted(path for path in REQUIRED_FILES if not (root / path).is_file())
    if missing:
        raise SystemExit(f"missing S01 files: {missing}")

    contract = load_contract(root)
    construct = load_json(root / "research/construct-map.v1.json")
    terminology = load_json(root / "research/terminology-registry.v1.json")
    policy = load_json(root / "research/claim-policy.v1.json")
    acceptance = load_json(root / "research/s01-acceptance-contract.v1.json")
    schema_index = load_json(root / "research/schema-index.v1.json")
    schemas = [
        load_json(root / "schemas/codeprobe-review-report-v3.schema.json"),
        load_json(root / "schemas/codeprobe-feedback-action-v1.schema.json"),
        load_json(root / "schemas/codeprobe-feedback-response-v1.schema.json"),
        load_json(root / "schemas/codeprobe-legacy-migration-envelope-v1.schema.json"),
        load_json(root / "schemas/codeprobe-policy-evaluation-profile-v1.schema.json"),
        load_json(root / "schemas/codeprobe-process-evidence-v1.schema.json"),
    ]

    if construct.get("schema") != "codeprobe-construct-map/v1" or len(construct.get("dimensions", [])) != 7:
        raise SystemExit("construct map must contain exactly seven candidate dimensions")
    required_dimension_fields = {
        "dimension_id", "label", "status", "observable_families", "allowed_interpretations",
        "permitted_actions", "prohibited_inferences", "nuisance_factors",
        "metamorphic_expectations", "evidence_gate"
    }
    for dimension in construct["dimensions"]:
        if set(dimension) != required_dimension_fields:
            raise SystemExit(f"incomplete construct-map entry: {dimension.get('dimension_id')}")
        for key in (
            "observable_families", "allowed_interpretations", "permitted_actions",
            "prohibited_inferences", "nuisance_factors", "metamorphic_expectations"
        ):
            if not dimension[key]:
                raise SystemExit(f"empty {key} in {dimension['dimension_id']}")

    if terminology.get("legacy_namespace", {}).get("read_only") is not True:
        raise SystemExit("legacy namespace must be read-only")
    if acceptance.get("source", {}).get("base_commit") != "d5e1aa9e86e855f05ea570de22110aefc972b400":
        raise SystemExit("S01 base commit drift")
    if acceptance.get("decisions", {}).get("core_scalar") != "absent":
        raise SystemExit("S01 core scalar decision is not fail-closed")


    indexed = schema_index.get("schemas", [])
    if len(indexed) != len(schemas):
        raise SystemExit("schema index and schema inventory differ")
    indexed_paths = [item.get("path") for item in indexed]
    indexed_ids = [item.get("id") for item in indexed]
    if len(indexed_paths) != len(set(indexed_paths)) or len(indexed_ids) != len(set(indexed_ids)):
        raise SystemExit("schema index contains duplicate paths or identifiers")
    actual_by_id = {}
    for item in indexed:
        path = root / item["path"]
        schema = load_json(path)
        if schema.get("$id") != item["id"]:
            raise SystemExit(f"schema identifier mismatch: {item['path']}")
        actual_by_id[item["id"]] = item["path"]
    schema_dir = root / "schemas"

    def resolve_pointer(document, fragment, label):
        if not fragment:
            return
        if not fragment.startswith("/"):
            raise SystemExit(f"unsupported schema fragment #{fragment} in {label}")
        node = document
        for raw in fragment[1:].split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                try:
                    node = node[int(token)]
                except (ValueError, IndexError) as exc:
                    raise SystemExit(f"unresolved schema fragment #{fragment} in {label}") from exc
            elif isinstance(node, dict) and token in node:
                node = node[token]
            else:
                raise SystemExit(f"unresolved schema fragment #{fragment} in {label}")

    by_path = {item["path"]: load_json(root / item["path"]) for item in indexed}
    by_id = {schema["$id"]: schema for schema in by_path.values()}
    for item in indexed:
        schema = by_path[item["path"]]
        stack = [schema]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                ref = node.get("$ref")
                if isinstance(ref, str):
                    target_text, separator, fragment = ref.partition("#")
                    if not target_text:
                        target_schema = schema
                    elif target_text.startswith("https://"):
                        target_schema = by_id.get(target_text)
                        if target_schema is None:
                            raise SystemExit(f"unindexed absolute schema reference {ref!r} in {item['path']}")
                    else:
                        target_path = (Path(item["path"]).parent / target_text).as_posix()
                        target_schema = by_path.get(target_path)
                        if target_schema is None or not (root / target_path).is_file():
                            raise SystemExit(f"unresolved schema reference {ref!r} in {item['path']}")
                    if separator:
                        resolve_pointer(target_schema, fragment, item["path"])
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)

    forbidden = {item.lower().replace("-", "_") for item in policy["forbidden_identifiers"]}
    for schema in schemas:
        for path, key in walk_keys(schema):
            normalised = str(key).lower().replace("-", "_").replace(" ", "_")
            if normalised in forbidden:
                raise SystemExit(f"schema key {path}.{key} violates claim policy")

    legacy_markers = tuple(marker.lower() for marker in policy["legacy_discussion_markers"])
    for relative in PUBLIC_CONTRACT_FILES:
        for number, line in enumerate((root / relative).read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            for phrase in policy["forbidden_affirmative_phrases"]:
                if phrase in lowered and not any(marker in lowered for marker in legacy_markers):
                    raise SystemExit(f"affirmative prohibited phrase in {relative}:{number}: {phrase}")

    valid = load_json(root / "tests/fixtures/s01/valid-review-report.json")
    contract.validate_review_report(valid)
    invalid = load_json(root / "tests/fixtures/s01/invalid-authorship-report.json")
    try:
        contract.validate_review_report(invalid)
    except ValueError:
        pass
    else:
        raise SystemExit("invalid authorship-like report was accepted")

    legacy = load_json(root / "tests/fixtures/s01/legacy-file-report-v2.2.0.json")
    envelope = contract.migrate_legacy_report(legacy)
    if envelope["non_equivalent"] is not True or not envelope["discarded_semantics"]:
        raise SystemExit("legacy migration did not preserve non-equivalence and discarded semantics")

    report_schema = load_json(root / "schemas/codeprobe-review-report-v3.schema.json")
    observation_properties = report_schema["$defs"]["observation"]["properties"]
    if "applicability" not in observation_properties or "applicable" in observation_properties:
        raise SystemExit("observation applicability is not the required typed contract")
    if set(observation_properties["measurement_scale"]["enum"]) != {"nominal", "ordinal", "interval", "ratio"}:
        raise SystemExit("measurement-scale contract is inconsistent")
    feedback_schema = load_json(root / "schemas/codeprobe-feedback-action-v1.schema.json")
    if "source_evidence_refs" not in feedback_schema["required"] or "policy_rule_id" not in feedback_schema["required"]:
        raise SystemExit("feedback traceability contract is incomplete")
    if "acknowledgement_state" in feedback_schema.get("properties", {}):
        raise SystemExit("mutable acknowledgement leaked into immutable feedback action")

    profile = load_json(root / "tests/fixtures/s01/legacy-calibration-provenance-labels.json")
    try:
        contract.migrate_legacy_report(legacy, policy_profile=profile)
    except ValueError:
        pass
    else:
        raise SystemExit("provenance-labelled legacy policy was accepted")

    workflow = (root / ".github/workflows/s01-construct-contract.yml").read_text(encoding="utf-8")
    if "research/codeprobe-s01-evidence-contract-20260911" not in workflow:
        raise SystemExit("phase workflow does not bind the intended S01 branch")
    if "permissions:\n  contents: read" not in workflow:
        raise SystemExit("phase workflow permissions are not read-only")
    if re.search(r"\b(push|pull_request_target):\s*\{", workflow):
        raise SystemExit("unexpected compact workflow trigger")

    print(
        "PASS: S01 construct map, terminology, schemas, non-scalar decision, "
        "legacy refusal and negative-claim controls verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
