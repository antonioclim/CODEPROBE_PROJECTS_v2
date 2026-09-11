#!/usr/bin/env python3
"""Evidence-bounded report-contract prototype for CodeProbe S01.

This module defines and validates the v3 construct boundary. It deliberately does
not import or modify the v2.2.0 measurement kernel. The legacy migration function
produces a non-equivalent read-only envelope, never a complete v3 report.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

REPORT_SCHEMA = "codeprobe-review-report/v3"
EVIDENCE_PROFILE_SCHEMA = "codeprobe-review-evidence-vector/v1"
LEGACY_ENVELOPE_SCHEMA = "codeprobe-legacy-migration-envelope/v1"
POLICY_CATALOGUE_SCHEMA = "codeprobe-feedback-policy-catalogue/v1"
CONTRACT_VERSION = "1.1.0"

APPLICABILITY_STATES = frozenset(
    {"observed", "not_applicable", "insufficient_evidence", "unavailable"}
)
MEASUREMENT_SCALES = frozenset({"nominal", "ordinal", "interval", "ratio"})
SOURCE_COORDINATE_SYSTEMS = {
    "byte_span": "utf8_byte_offsets_half_open",
    "line_span": "physical_line_numbers_inclusive",
    "entity": "entity_identifier",
    "project_record": "project_record_identifier",
}

REQUIRED_NON_INFERENCES = (
    "The report does not estimate or classify source-code authorship.",
    "The report does not determine misconduct, cheating or independent work.",
    "The report does not recommend or trigger disciplinary sanctions.",
    "Code-derived observations do not establish why a code property is present.",
)

FORBIDDEN_IDENTIFIERS = frozenset(
    {
        "ai_probability",
        "authorship_probability",
        "human_likelihood",
        "misconduct_verdict",
        "sanction_trigger",
        "review_trigger",
        "overall_score",
        "ai_generated",
        "hybrid_label",
    }
)

FORBIDDEN_ACTION_PHRASES = (
    "manual review required",
    "sanction recommended",
    "disciplinary action required",
    "determines misconduct",
    "identifies cheating",
    "probability of ai authorship",
)

LEGACY_DISCARDED_FIELDS = frozenset(
    {
        "overall_score",
        "score",
        "verdict",
        "review_trigger",
        "ai_score",
        "ai_probability",
        "authorship_probability",
        "concern_band",
        "risk_band",
    }
)

PROVENANCE_LABEL_VALUES = frozenset(
    {
        "human",
        "ai",
        "ai_generated",
        "ai-generated",
        "machine_generated",
        "machine-generated",
        "llm_generated",
        "llm-generated",
        "hybrid",
        "mixed_authorship",
    }
)

TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "report_kind",
        "software",
        "input",
        "specification_catalogue",
        "policy_catalogue",
        "observations",
        "review_evidence",
        "feedback_actions",
        "non_inferences",
        "legacy_compatibility",
        "deterministic_digest",
    }
)

OBSERVATION_FIELDS = frozenset(
    {
        "observation_id",
        "spec_version",
        "entity",
        "attribute",
        "value",
        "unit",
        "measurement_scale",
        "applicability",
        "scope_qualification",
        "source_evidence",
        "instrumentation",
        "metamorphic_contract",
        "fingerprint",
    }
)

DIMENSION_FIELDS = frozenset(
    {
        "dimension_id",
        "spec_version",
        "status",
        "observation_refs",
        "interpretation",
        "limitations",
    }
)

ACTION_FIELDS = frozenset(
    {
        "action_id",
        "dimension_id",
        "observation_refs",
        "policy_rule_id",
        "review_question",
        "suggested_change",
        "rationale",
        "expected_benefit",
        "trade_offs",
        "source_evidence_refs",
        "applicability",
        "reversible",
    }
)


def canonical_json(value: Any) -> str:
    """Return deterministic UTF-8 JSON text after rejecting non-finite values."""

    def reject_non_finite(node: Any, path: str = "$" ) -> None:
        if isinstance(node, float) and not math.isfinite(node):
            raise ValueError(f"{path} contains a non-finite number")
        if isinstance(node, Mapping):
            for key, child in node.items():
                reject_non_finite(child, f"{path}.{key}")
        elif isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray)):
            for index, child in enumerate(node):
                reject_non_finite(child, f"{path}[{index}]")

    reject_non_finite(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def strict_json_loads(text: str, *, label: str = "JSON") -> dict[str, Any]:
    if not isinstance(text, str):
        raise TypeError(f"{label} must be text")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def finite(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"{label} contains a non-finite number")
        return number

    try:
        result = json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_float=finite,
            parse_constant=finite,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise ValueError(f"{label} root must be an object")
    return result


def _normalise_identifier(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value).strip())
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _is_forbidden_identifier(value: str) -> bool:
    name = _normalise_identifier(value)
    if name in FORBIDDEN_IDENTIFIERS:
        return True
    tokens = set(name.split("_"))
    provenance = bool(tokens & {"ai", "human", "authorship", "author", "creator", "provenance", "origin", "generator"})
    classifier = bool(tokens & {"probability", "likelihood", "confidence", "score", "class", "classification", "label", "verdict"})
    consequential = bool(tokens & {"misconduct", "cheating", "sanction", "disciplinary"})
    decision = bool(tokens & {"probability", "likelihood", "confidence", "score", "class", "classification", "label", "verdict", "trigger", "recommendation", "decision", "required", "flag"})
    independence = {"independent", "work"}.issubset(tokens)
    return (provenance and classifier) or (consequential and decision) or (independence and decision)


def _walk(node: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
    yield path, node
    if isinstance(node, Mapping):
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray)):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


def assert_no_forbidden_identifiers(node: Any) -> None:
    for path, value in _walk(node):
        if not isinstance(value, Mapping):
            continue
        for key in value:
            if _is_forbidden_identifier(str(key)):
                raise ValueError(f"{path} contains prohibited identifier {key!r}")


def assert_no_prohibited_affirmative_claims(node: Any) -> None:
    patterns = (
        re.compile(r"\b(?:detects?|identifies?|classifies?|estimates?)\b.{0,48}\b(?:ai[- ]generated|authorship|source origin)\b", re.I | re.S),
        re.compile(r"\b(?:probability|likelihood|score)\b.{0,32}\b(?:ai[- ]generated|authorship|human[- ]written)\b", re.I | re.S),
        re.compile(r"\b(?:determines?|identifies?|proves?)\b.{0,32}\b(?:misconduct|cheating|independent work)\b", re.I | re.S),
        re.compile(r"\b(?:sanction|disciplinary action)\b.{0,24}\b(?:recommended|required|triggered)\b", re.I | re.S),
        re.compile(r"\bmanual review required\b", re.I | re.S),
        re.compile(r"\b(?:code|source|submission|artefact)\b.{0,40}\b(?:is|was|appears|likely)\b.{0,40}\b(?:ai[- ]generated|human[- ]written)\b", re.I | re.S),
        re.compile(r"\b(?:ai[- ]generated|human[- ]written)\b.{0,40}\b(?:code|source|submission|artefact)\b", re.I | re.S),
    )
    for path, value in _walk(node):
        if not isinstance(value, str):
            continue
        if value in REQUIRED_NON_INFERENCES:
            continue
        for pattern in patterns:
            if pattern.search(value):
                raise ValueError(f"{path} contains a prohibited affirmative claim")


def assert_no_provenance_policy_labels(node: Any) -> None:
    for path, value in _walk(node):
        if isinstance(value, str) and _normalise_identifier(value) in PROVENANCE_LABEL_VALUES:
            raise ValueError(f"{path} contains a provenance label that is not a v3 policy target")
        if isinstance(value, Mapping):
            for key in value:
                key_name = _normalise_identifier(str(key))
                if key_name in {"authorship", "source_origin", "provenance_class", "creator_class"}:
                    raise ValueError(f"{path} contains prohibited policy key {key!r}")


def _validate_sha256(value: Any, label: str) -> str:
    digest = _require_text(value, label)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{label} must be lower-case SHA-256")
    return digest


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _require_exact_fields(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    extras = set(value) - set(allowed)
    if extras:
        raise ValueError(f"{label} contains unsupported fields: {sorted(extras)}")


def _require_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"{label} must be {'text' if allow_empty else 'non-empty text'}")
    return value


def _require_identifier(value: Any, label: str) -> str:
    identifier = _require_text(value, label)
    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", identifier) is None:
        raise ValueError(f"{label} must be a lower-case stable identifier")
    return identifier


def _require_string_list(value: Any, label: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list with at least {minimum} item(s)")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} contains duplicates")
    return value


def _validate_observation(value: Any, index: int) -> tuple[str, set[str]]:
    record = _require_mapping(value, f"observations[{index}]")
    _require_exact_fields(record, OBSERVATION_FIELDS, f"observations[{index}]")
    missing = OBSERVATION_FIELDS - set(record)
    if missing:
        raise ValueError(f"observations[{index}] is missing fields: {sorted(missing)}")
    observation_id = _require_identifier(record["observation_id"], f"observations[{index}].observation_id")
    _require_text(record["spec_version"], f"observations[{index}].spec_version")
    _require_text(record["attribute"], f"observations[{index}].attribute")
    _require_text(record["unit"], f"observations[{index}].unit")
    if record["measurement_scale"] not in MEASUREMENT_SCALES:
        raise ValueError(f"observations[{index}].measurement_scale is unsupported")

    raw_value = record["value"]
    if raw_value is not None and not isinstance(raw_value, (str, bool, int, float)):
        raise ValueError(f"observations[{index}].value must be an atomic JSON scalar")
    if isinstance(raw_value, float) and not math.isfinite(raw_value):
        raise ValueError(f"observations[{index}].value must be finite")

    applicability = _require_mapping(record["applicability"], f"observations[{index}].applicability")
    if set(applicability) != {"status", "reason"}:
        raise ValueError(f"observations[{index}].applicability has an unsupported shape")
    status = applicability["status"]
    if status not in APPLICABILITY_STATES:
        raise ValueError(f"observations[{index}].applicability.status is unsupported")
    reason = _require_text(
        applicability["reason"],
        f"observations[{index}].applicability.reason",
        allow_empty=True,
    )
    if status == "observed":
        if raw_value is None:
            raise ValueError(f"observations[{index}] is observed but has no value")
        if reason:
            raise ValueError(f"observations[{index}] is observed but declares an unavailable reason")
    else:
        if raw_value is not None:
            raise ValueError(f"observations[{index}] is {status} but supplies a value")
        if not reason:
            raise ValueError(f"observations[{index}] is {status} without a reason")

    _require_text(record["scope_qualification"], f"observations[{index}].scope_qualification")
    evidence = record["source_evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(f"observations[{index}].source_evidence must be a non-empty list")
    evidence_ids: set[str] = set()
    for evidence_index, item in enumerate(evidence):
        label = f"observations[{index}].source_evidence[{evidence_index}]"
        source = _require_mapping(item, label)
        expected = {"evidence_id", "source_id", "start", "end", "evidence_kind", "coordinate_system"}
        if set(source) != expected:
            raise ValueError(f"{label} has an unsupported shape")
        evidence_id = _require_identifier(source["evidence_id"], f"{label}.evidence_id")
        if evidence_id in evidence_ids:
            raise ValueError(f"{label}.evidence_id is duplicated within the observation")
        evidence_ids.add(evidence_id)
        _require_text(source["source_id"], f"{label}.source_id")
        kind = source["evidence_kind"]
        if kind not in SOURCE_COORDINATE_SYSTEMS:
            raise ValueError(f"{label}.evidence_kind is unsupported")
        expected_coordinate = SOURCE_COORDINATE_SYSTEMS[kind]
        if source["coordinate_system"] != expected_coordinate:
            raise ValueError(
                f"{label}.coordinate_system must be {expected_coordinate!r} for {kind!r}"
            )
        minimum = 1 if kind == "line_span" else 0
        if not isinstance(source["start"], int) or isinstance(source["start"], bool) or source["start"] < minimum:
            raise ValueError(f"{label}.start violates the declared coordinate system")
        if not isinstance(source["end"], int) or isinstance(source["end"], bool) or source["end"] < source["start"]:
            raise ValueError(f"{label}.end must not precede start")
    entity = _require_mapping(record["entity"], f"observations[{index}].entity")
    if set(entity) != {"kind", "identity"} or entity["kind"] not in {"file", "function", "project", "resource", "documentation"}:
        raise ValueError(f"observations[{index}].entity has an unsupported shape")
    _require_text(entity["identity"], f"observations[{index}].entity.identity")
    instrumentation = _require_mapping(record["instrumentation"], f"observations[{index}].instrumentation")
    if set(instrumentation) != {"adapter", "runtime"}:
        raise ValueError(f"observations[{index}].instrumentation has an unsupported shape")
    _require_text(instrumentation["adapter"], f"observations[{index}].instrumentation.adapter")
    _require_text(instrumentation["runtime"], f"observations[{index}].instrumentation.runtime")
    _require_text(record["metamorphic_contract"], f"observations[{index}].metamorphic_contract")
    _validate_sha256(record["fingerprint"], f"observations[{index}].fingerprint")
    return observation_id, evidence_ids


def _validate_dimension(value: Any, index: int, observation_ids: set[str]) -> tuple[str, set[str]]:
    record = _require_mapping(value, f"review_evidence.dimensions[{index}]")
    _require_exact_fields(record, DIMENSION_FIELDS, f"review_evidence.dimensions[{index}]")
    missing = DIMENSION_FIELDS - set(record)
    if missing:
        raise ValueError(f"review_evidence.dimensions[{index}] is missing fields: {sorted(missing)}")
    dimension_id = _require_identifier(record["dimension_id"], f"review_evidence.dimensions[{index}].dimension_id")
    _require_text(record["spec_version"], f"review_evidence.dimensions[{index}].spec_version")
    status = record["status"]
    if status not in {"evidence_available", "insufficient_evidence", "not_applicable", "unavailable"}:
        raise ValueError(f"review_evidence.dimensions[{index}].status is unsupported")
    refs = _require_string_list(record["observation_refs"], f"review_evidence.dimensions[{index}].observation_refs")
    unknown = set(refs) - observation_ids
    if unknown:
        raise ValueError(f"review_evidence.dimensions[{index}] references unknown observations: {sorted(unknown)}")
    if status == "evidence_available" and not refs:
        raise ValueError(f"review_evidence.dimensions[{index}] has evidence_available without references")
    if status == "not_applicable" and refs:
        raise ValueError(f"review_evidence.dimensions[{index}] is not_applicable but references observations")
    _require_text(record["interpretation"], f"review_evidence.dimensions[{index}].interpretation")
    _require_string_list(record["limitations"], f"review_evidence.dimensions[{index}].limitations")
    return dimension_id, set(refs)


def validate_feedback_action(
    value: Any,
    *,
    observation_ids: set[str] | None = None,
    dimension_observation_refs: Mapping[str, set[str]] | None = None,
    observation_evidence_refs: Mapping[str, set[str]] | None = None,
    policy_rule_ids: set[str] | None = None,
) -> None:
    record = _require_mapping(value, "feedback action")
    _require_exact_fields(record, ACTION_FIELDS, "feedback action")
    missing = ACTION_FIELDS - set(record)
    if missing:
        raise ValueError(f"feedback action is missing fields: {sorted(missing)}")
    _require_identifier(record["action_id"], "feedback action.action_id")
    dimension_id = _require_identifier(record["dimension_id"], "feedback action.dimension_id")
    refs = _require_string_list(record["observation_refs"], "feedback action.observation_refs", minimum=1)
    if observation_ids is not None and set(refs) - observation_ids:
        raise ValueError("feedback action references an unknown observation")
    if dimension_observation_refs is not None:
        if dimension_id not in dimension_observation_refs:
            raise ValueError("feedback action references an unknown dimension")
        unrelated = set(refs) - dimension_observation_refs[dimension_id]
        if unrelated:
            raise ValueError("feedback action references observations outside its declared dimension")
    policy_rule_id = _require_identifier(record["policy_rule_id"], "feedback action.policy_rule_id")
    if policy_rule_ids is not None and policy_rule_id not in policy_rule_ids:
        raise ValueError("feedback action references an unknown policy rule")
    evidence_refs = _require_string_list(
        record["source_evidence_refs"], "feedback action.source_evidence_refs", minimum=1
    )
    if observation_evidence_refs is not None:
        allowed_evidence: set[str] = set()
        for observation_id in refs:
            allowed_evidence.update(observation_evidence_refs.get(observation_id, set()))
        unknown_evidence = set(evidence_refs) - allowed_evidence
        if unknown_evidence:
            raise ValueError("feedback action references source evidence not owned by its observations")
    question = _require_text(record["review_question"], "feedback action.review_question")
    if not question.rstrip().endswith("?"):
        raise ValueError("feedback action.review_question must be framed as a question")
    for key in ("suggested_change", "rationale", "expected_benefit"):
        _require_text(record[key], f"feedback action.{key}")
    _require_string_list(record["trade_offs"], "feedback action.trade_offs")
    if record["applicability"] not in {"supported", "qualified", "insufficient"}:
        raise ValueError("feedback action.applicability is unsupported")
    if record["reversible"] is not True:
        raise ValueError("feedback action must be explicitly reversible")
    rendered = canonical_json(record).lower()
    for phrase in FORBIDDEN_ACTION_PHRASES:
        if phrase in rendered:
            raise ValueError(f"feedback action contains prohibited consequential phrase: {phrase}")


def validate_review_report(report: Any, *, check_digest: bool = True) -> None:
    root = _require_mapping(report, "report")
    # Semantic prohibitions are checked before ordinary shape errors so a
    # prohibited field cannot hide behind the weaker "unknown field" message.
    assert_no_forbidden_identifiers(root)
    assert_no_prohibited_affirmative_claims(root)
    _require_exact_fields(root, TOP_LEVEL_FIELDS, "report")
    required = TOP_LEVEL_FIELDS - {"legacy_compatibility"}
    missing = required - set(root)
    if missing:
        raise ValueError(f"report is missing fields: {sorted(missing)}")
    if root["schema"] != REPORT_SCHEMA:
        raise ValueError("report.schema is unsupported")
    if root["report_kind"] not in {"file", "project"}:
        raise ValueError("report.report_kind is unsupported")
    software = _require_mapping(root["software"], "report.software")
    if set(software) != {"name", "version", "contract_version"}:
        raise ValueError("report.software has an unsupported shape")
    if software.get("name") != "CodeProbe" or software.get("contract_version") != CONTRACT_VERSION:
        raise ValueError("report.software identity is incompatible with the S01 contract")
    _require_text(software.get("version"), "report.software.version")
    input_record = _require_mapping(root["input"], "report.input")
    if set(input_record) != {"kind", "fingerprint", "provenance"} or input_record.get("kind") not in {"file", "project"}:
        raise ValueError("report.input has an unsupported shape")
    _validate_sha256(input_record.get("fingerprint"), "report.input.fingerprint")
    _require_text(input_record.get("provenance"), "report.input.provenance")
    catalogue = _require_mapping(root["specification_catalogue"], "report.specification_catalogue")
    if set(catalogue) != {"schema", "version", "digest"} or catalogue.get("schema") != "codeprobe-observation-catalogue/v1":
        raise ValueError("report.specification_catalogue has an unsupported shape")
    _require_text(catalogue.get("version"), "report.specification_catalogue.version")
    _validate_sha256(catalogue.get("digest"), "report.specification_catalogue.digest")
    policy_catalogue = _require_mapping(root["policy_catalogue"], "report.policy_catalogue")
    if set(policy_catalogue) != {"schema", "version", "digest", "rule_ids"} or policy_catalogue.get("schema") != POLICY_CATALOGUE_SCHEMA:
        raise ValueError("report.policy_catalogue has an unsupported shape")
    _require_text(policy_catalogue.get("version"), "report.policy_catalogue.version")
    _validate_sha256(policy_catalogue.get("digest"), "report.policy_catalogue.digest")
    policy_rule_ids = {
        _require_identifier(value, "report.policy_catalogue.rule_ids[]")
        for value in _require_string_list(policy_catalogue.get("rule_ids"), "report.policy_catalogue.rule_ids", minimum=1)
    }

    observations = root["observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("report.observations must be a non-empty list")
    observation_ids: set[str] = set()
    observation_evidence_refs: dict[str, set[str]] = {}
    all_evidence_ids: set[str] = set()
    for index, item in enumerate(observations):
        observation_id, evidence_ids = _validate_observation(item, index)
        if observation_id in observation_ids:
            raise ValueError("report.observations contains duplicate identifiers")
        duplicate_evidence = evidence_ids & all_evidence_ids
        if duplicate_evidence:
            raise ValueError(f"report.observations reuses source-evidence identifiers: {sorted(duplicate_evidence)}")
        observation_ids.add(observation_id)
        all_evidence_ids.update(evidence_ids)
        observation_evidence_refs[observation_id] = evidence_ids

    evidence = _require_mapping(root["review_evidence"], "report.review_evidence")
    if set(evidence) != {"profile_schema", "dimensions", "composition_rule"}:
        raise ValueError("report.review_evidence has an unsupported shape")
    if evidence["profile_schema"] != EVIDENCE_PROFILE_SCHEMA:
        raise ValueError("report.review_evidence.profile_schema is unsupported")
    if evidence["composition_rule"] != "vector_only_non_compensatory":
        raise ValueError("report.review_evidence.composition_rule must be vector-only and non-compensatory")
    dimensions = evidence["dimensions"]
    if not isinstance(dimensions, list) or not dimensions:
        raise ValueError("report.review_evidence.dimensions must be a non-empty list")
    dimension_observation_refs: dict[str, set[str]] = {}
    for index, item in enumerate(dimensions):
        dimension_id, refs = _validate_dimension(item, index, observation_ids)
        if dimension_id in dimension_observation_refs:
            raise ValueError("report.review_evidence.dimensions contains duplicate identifiers")
        dimension_observation_refs[dimension_id] = refs

    actions = root["feedback_actions"]
    if not isinstance(actions, list):
        raise ValueError("report.feedback_actions must be a list")
    action_ids: set[str] = set()
    for action in actions:
        validate_feedback_action(
            action,
            observation_ids=observation_ids,
            dimension_observation_refs=dimension_observation_refs,
            observation_evidence_refs=observation_evidence_refs,
            policy_rule_ids=policy_rule_ids,
        )
        action_id = action["action_id"]
        if action_id in action_ids:
            raise ValueError("report.feedback_actions contains duplicate identifiers")
        action_ids.add(action_id)
    non_inferences = _require_string_list(root["non_inferences"], "report.non_inferences")
    missing_non_inferences = set(REQUIRED_NON_INFERENCES) - set(non_inferences)
    if missing_non_inferences:
        raise ValueError(f"report is missing required non-inferences: {sorted(missing_non_inferences)}")
    legacy = root.get("legacy_compatibility")
    if legacy is not None:
        legacy_record = _require_mapping(legacy, "report.legacy_compatibility")
        expected_legacy = {"source_schema", "source_digest", "source_digest_scope", "non_equivalent", "discarded_fields"}
        if set(legacy_record) != expected_legacy:
            raise ValueError("report.legacy_compatibility has an unsupported shape")
        if legacy_record.get("non_equivalent") is not True:
            raise ValueError("report.legacy_compatibility must declare non-equivalence")
        if legacy_record.get("source_digest_scope") != "canonical_json":
            raise ValueError("report.legacy_compatibility source-digest scope is unsupported")
        _require_text(legacy_record.get("source_schema"), "report.legacy_compatibility.source_schema")
        _validate_sha256(legacy_record.get("source_digest"), "report.legacy_compatibility.source_digest")
        _require_string_list(legacy_record.get("discarded_fields"), "report.legacy_compatibility.discarded_fields")
    digest = _validate_sha256(root["deterministic_digest"], "report.deterministic_digest")
    if check_digest:
        deterministic = dict(root)
        deterministic["deterministic_digest"] = "0" * 64
        expected = digest_json(deterministic)
        if digest != expected:
            raise ValueError("report.deterministic_digest does not match canonical report content")


def finalise_report(report: Mapping[str, Any]) -> dict[str, Any]:
    candidate = json.loads(canonical_json(report))
    candidate["deterministic_digest"] = "0" * 64
    candidate["deterministic_digest"] = digest_json(candidate)
    validate_review_report(candidate)
    return candidate


def _legacy_source_schema(report: Mapping[str, Any]) -> str:
    candidates = (
        report.get("schema_version"),
        report.get("report_schema_version"),
        report.get("project_schema_version"),
        report.get("schema"),
        report.get("version"),
    )
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unversioned-legacy-report"


def _legacy_kind(report: Mapping[str, Any]) -> str:
    for key in ("report_kind", "kind", "analysis_kind"):
        value = report.get(key)
        if value in {"file", "project"}:
            return str(value)
    if "files" in report or "project" in report:
        return "project"
    if "metrics" in report or "language" in report:
        return "file"
    return "unknown"


def _collect_legacy_values(
    node: Any,
    path: str = "$",
    *,
    maximum: int = 10_000,
) -> tuple[list[dict[str, Any]], set[str]]:
    preserved: list[dict[str, Any]] = []
    discarded: set[str] = set()

    def visit(value: Any, current: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                child_path = f"{current}.{key}"
                if _normalise_identifier(str(key)) in LEGACY_DISCARDED_FIELDS or _is_forbidden_identifier(str(key)):
                    discarded.add(child_path)
                    continue
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{current}[{index}]")
        elif value is None or isinstance(value, (bool, int, float, str)):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(f"legacy report contains non-finite value at {current}")
            if isinstance(value, str) and _normalise_identifier(value) in PROVENANCE_LABEL_VALUES:
                discarded.add(current)
                return
            if len(preserved) >= maximum:
                raise ValueError(f"legacy report exceeds the {maximum}-value migration bound")
            preserved.append(
                {
                    "legacy_path": current,
                    "value": value,
                    "interpretation_status": "archival_unmapped_value",
                }
            )

    visit(node, path)
    return preserved, discarded


def migrate_legacy_report(report: Any, *, policy_profile: Any | None = None) -> dict[str, Any]:
    root = _require_mapping(report, "legacy report")
    if policy_profile is not None:
        _require_mapping(policy_profile, "legacy policy profile")
        assert_no_provenance_policy_labels(policy_profile)
    source_schema = _legacy_source_schema(root)
    source_kind = _legacy_kind(root)
    if source_schema == "unversioned-legacy-report" and source_kind == "unknown":
        raise ValueError("legacy report is too ambiguous for a safe migration envelope")
    preserved, discarded = _collect_legacy_values(root)
    envelope = {
        "schema": LEGACY_ENVELOPE_SCHEMA,
        "source_schema": source_schema,
        "source_kind": source_kind,
        "source_digest": digest_json(root),
        "non_equivalent": True,
        "source_digest_scope": "canonical_json",
        "preserved_values": preserved,
        "discarded_semantics": sorted(discarded),
        "warnings": [
            "This envelope is read-only and is not a complete v3 review report.",
            "Legacy scalar, band, threshold and provenance-like semantics have no v3 equivalent.",
            "Preserved values require metric-level specification before they can support a v3 interpretation."
        ],
    }
    return envelope


def read_strict_json(path: Path, *, label: str) -> dict[str, Any]:
    return strict_json_loads(path.read_text(encoding="utf-8"), label=label)
