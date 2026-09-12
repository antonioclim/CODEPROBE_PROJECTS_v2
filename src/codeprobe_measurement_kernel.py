
"""CodeProbe S02 reference measurement kernel.

This module emits atomic, evidence-bounded observations. It does not emit a
global score, provenance probability, misconduct verdict or sanction trigger.
The implementation is a conformance reference for the S02 specifications, not
evidence that the candidate review dimensions are empirically valid.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import io
import re
import stat
import tokenize
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

KERNEL_SCHEMA = "codeprobe-measurement-kernel-result/v1"
KERNEL_VERSION = "1.1.0"
CATALOGUE_SCHEMA = "codeprobe-observation-catalogue/v1"
DEFAULT_MAX_BYTES = 1_000_000
APPLICABILITY_STATES = frozenset({"observed", "not_applicable", "insufficient_evidence", "unavailable"})
FORBIDDEN_OUTPUT_KEYS = frozenset({
    "overall_score", "review_trigger", "ai_probability", "authorship_probability",
    "human_likelihood", "misconduct_verdict", "sanction_trigger",
})
REQUIRED_NON_INFERENCES = (
    "The report does not estimate or classify who or what authored the source.",
    "The report does not determine misconduct, cheating or independent work.",
    "The report does not recommend or trigger a sanction.",
    "A code-derived observation does not establish the cause of the observed property.",
)


# S03 enforcement of the unchanged v1.1.0 atomic specification codomains.
_VALUE_CONTRACTS = {
    'source.byte_count': ('integer', 'byte', 0, None, ()),
    'source.normalized_codepoint_count': ('integer', 'codepoint', 0, None, ()),
    'source.physical_line_count': ('integer', 'line', 0, None, ()),
    'source.nonblank_line_count': ('integer', 'line', 0, None, ()),
    'source.blank_line_count': ('integer', 'line', 0, None, ()),
    'source.max_line_length_codepoints': ('integer', 'codepoint_per_line', 0, None, ()),
    'source.mean_line_length_codepoints': ('number', 'codepoint_per_line', 0, None, ()),
    'source.population_sd_line_length_codepoints': ('number', 'codepoint_per_line', 0, None, ()),
    'source.line_length_cv': ('number', 'dimensionless', 0, None, ()),
    'source.trailing_whitespace_line_count': ('integer', 'line', 0, None, ()),
    'source.mixed_indentation_line_count': ('integer', 'line', 0, None, ()),
    'source.max_blank_line_run_length': ('integer', 'line', 0, None, ()),
    'python.parse_status': ('string', 'category', None, None, ('parsed', 'syntax_error')),
    'python.function_definition_count': ('integer', 'definition', 0, None, ()),
    'python.async_function_definition_count': ('integer', 'definition', 0, None, ()),
    'python.class_definition_count': ('integer', 'definition', 0, None, ()),
    'python.import_statement_count': ('integer', 'statement', 0, None, ()),
    'python.imported_binding_count': ('integer', 'binding', 0, None, ()),
    'python.wildcard_import_count': ('integer', 'statement', 0, None, ()),
    'python.comment_token_count': ('integer', 'token', 0, None, ()),
    'python.comment_physical_line_count': ('integer', 'line', 0, None, ()),
    'python.comment_line_proportion': ('number', 'proportion', 0, 1, ()),
    'python.docstring_eligible_definition_count': ('integer', 'definition', 0, None, ()),
    'python.docstring_present_definition_count': ('integer', 'definition', 0, None, ()),
    'python.docstring_coverage_proportion': ('number', 'proportion', 0, 1, ()),
    'python.annotation_eligible_slot_count': ('integer', 'slot', 0, None, ()),
    'python.annotation_present_slot_count': ('integer', 'slot', 0, None, ()),
    'python.annotation_coverage_proportion': ('number', 'proportion', 0, 1, ()),
    'python.numeric_literal_count': ('integer', 'literal', 0, None, ()),
    'python.exception_handler_count': ('integer', 'handler', 0, None, ()),
    'python.raise_statement_count': ('integer', 'statement', 0, None, ()),
    'python.callable.physical_span_lines': ('integer', 'line', 1, None, ()),
    'python.callable.decision_point_count': ('integer', 'decision_point', 0, None, ()),
    'python.callable.mccabe_complexity': ('integer', 'complexity_unit', 1, None, ()),
    'python.callable.max_control_nesting_depth': ('integer', 'level', 0, None, ()),
    'markdown.parse_status': ('string', 'category', None, None, ('complete', 'unclosed_fence')),
    'markdown.atx_heading_count': ('integer', 'heading', 0, None, ()),
    'markdown.setext_heading_count': ('integer', 'heading', 0, None, ()),
    'markdown.fenced_code_block_count': ('integer', 'block', 0, None, ()),
    'markdown.heading_level_jump_count': ('integer', 'transition', 0, None, ()),
}


class MeasurementError(ValueError):
    """Fail-closed measurement or intake error with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class IntakeRecord:
    path: str
    raw_bytes: bytes
    text: str
    raw_sha256: str
    normalised_sha256: str
    encoding: str
    normalisation: str
    physical_lines: Tuple[str, ...]


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _physical_lines(text: str) -> Tuple[str, ...]:
    if text == "":
        return ()
    records = text.split("\n")
    if text.endswith("\n"):
        records.pop()
    return tuple(records)


def intake_from_bytes(data: bytes, *, path: str = "<memory>", max_bytes: int = DEFAULT_MAX_BYTES) -> IntakeRecord:
    if isinstance(data, bytearray):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if len(data) > max_bytes:
        raise MeasurementError("ME-002", f"source exceeds the {max_bytes}-byte intake limit")
    if b"\0" in data:
        raise MeasurementError("ME-004", "source text containing NUL bytes is not accepted")
    encoding = "utf-8"
    payload = data
    if payload.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
        payload = payload[3:]
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MeasurementError("ME-003", "source is not strict UTF-8") from exc
    text = _normalise_newlines(decoded)
    normalised = text.encode("utf-8")
    return IntakeRecord(
        path=str(path),
        raw_bytes=data,
        text=text,
        raw_sha256=sha256_hex(data),
        normalised_sha256=sha256_hex(normalised),
        encoding=encoding,
        normalisation="utf8_bom_strip+crlf_cr_to_lf",
        physical_lines=_physical_lines(text),
    )


def read_bounded_source(path: os.PathLike[str] | str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> IntakeRecord:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    target = Path(path)
    try:
        before = target.lstat()
    except OSError as exc:
        raise MeasurementError("ME-001", f"source path cannot be inspected: {target}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise MeasurementError("ME-001", "source path must be a non-symlink regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise MeasurementError("ME-001", "source path could not be opened under the regular-file contract") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise MeasurementError("ME-001", "opened source is not a regular file")
        if hasattr(before, "st_ino") and (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise MeasurementError("ME-005", "source identity changed between inspection and open")
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise MeasurementError("ME-002", f"source exceeds the {max_bytes}-byte intake limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if any(getattr(opened, field, None) != getattr(after, field, None) for field in identity_fields):
        raise MeasurementError("ME-005", "source metadata changed while bytes were read")
    data = b"".join(chunks)
    if len(data) != opened.st_size:
        raise MeasurementError("ME-005", "source size changed or did not match the bytes read")
    return intake_from_bytes(data, path=str(target), max_bytes=max_bytes)


def _whole_evidence(intake: IntakeRecord) -> Dict[str, Any]:
    end_line = max(1, len(intake.physical_lines))
    evidence_id = f"evidence:{intake.normalised_sha256}:whole_artifact:L1-L{end_line}:C0-C0"
    return {
        "evidence_id": evidence_id,
        "path": intake.path,
        "normalised_sha256": intake.normalised_sha256,
        "start_line": 1,
        "end_line": end_line,
        "start_column": 0,
        "end_column": 0,
        "scope": "whole_artifact",
    }


def _span_evidence(intake: IntakeRecord, start_line: int, end_line: int, *, scope: str) -> Dict[str, Any]:
    if start_line < 1 or end_line < start_line:
        raise ValueError("invalid source span")
    evidence_id = f"evidence:{intake.normalised_sha256}:{scope}:L{start_line}-L{end_line}:C0-C0"
    return {
        "evidence_id": evidence_id,
        "path": intake.path,
        "normalised_sha256": intake.normalised_sha256,
        "start_line": start_line,
        "end_line": end_line,
        "start_column": 0,
        "end_column": 0,
        "scope": scope,
    }


def _record_id(specification_id: str, entity_id: str, evidence_ids: Sequence[str]) -> str:
    seed = canonical_json({
        "specification_id": specification_id,
        "entity_id": entity_id,
        "source_evidence_ids": list(evidence_ids),
    }).encode("utf-8")
    return "observation:" + hashlib.sha256(seed).hexdigest()


def observation(
    observation_id: str,
    *,
    entity_id: str,
    entity_kind: str,
    path: str,
    value: Any,
    measurement_scale: str,
    unit: str,
    state: str = "observed",
    reason_code: str = "",
    reason: str = "",
    evidence_ids: Sequence[str],
    parser: str,
    limitations: Sequence[str] = (),
) -> Dict[str, Any]:
    if state not in APPLICABILITY_STATES:
        raise ValueError(f"unknown applicability state: {state}")
    if state == "observed" and value is None:
        raise ValueError("observed values cannot be null")
    if state != "observed" and value is not None:
        raise ValueError("non-observed values must be null")
    if isinstance(value, (dict, list, tuple, set)):
        raise ValueError("atomic observation values must be JSON scalars")
    specification_id = f"codeprobe-observation/{observation_id}/1.1.0"
    record = {
        "record_id": _record_id(specification_id, entity_id, evidence_ids),
        "specification_id": specification_id,
        "observation_id": observation_id,
        "entity": {
            "entity_id": entity_id,
            "entity_kind": entity_kind,
            "path": path,
        },
        "applicability": {
            "state": state,
            "reason_code": reason_code,
            "reason": reason,
        },
        "value": value,
        "measurement_scale": measurement_scale,
        "unit": unit,
        "source_evidence_ids": list(evidence_ids),
        "instrumentation": {
            "component": "codeprobe_measurement_kernel",
            "algorithm_version": KERNEL_VERSION,
            "parser": parser,
        },
        "limitations": list(limitations),
    }
    validate_observation_record(record)
    return record


def _normalise_identifier(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value).strip())
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _is_forbidden_identifier(value: str) -> bool:
    name = _normalise_identifier(value)
    if name in FORBIDDEN_OUTPUT_KEYS:
        return True
    tokens = set(name.split("_"))
    provenance = bool(tokens & {"ai", "human", "authorship", "author", "creator", "provenance", "origin", "generator"})
    classifier = bool(tokens & {"probability", "likelihood", "confidence", "score", "class", "classification", "label", "verdict"})
    consequential = bool(tokens & {"misconduct", "cheating", "sanction", "disciplinary"})
    decision = bool(tokens & {"probability", "likelihood", "confidence", "score", "class", "classification", "label", "verdict", "trigger", "recommendation", "decision", "required", "flag"})
    return (provenance and classifier) or (consequential and decision)


def validate_observation_record(record: Mapping[str, Any]) -> None:
    required = {
        "record_id", "specification_id", "observation_id", "entity",
        "applicability", "value", "measurement_scale", "unit",
        "source_evidence_ids", "instrumentation", "limitations",
    }
    if set(record) != required:
        raise ValueError(f"observation fields differ from contract: {sorted(set(record) ^ required)}")
    observation_id = record["observation_id"]
    if not isinstance(observation_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", observation_id) is None:
        raise ValueError("invalid observation identifier")
    expected_specification = f"codeprobe-observation/{observation_id}/{KERNEL_VERSION}"
    if record["specification_id"] != expected_specification:
        raise ValueError("observation specification identity mismatch")
    if not isinstance(record["record_id"], str) or re.fullmatch(r"observation:[0-9a-f]{64}", record["record_id"]) is None:
        raise ValueError("invalid observation record identifier")

    entity = record["entity"]
    if not isinstance(entity, Mapping) or set(entity) != {"entity_id", "entity_kind", "path"}:
        raise ValueError("invalid observation entity")
    if not all(isinstance(entity[key], str) and entity[key] for key in ("entity_id", "entity_kind")) or not isinstance(entity["path"], str):
        raise ValueError("invalid observation entity values")
    if entity["entity_kind"] not in {"source_artifact", "python_module", "python_callable", "markdown_document"}:
        raise ValueError("unsupported observation entity kind")

    expected_kind = (
        "python_callable" if observation_id.startswith("python.callable.") else
        "python_module" if observation_id.startswith("python.") else
        "markdown_document" if observation_id.startswith("markdown.") else "source_artifact"
    )
    if entity["entity_kind"] != expected_kind:
        raise ValueError("observation entity kind differs from its specification")
    if expected_kind != "python_callable" and entity["entity_id"] != ("source" if expected_kind == "source_artifact" else expected_kind):
        raise ValueError("singleton observation entity identity differs from its specification")

    applicability = record["applicability"]
    if not isinstance(applicability, Mapping) or set(applicability) != {"state", "reason_code", "reason"}:
        raise ValueError("invalid applicability object")
    state = applicability.get("state")
    if state not in APPLICABILITY_STATES:
        raise ValueError("invalid applicability state")
    if (state == "observed") != (record["value"] is not None):
        raise ValueError("applicability/value mismatch")
    if state == "observed":
        if applicability["reason_code"] or applicability["reason"]:
            raise ValueError("observed values cannot carry an unavailability reason")
    elif not isinstance(applicability["reason_code"], str) or not applicability["reason_code"].strip() or not isinstance(applicability["reason"], str) or not applicability["reason"].strip():
        raise ValueError("non-observed values require a reason code and explanation")

    value = record["value"]
    if value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("observation value is not an atomic JSON scalar")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("observation value must be finite")
    if observation_id not in _VALUE_CONTRACTS:
        raise ValueError("observation identifier has no declared value contract")
    domain, expected_unit, minimum, maximum, categories = _VALUE_CONTRACTS[observation_id]
    if record["unit"] != expected_unit or record["measurement_scale"] != ("nominal" if domain == "string" else "ratio"):
        raise ValueError("observation unit or scale differs from its specification")
    if value is not None:
        if domain == "string":
            if type(value) is not str or value not in categories:
                raise ValueError("observation category lies outside its codomain")
        else:
            if type(value) not in ((int,) if domain == "integer" else (int, float)):
                raise ValueError("observation numeric type differs from its codomain")
            if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
                raise ValueError("observation value lies outside its codomain")
    if record["measurement_scale"] not in {"nominal", "ordinal", "interval", "ratio"}:
        raise ValueError("invalid measurement scale")
    if not isinstance(record["unit"], str) or not record["unit"].strip():
        raise ValueError("observation unit is required")

    evidence_ids = record["source_evidence_ids"]
    if not isinstance(evidence_ids, list) or not evidence_ids or len(evidence_ids) != len(set(evidence_ids)) or not all(isinstance(item, str) and item for item in evidence_ids):
        raise ValueError("unique source evidence identifiers are required")
    if record["record_id"] != _record_id(record["specification_id"], entity["entity_id"], evidence_ids):
        raise ValueError("observation record identity does not match its defining fields")
    instrumentation = record["instrumentation"]
    if not isinstance(instrumentation, Mapping) or set(instrumentation) != {"component", "algorithm_version", "parser"}:
        raise ValueError("invalid instrumentation object")
    if instrumentation["component"] != "codeprobe_measurement_kernel" or instrumentation["algorithm_version"] != KERNEL_VERSION or not isinstance(instrumentation["parser"], str) or not instrumentation["parser"].strip():
        raise ValueError("instrumentation identity mismatch")
    if not isinstance(record["limitations"], list) or not all(isinstance(item, str) and item.strip() for item in record["limitations"]):
        raise ValueError("limitations must be non-empty strings")
    if any(_is_forbidden_identifier(key) for key in _recursive_keys(record)):
        raise ValueError("forbidden identifier in observation output")


def _recursive_keys(value: Any) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield str(key)
            yield from _recursive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _recursive_keys(nested)


def _rounded(value: float) -> float:
    rendered = round(float(value), 12)
    return 0.0 if rendered == -0.0 else rendered


def _generic_observations(intake: IntakeRecord, whole_id: str) -> List[Dict[str, Any]]:
    lines = intake.physical_lines
    lengths = [len(line) for line in lines]
    nonblank = sum(bool(line.strip()) for line in lines)
    blank = len(lines) - nonblank
    trailing = sum(bool(re.search(r"[ \t]+$", line)) for line in lines)
    mixed = 0
    max_blank_run = 0
    current_blank_run = 0
    for line in lines:
        if line.strip():
            current_blank_run = 0
            prefix_length = len(line) - len(line.lstrip(" \t"))
            prefix = line[:prefix_length]
            if " " in prefix and "\t" in prefix:
                mixed += 1
        else:
            current_blank_run += 1
            max_blank_run = max(max_blank_run, current_blank_run)
    base = {
        "entity_id": "source",
        "entity_kind": "source_artifact",
        "path": intake.path,
        "evidence_ids": [whole_id],
        "parser": "bounded_utf8_line_scanner/1.1.0",
    }
    records = [
        observation("source.byte_count", value=len(intake.raw_bytes), measurement_scale="ratio", unit="byte", **base),
        observation("source.normalized_codepoint_count", value=len(intake.text), measurement_scale="ratio", unit="codepoint", **base),
        observation("source.physical_line_count", value=len(lines), measurement_scale="ratio", unit="line", **base),
        observation("source.nonblank_line_count", value=nonblank, measurement_scale="ratio", unit="line", **base),
        observation("source.blank_line_count", value=blank, measurement_scale="ratio", unit="line", **base),
        observation("source.trailing_whitespace_line_count", value=trailing, measurement_scale="ratio", unit="line", **base),
        observation("source.mixed_indentation_line_count", value=mixed, measurement_scale="ratio", unit="line", **base),
        observation("source.max_blank_line_run_length", value=max_blank_run, measurement_scale="ratio", unit="line", **base),
    ]
    if lengths:
        mean = math.fsum(lengths) / len(lengths)
        records.extend([
            observation("source.max_line_length_codepoints", value=max(lengths), measurement_scale="ratio", unit="codepoint_per_line", **base),
            observation("source.mean_line_length_codepoints", value=_rounded(mean), measurement_scale="ratio", unit="codepoint_per_line", **base),
        ])
    else:
        for oid, unit in (
            ("source.max_line_length_codepoints", "codepoint_per_line"),
            ("source.mean_line_length_codepoints", "codepoint_per_line"),
        ):
            records.append(observation(
                oid, value=None, measurement_scale="ratio", unit=unit,
                state="insufficient_evidence", reason_code="ME-012",
                reason="The source has no physical lines.", **base
            ))
    if len(lengths) >= 2:
        mean = math.fsum(lengths) / len(lengths)
        variance = math.fsum((length - mean) ** 2 for length in lengths) / len(lengths)
        sd = math.sqrt(variance)
        records.append(observation("source.population_sd_line_length_codepoints",
                                   value=_rounded(sd), measurement_scale="ratio",
                                   unit="codepoint_per_line", **base))
        if mean == 0:
            records.append(observation(
                "source.line_length_cv", value=None, measurement_scale="ratio", unit="dimensionless",
                state="insufficient_evidence", reason_code="ME-012",
                reason="The line-length mean is zero.", **base
            ))
        else:
            records.append(observation("source.line_length_cv", value=_rounded(sd / mean),
                                       measurement_scale="ratio", unit="dimensionless", **base))
    else:
        for oid, unit in (
            ("source.population_sd_line_length_codepoints", "codepoint_per_line"),
            ("source.line_length_cv", "dimensionless"),
        ):
            records.append(observation(
                oid, value=None, measurement_scale="ratio", unit=unit,
                state="insufficient_evidence", reason_code="ME-012",
                reason="At least two physical lines are required.", **base
            ))
    return records


def _unavailable_python_records(intake: IntakeRecord, whole_id: str, reason: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    module_specs = (
        ("python.function_definition_count", "definition"),
        ("python.async_function_definition_count", "definition"),
        ("python.class_definition_count", "definition"),
        ("python.import_statement_count", "statement"),
        ("python.imported_binding_count", "binding"),
        ("python.wildcard_import_count", "statement"),
        ("python.numeric_literal_count", "literal"),
        ("python.exception_handler_count", "handler"),
        ("python.raise_statement_count", "statement"),
        ("python.docstring_eligible_definition_count", "definition"),
        ("python.docstring_present_definition_count", "definition"),
        ("python.docstring_coverage_proportion", "proportion"),
        ("python.annotation_eligible_slot_count", "slot"),
        ("python.annotation_present_slot_count", "slot"),
        ("python.annotation_coverage_proportion", "proportion"),
    )
    for oid, unit in module_specs:
        records.append(observation(
            oid, entity_id="python_module", entity_kind="python_module", path=intake.path,
            value=None, measurement_scale="ratio", unit=unit, state="unavailable",
            reason_code="ME-006", reason=reason, evidence_ids=[whole_id],
            parser="CPython_ast/declared_runtime",
            limitations=("Dependent on a successful CPython AST parse.",)
        ))
    return records


def _not_applicable_python_records(intake: IntakeRecord, whole_id: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    module_specs = (
        ("python.parse_status", "category", "nominal"),
        ("python.function_definition_count", "definition", "ratio"),
        ("python.async_function_definition_count", "definition", "ratio"),
        ("python.class_definition_count", "definition", "ratio"),
        ("python.import_statement_count", "statement", "ratio"),
        ("python.imported_binding_count", "binding", "ratio"),
        ("python.wildcard_import_count", "statement", "ratio"),
        ("python.comment_token_count", "token", "ratio"),
        ("python.comment_physical_line_count", "line", "ratio"),
        ("python.comment_line_proportion", "proportion", "ratio"),
        ("python.docstring_eligible_definition_count", "definition", "ratio"),
        ("python.docstring_present_definition_count", "definition", "ratio"),
        ("python.docstring_coverage_proportion", "proportion", "ratio"),
        ("python.annotation_eligible_slot_count", "slot", "ratio"),
        ("python.annotation_present_slot_count", "slot", "ratio"),
        ("python.annotation_coverage_proportion", "proportion", "ratio"),
        ("python.numeric_literal_count", "literal", "ratio"),
        ("python.exception_handler_count", "handler", "ratio"),
        ("python.raise_statement_count", "statement", "ratio"),
    )
    for oid, unit, scale in module_specs:
        records.append(observation(
            oid, entity_id="python_module", entity_kind="python_module", path=intake.path,
            value=None, measurement_scale=scale, unit=unit, state="not_applicable",
            reason_code="language_not_python", reason="The declared language is not Python.",
            evidence_ids=[whole_id], parser="CPython_ast_and_tokenize/declared_runtime",
            limitations=("Observation applies only to Python.",)
        ))
    return records


def _annotation_counts(functions: Sequence[ast.AST]) -> Tuple[int, int]:
    eligible = 0
    present = 0
    for node in functions:
        args = node.args  # type: ignore[attr-defined]
        parameters = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        if args.vararg is not None:
            parameters.append(args.vararg)
        if args.kwarg is not None:
            parameters.append(args.kwarg)
        eligible += len(parameters) + 1
        present += sum(parameter.annotation is not None for parameter in parameters)
        present += int(getattr(node, "returns", None) is not None)
    return eligible, present


def _numeric_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, (int, float, complex)) and not isinstance(node.value, bool)


def _callable_nodes(tree: ast.AST) -> List[ast.AST]:
    result = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return sorted(result, key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0), getattr(node, "name", "")))


class _CallableMetrics(ast.NodeVisitor):
    def __init__(self, root: ast.AST) -> None:
        self.root = root
        self.decision_points = 0
        self.max_depth = 0
        self._depth = 0

    def visit(self, node: ast.AST) -> Any:
        if node is not self.root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return None
        return super().visit(node)

    def _container(self, node: ast.AST) -> None:
        self._depth += 1
        self.max_depth = max(self.max_depth, self._depth)
        self.generic_visit(node)
        self._depth -= 1

    def visit_If(self, node: ast.If) -> None:
        self.decision_points += 1
        self._container(node)

    def visit_For(self, node: ast.For) -> None:
        self.decision_points += 1
        self._container(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.decision_points += 1
        self._container(node)

    def visit_While(self, node: ast.While) -> None:
        self.decision_points += 1
        self._container(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.decision_points += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.decision_points += len(node.handlers)
        self._container(node)

    if hasattr(ast, "TryStar"):
        def visit_TryStar(self, node: ast.AST) -> None:  # type: ignore[no-redef]
            self.decision_points += len(getattr(node, "handlers", ()))
            self._container(node)

    def visit_With(self, node: ast.With) -> None:
        self._container(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._container(node)

    if hasattr(ast, "Match"):
        def visit_Match(self, node: ast.AST) -> None:  # type: ignore[no-redef]
            self.decision_points += len(getattr(node, "cases", ()))
            self._container(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def _visit_comprehension(self, node: ast.AST) -> None:
        generators = getattr(node, "generators", ())
        self.decision_points += len(generators) + sum(len(generator.ifs) for generator in generators)
        self.generic_visit(node)


def _python_observations(intake: IntakeRecord, whole_id: str, evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(intake.text, filename=intake.path, type_comments=True)
    except SyntaxError as exc:
        records.append(observation(
            "python.parse_status", entity_id="python_module", entity_kind="python_module",
            path=intake.path, value="syntax_error", measurement_scale="nominal", unit="category",
            evidence_ids=[whole_id], parser="CPython_ast/declared_runtime",
            limitations=(f"SyntaxError at line {exc.lineno or 0}; dependent observations are unavailable.",)
        ))
        records.extend(_unavailable_python_records(intake, whole_id, "CPython ast.parse reported a syntax error."))
        token_records = _python_comment_observations(intake, whole_id)
        records.extend(token_records)
        return records

    records.append(observation(
        "python.parse_status", entity_id="python_module", entity_kind="python_module",
        path=intake.path, value="parsed", measurement_scale="nominal", unit="category",
        evidence_ids=[whole_id], parser="CPython_ast/declared_runtime",
        limitations=("A successful parse does not imply executable or semantic correctness.",)
    ))

    nodes = list(ast.walk(tree))
    functions = _callable_nodes(tree)
    sync_count = sum(isinstance(node, ast.FunctionDef) for node in nodes)
    async_count = sum(isinstance(node, ast.AsyncFunctionDef) for node in nodes)
    class_count = sum(isinstance(node, ast.ClassDef) for node in nodes)
    imports = [node for node in nodes if isinstance(node, (ast.Import, ast.ImportFrom))]
    imported_bindings = 0
    wildcard = 0
    for node in imports:
        for alias in node.names:
            if isinstance(node, ast.ImportFrom) and alias.name == "*":
                wildcard += 1
            else:
                imported_bindings += 1
    numeric = sum(_numeric_literal(node) for node in nodes)
    handlers = sum(isinstance(node, ast.ExceptHandler) for node in nodes)
    raises = sum(isinstance(node, ast.Raise) for node in nodes)
    eligible_definitions = [
        node for node in nodes if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    present_docstrings = sum(ast.get_docstring(node, clean=False) is not None for node in eligible_definitions)
    annotation_eligible, annotation_present = _annotation_counts(functions)

    base = {
        "entity_id": "python_module",
        "entity_kind": "python_module",
        "path": intake.path,
        "evidence_ids": [whole_id],
        "parser": "CPython_ast/declared_runtime",
        "limitations": ("Counts are syntactic and do not resolve runtime execution.",),
    }
    values = (
        ("python.function_definition_count", sync_count, "definition"),
        ("python.async_function_definition_count", async_count, "definition"),
        ("python.class_definition_count", class_count, "definition"),
        ("python.import_statement_count", len(imports), "statement"),
        ("python.imported_binding_count", imported_bindings, "binding"),
        ("python.wildcard_import_count", wildcard, "statement"),
        ("python.numeric_literal_count", numeric, "literal"),
        ("python.exception_handler_count", handlers, "handler"),
        ("python.raise_statement_count", raises, "statement"),
        ("python.docstring_eligible_definition_count", len(eligible_definitions), "definition"),
        ("python.docstring_present_definition_count", present_docstrings, "definition"),
        ("python.annotation_eligible_slot_count", annotation_eligible, "slot"),
        ("python.annotation_present_slot_count", annotation_present, "slot"),
    )
    for oid, value, unit in values:
        records.append(observation(oid, value=value, measurement_scale="ratio", unit=unit, **base))
    if eligible_definitions:
        records.append(observation(
            "python.docstring_coverage_proportion",
            value=_rounded(present_docstrings / len(eligible_definitions)),
            measurement_scale="ratio", unit="proportion", **base
        ))
    else:
        records.append(observation(
            "python.docstring_coverage_proportion", value=None,
            measurement_scale="ratio", unit="proportion", state="insufficient_evidence",
            reason_code="ME-012", reason="No docstring-eligible definitions exist.", **base
        ))
    if annotation_eligible:
        records.append(observation(
            "python.annotation_coverage_proportion",
            value=_rounded(annotation_present / annotation_eligible),
            measurement_scale="ratio", unit="proportion", **base
        ))
    else:
        records.append(observation(
            "python.annotation_coverage_proportion", value=None,
            measurement_scale="ratio", unit="proportion", state="insufficient_evidence",
            reason_code="ME-012", reason="No function-signature annotation slots exist.", **base
        ))

    records.extend(_python_comment_observations(intake, whole_id))

    for ordinal, node in enumerate(functions, 1):
        start = int(getattr(node, "lineno", 0) or 0)
        end = int(getattr(node, "end_lineno", 0) or 0)
        name = str(getattr(node, "name", "<lambda>"))
        entity_id = f"python_callable:{ordinal}:{name}:L{start}"
        if start < 1 or end < start:
            evidence_ids = [whole_id]
            records.append(observation(
                "python.callable.physical_span_lines", entity_id=entity_id,
                entity_kind="python_callable", path=intake.path, value=None,
                measurement_scale="ratio", unit="line", state="unavailable",
                reason_code="ME-013", reason="The parser did not provide a complete source span.",
                evidence_ids=evidence_ids, parser="CPython_ast_callable_visitor/1.1.0",
                limitations=("Source span is unavailable.",)
            ))
            continue
        span = _span_evidence(intake, start, end, scope="python_callable")
        evidence.append(span)
        evidence_ids = [span["evidence_id"]]
        metrics = _CallableMetrics(node)
        metrics.visit(node)
        common = {
            "entity_id": entity_id,
            "entity_kind": "python_callable",
            "path": intake.path,
            "evidence_ids": evidence_ids,
            "parser": "CPython_ast_callable_visitor/1.1.0",
            "limitations": (
                "Nested function, lambda and class bodies are excluded from the enclosing callable.",
                "The control-node convention is finite and is not a universal CFG metric.",
            ),
        }
        records.extend([
            observation("python.callable.physical_span_lines", value=end - start + 1,
                        measurement_scale="ratio", unit="line", **common),
            observation("python.callable.decision_point_count", value=metrics.decision_points,
                        measurement_scale="ratio", unit="decision_point", **common),
            observation("python.callable.mccabe_complexity", value=1 + metrics.decision_points,
                        measurement_scale="ratio", unit="complexity_unit", **common),
            observation("python.callable.max_control_nesting_depth", value=metrics.max_depth,
                        measurement_scale="ratio", unit="level", **common),
        ])
    return records


def _python_comment_observations(intake: IntakeRecord, whole_id: str) -> List[Dict[str, Any]]:
    base = {
        "entity_id": "python_module",
        "entity_kind": "python_module",
        "path": intake.path,
        "evidence_ids": [whole_id],
        "parser": "CPython_tokenize/declared_runtime",
        "limitations": ("Comment tokens are lexical and do not assess explanatory quality.",),
    }
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(intake.text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        return [
            observation("python.comment_token_count", value=None, measurement_scale="ratio", unit="token",
                        state="unavailable", reason_code="ME-007", reason=type(exc).__name__, **base),
            observation("python.comment_physical_line_count", value=None, measurement_scale="ratio", unit="line",
                        state="unavailable", reason_code="ME-007", reason=type(exc).__name__, **base),
            observation("python.comment_line_proportion", value=None, measurement_scale="ratio", unit="proportion",
                        state="unavailable", reason_code="ME-007", reason=type(exc).__name__, **base),
        ]
    comments = [token for token in tokens if token.type == tokenize.COMMENT]
    line_count = len({token.start[0] for token in comments})
    records = [
        observation("python.comment_token_count", value=len(comments), measurement_scale="ratio", unit="token", **base),
        observation("python.comment_physical_line_count", value=line_count, measurement_scale="ratio", unit="line", **base),
    ]
    denominator = len(intake.physical_lines)
    if denominator:
        records.append(observation("python.comment_line_proportion",
                                   value=_rounded(line_count / denominator),
                                   measurement_scale="ratio", unit="proportion", **base))
    else:
        records.append(observation(
            "python.comment_line_proportion", value=None, measurement_scale="ratio",
            unit="proportion", state="insufficient_evidence", reason_code="ME-012",
            reason="The source has no physical lines.", **base
        ))
    return records


def _markdown_scan(lines: Sequence[str]) -> Tuple[str, int, int, int, int]:
    import re

    fence_character: Optional[str] = None
    fence_length = 0
    fence_count = 0
    headings: List[int] = []
    atx = 0
    setext = 0
    index = 0
    while index < len(lines):
        line = lines[index]
        if fence_character is not None:
            close = re.match(r"^[ ]{0,3}([`~]+)[ \t]*$", line)
            if close and set(close.group(1)) == {fence_character} and len(close.group(1)) >= fence_length:
                fence_character = None
                fence_length = 0
            index += 1
            continue
        opener = re.match(r"^[ ]{0,3}(`{3,}|~{3,})(.*)$", line)
        if opener:
            run = opener.group(1)
            info = opener.group(2)
            if run[0] != "`" or "`" not in info:
                fence_character = run[0]
                fence_length = len(run)
                fence_count += 1
                index += 1
                continue
        atx_match = re.match(r"^[ ]{0,3}(#{1,6})(?:[ \t]+|$)", line)
        if atx_match:
            atx += 1
            headings.append(len(atx_match.group(1)))
            index += 1
            continue
        if line.strip() and index + 1 < len(lines):
            underline = re.match(r"^[ ]{0,3}(=+|-+)[ \t]*$", lines[index + 1])
            if underline:
                setext += 1
                headings.append(1 if underline.group(1)[0] == "=" else 2)
                index += 2
                continue
        index += 1
    jumps = sum(current - previous > 1 for previous, current in zip(headings, headings[1:]))
    status = "unclosed_fence" if fence_character is not None else "complete"
    return status, atx, setext, fence_count, jumps


def _markdown_observations(intake: IntakeRecord, whole_id: str) -> List[Dict[str, Any]]:
    status, atx, setext, fences, jumps = _markdown_scan(intake.physical_lines)
    base = {
        "entity_id": "markdown_document",
        "entity_kind": "markdown_document",
        "path": intake.path,
        "evidence_ids": [whole_id],
        "parser": "finite_markdown_scanner/1.1.0",
        "limitations": ("The scanner implements only the declared finite heading and fence subset.",),
    }
    return [
        observation("markdown.parse_status", value=status, measurement_scale="nominal", unit="category", **base),
        observation("markdown.atx_heading_count", value=atx, measurement_scale="ratio", unit="heading", **base),
        observation("markdown.setext_heading_count", value=setext, measurement_scale="ratio", unit="heading", **base),
        observation("markdown.fenced_code_block_count", value=fences, measurement_scale="ratio", unit="block", **base),
        observation("markdown.heading_level_jump_count", value=jumps, measurement_scale="ratio", unit="transition", **base),
    ]


def _not_applicable_markdown_records(intake: IntakeRecord, whole_id: str) -> List[Dict[str, Any]]:
    records = []
    for oid, unit, scale in (
        ("markdown.parse_status", "category", "nominal"),
        ("markdown.atx_heading_count", "heading", "ratio"),
        ("markdown.setext_heading_count", "heading", "ratio"),
        ("markdown.fenced_code_block_count", "block", "ratio"),
        ("markdown.heading_level_jump_count", "transition", "ratio"),
    ):
        records.append(observation(
            oid, entity_id="markdown_document", entity_kind="markdown_document",
            path=intake.path, value=None, measurement_scale=scale, unit=unit,
            state="not_applicable", reason_code="language_not_markdown",
            reason="The declared language is not Markdown.", evidence_ids=[whole_id],
            parser="finite_markdown_scanner/1.1.0",
            limitations=("Observation applies only to Markdown.",)
        ))
    return records


def _measurement_digest_scope(result: Mapping[str, Any]) -> Dict[str, Any]:
    artifact = result["artifact"]
    return {
        "schema": result["schema"],
        "kernel_version": result["kernel_version"],
        "catalogue_schema": result["catalogue_schema"],
        "artifact": {
            "language": artifact["language"],
            "raw_sha256": artifact["raw_sha256"],
            "normalised_sha256": artifact["normalised_sha256"],
            "encoding": artifact["encoding"],
            "normalisation": artifact["normalisation"],
        },
        "source_evidence": [
            {key: value for key, value in item.items() if key != "path"}
            for item in result["source_evidence"]
        ],
        "observations": [
            {
                **item,
                "entity": {key: value for key, value in item["entity"].items() if key != "path"},
            }
            for item in result["observations"]
        ],
        "non_inferences": result["non_inferences"],
        "legacy_compatibility": result["legacy_compatibility"],
    }


def _measure_bytes_unchecked(data: bytes, *, language: str, path: str = "<memory>",
                  max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    language_normalised = str(language).strip().lower()
    if language_normalised not in {"python", "markdown", "text"}:
        raise MeasurementError("ME-008", "language must be python, markdown or text in the S02 reference kernel")
    intake = intake_from_bytes(data, path=path, max_bytes=max_bytes)
    evidence: List[Dict[str, Any]] = [_whole_evidence(intake)]
    whole_id = evidence[0]["evidence_id"]
    observations = _generic_observations(intake, whole_id)
    if language_normalised == "python":
        observations.extend(_python_observations(intake, whole_id, evidence))
        observations.extend(_not_applicable_markdown_records(intake, whole_id))
    elif language_normalised == "markdown":
        observations.extend(_not_applicable_python_records(intake, whole_id))
        observations.extend(_markdown_observations(intake, whole_id))
    else:
        observations.extend(_not_applicable_python_records(intake, whole_id))
        observations.extend(_not_applicable_markdown_records(intake, whole_id))
    observations.sort(key=lambda item: (item["specification_id"], item["entity"]["entity_id"], item["record_id"]))
    evidence.sort(key=lambda item: item["evidence_id"])
    observation_payload = {
        "schema": KERNEL_SCHEMA,
        "kernel_version": KERNEL_VERSION,
        "catalogue_schema": CATALOGUE_SCHEMA,
        "artifact": {
            "path": intake.path,
            "language": language_normalised,
            "raw_sha256": intake.raw_sha256,
            "normalised_sha256": intake.normalised_sha256,
            "encoding": intake.encoding,
            "normalisation": intake.normalisation,
        },
        "source_evidence": evidence,
        "observations": observations,
        "non_inferences": list(REQUIRED_NON_INFERENCES),
        "legacy_compatibility": {
            "non_equivalent": True,
            "legacy_scalar_mapped": False,
        },
    }
    validate_kernel_result(observation_payload)
    observation_payload["measurement_digest"] = sha256_hex(
        canonical_json(_measurement_digest_scope(observation_payload)).encode("utf-8")
    )
    validate_kernel_result(observation_payload)
    return observation_payload


def measure_bytes(data: bytes, *, language: str, path: str = "<memory>",
                  max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    """Measure under the finite contract; reject recoverable resource failures.

    This boundary is not OS-level containment. Native crashes, process-wide
    exhaustion and failures while constructing an exception remain outside it.
    """
    try:
        return _measure_bytes_unchecked(data, language=language, path=path, max_bytes=max_bytes)
    except (MemoryError, RecursionError) as exc:
        raise MeasurementError("ME-015", "Python measurement exceeded a recoverable runtime resource limit") from exc


def measure_file(path: os.PathLike[str] | str, *, language: str,
                 max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    intake = read_bounded_source(path, max_bytes=max_bytes)
    return measure_bytes(intake.raw_bytes, language=language, path=intake.path, max_bytes=max_bytes)


def validate_kernel_result(result: Mapping[str, Any]) -> None:
    required = {
        "schema", "kernel_version", "catalogue_schema", "artifact",
        "source_evidence", "observations", "non_inferences", "legacy_compatibility",
    }
    allowed = required | {"measurement_digest"}
    if not required.issubset(result) or not set(result).issubset(allowed):
        raise ValueError(f"kernel result fields differ from contract: {sorted(set(result) ^ required)}")
    if result["schema"] != KERNEL_SCHEMA or result["kernel_version"] != KERNEL_VERSION or result["catalogue_schema"] != CATALOGUE_SCHEMA:
        raise ValueError("kernel identity mismatch")
    if any(_is_forbidden_identifier(key) for key in _recursive_keys(result)):
        raise ValueError("forbidden scalar or provenance identifier in kernel output")
    if tuple(result["non_inferences"]) != REQUIRED_NON_INFERENCES:
        raise ValueError("required non-inferences are missing or altered")
    if result["legacy_compatibility"] != {"non_equivalent": True, "legacy_scalar_mapped": False}:
        raise ValueError("legacy non-equivalence contract failed")

    artifact = result["artifact"]
    artifact_fields = {"path", "language", "raw_sha256", "normalised_sha256", "encoding", "normalisation"}
    if not isinstance(artifact, Mapping) or set(artifact) != artifact_fields:
        raise ValueError("artifact identity fields differ from contract")
    if artifact["language"] not in {"python", "markdown", "text"} or artifact["encoding"] not in {"utf-8", "utf-8-sig"}:
        raise ValueError("artifact language or encoding is invalid")
    for key in ("raw_sha256", "normalised_sha256"):
        if not isinstance(artifact[key], str) or re.fullmatch(r"[0-9a-f]{64}", artifact[key]) is None:
            raise ValueError(f"artifact {key} is invalid")
    if not isinstance(artifact["path"], str) or not isinstance(artifact["normalisation"], str) or not artifact["normalisation"].strip():
        raise ValueError("artifact path or normalisation is invalid")

    source_evidence = result["source_evidence"]
    if not isinstance(source_evidence, list) or not source_evidence:
        raise ValueError("source evidence is required")
    evidence_ids = set()
    evidence_fields = {"evidence_id", "path", "normalised_sha256", "start_line", "end_line", "start_column", "end_column", "scope"}
    for item in source_evidence:
        if not isinstance(item, Mapping) or set(item) != evidence_fields:
            raise ValueError("source evidence fields differ from contract")
        if not isinstance(item["evidence_id"], str) or not item["evidence_id"].startswith(f"evidence:{artifact['normalised_sha256']}:"):
            raise ValueError("source evidence identifier is not bound to the normalised artefact")
        if item["evidence_id"] in evidence_ids:
            raise ValueError("duplicate source evidence identifiers")
        evidence_ids.add(item["evidence_id"])
        if item["normalised_sha256"] != artifact["normalised_sha256"] or item["path"] != artifact["path"]:
            raise ValueError("source evidence artefact identity mismatch")
        if not all(isinstance(item[key], int) and not isinstance(item[key], bool) for key in ("start_line", "end_line", "start_column", "end_column")):
            raise ValueError("source evidence coordinates must be integers")
        if item["start_line"] < 1 or item["end_line"] < item["start_line"] or item["start_column"] < 0 or item["end_column"] < 0:
            raise ValueError("source evidence coordinates are invalid")
        if item["scope"] not in {"whole_artifact", "python_callable"}:
            raise ValueError("source evidence scope is unsupported")
        expected_evidence_id = (
            f"evidence:{item['normalised_sha256']}:{item['scope']}:"
            f"L{item['start_line']}-L{item['end_line']}:C{item['start_column']}-C{item['end_column']}"
        )
        if item["evidence_id"] != expected_evidence_id:
            raise ValueError("source evidence identity does not bind its coordinates")

    observations = result["observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError("observations are required")
    record_ids = set()
    for record in observations:
        validate_observation_record(record)
        if record["entity"]["path"] != artifact["path"]:
            raise ValueError("observation entity does not belong to the declared artefact path")
        if record["record_id"] in record_ids:
            raise ValueError("duplicate observation record identifier")
        record_ids.add(record["record_id"])
        if not set(record["source_evidence_ids"]).issubset(evidence_ids):
            raise ValueError("observation references unknown source evidence")
        expected_scope = "python_callable" if record["entity"]["entity_kind"] == "python_callable" else "whole_artifact"
        # An unavailable parser span cannot identify callable coordinates. Keep the
        # existing ME-013 whole-artifact fallback without permitting observed data
        # to borrow evidence at a different scope.
        if (record["observation_id"] == "python.callable.physical_span_lines"
                and record["applicability"]["state"] == "unavailable"
                and record["applicability"]["reason_code"] == "ME-013"):
            expected_scope = "whole_artifact"
        if any(item["scope"] != expected_scope for item in source_evidence if item["evidence_id"] in record["source_evidence_ids"]):
            raise ValueError("observation evidence scope differs from its entity scope")

    if "measurement_digest" in result:
        digest = result["measurement_digest"]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("measurement digest is invalid")
        expected = sha256_hex(canonical_json(_measurement_digest_scope(result)).encode("utf-8"))
        if digest != expected:
            raise ValueError("measurement digest does not match the deterministic scope")


def catalogue_observation_ids(catalogue: Mapping[str, Any]) -> set[str]:
    return {item["observation_id"] for item in catalogue.get("observations", [])}


def verify_result_against_catalogue(result: Mapping[str, Any], catalogue: Mapping[str, Any]) -> None:
    specifications = {item["observation_id"]: item for item in catalogue.get("observations", [])}
    expected = set(specifications)
    records_by_id: Dict[str, List[Mapping[str, Any]]] = {}
    for record in result["observations"]:
        records_by_id.setdefault(record["observation_id"], []).append(record)
    seen = set(records_by_id)
    unknown = seen - expected
    if unknown:
        raise ValueError(f"kernel emitted observations absent from the catalogue: {sorted(unknown)}")
    missing_singletons = {
        observation_id for observation_id, item in specifications.items()
        if item["instance_cardinality"] == "one_per_artifact" and len(records_by_id.get(observation_id, ())) != 1
    }
    if missing_singletons:
        raise ValueError(f"kernel singleton cardinality failed: {sorted(missing_singletons)}")
    for observation_id, records in records_by_id.items():
        specification = specifications[observation_id]
        if specification["instance_cardinality"] == "zero_or_more_per_artifact":
            if any(record["entity"]["entity_kind"] != "python_callable" for record in records):
                raise ValueError(f"callable observation has a non-callable entity: {observation_id}")
        elif specification["instance_cardinality"] == "one_per_artifact":
            if len(records) != 1:
                raise ValueError(f"artifact observation repeated: {observation_id}")
        else:
            raise ValueError(f"unsupported observation cardinality: {observation_id}")


__all__ = [
    "APPLICABILITY_STATES", "CATALOGUE_SCHEMA", "DEFAULT_MAX_BYTES",
    "KERNEL_SCHEMA", "KERNEL_VERSION", "MeasurementError", "canonical_json",
    "catalogue_observation_ids", "git_blob_sha1", "intake_from_bytes",
    "measure_bytes", "measure_file", "read_bounded_source", "sha256_hex",
    "validate_kernel_result", "validate_observation_record",
    "verify_result_against_catalogue",
]
