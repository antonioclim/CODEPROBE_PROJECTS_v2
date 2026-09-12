"""Adapter from S02 kernel records to the S01 evidence-bounded observation schema.

The adapter is intentionally one-way. It does not translate any v2 scalar,
threshold, band, provenance label or verdict into a v3 observation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

ADAPTER_VERSION = "1.1.0"
REQUIRED_MAPPING = {
    "observation_id": "observation_id",
    "value": "value",
    "unit": "unit",
    "measurement_scale": "measurement_scale",
}
TEMPLATE_FALLBACK = {
    "spec_version",
    "entity",
    "attribute",
    "applicability",
    "scope_qualification",
    "source_evidence",
    "instrumentation",
    "metamorphic_contract",
    "fingerprint",
}
UNMAPPED_REQUIRED_PROPERTIES: list[str] = []

_ENTITY_KIND = {
    "source_artifact": "file",
    "python_module": "file",
    "python_callable": "function",
    "markdown_document": "documentation",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _get(record: Mapping[str, Any], path: str) -> Any:
    value: Any = record
    for component in path.split("."):
        value = value[component]
    return value


def adapt_observation(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a structurally valid S01 observation envelope.

    Source evidence is represented by stable identifiers because the S02 kernel
    owns the detailed span catalogue. S04 may enrich this boundary, but it may
    not weaken the non-equivalence or claim restrictions established here.
    """
    output = {target: _get(record, source) for target, source in REQUIRED_MAPPING.items()}
    specification = str(record["specification_id"])
    spec_version = specification.rsplit("/", 1)[-1]
    applicability = record["applicability"]
    evidence_refs = list(record["source_evidence_ids"])
    output.update({
        "spec_version": spec_version,
        "entity": {
            "kind": _ENTITY_KIND.get(str(record["entity"]["entity_kind"]), "resource"),
            "identity": str(record["entity"]["entity_id"]),
        },
        "attribute": str(record["observation_id"]),
        "applicability": {
            "status": str(applicability["state"]),
            "reason": "" if applicability["state"] == "observed" else str(applicability.get("reason") or applicability.get("reason_code") or "Unavailable under the declared contract."),
        },
        "scope_qualification": "; ".join(str(x) for x in record.get("limitations", [])) or "Bounded by the S02 measurement specification.",
        "source_evidence": [
            {
                "evidence_id": evidence_id,
                "source_id": evidence_id,
                "start": 0,
                "end": 0,
                "evidence_kind": "entity",
                "coordinate_system": "entity_identifier",
            }
            for evidence_id in evidence_refs
        ],
        "instrumentation": {
            "adapter": f"codeprobe_s01_observation_adapter/{ADAPTER_VERSION}",
            "runtime": str(record["instrumentation"]["parser"]),
        },
        "metamorphic_contract": f"See research/observation-catalogue.v1.json#{record['observation_id']}",
    })
    fingerprint_scope = {key: value for key, value in output.items() if key != "fingerprint"}
    output["fingerprint"] = hashlib.sha256(_canonical(fingerprint_scope)).hexdigest()
    return output


__all__ = [
    "ADAPTER_VERSION", "REQUIRED_MAPPING", "TEMPLATE_FALLBACK",
    "UNMAPPED_REQUIRED_PROPERTIES", "adapt_observation",
]
