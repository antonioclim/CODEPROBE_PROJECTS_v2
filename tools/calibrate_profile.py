#!/usr/bin/env python3
"""Build a scoped CodeProbe profile with independent holdout evaluation."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit("this command requires isolated, site-free Python; rerun it with -I -S -B")

import argparse
import csv
import hashlib
import io
import json
import os
import stat
import statistics
import time
import uuid
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for _path in (SRC, TOOLS):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import codeprobe_runtime as engine
from codeprobe_engine.project_io import (
    DEFAULT_MAX_ARCHIVE_BYTES,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_IGNORE_BYTES,
    DEFAULT_MAX_IGNORE_RULES,
    DEFAULT_MAX_TOTAL_BYTES,
    ProjectInputError,
    project_payload_from_path,
    read_bounded_regular_file,
)

NEGATIVE_LABELS = {"human", "known_human", "declared_human", "pre_llm", "student_human", "no_ai"}
POSITIVE_LABELS = {"ai", "llm", "generated", "ai_generated", "llm_generated", "heavy_ai", "synthetic_ai"}
HYBRID_LABELS = {"hybrid", "assisted", "ai_assisted", "light_ai", "mixed", "revised_ai"}
SUPPORTED_LABELS = NEGATIVE_LABELS | POSITIVE_LABELS | HYBRID_LABELS
FIT_SPLITS = {"fit", "train", "training", "selection"}
EVALUATION_SPLITS = {"evaluation", "evaluate", "eval", "test", "holdout", "validation"}
DEFAULT_MAX_MANIFEST_BYTES = 4_000_000


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


@dataclass
class SampleResult:
    path: str
    label: str
    kind: str
    language: str
    score: Optional[float]
    applicable: bool
    sloc: int
    verdict_class: str
    warning: str = ""
    sample_id: str = ""
    split: str = ""
    group_id: str = ""
    scoring_contract: Optional[Dict[str, str]] = None
    decision_score: Optional[float] = None


def load_manifest(path: Path) -> Dict[str, Any]:
    path = Path(os.path.abspath(os.fspath(path)))
    data = read_bounded_regular_file(
        path, root=path.parent, max_bytes=DEFAULT_MAX_MANIFEST_BYTES
    )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("calibration manifest must be UTF-8 text") from exc
    if path.suffix.lower() == ".csv":
        reader = csv.DictReader(io.StringIO(text, newline=""))
        fieldnames = list(reader.fieldnames or [])
        portable_fields = [str(name or "").strip().casefold() for name in fieldnames]
        if not portable_fields or any(not name for name in portable_fields):
            raise ValueError("CSV calibration manifest must have non-empty column names")
        if len(set(portable_fields)) != len(portable_fields):
            raise ValueError("CSV calibration manifest has duplicate column names")
        rows = list(reader)
        if any(None in row for row in rows):
            raise ValueError("CSV calibration manifest row has more values than its header")
        return {"profile_id": path.stem, "label": path.stem, "samples": rows}
    parsed = json.loads(text, object_pairs_hook=_unique_json_object)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("samples"), list):
        raise ValueError("JSON manifest must be an object containing a samples list.")
    return parsed


def _load_json_object_file(path: Path, label: str) -> Dict[str, Any]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    data = read_bounded_regular_file(
        absolute, root=absolute.parent, max_bytes=DEFAULT_MAX_MANIFEST_BYTES
    )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8 JSON") from exc
    parsed = json.loads(text, object_pairs_hook=_unique_json_object)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def resolve_sample_path(base_dir: Path, sample_path: str) -> Path:
    base = Path(os.path.abspath(os.fspath(base_dir)))
    candidate = Path(sample_path)
    if not candidate.is_absolute():
        candidate = base / candidate
    candidate = Path(os.path.abspath(os.fspath(candidate)))
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError("calibration samples must remain below the declared corpus root") from exc
    return candidate


def sample_kind(path: Path, record: Dict[str, Any]) -> str:
    explicit = str(record.get("kind") or record.get("mode") or "").strip().lower()
    if explicit in {"file", "project"}:
        return explicit
    if path.suffix.lower() == ".zip":
        return "project"
    try:
        metadata = path.lstat()
    except OSError:
        return "file"
    return "project" if stat.S_ISDIR(metadata.st_mode) else "file"


def _normalise_label(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _normalise_split(value: object) -> str:
    raw = str(value or "").strip().lower().replace("-", "_")
    if not raw:
        return ""
    if raw in FIT_SPLITS:
        return "fit"
    if raw in EVALUATION_SPLITS:
        return "evaluation"
    raise ValueError(f"unsupported calibration split: {raw!r}")


def _stratum(label: str) -> str:
    return "human" if label in NEGATIVE_LABELS else "positive"


def _portable_identifier(value: object) -> str:
    raw = str(value or "").replace("\\", "/")
    pure = PurePosixPath(raw)
    if (
        not raw
        or pure.is_absolute()
        or (len(raw) >= 3 and raw[0].isalpha() and raw[1:3] == ":/")
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
        or raw != unicodedata.normalize("NFC", raw)
    ):
        return ""
    return pure.as_posix()


def _pseudonymous_identifier(value: object, index: int, suffix: str = "") -> str:
    del index  # retained in the signature for compatibility with existing callers
    digest = hashlib.sha256(
        str(value).encode("utf-8", errors="backslashreplace")
    ).hexdigest()[:24]
    return f"sample-{digest}{suffix.lower()[:12]}"


def _safe_relative_identifier(
    base_dir: Path, path: Path, raw_path: str, index: int
) -> str:
    try:
        relative = path.relative_to(base_dir).as_posix()
    except ValueError:
        relative = ""
    candidate = _portable_identifier(relative or raw_path)
    return candidate or _pseudonymous_identifier(raw_path, index, path.suffix)


def _safe_output_identifier(value: str, index: int) -> str:
    candidate = _portable_identifier(value)
    return candidate or _pseudonymous_identifier(value, index, Path(value).suffix)


def _group_token(value: object, fallback: str) -> str:
    raw = str(value or fallback)
    return "group-" + hashlib.sha256(raw.encode("utf-8", errors="backslashreplace")).hexdigest()[:16]


def _read_text_file(path: Path, root: Path) -> str:
    data = read_bounded_regular_file(path, root=root, max_bytes=engine.PROJECT_MAX_FILE_BYTES_DEFAULT)
    text, warning = engine.decode_text_bytes(data)
    if text is None:
        raise ValueError(warning or "file is not readable text")
    return text


def analyse_sample(
    path: Path,
    record: Dict[str, Any],
    profile: str,
    *,
    base_dir: Path | None = None,
    metric_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
    sample_id: str = "",
    split: str = "",
    group_id: str = "",
) -> SampleResult:
    label = _normalise_label(record.get("label") or record.get("class"))
    if label not in SUPPORTED_LABELS:
        raise ValueError(f"unsupported or missing label for {sample_id or path.name}: {label!r}")
    kind = sample_kind(path, record)
    language_hint = record.get("language_hint") or record.get("language") or None
    safe_id = sample_id or _safe_output_identifier(str(path), 0)
    safe_group = group_id or _group_token(record.get("group") or record.get("group_id"), safe_id)
    root = base_dir or path.parent
    try:
        if kind == "project":
            payload = project_payload_from_path(
                path,
                include_binary_placeholders=False,
                max_archive_bytes=DEFAULT_MAX_ARCHIVE_BYTES,
                max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
                max_entries=DEFAULT_MAX_ENTRIES,
                max_ignore_bytes=DEFAULT_MAX_IGNORE_BYTES,
                max_ignore_rules=DEFAULT_MAX_IGNORE_RULES,
            )
            payload["profile"] = profile
            payload["config_override"] = metric_overrides
            payload["require_python_ast"] = True
            result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
            report = result["project_report"]
        else:
            payload = {
                "code": _read_text_file(path, root),
                "require_python_ast": True,
                "filename": path.name,
                "profile": profile,
                "config_override": metric_overrides,
                "language_hint": None if language_hint == "auto" else language_hint,
            }
            report = json.loads(engine.codeprobe_analyze(json.dumps(payload)))["report"]
        applicable = bool(report.get("overall_applicable"))
        score = float(report.get("overall_score", 0.0)) if applicable else None
        return SampleResult(
            path=safe_id,
            sample_id=safe_id,
            group_id=safe_group,
            split=_normalise_split(split),
            label=label,
            kind=kind,
            language=str(report.get("language") or ("project" if kind == "project" else "unknown")),
            score=score,
            applicable=applicable,
            sloc=int(report.get("sloc") or report.get("total_sloc") or 0),
            verdict_class=str(report.get("verdict_class") or "insufficient"),
            decision_score=float(report["decision_score"]) if applicable else None,
            scoring_contract=engine.scoring_contract(profile, engine.merged_metric_config(profile, metric_overrides)),
        )
    except Exception as exc:
        return SampleResult(
            path=safe_id,
            sample_id=safe_id,
            group_id=safe_group,
            split=_normalise_split(split),
            label=label,
            kind=kind,
            language="unknown",
            score=None,
            applicable=False,
            sloc=0,
            verdict_class="error",
            warning=f"{type(exc).__name__}: {exc}",
        )


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    q = max(0.0, min(1.0, q))
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    fraction = position - low
    return ordered[low] + (ordered[high] - ordered[low]) * fraction


def describe_scores(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "mean": round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "stdev": round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
        "min": round(min(values), 4),
        "p10": round(percentile(values, 0.10), 4),
        "p25": round(percentile(values, 0.25), 4),
        "p75": round(percentile(values, 0.75), 4),
        "p90": round(percentile(values, 0.90), 4),
        "max": round(max(values), 4),
    }


def threshold_rates(human_scores: Sequence[float], ai_scores: Sequence[float], hybrid_scores: Sequence[float], threshold: float) -> Dict[str, float]:
    positive_scores = list(ai_scores) + list(hybrid_scores)
    return {
        "threshold": round(threshold, 4),
        "false_positive_rate": round(sum(score >= threshold for score in human_scores) / len(human_scores), 4) if human_scores else 0.0,
        "ai_generated_review_rate": round(sum(score >= threshold for score in ai_scores) / len(ai_scores), 4) if ai_scores else 0.0,
        "hybrid_review_rate": round(sum(score >= threshold for score in hybrid_scores) / len(hybrid_scores), 4) if hybrid_scores else 0.0,
        "true_positive_rate": round(sum(score >= threshold for score in positive_scores) / len(positive_scores), 4) if positive_scores else 0.0,
    }


def choose_review_trigger(human_scores: Sequence[float], ai_scores: Sequence[float], hybrid_scores: Sequence[float], target_fpr: float) -> Tuple[float, List[Dict[str, float]], str]:
    positive_scores = list(ai_scores) + list(hybrid_scores)
    grid = [round(x / 100.0, 2) for x in range(10, 91)]
    rows = [threshold_rates(human_scores, ai_scores, hybrid_scores, threshold) for threshold in grid]
    if human_scores and positive_scores:
        eligible = [row for row in rows if sum(score >= row["threshold"] for score in human_scores) / len(human_scores) <= target_fpr]
        if eligible:
            best = max(eligible, key=lambda row: (row["true_positive_rate"], -row["threshold"]))
            return best["threshold"], rows, "selected_from_grid_at_target_fpr"
    if human_scores:
        trigger = min(0.90, max(0.40, percentile(human_scores, 1.0 - target_fpr)))
        return round(trigger, 2), rows, "human_percentile_fallback"
    return 0.60, rows, "default_fallback_insufficient_labels"


def bands_from_trigger(trigger: float) -> Dict[str, float]:
    low = min(0.35, max(0.18, trigger * 0.55))
    moderate = min(0.55, max(low + 0.10, trigger * 0.80))
    elevated = min(0.85, max(moderate + 0.10, trigger + 0.10))
    return {"low_max": round(low, 4), "moderate_max": round(moderate, 4), "elevated_max": round(elevated, 4), "review_trigger": round(trigger, 4)}


def label_groups(results: Sequence[SampleResult]) -> Tuple[List[float], List[float], List[float]]:
    applicable = [item for item in results if item.applicable and item.score is not None]
    return (
        [float(item.decision_score if item.decision_score is not None else item.score) for item in applicable if item.label in NEGATIVE_LABELS],
        [float(item.decision_score if item.decision_score is not None else item.score) for item in applicable if item.label in POSITIVE_LABELS],
        [float(item.decision_score if item.decision_score is not None else item.score) for item in applicable if item.label in HYBRID_LABELS],
    )


def _normalise_results(results: Sequence[SampleResult]) -> list[SampleResult]:
    normalised: list[SampleResult] = []
    for index, item in enumerate(results):
        identifier = _safe_output_identifier(item.sample_id or item.path, index)
        split = _normalise_split(item.split)
        group = item.group_id if str(item.group_id).startswith("group-") else _group_token(item.group_id, identifier)
        normalised.append(replace(item, path=identifier, sample_id=identifier, group_id=group, split=split))
    return normalised


def _assign_splits(results: Sequence[SampleResult], manifest: Dict[str, Any]) -> tuple[list[SampleResult], str]:
    group_strata: dict[str, str] = {}
    for item in results:
        stratum = _stratum(item.label)
        previous = group_strata.setdefault(item.group_id, stratum)
        if previous != stratum:
            raise ValueError(
                "one calibration group cannot mix known-human and positive labels"
            )
    values = [item.split for item in results]
    if any(values):
        if not all(values):
            raise ValueError("explicit calibration splits must be supplied for every sample")
        assigned = list(results)
        strategy = "explicit_group_holdout"
    else:
        fraction = float(manifest.get("evaluation_fraction", 0.25))
        if not 0.10 <= fraction <= 0.50:
            raise ValueError("evaluation_fraction must be between 0.10 and 0.50")
        seed = str(manifest.get("split_seed") or "codeprobe-calibration-v1")
        groups_by_stratum: dict[str, set[str]] = {"human": set(), "positive": set()}
        for item in results:
            groups_by_stratum[_stratum(item.label)].add(item.group_id)
        evaluation_groups: set[str] = set()
        for stratum, groups in groups_by_stratum.items():
            if len(groups) < 2:
                raise ValueError(f"independent evaluation requires at least two {stratum} groups")
            ordered = sorted(groups, key=lambda value: hashlib.sha256(f"{seed}|{stratum}|{value}".encode()).hexdigest())
            count = max(1, min(len(ordered) - 1, round(len(ordered) * fraction)))
            evaluation_groups.update(ordered[:count])
        assigned = [replace(item, split="evaluation" if item.group_id in evaluation_groups else "fit") for item in results]
        strategy = "deterministic_stratified_group_holdout"
    group_splits: dict[str, str] = {}
    for item in assigned:
        previous = group_splits.setdefault(item.group_id, item.split)
        if previous != item.split:
            raise ValueError("all samples from one calibration group must remain in one partition")
    return assigned, strategy


def _require_partition_balance(results: Sequence[SampleResult], label: str) -> None:
    human, ai, hybrid = label_groups(results)
    if not human:
        raise ValueError(f"{label} partition has no applicable known-human sample")
    if not (ai or hybrid):
        raise ValueError(f"{label} partition has no applicable AI-generated or hybrid sample")


def _profile_domain(results: Sequence[SampleResult]) -> tuple[str, str]:
    applicable = [item for item in results if item.applicable and item.score is not None]
    kinds = {item.kind for item in applicable}
    if len(kinds) != 1:
        raise ValueError("one calibration profile cannot mix file and project report kinds")
    kind = next(iter(kinds))
    languages = {item.language for item in applicable}
    if len(languages) != 1:
        raise ValueError("one calibration profile cannot mix languages; generate one profile per language")
    language = next(iter(languages))
    if kind == "project" and language != "project":
        raise ValueError("project calibration samples must yield project reports")
    return kind, language


def _opaque_sample_results(results: Sequence[SampleResult]) -> list[dict[str, Any]]:
    """Replace identifiers only after grouping, partitioning and estimation.

    The private deterministic identities never leave this function through the
    exported table. Tokens are independent of names and fresh for each export.
    They prevent direct dictionary lookup, not linkage through scores or order.
    """
    groups: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for item in results:
        sample_token = "sample-" + uuid.uuid4().hex
        if item.group_id not in groups:
            groups[item.group_id] = "group-" + uuid.uuid4().hex
        row = replace(item, path=sample_token, sample_id=sample_token,
                      group_id=groups[item.group_id])
        rows.append(dict(row.__dict__))
    return rows


def build_profile(manifest: Dict[str, Any], results: Sequence[SampleResult], target_fpr: float) -> Dict[str, Any]:
    if not isinstance(target_fpr, (int, float)) or isinstance(target_fpr, bool) or not 0 <= target_fpr <= 1:
        raise ValueError("target_fpr must be between 0 and 1")
    normalised = _normalise_results(results)
    failures = [item for item in normalised if item.verdict_class in {"error", "missing"}]
    if failures:
        detail = "; ".join(f"{item.sample_id}: {item.warning or item.verdict_class}" for item in failures[:5])
        raise ValueError(f"calibration aborted because sample analysis failed: {detail}")
    non_applicable = [
        item
        for item in normalised
        if not item.applicable or item.score is None
    ]
    if non_applicable:
        detail = ", ".join(item.sample_id for item in non_applicable[:5])
        raise ValueError(
            "calibration aborted because every sample must yield an applicable "
            f"score: {detail}"
        )
    metric_overrides = manifest.get("metric_overrides") or {}
    metric_overrides = engine.validate_metric_config_override(metric_overrides)
    base_profile = manifest.get("base_profile", "default")
    expected_contract = engine.scoring_contract(base_profile, engine.merged_metric_config(base_profile, metric_overrides))
    contracts = [item.scoring_contract for item in normalised]
    bound_scores = all(contract == expected_contract for contract in contracts)
    if any(contract is not None for contract in contracts) and not bound_scores:
        raise ValueError("Calibration samples do not share the effective scoring contract.")
    assigned, strategy = _assign_splits(normalised, manifest)
    kind, language = _profile_domain(assigned)
    fit = [item for item in assigned if item.split == "fit"]
    evaluation = [item for item in assigned if item.split == "evaluation"]
    _require_partition_balance(fit, "fit")
    _require_partition_balance(evaluation, "evaluation")
    fit_human, fit_ai, fit_hybrid = label_groups(fit)
    eval_human, eval_ai, eval_hybrid = label_groups(evaluation)
    all_human, all_ai, all_hybrid = label_groups(assigned)
    trigger, sensitivity, trigger_source = choose_review_trigger(fit_human, fit_ai, fit_hybrid, target_fpr)
    fit_rates = threshold_rates(fit_human, fit_ai, fit_hybrid, trigger)
    evaluation_rates = threshold_rates(eval_human, eval_ai, eval_hybrid, trigger)
    # Feasibility is judged on fit data only; the holdout never selects a threshold.
    target_met = sum(score >= trigger for score in fit_human) / len(fit_human) <= target_fpr
    grid_feasible = any(sum(score >= row["threshold"] for score in fit_human) / len(fit_human) <= target_fpr for row in sensitivity)
    bands = bands_from_trigger(trigger)
    profile_id = str(manifest.get("profile_id") or manifest.get("name") or "course-local-profile")
    label = str(manifest.get("label") or manifest.get("title") or profile_id)
    validation = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_version": engine.APP_VERSION,
        "target_false_positive_rate": target_fpr,
        "trigger_source": trigger_source,
        "target_met": target_met,
        "grid_feasible": grid_feasible,
        "evaluation_target_met": sum(score >= trigger for score in eval_human) / len(eval_human) <= target_fpr,
        "target_status": "fit-target-met" if target_met else "fit-target-unmet",
        "scoring_contract": expected_contract if bound_scores else None,
        "sample_count": len(assigned),
        "applicable_sample_count": len([item for item in assigned if item.applicable]),
        "evaluation_design": {
            "strategy": strategy,
            "independent_holdout": True,
            "selection_partition": "fit",
            "performance_partition": "evaluation",
            "group_exclusive": True,
            "independence_basis": "declared group identifiers plus physical filesystem identity checks",
            "independence_limitation": "Copied-identical, templated or semantically related samples are not inferred automatically.",
            "fit_sample_count": len(fit),
            "evaluation_sample_count": len(evaluation),
            "fit_group_count": len({item.group_id for item in fit}),
            "evaluation_group_count": len({item.group_id for item in evaluation}),
        },
        "score_distributions": {
            "human": describe_scores(all_human),
            "ai_generated": describe_scores(all_ai),
            "hybrid": describe_scores(all_hybrid),
        },
        "fit_score_distributions": {
            "human": describe_scores(fit_human),
            "ai_generated": describe_scores(fit_ai),
            "hybrid": describe_scores(fit_hybrid),
        },
        "evaluation_score_distributions": {
            "human": describe_scores(eval_human),
            "ai_generated": describe_scores(eval_ai),
            "hybrid": describe_scores(eval_hybrid),
        },
        "fit_at_selected_trigger": fit_rates,
        "evaluation_at_selected_trigger": evaluation_rates,
        "sensitivity_partition": "fit",
        "sensitivity": sensitivity,
        "identifier_policy": {
            "scheme": "random-uuid4-per-export/v1",
            "applied_after_partitioning": True,
            "mapping_exported": False,
            "limitation": "Scores, labels, row order and group sizes can still permit linkage; this is not anonymisation.",
        },
        "sample_results": _opaque_sample_results(assigned),
    }
    notes = [
        "Generated by tools/calibrate_profile.py from labelled local samples.",
        "Generated from a group-exclusive fit/evaluation design.",
        "The trigger was selected only on the fit partition; reported performance comes from the untouched evaluation partition.",
        "Sample and group identifiers are replaced by fresh random tokens after partitioning; paths and identity mappings are not exported.",
        "The trigger is a review threshold, not a probability boundary and not evidence of misconduct.",
    ]
    if len(fit_human) < 20 or len(fit_ai) + len(fit_hybrid) < 20 or len(eval_human) < 10 or len(eval_ai) + len(eval_hybrid) < 10:
        notes.append("Calibration partitions are small; treat this profile as a draft and expand the corpus before high-stakes use.")
    if not target_met:
        notes.append("The requested fit target was not met on the configured threshold grid. This draft is non-operational; evaluation data must not be used to select a replacement threshold.")
    if not bound_scores:
        notes.append("Input scores have no verified common engine/configuration identity. This summary is non-operational.")
    return {
        "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
        "scoring_contract": expected_contract if bound_scores else None,
        "operational": target_met and bound_scores,
        "operational_reason": "fit-target-met-and-scoring-bound" if target_met and bound_scores else ("fit-target-unmet" if not target_met else "unbound-sample-scores"),
        "profile_id": profile_id,
        "label": label,
        "course": manifest.get("course", ""),
        "assignment": manifest.get("assignment", ""),
        "profile_version": manifest.get("profile_version", ""),
        "scope": {"report_kinds": [kind], "languages": [language], "mixed_domains_permitted": False},
        "review_policy": {"file": dict(bands), "project": dict(bands)},
        "calibrated_policy_kind": kind,
        "metric_overrides": metric_overrides,
        "validation": validation,
        "notes": notes,
    }


def write_summary(path: Path, profile: Dict[str, Any]) -> None:
    validation = profile.get("validation", {})
    design = validation.get("evaluation_design", {})
    evaluation = validation.get("evaluation_at_selected_trigger", {})
    distributions = validation.get("evaluation_score_distributions", {})
    sensitivity = validation.get("sensitivity", [])
    scope = profile.get("scope", {})
    kind = (scope.get("report_kinds") or ["file"])[0]
    trigger = float(profile.get("review_policy", {}).get(kind, {}).get("review_trigger", 0.60))
    lines = [
        f"# CodeProbe calibration summary — {profile.get('label', profile.get('profile_id', 'course-local'))}",
        "",
        f"Generated with CodeProbe {engine.APP_VERSION}.",
        f"Calibrated scope: `{kind}` / `{', '.join(scope.get('languages') or [])}`.",
        f"Suggested local review trigger: **{trigger * 100:.1f}%**.",
        f"Operational for replay: `{profile.get('operational', False)}` ({profile.get('operational_reason', 'unbound')}).",
        f"Fit target met: `{validation.get('target_met', False)}`; evaluation target met: `{validation.get('evaluation_target_met', False)}` (not used for selection).",
        f"Selection source: `{validation.get('trigger_source', 'unknown')}` using only the fit partition.",
        f"Evaluation design: `{design.get('strategy', 'unknown')}`; group-exclusive independent holdout: `{design.get('independent_holdout', False)}`.",
        f"Fit/evaluation samples: {design.get('fit_sample_count', 0)}/{design.get('evaluation_sample_count', 0)}.",
        "",
        "## Independent evaluation at the selected trigger",
        "",
        f"- Known-human false-positive review rate: {float(evaluation.get('false_positive_rate', 0.0)):.3f}",
        f"- AI-generated review rate: {float(evaluation.get('ai_generated_review_rate', 0.0)):.3f}",
        f"- Hybrid review rate: {float(evaluation.get('hybrid_review_rate', 0.0)):.3f}",
        f"- Combined positive review rate: {float(evaluation.get('true_positive_rate', 0.0)):.3f}",
        "",
        "## Evaluation score distributions",
        "",
        "| Label group | n | mean | median | p90 | max |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for group in ("human", "ai_generated", "hybrid"):
        stats = distributions.get(group, {"count": 0})
        lines.append(f"| {group} | {stats.get('count', 0)} | {stats.get('mean', 'n/a')} | {stats.get('median', 'n/a')} | {stats.get('p90', 'n/a')} | {stats.get('max', 'n/a')} |")
    lines.extend(["", "## Fit-partition sensitivity grid", "", "| threshold | fit human FPR | fit AI review rate | fit hybrid review rate | fit combined positive rate |", "|---:|---:|---:|---:|---:|"])
    for row in sensitivity:
        if int(float(row["threshold"]) * 100) % 5 == 0:
            lines.append(f"| {row['threshold']:.2f} | {row['false_positive_rate']:.3f} | {row.get('ai_generated_review_rate', 0.0):.3f} | {row.get('hybrid_review_rate', 0.0):.3f} | {row['true_positive_rate']:.3f} |")
    lines.extend(["", "## Caveats", ""])
    lines.extend(f"- {note}" for note in profile.get("notes", []))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_observations_csv(path: Path, results: Sequence[SampleResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["sample_id", "group_id", "split", "path", "label", "kind", "language", "applicable", "score", "score_percent", "decision_score", "sloc", "verdict_class", "warning"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index, item in enumerate(_normalise_results(results)):
            writer.writerow({
                "sample_id": item.sample_id,
                "group_id": item.group_id,
                "split": item.split,
                "path": item.sample_id,
                "label": item.label,
                "kind": item.kind,
                "language": item.language,
                "applicable": item.applicable,
                "score": "" if item.score is None else f"{item.score:.6f}",
                "score_percent": "" if item.score is None else f"{item.score * 100:.2f}",
                "decision_score": "" if item.decision_score is None else repr(item.decision_score),
                "sloc": item.sloc,
                "verdict_class": item.verdict_class,
                "warning": item.warning,
            })


def write_sensitivity_csv(path: Path, profile: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["threshold", "false_positive_rate", "ai_generated_review_rate", "hybrid_review_rate", "true_positive_rate"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in profile.get("validation", {}).get("sensitivity", []):
            writer.writerow({field: row.get(field, "") for field in fields})


def _manifest_records(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    samples = manifest.get("samples") or manifest.get("records") or []
    if not isinstance(samples, list):
        raise ValueError("calibration manifest must contain a samples/records list")
    if any(not isinstance(item, dict) for item in samples):
        raise ValueError("every calibration sample record must be a JSON object")
    return list(samples)


def _output_paths(args: Any, manifest_path: Path) -> dict[str, Path]:
    profile_override = getattr(args, "profile_out", None) or getattr(args, "json_out", None)
    summary_override = getattr(args, "summary_out", None) or getattr(args, "md_out", None)
    if getattr(args, "out_dir", None):
        out_dir = Path(args.out_dir).absolute()
    elif profile_override:
        out_dir = Path(profile_override).absolute().parent
    else:
        out_dir = manifest_path.with_suffix("")
    return {
        "profile_path": Path(profile_override).absolute() if profile_override else out_dir / "calibration_profile.json",
        "summary_path": Path(summary_override).absolute() if summary_override else out_dir / "validation_summary.md",
        "observations_path": Path(args.csv_out).absolute() if getattr(args, "csv_out", None) else out_dir / "calibration_observations.csv",
        "sensitivity_path": Path(args.sensitivity_out).absolute() if getattr(args, "sensitivity_out", None) else out_dir / "threshold_sensitivity.csv",
    }


def _output_path_key(path: Path) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path))).casefold()


def _validate_output_destination(name: str, path: Path) -> Path:
    """Return a canonical destination while refusing a redirected output file."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = absolute.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError(f"cannot inspect {name}: {exc}") from exc
    else:
        attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
        reparse = bool(
            attributes
            & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        )
        if stat.S_ISLNK(metadata.st_mode) or reparse:
            raise ValueError(f"{name} must not use a link or reparse point")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(
                f"{name} must be a regular file when it already exists"
            )

    # Canonicalise pre-existing parent aliases before validation and writing.
    # This preserves the leaf no-link rule without rejecting standard host paths
    # such as macOS /tmp and /var, which are themselves filesystem aliases.
    canonical = Path(os.path.realpath(os.fspath(absolute)))
    current = canonical.parent
    while True:
        try:
            ancestor = current.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ValueError(f"cannot inspect {name}: {exc}") from exc
        else:
            attributes = int(getattr(ancestor, "st_file_attributes", 0) or 0)
            reparse = bool(
                attributes
                & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            )
            if stat.S_ISLNK(ancestor.st_mode) or reparse:
                raise ValueError(f"{name} has an unresolved link or reparse ancestor")
            if not stat.S_ISDIR(ancestor.st_mode):
                raise ValueError(f"{name} has a non-directory ancestor")
        parent = current.parent
        if parent == current:
            break
        current = parent
    return canonical


def _validate_output_paths(
    outputs: Dict[str, Path],
    *,
    manifest_path: Path,
    sample_paths: Sequence[tuple[Path, str]],
) -> None:
    portable: dict[str, str] = {}
    manifest_key = _output_path_key(manifest_path)
    sample_keys = [
        (_output_path_key(path), path, kind)
        for path, kind in sample_paths
    ]
    for name, path in list(outputs.items()):
        absolute = _validate_output_destination(name, path)
        outputs[name] = absolute
        key = _output_path_key(absolute)
        if key in portable:
            raise ValueError(
                f"calibration output paths collide: {portable[key]} and {name}"
            )
        portable[key] = name
        if key == manifest_key:
            raise ValueError(f"{name} must not overwrite the calibration manifest")
        for sample_key, sample_path, kind in sample_keys:
            if kind == "project":
                try:
                    sample_metadata = sample_path.lstat()
                except OSError:
                    continue
                if stat.S_ISDIR(sample_metadata.st_mode):
                    sample_real = Path(os.path.realpath(os.fspath(sample_path)))
                    output_real = Path(os.path.realpath(os.fspath(absolute)))
                    try:
                        output_real.relative_to(sample_real)
                    except ValueError:
                        pass
                    else:
                        raise ValueError(
                            f"{name} must not be written inside a project calibration sample"
                        )
                    continue
            if key == sample_key:
                raise ValueError(f"{name} must not overwrite a calibration sample")


def run_calibration(args: Any) -> Dict[str, Any]:
    manifest_path = Path(args.manifest).absolute()
    manifest = load_manifest(manifest_path)
    if getattr(args, "profile_id", None):
        manifest["profile_id"] = args.profile_id
    if getattr(args, "label", None):
        manifest["label"] = args.label
    if getattr(args, "profile_version", None):
        manifest["profile_version"] = args.profile_version
    if getattr(args, "config", None):
        manifest["metric_overrides"] = _load_json_object_file(
            Path(args.config), "metric override configuration"
        )
    if getattr(args, "evaluation_fraction", None) is not None:
        manifest["evaluation_fraction"] = float(args.evaluation_fraction)
    if getattr(args, "split_seed", None):
        manifest["split_seed"] = str(args.split_seed)

    base_dir = Path(getattr(args, "root", "") or manifest_path.parent).absolute()
    target_fpr = float(getattr(args, "target_fpr", 0.10))
    target_fpr = target_fpr / 100.0 if target_fpr > 1.0 else target_fpr
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("target_fpr must be between 0 and 1, or between 0 and 100 as a percentage")
    profile_name = getattr(args, "profile", "default") or "default"
    if profile_name not in engine.SCORING_PROFILES:
        raise ValueError("Unknown calibration base profile")
    manifest["base_profile"] = profile_name
    manifest["metric_overrides"] = engine.validate_metric_config_override(manifest.get("metric_overrides") or {})
    results: List[SampleResult] = []
    records = _manifest_records(manifest)
    if not records:
        raise ValueError("calibration manifest contains no sample records")
    explicit_split_presence = [bool(str(record.get("split") or record.get("partition") or "").strip()) for record in records]
    if any(explicit_split_presence) and not all(explicit_split_presence):
        raise ValueError("explicit split/partition must be supplied for every calibration sample")
    sample_paths: list[tuple[Path, str]] = []
    seen_sources: dict[str, str] = {}
    seen_physical_sources: dict[tuple[int, int], str] = {}
    seen_identifiers: set[str] = set()
    for index, record in enumerate(records):
        raw_path = record.get("path") or record.get("file") or record.get("folder") or record.get("zip")
        label = _normalise_label(record.get("label") or record.get("class"))
        if not raw_path:
            results.append(SampleResult(f"sample-{index}", label, "file", "unknown", None, False, 0, "missing", "sample path missing", f"sample-{index}", _normalise_split(record.get("split") or record.get("partition")), _group_token(record.get("group"), f"sample-{index}")))
            continue
        path = resolve_sample_path(base_dir, str(raw_path))
        declared_sample_id = record.get("sample_id") or record.get("sample_key")
        if declared_sample_id:
            sample_id = _safe_output_identifier(str(declared_sample_id), index)
        else:
            try:
                identifier_source = path.relative_to(base_dir).as_posix()
            except ValueError:
                identifier_source = str(raw_path)
            sample_id = _pseudonymous_identifier(
                identifier_source, index, path.suffix
            )
        source_key = os.path.normcase(os.fspath(path)).casefold()
        if source_key in seen_sources:
            raise ValueError(
                f"duplicate calibration sample source: {sample_id} and "
                f"{seen_sources[source_key]}"
            )
        if sample_id.casefold() in seen_identifiers:
            raise ValueError(f"duplicate calibration sample identifier: {sample_id}")
        seen_sources[source_key] = sample_id
        seen_identifiers.add(sample_id.casefold())
        group_id = _group_token(record.get("group") or record.get("group_id") or record.get("student_id") or record.get("submission_id"), sample_id)
        split = _normalise_split(record.get("split") or record.get("partition"))
        kind = sample_kind(path, record)
        try:
            metadata = path.lstat()
        except OSError:
            results.append(SampleResult(sample_id, label, kind, "unknown", None, False, 0, "missing", "path does not exist", sample_id, split, group_id))
            continue
        inode = int(getattr(metadata, "st_ino", 0) or 0)
        if inode:
            physical_key = (int(getattr(metadata, "st_dev", 0) or 0), inode)
            previous_sample = seen_physical_sources.get(physical_key)
            if previous_sample is not None:
                raise ValueError(
                    f"duplicate calibration sample physical source: {sample_id} and "
                    f"{previous_sample}"
                )
            seen_physical_sources[physical_key] = sample_id
        sample_paths.append((path, kind))
        results.append(analyse_sample(path, record, profile_name, base_dir=base_dir, metric_overrides=manifest["metric_overrides"], sample_id=sample_id, split=split, group_id=group_id))
    failures = [item for item in results if item.verdict_class in {"error", "missing"}]
    if failures:
        detail = "; ".join(f"{item.sample_id}: {item.warning}" for item in failures[:5])
        raise ValueError(f"calibration aborted because sample analysis failed: {detail}")
    profile = build_profile(manifest, results, target_fpr)
    assigned = [SampleResult(**item) for item in profile["validation"]["sample_results"]]
    outputs = _output_paths(args, manifest_path)
    _validate_output_paths(
        outputs,
        manifest_path=manifest_path,
        sample_paths=sample_paths,
    )
    # Serialise before creating any output: diagnostics must also be valid JSON.
    profile_json = json.dumps(profile, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    for output in outputs.values():
        output.parent.mkdir(parents=True, exist_ok=True)
    outputs["profile_path"].write_text(
        profile_json,
        encoding="utf-8",
    )
    write_observations_csv(outputs["observations_path"], assigned)
    write_sensitivity_csv(outputs["sensitivity_path"], profile)
    write_summary(outputs["summary_path"], profile)
    return {
        "profile": profile,
        "results": [item.__dict__ for item in assigned],
        **{name: str(path) for name, path in outputs.items()},
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a scoped CodeProbe calibration profile with independent evaluation.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", default="")
    parser.add_argument("--profile", default="default", choices=sorted(engine.SCORING_PROFILES))
    parser.add_argument("--profile-id", default="")
    parser.add_argument("--label", default="")
    parser.add_argument("--profile-version", default="")
    parser.add_argument("--target-fpr", type=float, default=0.10)
    parser.add_argument("--evaluation-fraction", type=float, default=None)
    parser.add_argument("--split-seed", default="")
    parser.add_argument("--min-per-class-for-language", type=int, default=10)
    parser.add_argument("--config")
    parser.add_argument("--out-dir")
    parser.add_argument("--profile-out")
    parser.add_argument("--summary-out")
    parser.add_argument("--json-out")
    parser.add_argument("--md-out")
    parser.add_argument("--csv-out")
    parser.add_argument("--sensitivity-out")
    args = parser.parse_args(argv)
    profile_out = args.profile_out or args.json_out
    summary_out = args.summary_out or args.md_out
    if not args.out_dir and not profile_out:
        parser.error("provide --out-dir or --profile-out/--json-out")
    result = run_calibration(args)
    written_profile = result["profile_path"]
    written_summary = result["summary_path"]
    written_observations = result["observations_path"]
    written_sensitivity = result["sensitivity_path"]
    print(f"Wrote calibration profile: {written_profile}")
    print(f"Wrote validation summary: {written_summary}")
    print(f"Wrote observations CSV: {written_observations}")
    print(f"Wrote threshold sensitivity CSV: {written_sensitivity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
