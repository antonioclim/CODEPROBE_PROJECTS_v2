#!/usr/bin/env python3
"""Build a course-local CodeProbe calibration profile from labelled samples.

The script estimates a local review trigger from a labelled corpus. It does not
prove authorship. The exported profile is intended to replace the bundled 60%
review trigger with an auditable local policy when a course team has collected
known-human, AI-generated and optionally hybrid samples for comparable tasks.

JSON manifest example:

{
  "profile_id": "intro-python-2026-v1",
  "label": "Intro Python 2026 calibration",
  "course": "Introductory Programming",
  "samples": [
    {"path": "samples/human/main.py", "label": "human", "language_hint": "python"},
    {"path": "samples/llm/main.py", "label": "ai_generated", "language_hint": "python"},
    {"path": "samples/hybrid/project", "label": "hybrid", "kind": "project"}
  ]
}

CSV manifests are also accepted with at least path,label columns.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for _path in (SRC, TOOLS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import codeprobe_runtime as engine
from codeprobe_engine.project_io import project_payload_from_path

NEGATIVE_LABELS = {"human", "known_human", "declared_human", "pre_llm", "student_human", "no_ai"}
POSITIVE_LABELS = {"ai", "llm", "generated", "ai_generated", "llm_generated", "heavy_ai", "synthetic_ai"}
HYBRID_LABELS = {"hybrid", "assisted", "ai_assisted", "light_ai", "mixed", "revised_ai"}
SUPPORTED_LABELS = NEGATIVE_LABELS | POSITIVE_LABELS | HYBRID_LABELS


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


def load_manifest(path: Path) -> Dict[str, Any]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.DictReader(handle))
        return {"profile_id": path.stem, "label": path.stem, "samples": rows}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSON manifest must be an object.")
    if not isinstance(data.get("samples"), list):
        raise ValueError("JSON manifest must contain a samples list.")
    return data


def resolve_sample_path(base_dir: Path, sample_path: str) -> Path:
    candidate = Path(sample_path)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate.resolve()


def sample_kind(path: Path, record: Dict[str, Any]) -> str:
    explicit = str(record.get("kind") or record.get("mode") or "").strip().lower()
    if explicit in {"file", "project"}:
        return explicit
    if path.is_dir() or path.suffix.lower() == ".zip":
        return "project"
    return "file"


def _read_text_file(path: Path) -> str:
    data = path.read_bytes()
    text, warning = engine.decode_text_bytes(data)
    if text is None:
        raise ValueError(warning or "file is not readable text")
    return text



def analyse_sample(path: Path, record: Dict[str, Any], profile: str) -> SampleResult:
    label = str(record.get("label") or record.get("class") or "").strip().lower().replace("-", "_")
    if label not in SUPPORTED_LABELS:
        raise ValueError(f"Unsupported or missing label for {path}: {label!r}")
    kind = sample_kind(path, record)
    language_hint = record.get("language_hint") or record.get("language") or None
    try:
        if kind == "project":
            payload = project_payload_from_path(path, include_binary_placeholders=False)
            payload["profile"] = profile
            result = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
            report = result["project_report"]
        else:
            payload = {
                "code": _read_text_file(path),
                "filename": path.name,
                "profile": profile,
                "language_hint": None if language_hint == "auto" else language_hint,
            }
            result = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
            report = result["report"]
        applicable = bool(report.get("overall_applicable"))
        score = float(report.get("overall_score", 0.0)) if applicable else None
        return SampleResult(
            path=str(path),
            label=label,
            kind=kind,
            language=str(report.get("language") or "unknown"),
            score=score,
            applicable=applicable,
            sloc=int(report.get("sloc") or report.get("total_sloc") or 0),
            verdict_class=str(report.get("verdict_class") or "insufficient"),
        )
    except Exception as exc:
        return SampleResult(str(path), label, kind, "unknown", None, False, 0, "error", str(exc))


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


def threshold_rates(
    human_scores: Sequence[float],
    ai_scores: Sequence[float],
    hybrid_scores: Sequence[float],
    threshold: float,
) -> Dict[str, float]:
    positive_scores = list(ai_scores) + list(hybrid_scores)
    fpr = sum(score >= threshold for score in human_scores) / len(human_scores) if human_scores else 0.0
    ai_review_rate = sum(score >= threshold for score in ai_scores) / len(ai_scores) if ai_scores else 0.0
    hybrid_review_rate = sum(score >= threshold for score in hybrid_scores) / len(hybrid_scores) if hybrid_scores else 0.0
    tpr = sum(score >= threshold for score in positive_scores) / len(positive_scores) if positive_scores else 0.0
    return {
        "threshold": round(threshold, 4),
        "false_positive_rate": round(fpr, 4),
        "ai_generated_review_rate": round(ai_review_rate, 4),
        "hybrid_review_rate": round(hybrid_review_rate, 4),
        "true_positive_rate": round(tpr, 4),
    }


def choose_review_trigger(
    human_scores: Sequence[float],
    ai_scores: Sequence[float],
    hybrid_scores: Sequence[float],
    target_fpr: float,
) -> Tuple[float, List[Dict[str, float]], str]:
    positive_scores = list(ai_scores) + list(hybrid_scores)
    grid = [round(x / 100.0, 2) for x in range(10, 91)]
    rows = [threshold_rates(human_scores, ai_scores, hybrid_scores, threshold) for threshold in grid]
    if human_scores and positive_scores:
        eligible = [row for row in rows if row["false_positive_rate"] <= target_fpr]
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
    human = [float(item.score) for item in applicable if item.label in NEGATIVE_LABELS]
    ai = [float(item.score) for item in applicable if item.label in POSITIVE_LABELS]
    hybrid = [float(item.score) for item in applicable if item.label in HYBRID_LABELS]
    return human, ai, hybrid


def build_profile(manifest: Dict[str, Any], results: Sequence[SampleResult], target_fpr: float) -> Dict[str, Any]:
    human_scores, ai_scores, hybrid_scores = label_groups(results)
    positive_scores = list(ai_scores) + list(hybrid_scores)
    trigger, sensitivity, trigger_source = choose_review_trigger(human_scores, ai_scores, hybrid_scores, target_fpr)
    bands = bands_from_trigger(trigger)
    profile_id = str(manifest.get("profile_id") or manifest.get("name") or "course-local-profile")
    label = str(manifest.get("label") or manifest.get("title") or profile_id)
    validation = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool_version": engine.APP_VERSION,
        "target_false_positive_rate": target_fpr,
        "trigger_source": trigger_source,
        "sample_count": len(results),
        "applicable_sample_count": len([item for item in results if item.applicable]),
        "score_distributions": {
            "human": describe_scores(human_scores),
            "ai_generated": describe_scores(ai_scores),
            "hybrid": describe_scores(hybrid_scores),
        },
        "sensitivity": sensitivity,
        "sample_results": [item.__dict__ for item in results],
    }
    notes = [
        "Generated by tools/calibrate_profile.py from labelled local samples.",
        "The trigger is a review threshold, not a probability boundary and not evidence of misconduct.",
    ]
    if len(human_scores) < 20 or len(ai_scores) < 20:
        notes.append("Calibration sample is small; treat this profile as a draft and expand the corpus before high-stakes use.")
    return {
        "schema_version": engine.CALIBRATION_PROFILE_SCHEMA,
        "profile_id": profile_id,
        "label": label,
        "course": manifest.get("course", ""),
        "assignment": manifest.get("assignment", ""),
        "profile_version": manifest.get("profile_version", ""),
        "review_policy": {"file": bands, "project": dict(bands)},
        "metric_overrides": manifest.get("metric_overrides", {}),
        "validation": validation,
        "notes": notes,
    }


def write_summary(path: Path, profile: Dict[str, Any]) -> None:
    validation = profile.get("validation", {})
    distributions = validation.get("score_distributions", {})
    sensitivity = validation.get("sensitivity", [])
    trigger = float(profile.get("review_policy", {}).get("file", {}).get("review_trigger", 0.60))
    lines = [
        f"# CodeProbe calibration summary — {profile.get('label', profile.get('profile_id', 'course-local'))}",
        "",
        f"Generated with CodeProbe {engine.APP_VERSION}.",
        f"Suggested local review trigger: **{trigger * 100:.1f}%**.",
        f"Trigger source: `{validation.get('trigger_source', 'unknown')}`.",
        f"Target false-positive rate: {float(validation.get('target_false_positive_rate', 0.10)) * 100:.1f}%.",
        "",
        "## Score distributions",
        "",
        "| Label group | n | mean | median | p90 | max |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label in ("human", "ai_generated", "hybrid"):
        stats = distributions.get(label, {"count": 0})
        lines.append(f"| {label} | {stats.get('count', 0)} | {stats.get('mean', 'n/a')} | {stats.get('median', 'n/a')} | {stats.get('p90', 'n/a')} | {stats.get('max', 'n/a')} |")
    lines.extend([
        "",
        "## Sensitivity grid",
        "",
        "| threshold | human false-positive rate | AI-generated review rate | hybrid review rate | combined positive review rate |",
        "|---:|---:|---:|---:|---:|",
    ])
    for row in sensitivity:
        if int(float(row["threshold"]) * 100) % 5 == 0:
            lines.append(f"| {row['threshold']:.2f} | {row['false_positive_rate']:.3f} | {row.get('ai_generated_review_rate', 0.0):.3f} | {row.get('hybrid_review_rate', 0.0):.3f} | {row['true_positive_rate']:.3f} |")
    lines.extend(["", "## Caveats", ""])
    lines.extend(f"- {note}" for note in profile.get("notes", []))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_observations_csv(path: Path, results: Sequence[SampleResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "label", "kind", "language", "applicable", "score", "score_percent", "sloc", "verdict_class", "warning"])
        writer.writeheader()
        for item in results:
            writer.writerow({
                "path": item.path,
                "label": item.label,
                "kind": item.kind,
                "language": item.language,
                "applicable": item.applicable,
                "score": "" if item.score is None else f"{item.score:.6f}",
                "score_percent": "" if item.score is None else f"{item.score * 100:.2f}",
                "sloc": item.sloc,
                "verdict_class": item.verdict_class,
                "warning": item.warning,
            })


def write_sensitivity_csv(path: Path, profile: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["threshold", "false_positive_rate", "ai_generated_review_rate", "hybrid_review_rate", "true_positive_rate"])
        writer.writeheader()
        for row in profile.get("validation", {}).get("sensitivity", []):
            writer.writerow({"threshold": row.get("threshold", ""), "false_positive_rate": row.get("false_positive_rate", ""), "ai_generated_review_rate": row.get("ai_generated_review_rate", ""), "hybrid_review_rate": row.get("hybrid_review_rate", ""), "true_positive_rate": row.get("true_positive_rate", "")})


def _manifest_records(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    samples = manifest.get("samples") or manifest.get("records") or []
    if not isinstance(samples, list):
        raise ValueError("Calibration manifest must contain a samples/records list.")
    return [item for item in samples if isinstance(item, dict)]


def run_calibration(args: Any) -> Dict[str, Any]:
    """Programmatic calibration entry point used by tests and local automation."""
    manifest_path = Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path)
    if getattr(args, "profile_id", None):
        manifest["profile_id"] = args.profile_id
    if getattr(args, "label", None):
        manifest["label"] = args.label
    if getattr(args, "profile_version", None):
        manifest["profile_version"] = args.profile_version
    if getattr(args, "config", None):
        manifest["metric_overrides"] = json.loads(Path(args.config).read_text(encoding="utf-8"))

    base_dir = Path(getattr(args, "root", "") or manifest_path.parent).resolve()
    target_fpr = float(getattr(args, "target_fpr", 0.10))
    target_fpr = target_fpr / 100.0 if target_fpr > 1.0 else target_fpr
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("target_fpr must be between 0 and 1, or between 0 and 100 as a percentage.")

    profile_name = getattr(args, "profile", "default") or "default"
    results: List[SampleResult] = []
    for record in _manifest_records(manifest):
        raw_path = record.get("path") or record.get("file") or record.get("folder") or record.get("zip")
        if not raw_path:
            results.append(SampleResult("", str(record.get("label") or "unknown"), "file", "unknown", None, False, 0, "missing", "sample path missing"))
            continue
        path = resolve_sample_path(base_dir, str(raw_path))
        if not path.exists():
            results.append(SampleResult(str(path), str(record.get("label") or "unknown"), sample_kind(path, record), "unknown", None, False, 0, "missing", "path does not exist"))
            continue
        results.append(analyse_sample(path, record, profile_name))

    profile = build_profile(manifest, results, target_fpr)
    out_dir = Path(getattr(args, "out_dir", "") or manifest_path.with_suffix(""))
    out_dir.mkdir(parents=True, exist_ok=True)
    profile_path = out_dir / "calibration_profile.json"
    observations_path = out_dir / "calibration_observations.csv"
    sensitivity_path = out_dir / "threshold_sensitivity.csv"
    summary_path = out_dir / "validation_summary.md"
    profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    write_observations_csv(observations_path, results)
    write_sensitivity_csv(sensitivity_path, profile)
    write_summary(summary_path, profile)
    return {
        "profile": profile,
        "results": [item.__dict__ for item in results],
        "profile_path": str(profile_path),
        "observations_path": str(observations_path),
        "sensitivity_path": str(sensitivity_path),
        "summary_path": str(summary_path),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a course-local CodeProbe calibration profile from labelled samples.")
    parser.add_argument("--manifest", required=True, help="JSON or CSV manifest with labelled samples.")
    parser.add_argument("--root", default="", help="Optional root directory for manifest paths; defaults to the manifest directory.")
    parser.add_argument("--profile", default="default", choices=sorted(engine.SCORING_PROFILES), help="CodeProbe metric profile used when scoring calibration samples.")
    parser.add_argument("--profile-id", default="", help="Identifier for the exported calibration profile; defaults to the manifest profile_id.")
    parser.add_argument("--label", default="", help="Human-readable label for the profile; defaults to the manifest label.")
    parser.add_argument("--profile-version", default="", help="Optional version label for the exported calibration profile.")
    parser.add_argument("--target-fpr", type=float, default=0.10, help="Target false-positive rate for known-human samples, as fraction or percent.")
    parser.add_argument("--min-per-class-for-language", type=int, default=10, help="Advisory minimum class size recorded in the validation summary.")
    parser.add_argument("--config", help="Optional metric override JSON to store in the generated profile.")
    parser.add_argument("--out-dir", help="Directory for calibration_profile.json, validation_summary.md and CSV outputs.")
    parser.add_argument("--profile-out", help="Path for generated calibration profile JSON.")
    parser.add_argument("--summary-out", help="Path for generated Markdown validation summary.")
    parser.add_argument("--json-out", help="Alias for --profile-out.")
    parser.add_argument("--md-out", help="Alias for --summary-out.")
    parser.add_argument("--csv-out", help="Optional path for calibration observations CSV.")
    parser.add_argument("--sensitivity-out", help="Optional path for threshold sensitivity CSV.")
    args = parser.parse_args(argv)

    profile_out = args.profile_out or args.json_out
    summary_out = args.summary_out or args.md_out
    if not args.out_dir and not profile_out:
        parser.error("Provide --out-dir or --profile-out/--json-out.")

    result = run_calibration(args)
    profile = result["profile"]
    written_profile = result["profile_path"]
    written_summary = result["summary_path"]
    written_observations = result["observations_path"]
    written_sensitivity = result["sensitivity_path"]

    if profile_out:
        path = Path(profile_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
        written_profile = str(path)
    if summary_out:
        path = Path(summary_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_summary(path, profile)
        written_summary = str(path)
    if args.csv_out:
        path = Path(args.csv_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_observations_csv(path, [SampleResult(**item) for item in result.get("results", [])])
        written_observations = str(path)
    if args.sensitivity_out:
        path = Path(args.sensitivity_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_sensitivity_csv(path, profile)
        written_sensitivity = str(path)

    print(f"Wrote calibration profile: {written_profile}")
    print(f"Wrote validation summary: {written_summary}")
    print(f"Wrote observations CSV: {written_observations}")
    print(f"Wrote threshold sensitivity CSV: {written_sensitivity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
