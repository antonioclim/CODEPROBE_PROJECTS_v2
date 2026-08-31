#!/usr/bin/env python3
"""Compatibility CLI for folder-based CodeProbe calibration.

This wrapper accepts a simple labelled-folder corpus and delegates the actual
profile construction to :mod:`calibrate_profile`. It exists for instructors who
prefer a minimal directory convention:

    calibration_corpus/
    ├── human/
    ├── ai/
    └── hybrid/

For project-level samples, mixed metadata, ZIP samples or per-sample language
hints, use ``tools/calibrate_profile.py`` with a JSON or CSV manifest instead.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site
):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for _path in (SRC, TOOLS):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import calibrate_profile
import codeprobe_runtime as engine

LABEL_FOLDER_MAP = {
    "human": "human",
    "known_human": "human",
    "declared_human": "human",
    "pre_llm": "human",
    "student_human": "human",
    "no_ai": "human",
    "ai": "ai_generated",
    "llm": "ai_generated",
    "generated": "ai_generated",
    "ai_generated": "ai_generated",
    "llm_generated": "ai_generated",
    "heavy_ai": "ai_generated",
    "synthetic_ai": "ai_generated",
    "hybrid": "hybrid",
    "assisted": "hybrid",
    "ai_assisted": "hybrid",
    "light_ai": "hybrid",
    "mixed": "hybrid",
    "revised_ai": "hybrid",
}


def slugify(value: str, fallback: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip().lower()).strip("-._")
    return text or fallback


def _should_skip(path: Path, root: Path, ignore_rules: List[engine.IgnoreRule]) -> bool:
    relative = path.relative_to(root).as_posix()
    if engine.project_path_is_ignored(relative, ignore_rules):
        return True
    if any(part.startswith(".") for part in path.relative_to(root).parts):
        return True
    return False


def _source_sample_record(path: Path, corpus_root: Path, label: str, language: str) -> Optional[Dict[str, Any]]:
    if path.suffix.lower() == ".zip":
        return {"path": path.relative_to(corpus_root).as_posix(), "label": label, "kind": "project"}
    extension = path.suffix.lower().lstrip(".")
    if extension not in engine.PROJECT_CODE_EXTENSIONS:
        return None
    record: Dict[str, Any] = {"path": path.relative_to(corpus_root).as_posix(), "label": label, "kind": "file"}
    if language:
        record["language_hint"] = language
    return record


def build_manifest_from_corpus(corpus_root: Path, course: str, assignment: str, profile_id: str, label: str, language: str = "") -> Dict[str, Any]:
    if not corpus_root.exists() or not corpus_root.is_dir():
        raise ValueError(f"Corpus root does not exist or is not a directory: {corpus_root}")

    default_rules = engine.parse_ignore_patterns(engine.default_project_ignore_text())
    samples: List[Dict[str, Any]] = []
    label_counts: Dict[str, int] = {}

    for folder in sorted(item for item in corpus_root.iterdir() if item.is_dir()):
        normalised = folder.name.strip().lower().replace("-", "_")
        if normalised not in LABEL_FOLDER_MAP:
            continue
        sample_label = LABEL_FOLDER_MAP[normalised]
        for path in sorted(folder.rglob("*")):
            if not path.is_file():
                continue
            if _should_skip(path, corpus_root, default_rules):
                continue
            record = _source_sample_record(path, corpus_root, sample_label, language)
            if record:
                samples.append(record)
                label_counts[sample_label] = label_counts.get(sample_label, 0) + 1

    if not samples:
        raise ValueError("No analysable source samples were found under labelled folders such as human/, ai/ or hybrid/.")

    return {
        "profile_id": profile_id,
        "label": label,
        "course": course,
        "assignment": assignment,
        "source": "labelled-folder-corpus",
        "samples": samples,
        "folder_label_counts": label_counts,
        "notes": [
            "Generated from a labelled-folder corpus via tools/calibrate_corpus.py.",
            "The generated trigger is a local review trigger, not proof of authorship.",
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a CodeProbe calibration profile from human/ai/hybrid folders.")
    parser.add_argument("--corpus-root", required=True, help="Folder containing labelled subfolders such as human/, ai/ and hybrid/.")
    parser.add_argument("--course", default="course", help="Course identifier used in profile metadata.")
    parser.add_argument("--assignment", default="assignment", help="Assignment identifier used in profile metadata.")
    parser.add_argument("--profile-id", default="", help="Identifier for the generated profile.")
    parser.add_argument("--label", default="", help="Human-readable profile label.")
    parser.add_argument("--language", default="", help="Optional language hint applied to all file samples, e.g. python or javascript.")
    parser.add_argument("--profile", default="default", choices=sorted(engine.SCORING_PROFILES), help="CodeProbe scoring profile used for sample scoring.")
    parser.add_argument("--target-false-positive-rate", "--target-fpr", type=float, default=0.10, dest="target_fpr", help="Target false-positive review rate as fraction or percentage.")
    parser.add_argument("--config", help="Optional metric override JSON stored in the generated profile.")
    parser.add_argument("--out-dir", help="Directory for default output names.")
    parser.add_argument("--json-out", "--profile-out", dest="profile_out", help="Generated calibration profile JSON path.")
    parser.add_argument("--markdown-out", "--summary-out", "--md-out", dest="summary_out", help="Generated Markdown validation summary path.")
    parser.add_argument("--scores-out", "--csv-out", dest="csv_out", help="Generated per-sample observations CSV path.")
    parser.add_argument("--sensitivity-out", help="Generated threshold-sensitivity CSV path.")
    parser.add_argument("--manifest-out", help="Optional path to save the generated manifest used for calibration.")
    args = parser.parse_args(argv)

    corpus_root = Path(args.corpus_root).resolve()
    course_slug = slugify(args.course, "course")
    assignment_slug = slugify(args.assignment, "assignment")
    profile_id = args.profile_id or f"{course_slug}-{assignment_slug}-v1"
    label = args.label or f"{args.course} {args.assignment} local calibration".strip()

    try:
        manifest = build_manifest_from_corpus(corpus_root, args.course, args.assignment, profile_id, label, args.language)
        out_dir = Path(args.out_dir or corpus_root / "codeprobe_calibration_output").resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = Path(args.manifest_out).resolve() if args.manifest_out else out_dir / "generated_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

        forwarded = [
            "--manifest", str(manifest_path),
            "--root", str(corpus_root),
            "--profile", args.profile,
            "--profile-id", profile_id,
            "--label", label,
            "--target-fpr", str(args.target_fpr),
            "--out-dir", str(out_dir),
        ]
        if args.config:
            forwarded.extend(["--config", args.config])
        if args.profile_out:
            forwarded.extend(["--profile-out", args.profile_out])
        if args.summary_out:
            forwarded.extend(["--summary-out", args.summary_out])
        if args.csv_out:
            forwarded.extend(["--csv-out", args.csv_out])
        if args.sensitivity_out:
            forwarded.extend(["--sensitivity-out", args.sensitivity_out])
        return calibrate_profile.main(forwarded)
    except Exception as exc:
        print(f"Calibration failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
