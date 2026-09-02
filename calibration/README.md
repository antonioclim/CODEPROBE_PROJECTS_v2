# Course-local calibration

CodeProbe's bundled thresholds are deliberately provisional. They are useful for formative self-review, but they are not empirical evidence for a specific course, programming language or assignment type. Phase 4 introduced calibration workflows that let an instructor replace the generic 60% review trigger with a local, documented profile.

Keep the actual calibration corpus outside the student-facing repository. Retain only templates, profiles that have been approved for distribution, and validation summaries that do not disclose student identities.

## Useful labels

- `human` — local baseline code with strong process evidence;
- `ai_generated` — LLM-generated code for the same or comparable prompts;
- `hybrid` — declared AI-assisted code with substantive human revision.

## Option A: labelled folders

Use `tools/calibrate_corpus.py` when the corpus is organised as labelled folders:

```text
calibration_corpus/
├── human/
├── ai/
└── hybrid/
```

Command:

```bash
python3 tools/calibrate_corpus.py \
  --corpus-root path/to/calibration_corpus \
  --course intro-python-2026 \
  --assignment project-1 \
  --target-false-positive-rate 0.05 \
  --json-out calibration/intro-python-2026-profile.json \
  --markdown-out calibration/intro-python-2026-validation.md \
  --scores-out calibration/intro-python-2026-scores.csv
```

## Option B: manifest inventory

Use `tools/calibrate_profile.py` when each sample needs explicit metadata, or when files, project folders and ZIP archives are mixed.

CSV manifest:

```csv
path,label,language_hint,kind,notes
samples/student_001.py,human,python,file,strong process evidence
samples/llm_001.py,ai_generated,python,file,generated from same brief
samples/hybrid_project,hybrid,python,project,declared assisted project folder
```

JSON manifest:

```json
{
  "profile_id": "intro-python-2026-v1",
  "label": "Intro Python 2026 project profile",
  "course": "Introductory Programming",
  "samples": [
    {"path": "samples/human/student_001.py", "label": "human", "language_hint": "python"},
    {"path": "samples/ai/llm_001.py", "label": "ai_generated", "language_hint": "python"},
    {"path": "samples/hybrid_project", "label": "hybrid", "kind": "project"}
  ]
}
```

Use `01-corpus-manifest-template.csv` or `01-corpus-manifest-template.json` as the starting point.

Command:

```bash
python3 tools/calibrate_profile.py \
  --manifest calibration/01-corpus-manifest-template.json \
  --out-dir calibration/profiles/intro-python-2026 \
  --target-fpr 10
```

Explicit output paths:

```bash
python3 tools/calibrate_profile.py \
  --manifest calibration/01-corpus-manifest-template.csv \
  --profile-id intro-python-2026-v1 \
  --label "Intro Python 2026 project profile" \
  --target-fpr 10 \
  --profile-out calibration/profiles/intro-python-2026-profile.json \
  --summary-out calibration/reports/intro-python-2026-validation.md \
  --csv-out calibration/reports/intro-python-2026-observations.csv \
  --sensitivity-out calibration/reports/intro-python-2026-sensitivity.csv
```

## Use the generated profile

Paste the JSON file into the browser interface under **Calibration profile (optional JSON)** or supply it to the CLI:

```bash
python3 tools/analyze_project.py \
  --folder path/to/project \
  --calibration-profile calibration/profiles/intro-python-2026-profile.json \
  --json-out report.json \
  --text-out report.txt
```

## How to read the validation summary

The generated Markdown report contains:

- sample counts by label;
- language counts where available;
- score distributions by label;
- the suggested local review trigger;
- a sensitivity table across candidate thresholds;
- skipped-sample or error notes.

A profile is not strong enough for operational use if the human baseline is very small, labels are unreliable, one assignment type dominates, or the same code template appears in both human and AI-generated samples. Keep the generated profile with the course records, because the threshold is only defensible together with its validation summary.

## Ethical constraint

The calibration profile changes only the local review trigger and, optionally, metric overrides. It must not be used as automatic misconduct evidence. It is a way to reduce false positives and document local assumptions.

## Required fit/evaluation boundary

Use either an explicit `split` column/value (`fit` or `evaluation`) for every sample or allow the tool to create a deterministic stratified group holdout. Supply `group`, `student_id` or `submission_id` whenever several files come from one author or submission so related samples cannot cross partitions. At least two known-human groups and two positive groups are required. Generated observations never export absolute local paths.
The folder wrapper inspects a bounded, non-following file inventory. It rejects links and special entries, and generated manifests or profile outputs may not overwrite samples or use redirected output paths.
Sample paths are replaced with deterministic pseudonyms unless the manifest supplies a deliberate, non-sensitive `sample_id`. Reports created with a profile expose only compact aggregate validation metadata, not sample-level observations.

## Duplicate-evidence boundary

Hard-linked aliases of the same filesystem object are rejected. Copied-identical, templated or semantically related samples cannot be inferred reliably from filenames alone; curators must place dependent samples in the same group and exclude duplicated evidence.
The exported `independent_holdout` flag means group-exclusive separation under the declared group identifiers and physical-source checks. It is not evidence that copied, templated or semantically related samples are statistically independent.
