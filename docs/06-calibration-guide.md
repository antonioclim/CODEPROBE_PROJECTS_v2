# Local calibration guide

CodeProbe should be calibrated for the course, programming language and assignment family before its numeric review trigger is treated as operational. Calibration estimates where known-human, LLM-generated and declared-hybrid code fall under the same analysis pipeline used for submissions.

A calibration profile does **not** transform CodeProbe into an authorship detector. It records a locally approved review policy, sample counts and threshold sensitivity so that the bundled 60% trigger is not treated as universal.

## Recommended workflow

1. Collect a labelled local corpus for the assignment family.
2. Remove starter code, dependencies, generated files, build artefacts, minified assets and documentation.
3. Keep an inventory explaining why every sample belongs to `human`, `ai_generated` or `hybrid`.
4. Run the manifest-based calibration CLI.
5. Inspect the Markdown validation report and sensitivity grid.
6. Approve, revise or reject the recommended review trigger as a moderation decision.
7. Store the JSON profile and validation summary with the assignment records.
8. Rebuild the profile when the assignment, language, LLM landscape, teaching materials or course policy changes.

## Manifest format

Use `tools/calibrate_profile.py` with either a JSON manifest or a CSV manifest.

JSON example:

```json
{
  "profile_id": "intro-python-2026-v1",
  "label": "Intro Python 2026 project profile",
  "course": "Introductory Programming",
  "samples": [
    {"path": "samples/human/student_001.py", "label": "human", "language_hint": "python"},
    {"path": "samples/ai/llm_001.py", "label": "ai_generated", "language_hint": "python"},
    {"path": "samples/hybrid/project_001", "label": "hybrid", "kind": "project"}
  ]
}
```

CSV example:

```csv
path,label,language_hint,kind,notes
samples/student_001.py,human,python,file,strong process evidence
samples/llm_001.py,ai_generated,python,file,generated from same brief
samples/hybrid_project,hybrid,python,project,declared assisted project folder
```

Paths are resolved relative to the manifest location unless `--root` is supplied.

## Generate a profile

Directory-output form:

```bash
python3 tools/calibrate_profile.py \
  --manifest calibration/01-corpus-manifest-template.json \
  --out-dir calibration/profiles/intro-python-2026 \
  --target-fpr 10
```

Explicit-output form:

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

`--target-fpr` accepts either fractions (`0.10`) or percentages (`10`). The value represents the intended maximum review rate for labelled human samples, subject to the size and quality of the corpus.

## Using a generated profile

Paste the generated JSON into the browser field **Calibration profile (optional JSON)**, or use it through the CLI:

```bash
python3 tools/analyze_project.py \
  --folder path/to/submission \
  --calibration-profile calibration/profiles/intro-python-2026-profile.json \
  --json-out report.json \
  --text-out report.txt
```

The report records:

- `calibration_profile_id`;
- active `review_policy`;
- `review_trigger` and `review_trigger_percent`;
- whether the active trigger was reached;
- whether the trigger came from the bundled default or the local profile.

## Reading the sensitivity grid

The sensitivity grid reports the proportion of each labelled set that would be sent to review at each threshold. The `human` column is the false-positive review rate under the labelled human baseline. The operational trigger should be selected by balancing student fairness against the amount of manual review the course can sustain.

## Minimum quality checks before adoption

Do not approve a profile unless:

- the human sample count is large enough for a meaningful false-positive estimate;
- samples are from the same assignment family and language where possible;
- starter code and templates have been removed;
- labels are documented and auditable;
- the validation summary is retained;
- a human instructor has approved the final trigger.

## Non-negotiable caveat

A calibrated trigger is still a **review trigger**, not proof. A score above the trigger should lead to revision, explanation and evidence review, not an automatic academic-integrity conclusion. A low score means that the selected signals were not detected; it does not certify independent authorship.
