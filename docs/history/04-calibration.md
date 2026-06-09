# Phase 4 changeset — calibration, sensitivity and local review triggers

Phase 4 moves CodeProbe beyond a fixed generic trigger. The bundled 60% trigger is retained only as an explicit provisional default. Instructors can now create, inspect and apply course-local calibration profiles built from labelled local corpora.

## Version

- Engine version: `2.1.4`
- Report schema: `2.1.4` for file reports and `2.1.4-project` for project reports
- Calibration profile schema: `codeprobe-calibration-profile/v1`

## Added

- `tools/calibrate_profile.py`, a manifest-driven calibration CLI that can write profile JSON, Markdown summaries, observation CSVs and threshold-sensitivity CSVs.
- `tools/calibrate_corpus.py`, a labelled-folder convenience wrapper for simple `human/`, `ai/` and optional `hybrid/` corpora.
- `calibration/README.md`, explaining how to construct a local corpus and generate a profile.
- `calibration/02-calibration-profile-template.json`, a blank editable schema template.
- `calibration/03-example-calibration-profile.json`, an explicitly non-validated schema example.
- `calibration/01-corpus-manifest-template.csv` and `calibration/01-corpus-manifest-template.json`, for manifest-driven corpus calibration.
- `calibration/profiles/` and `calibration/reports/` as suggested output locations.
- `calibration/04-validation-summary-template.md`, for instructor approval records.
- Browser support for pasting an optional calibration profile JSON before single-file or project analysis.
- Project-mode support for optional calibration profiles in `app/project.html`.
- CLI support for `--calibration-profile` in `tools/analyze_project.py`.
- Report fields for calibration profile ID, review policy, review trigger, trigger status and calibration metadata.
- Regression tests for calibration profile parsing, trigger status, CLI schema and generated-profile usability.

## Changed

- The README and course-facing texts now describe 60% as a bundled provisional trigger, not a methodological constant.
- JSON and text reports now distinguish the AI-style concern score from the local review trigger.
- Project reports preserve the calibration metadata used to interpret the aggregate score.
- The UI summary displays the scoring profile together with the calibration profile label.

## Calibration workflow

A local profile is generated with:

```bash
python3 tools/calibrate_profile.py \
  --manifest path/to/calibration_manifest.csv \
  --root path/to/calibration_corpus \
  --profile-id intro-python-2026-v1 \
  --label "Intro Python 2026 project calibration" \
  --target-fpr 5 \
  --profile-out calibration/profiles/intro-python-2026-v1.json \
  --summary-out calibration/reports/intro-python-2026-v1.md \
  --csv-out calibration/reports/intro-python-2026-observations.csv \
  --sensitivity-out calibration/reports/intro-python-2026-sensitivity.csv
```

The generated profile can then be pasted into the browser interface or supplied to the CLI:

```bash
python3 tools/analyze_project.py \
  --folder path/to/project \
  --calibration-profile calibration/profiles/intro-python-2026-v1.json \
  --json-out report.json \
  --text-out report.txt
```

## Methodological effect

Before Phase 4, the score bands and the 60% trigger were generic defaults. After Phase 4, the tool can record whether it is operating with:

- the default provisional policy; or
- a named course-local profile with validation evidence.

This does not turn CodeProbe into an authorship detector. It reduces arbitrary threshold use and gives instructors a defensible way to document local false-positive control.

## Limitations remaining

- Local calibration quality depends entirely on the quality and representativeness of the labelled corpus.
- Small corpora can produce unstable thresholds.
- Assignment templates and starter code must still be excluded.
- Calibration does not prove AI authorship and cannot certify human authorship.
- Metric weights remain conservative unless explicitly overridden by a profile.
