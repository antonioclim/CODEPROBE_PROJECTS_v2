# Local calibration guide

CodeProbe should be calibrated for the course, programming language and assignment family before its numeric review trigger is treated as operational. Calibration estimates where known-human, LLM-generated and declared-hybrid code fall under the same analysis pipeline used for submissions.

A calibration profile does **not** transform CodeProbe into an authorship detector. It records a technically replayable review policy, sample counts and threshold sensitivity; institutional approval must be recorded separately so that the bundled 60% trigger is not treated as universal.

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
Manifest and corpus traversal rejects symbolic links, reparse points and special filesystem entries. Output paths must be distinct from the manifest and all samples; an output is also rejected when it is redirected through a link or placed inside a project sample.
Generated profiles replace internal sample and group identifiers with fresh per-export tokens, as described below. An explicit manifest identifier is not exported unchanged. Ordinary analysis reports retain aggregate calibration design and evaluation metadata but do not embed sample-level observations or the full sensitivity grid.

## Generate a profile

Directory-output form:

```bash
python3 -I -S -B tools/calibrate_profile.py \
  --manifest calibration/01-corpus-manifest-template.json \
  --out-dir calibration/profiles/intro-python-2026 \
  --target-fpr 10
```

Explicit-output form:

```bash
python3 -I -S -B tools/calibrate_profile.py \
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
python3 -I -S -B tools/analyze_project.py \
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

The sensitivity grid describes the fit partition only. Its human review rate is the count sent to review divided by eligible labelled-human observations, not a population false-positive probability. Selection uses the fit partition and the declared target. Evaluation is held apart from selection; a moderation decision must not silently retune the trigger against evaluation results. A changed selection protocol requires a separately documented calibration.

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

## Group-exclusive evaluation and profile scope

A generated profile must use group-exclusive fit and evaluation partitions. The review trigger is selected only on the fit partition. The untouched evaluation partition reports its own descriptive review rates. The additional pooled all-partition row is not an independent performance estimate. A profile is scoped to one report kind and one language; mixed file/project or mixed-language corpora must be split into separate profiles. Sample paths are corpus-relative or pseudonymised and failed sample reads abort generation before any profile is written.

## Duplicate-evidence boundary

Hard-linked aliases of the same filesystem object are rejected. Copied-identical, templated or semantically related samples cannot be inferred reliably from filenames alone; curators must place dependent samples in the same group and exclude duplicated evidence.
The exported `independent_holdout` flag means group-exclusive separation under the declared group identifiers and physical-source checks. It is not evidence that copied, templated or semantically related samples are statistically independent.

## Export identifier privacy

Internal deterministic keys still establish duplicate-source rejection, group equality and the fit/evaluation split. They do not appear in new sample-level exports. Only after partitioning and estimation, each sample receives a fresh UUID4 token and each distinct group receives a fresh token shared within that export. Profile JSON and observations CSV use the same tokens. Explicit manifest identifiers are also replaced, and no mapping is written. Re-running the same corpus preserves the analytical values but deliberately changes exported tokens and hence file digests.

This blocks direct guessing of a path against an exported deterministic hash; it is not anonymisation. Scores, labels, row order, group sizes and user-supplied free-text course/profile metadata may disclose or link identities. Curators must review those fields and protect input manifests and local failure diagnostics. Source ZIP/release reproducibility is distinct from deliberately random calibration-output identifiers.

## Bound scoring and feasibility

New generated profiles bind the fitted base mode, actual engine SHA-256 and
effective metric configuration to application. Manifest overrides and the
replacement `--config` override are applied before sample scoring. An omitted
mode selects the bound mode; an explicit mismatch or incompatible scope fails.
Old unbound profiles remain provisional and should be refitted before their
recorded evaluation is relied upon.

The unrounded `decision_score` drives selection and review comparisons.
`overall_score` remains the rounded presentation field. Profiles that cannot
meet the requested fit target on the configured grid remain inspectable drafts
with `operational: false`; application refuses them. Held-out evaluation reports
its own target result without influencing selection. Operational status is not
scientific validation or authorisation for high-stakes use. See
`docs/22-contract-reconciliation.md` for the precise compatibility boundary.

## Inactive thresholds and replay identity

Four retained threshold keys are deprecated because their values have no formula
consumer: `identifier_style.thresholds.ai_low`,
`identifier_style.thresholds.ai_high`,
`line_length_uniformity.thresholds.ai_high` and
`halstead_difficulty.thresholds.mi_high`. Existing valid overrides are still
accepted; Boolean, non-finite or structurally invalid values remain refused.
They do not become active tuning parameters merely because a manifest or profile
contains them.

Reports expose their abbreviated dotted names in
`tool_metadata.inactive_thresholds` and explain them in file/project notes and
text. These descriptions are outside the effective configuration. The digest
continues to include the retained threshold values: changing only an inactive
value leaves metric values and scores unchanged but changes configuration
identity. Applying that changed configuration to a profile bound to the previous
digest is refused. A digest match is a replay requirement, not proof that every
parameter influences a formula or that the profile is authentic.

Manifest overrides, or the replacement `--config`, must be fixed before sample
scoring. Generated profiles retain those validated overrides and bind their
effective configuration with the loaded engine and base mode. Omitting a
deprecated key from one override leaves the value from the remaining
configuration layers; it does not remove that key from the digested
configuration. Do not edit profile
identity fields to bypass a mismatch.

An engine change requires scoring the original curated samples again with the
declared grouping and fit/evaluation design, then reviewing the resulting
profile. This remains true for corrected identifier LTTR, register-pressure
normalisation or additional measurement metadata: the loaded engine identity
has changed. Synthetic boundary fixtures establish software behaviour only;
they are not a fitted corpus, new empirical evaluation or proof of improved
authorship detection. Metric units, finite extraction boundaries and the
declared pressure anchors are described in the
[report schema notes](03-report-schema.md#metric-values-and-measurement-scope).

## Counts, denominators and unavailable rates

The canonical `validation.descriptive_review_rates` object contains `fit`,
`evaluation` and `all`, each evaluated at the fit-selected threshold. Every
partition identifies its `unit`, sample count and distinct declared-group count.
Every label row identifies reviewed and eligible observations, all samples,
distinct groups, eligible groups and `rate = reviewed / eligible`. Thus two
reviewed human files out of four eligible files yield **2/4 = 0.5**, regardless
of whether the files belong to one group or four. Group counts are reported
separately; the files do not thereby become independent trials. For project
calibration the unit is the project report, not its constituent files.

With no eligible member of a class, `rate` is `null` and the summary displays
N/A. An observed **0/n**, where n is positive, remains an actual zero rate. The
pooled `positive` row combines AI-generated and hybrid labels and overlaps those
rows. Do not add their counts together a second time. The `all` partition pools
fit and evaluation: it is descriptive, not an additional held-out evaluation.

Legacy numeric aliases (`false_positive_rate`, `ai_generated_review_rate`,
`hybrid_review_rate` and `true_positive_rate`) remain compatible. They may store
0.0 for an absent class. The adjacent `rate_counts`,
`legacy_alias_qualification`/`legacy_rate_qualification` and new CSV
`*_reviewed`, `*_eligible`, `*_descriptive_rate` columns disambiguate that value.
A blank canonical rate in CSV is unavailable, not zero. Each sensitivity row
also names its fit partition, unit and interpretation.

Statistical independence is not established and uncertainty is not estimated.
Group-exclusive splitting does not justify a binomial interval by itself. No
fixed minimum sample count, effective sample size, confidence interval or
external detection accuracy is inferred from these descriptive counts.
`operational: true` means the fit target and scoring-identity requirements allow
technical replay. It is not institutional approval. Record adoption decisions
separately using `calibration/04-validation-summary-template.md`.

## Reference and configuration scope

The report's Evidence coverage label is a heuristic category, with the retained
`confidence` alias and explicit factors. It is not a confidence interval for a
calibration rate. Role labels, nominal weights and per-file eligible metric
weights are distinct. Enabling a custom contribution does not turn a contextual
metric or its references into validated authorship evidence. Keep the exact
engine and configuration identities with every fitted profile; source or
configuration changes can require refitting even when selected raw observations
remain unchanged.
