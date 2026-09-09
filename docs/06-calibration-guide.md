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

Use one report kind per profile. The [file-only JSON](../calibration/01-corpus-manifest-template.json) and [CSV](../calibration/01-corpus-manifest-template.csv) templates contain four explicit placeholder observations, one known-human and one positive observation in each of `fit` and `evaluation`. Their declared groups are distinct. The separate [project-only JSON](../calibration/01-project-corpus-manifest-template.json) and [CSV](../calibration/01-project-corpus-manifest-template.csv) templates use whole folders or source ZIPs as observations.

Four observations illustrate the software contract, not a recommended study size. Replacing only the paths can exercise a template; actual labels, grouping and sampling need independent justification. Neither an invented group name nor `operational: true` establishes an independent author or a statistically adequate corpus. CSV/JSON counterpart sample fields are semantically identical; JSON can additionally carry study-level metadata.

A file profile is restricted to one detected language. A project profile uses the scope marker `project`, regardless of the supported languages inside its member files. It calibrates the project aggregate, not each child file. File and project observations cannot be mixed. Project folders and ZIPs may share a project-only manifest where the sampling design justifies that choice.

`path`, `label`, `kind`, `language_hint`, `group_id` and `split` are the illustrated sample fields. The accepted group aliases are `group`, `student_id` and `submission_id`; use one unambiguous grouping field. Every explicit split must be present. A group cannot cross partitions or mix known-human and positive strata. Both partitions require applicable human and positive observations. With no explicit splits, deterministic stratified group holdout requires at least two groups per stratum. The labelled-folder wrapper does not derive groups from nested author/submission directories: use a manifest for related files.

Paths are relative to the manifest directory unless `--root` supplies the common corpus root; they must remain inside that root. Symlinks, special files, duplicate physical source aliases, invalid samples and destinations overlapping inputs are refused. The wrapper's generated manifest still contains relative source paths and is private. Random observation tokens do not anonymise the input manifest.

## Commands and outputs

Use the [single-line, cross-platform command examples](../calibration/README.md#prepare-a-private-workspace). They specify the kit working directory, a private sibling workspace, separate file/project manifests and outputs outside the source projects. Keep `-I -S -B`; omitting isolation or site suppression is a startup error. The project report directory must already exist, while calibration creates its output directories.

The manifest CLI writes a profile, validation summary, observations CSV and fit-sensitivity CSV. The folder wrapper additionally writes a generated manifest. Output validation and encoding precede publication, but individual atomic replacements do not constitute a transaction across all outputs; examine partial-publication errors.

`--target-fpr` specifies a fit-partition target, not an achieved population error probability. The default is 0.10; 0.05 and 5 both request 0.05 under the retained fraction/percentage convention. Study identifiers, explicit output paths and configuration overrides remain documented by `--help`.

The ignored `--min-per-class-for-language` argument has been removed. Delete it from scripts; it is now rejected before input reading or output publication. This does not introduce an arbitrary sample-size minimum or change the score/threshold-selection formula. The existing partition balance, small-partition warnings and technical operational tests remain in force.

## Using a generated profile

A generated **file** profile belongs in file analysis of the same language. A generated **project** profile belongs in browser project mode or `tools/analyze_project.py`; do not apply a file profile with that command. The [calibration workflow](../calibration/README.md#inspect-then-apply) includes a complete project generation/application sequence.

Inspect `operational`, `operational_reason` and `scope`, not just exit status. Successfully written diagnostics can describe an unmet fit target and a non-operational profile. The distributed profile template and example explicitly set `operational: false` and cannot be applied. Generate profiles from the curated corpus; do not activate an illustration or substitute guessed digest fields.

Reports expose the active policy, trigger, trigger status, profile identity and compact aggregate validation. Individual observations and the full sensitivity grid do not appear in compact report validation. Omitted scoring mode selects the bound mode; an incompatible mode, configuration, engine or report scope is refused. Native and Pyodide consumers must each meet their actual parser requirements.

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

A calibrated trigger is still a **review trigger**, not proof. A score at or above the active trigger should prompt code inspection, explanation and evidence review, not an automatic academic-integrity conclusion. Revise only for identified issues, not to force a lower score. A low score is not evidence of independent authorship.

## Group-exclusive evaluation and profile scope

A generated profile must use group-exclusive fit and evaluation partitions. The review trigger is selected only on the fit partition. The untouched evaluation partition reports its own descriptive review rates. The additional pooled all-partition row is not an independent performance estimate. A file profile is scoped to one report kind and one detected language. A project profile uses the `project` scope marker and may contain supported mixed-language members. Separate file/project corpora; do not infer per-language validity from a project profile. Input manifests retain paths, whereas sample-level observation exports replace identifiers. Failed sample reads abort generation before any profile is written.

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
