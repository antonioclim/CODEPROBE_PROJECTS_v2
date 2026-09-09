# Course-local calibration

Calibration records a local review policy, not an authorship probability. The bundled 60% review trigger is provisional. A generated profile is technically replayable only when its fit target and scoring-identity requirements are met; `operational: true` is not institutional approval or evidence of external validity.

## Choose one report kind

| Corpus unit | JSON template | CSV template | Generated scope |
|---|---|---|---|
| One source file per observation, one detected language | [File JSON](01-corpus-manifest-template.json) | [File CSV](01-corpus-manifest-template.csv) | `file`, for example `python` |
| One whole project per observation: folder or source ZIP | [Project JSON](01-project-corpus-manifest-template.json) | [Project CSV](01-project-corpus-manifest-template.csv) | `project` / `project` |

Do not mix file and project observations in one profile. File corpora must use one detected language. For project reports, `project` is a scope marker, not a programming language: a project may contain several supported languages. The project profile does not calibrate each child file independently. Folder and ZIP samples may share a project-only manifest when the declared study design supports that comparison.

Each template has four placeholder records: known-human and positive observations in both `fit` and `evaluation`, with four distinct declared `group_id` values. JSON and CSV counterparts have identical sample fields. This is the smallest illustrated wiring example, not a recommended research sample size. Replacing only paths can exercise the software; real adoption also requires defensible labels, grouping, sampling and a separately recorded decision. Four files, four group names and `operational: true` do not establish statistical independence.

Use `human` for a baseline supported by process evidence, `ai_generated` for documented generated examples and `hybrid` for declared assisted work with human revision. Curators must keep related authors, submissions and templates together. `group`, `student_id` and `submission_id` are accepted alternatives to `group_id`; supply one unambiguous grouping field. Labels are declarations, not facts inferred by the tool.

## Prepare a private workspace

Run the commands below from the **kit root**, containing `tools/`, `src/` and `calibration/`. `python` must resolve to the intended supported Python 3 interpreter on Windows, Linux or macOS. Where that executable is named `python3`, replace only the first word. Keep `-I -S -B`: the tools refuse startup without isolation and site suppression. These are single-line commands, so no shell-specific continuation syntax is needed.

Create a sibling directory `../codeprobe-local/`, outside both the kit and the source projects. Copy the chosen templates there as `file-manifest.json`/`.csv` or `project-manifest.json`/`.csv`. Replace sample paths with your corpus paths relative to that private directory. Do not run the shipped placeholders as though they were a distributed corpus. Input paths must remain inside the `--root`; without `--root`, they are relative to the manifest directory. Links, special files, duplicate physical inputs and invalid samples are refused.

The four commands below are alternative examples for the two units and two formats; a study does not need to fit the same corpus four times. Calibration creates its output directories. Create `../codeprobe-local/review/` yourself before the project-analysis command, because report parent directories must already exist. `project-to-review/` denotes a real project outside that report directory.

<!-- workflow-command:file-json -->
```console
python -I -S -B tools/calibrate_profile.py --manifest ../codeprobe-local/file-manifest.json --root ../codeprobe-local --out-dir ../codeprobe-local/file-output
```

<!-- workflow-command:file-csv -->
```console
python -I -S -B tools/calibrate_profile.py --manifest ../codeprobe-local/file-manifest.csv --root ../codeprobe-local --out-dir ../codeprobe-local/file-csv-output
```

<!-- workflow-command:project-json -->
```console
python -I -S -B tools/calibrate_profile.py --manifest ../codeprobe-local/project-manifest.json --root ../codeprobe-local --out-dir ../codeprobe-local/project-output
```

<!-- workflow-command:project-csv -->
```console
python -I -S -B tools/calibrate_profile.py --manifest ../codeprobe-local/project-manifest.csv --root ../codeprobe-local --out-dir ../codeprobe-local/project-csv-output
```

The default fit target is 0.10. `--target-fpr 0.05` requests 0.05; values above one are interpreted as percentages, so `--target-fpr 5` also requests 0.05. This target is not a measured population false-positive probability. Optional `--profile-id`, `--label` and `--profile-version` identify the study. A validated `--config` replaces the manifest's metric overrides before scoring; fix it before fitting.

## Inspect, then apply

Each calibration writes `calibration_profile.json`, `validation_summary.md`, `calibration_observations.csv` and `threshold_sensitivity.csv`. Explicit output flags remain available through `--help`. All destinations are validated together and encoded before publication; replacements are individually atomic, not a transaction across all files. Keep outputs distinct from consumed inputs and examine any partial-publication diagnostic.

Inspect `operational`, `operational_reason`, scope, fit/evaluation counts, group counts, the fit-selected trigger and held-out results. Exit zero means that diagnostics were written; a fit target can remain unmet. Such a profile has `operational: false` and is refused on application. The distributed [profile template](02-calibration-profile-template.json) and [example profile](03-example-calibration-profile.json) are explicitly non-operational illustrations, not profiles for students to apply.

For **file analysis**, paste a generated file profile into the main browser interface's calibration field and analyse a source file in the same language. For **project analysis**, use a generated project profile in project mode or the native project command below. Do not pass a file profile to this project command.

<!-- workflow-command:apply-project -->
```console
python -I -S -B tools/analyze_project.py --folder ../codeprobe-local/project-to-review --calibration-profile ../codeprobe-local/project-output/calibration_profile.json --json-out ../codeprobe-local/review/report.json --text-out ../codeprobe-local/review/report.txt
```

A bound profile selects its fitted scoring mode when `--profile` is omitted. Wrong report kind, file language, engine identity or effective configuration is refused. Regenerate from the curated corpus when the binding changes; editing profile hashes is not migration. Python AST and other finite-parser requirements still apply on the actual consumer runtime. A native interpreter accepting syntax does not imply that Pyodide accepts it.

## Labelled-folder convenience wrapper

Use the wrapper only when each admitted source file is a separate intended observation and the grouping assumptions are justified. Put at least two known-human and two positive groups under `independent-files/human/` and `independent-files/ai/`; `hybrid/` is also recognised. Nested directories do **not** establish author or submission groups. The wrapper assigns fallback identities per file, not inferred groups. For correlated files, explicit partitions, project folders or mixed metadata, use a scoped manifest instead. The wrapper can recognise ZIP samples as projects, but a mixed file/ZIP corpus is still rejected by the single-kind rule.

<!-- workflow-command:folder-wrapper -->
```console
python -I -S -B tools/calibrate_corpus.py --corpus-root ../codeprobe-local/independent-files --course EXAMPLE --assignment DEMO --out-dir ../codeprobe-local/wrapper-output
```

This adds `generated_manifest.json` to the four outputs. That manifest retains relative source paths and declared labels; it is private input metadata, not a sanitised observation export. The wrapper uses a bounded, non-following inventory. Empty, mixed-domain or insufficient-group corpora fail rather than silently producing a fallback profile.

## Groups, counts and privacy

Every explicit split must be supplied; each partition must contain applicable known-human and positive observations. A group cannot cross partitions or mix human and positive strata. Without explicit splits, deterministic stratified group holdout requires at least two groups per stratum. Copied-identical, templated or semantically related samples are not automatically recognised as independent or deduplicated. Physical alias rejection is a narrower check.

Internal deterministic keys support duplicate checks, grouping and partition assignment. Only after estimation are sample and distinct-group identifiers replaced with fresh UUID4 tokens. Explicit `sample_id` values are replaced too. Profile JSON and observations CSV share the same token mapping within one export, and no identity mapping is emitted. Repeating a fixed corpus preserves analytical values while tokens and export digests intentionally change. This is not anonymisation: scores, row order, labels, group sizes and free-text metadata can permit linkage. Source/release reproducibility is a separate contract. Protect manifests, generated manifests and local failure diagnostics.

Read canonical reviewed/eligible counts and separate group counts for `fit`, `evaluation` and pooled `all`. A project is one observation, not one trial per child file. An absent class has a null descriptive rate, not measured zero. The `independent_holdout` compatibility flag denotes separation from selection, not statistical independence. Small-partition warnings remain advisory; no fixed count establishes adequacy. Evaluation never selects a replacement threshold. See [the calibration guide](../docs/06-calibration-guide.md#counts-denominators-and-unavailable-rates).

## CLI migration

`--min-per-class-for-language` has been **removed**: the old parser accepted it but did not use its value. Remove it from existing scripts. It now produces an unrecognised-argument error before manifest reading or output publication. No arbitrary minimum has replaced it. Partition balance, group separation, small-corpus warnings and technical replay checks remain unchanged. This correction changes that CLI contract, not the scoring formula or engine identity.

A score at or above the active trigger prompts inspection and explanation, not a requirement to lower the number. Make changes only for identified code or documentation issues and record disclosures under the course policy. No result proves authorship or misconduct.
