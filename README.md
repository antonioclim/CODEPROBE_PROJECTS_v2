# CodeProbe evidence-contract research candidate

CodeProbe is a formative heuristic source-review implementation that keeps observation availability, measured values, interpretation policy, source localisation and consumer admission as separate records. This source-only candidate corresponds to the bounded research route described in the article **“CodeProbe: Evidence contracts for measurement, policy and source localisation in heuristic code review”**.

## Scope

This is a source-only CE19 local distribution candidate derived from the qualified CE04 native slice. It contains 28 exact CE04 components and one unchanged support helper. It is not the complete 348-file legacy application and does not restore the former global scalar, the old screenshot-threshold rule or origin-classification language as current scientific guidance.

The implementation is **not** an empirically validated AI-authorship detector, misconduct detector or authorship-probability estimator. It must not be used as a stand-alone basis for disciplinary decisions.

## Core route

- `src/codeprobe_measurement_kernel.py`: source observations and evidence coordinates;
- `src/codeprobe_interpretation.py`: explicit interpretation profiles;
- `src/codeprobe_reporting.py`: report-bundle construction and verification;
- `src/codeprobe_report_cli.py`: bounded command-line operations;
- `tools/codeprobe_s05.py`: source-only entry point;
- `schemas/`: machine-readable contracts;
- `research/`: claim, observation and acceptance records;
- `app/s05/`: standalone reader assets.

## Minimal local use

List the admitted interpretation profiles:

```text
python -I -S -B tools/codeprobe_s05.py profiles
```

The remaining commands require the explicit source path, language, profile identifier, profile digest and an absent output directory. Use `--help` before running them. The implementation refuses existing output directories and does not silently overwrite reports.

## Reproducibility boundary

The exact bounded CE09 qualification and the exact CE11 historical replay are preserved outside this repository candidate. CE09 reconstructs the retained tables and exercises the qualified CE04 slice. CE11 preserves the historical S05 comparator, including one failed predicate. The full CE11 executable package is not distributed in this source-only repository because third-party notice, source-availability and data-licence holds remain open.

The article source and editable figures are delivered separately in the CE19 submission and figure packages. They are not silently placed under the software MIT licence.

## Provenance

- CE04 complete source tree: `573c2127f47e0775f94739a5390a5aaaafbffaae`;
- CE04 commit: none;
- historical S05 commit: `78f853eff8185da170a67d9f11d159e23dde036f`;
- historical S05 tree: `218356c0dcdeb8e0025474dfb18087141d51df09`.

Do not substitute the locally repaired CE04 source into historical S05 results.

## Licence

The included CodeProbe software source remains under the existing MIT licence. No third-party executable, manuscript or figure is bundled. See `THIRD_PARTY_NOTICES.md` and `DISTRIBUTION_BOUNDARY.md`.

## Citation

Use `CITATION.cff`. Until a public release or DOI exists, cite the exact commit or archive checksum actually used.
