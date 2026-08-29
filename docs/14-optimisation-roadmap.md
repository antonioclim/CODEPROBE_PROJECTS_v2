# 14 — Optimisation roadmap

This roadmap records the completed generic hardening phases. Future work should be course-specific rather than another package-wide restructuring, unless new functionality requires it.

| Phase | Completed in | Main outcome |
|---:|---|---|
| 1 | v2.1.1 | cautious terminology, Markdown excluded from AI-style scoring, quality metrics separated |
| 2 | v2.1.2 | JavaScript scanner/extractor fixes and anti-false-positive tests |
| 3 | v2.1.3 | project mode, ZIP/folder handling, `.codeprobeignore` and source-only aggregation |
| 4 | v2.1.4 | local calibration profiles and threshold-sensitivity reporting |
| 5 | v2.1.5 | release metadata, maintainer support package and release validation tools |
| 6 | v2.1.6 | browser security hardening, CSP, SRI, runtime config and privacy controls |
| 7 | v2.1.7 | institutional teaching pack, review protocol and evidence rubric |
| 8 | v2.1.8 | dynamic UI, drag-and-drop intake and manual-review recommendations |
| 9 | v2.1.9 | fixed-metadata ZIP builds, package audits and GitHub ZIP-root hardening |
| 10 | v2.1.10 | naming policy, file catalogue, file-rename map and reference checking |
| 11 | v2.1.11 | documentation, educator and calibration resource migration |
| 12 | v2.1.12 | browser app, runtime, CLI and test naming migration |
| 13 | v2.2.0 | final naming-stable audit and release boundary |

## Current status

The generic kit is complete at v2.2.0. Its stable directories are `app/`, `src/`, `tools/`, `docs/`, `educator/`, `calibration/`, `release/` and `tests/`. The authoritative inventory is `docs/00-file-catalogue.md`; the machine-readable path record is `release/file-rename-map.csv`; the final release audit is `docs/15-final-release-audit.md`.

## Remaining local work

- Build a course-local calibration corpus.
- Generate and archive course-specific calibration profiles.
- Tune `.codeprobeignore` examples to match each assignment structure.
- Decide whether institutional deployment should use local Pyodide rather than the default CDN mode.
- Sign the release externally if required by local policy.
- Review the manual-review protocol annually against course practice and emerging detector limitations.
