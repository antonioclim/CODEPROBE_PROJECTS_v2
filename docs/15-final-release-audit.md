# 15 — Final release audit

This document records the v2.2.0 naming-stable release boundary. It is an internal audit note, not an authorship-classification claim.

## Stable package areas

- `app/` — static browser interface, CSS/JS assets, runtime configuration and Pyodide vendor placeholder.
- `src/` — Pyodide-compatible Python runtime and maintainer support package.
- `tools/` — command-line analysis, calibration, local serving, release building and audits.
- `docs/` — numbered technical documentation, visual assets and chronological phase history.
- `educator/` — student and instructor course resources.
- `calibration/` — corpus manifests, profile templates and validation-report placeholders.
- `release/` — release evidence, including `release/file-rename-map.csv` and `release/release-manifest.json`.
- `tests/` — behaviour-focused regression tests.

## Final audit checks

The release pipeline verifies:

1. Python compilation for runtime, support package, tools and tests;
2. unit-test discovery;
3. JavaScript syntax for the browser scripts;
4. CSP, inline-code and local SRI checks for the browser pages;
5. browser-resource integrity for local assets and the auditable runtime;
6. version consistency across runtime, UI, documentation and changelog;
7. file and project smoke reports;
8. institutional distribution artefact presence;
9. high-confidence Markdown/HTML file references;
10. file-rename-map coverage for every release file;
11. absence of uncontrolled references to retired active paths outside approved historical/audit files;
12. release-manifest writing and verification;
13. deterministic ZIP construction and sidecar generation.

## Interpretation boundary

CodeProbe reports a heuristic AI-style concern score. The score can guide revision and manual review, but it does not prove AI authorship, misconduct or independent authorship. Any triggered case must be read together with the analysed files, excluded-file inventory, repository history, tests, design notes, disclosure and, where required, an oral walkthrough.

## Final status

The v2.2.0 package is the naming-stable release. Future features should extend the existing directories rather than reintroducing unnumbered documentation, phase-numbered test filenames, ambiguous runtime paths or duplicate active release manifests.
