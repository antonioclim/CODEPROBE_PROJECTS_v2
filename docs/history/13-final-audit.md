# Phase 13 — Final audit and naming-stable release

Version: CodeProbe v2.2.0

## Purpose

Phase 13 closes the naming migration. Earlier phases introduced the reference map, moved documentation and educator resources, and then moved the browser UI, runtime, command-line tools and tests. This phase freezes those decisions into a naming-stable package.

## Changes

- The final generic release version is `2.2.0`.
- The package navigator is `00-kit-index.md`, so it appears before the longer documentation sequence.
- Release evidence is kept under `release/`, including `release/file-rename-map.csv` and `release/release-manifest.json`.
- The final release-audit note is `docs/15-final-release-audit.md`.
- The reference checker treats retired active paths as errors unless they occur in controlled history/audit locations.
- Browser resource-integrity metadata is verified against the current runtime and app assets.

## Acceptance criteria

The phase is accepted only when the full release pipeline passes, the release ZIP builds deterministically, and the active documentation, UI, configuration, tests and tools refer to the final path names. Historical names are retained only in the changelog, phase history, file catalogue, file-rename map and explicit regression tests.

## Deterministic audit note

The machine-readable final audit report uses a fixed release timestamp so that repeated source builds produce byte-identical ZIP archives. The ZIP sidecar records the actual package SHA-256 after packaging.
