# Phase 10 changeset — naming inventory, reference policy and migration map

Version: CodeProbe v2.1.10

Phase 10 does not rename runtime files yet. It establishes the controlled migration layer needed before any high-risk path changes are made.

## Added

- `docs/01-naming-policy.md` — naming rulebook for the stable package.
- `docs/00-file-catalogue.md` — complete inventory of current files and proposed final paths.
- `release/file-rename-map.csv` — machine-readable migration map.
- `tools/check_file_references.py` — high-confidence reference checker for Markdown links, HTML resources, browser integrity manifests and rename-map coverage.
- `tests/test_phase10_reference_integrity.py` — regression tests for the new reference layer.

## Updated

- `README.md` and `00-kit-index.md` now point maintainers to the naming policy and file catalogue.
- `CHANGELOG.md` records the v2.1.10 migration-control release.
- `tools/check_release.py` runs the reference-integrity audit as part of release validation.
- `tools/audit_institutional_pack.py` requires the new naming and catalogue artefacts.
- Version metadata now reports `2.1.10`.

## Reason

The next phases will rename and move many files. Without an explicit catalogue and reference checker, such a migration could easily break Pyodide loading, browser asset integrity, CLI commands, release validation, calibration examples or educator documentation.

## Acceptance criteria

- Every current file has a proposed final path.
- Proposed final paths are unique.
- High-confidence internal references resolve.
- Existing functional tests still pass.
- Release validation can rebuild the deterministic manifest and ZIP.
