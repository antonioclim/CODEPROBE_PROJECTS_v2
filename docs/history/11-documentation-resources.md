# Phase 11 changeset — documentation and course-resource naming

Version: CodeProbe v2.2.0

## Purpose

Phase 11 applies the low-risk part of the naming migration defined in Phase 10. It moves and shortens documentation, educator resources and calibration templates while leaving the browser runtime, UI assets, CLI scripts and tests in their Phase 10 locations.

## Renamed or moved areas

- Top-level methodology documents moved into the ordered `docs/` sequence.
- Instructor/student handouts moved from the former `educator_resources/` directory to the shorter `educator/` directory.
- Calibration templates were renamed with two-digit prefixes where they form a recommended workflow.
- Phase changesets were moved under `docs/history/` with compact chronological names.
- The interface preview image was moved to `docs/assets/interface-preview.png`.

## Deliberately unchanged

Phase 11 does not move `src/codeprobe_runtime.py`, the browser HTML/JS/CSS files, command-line tools or tests. Those higher-risk runtime moves are reserved for Phase 12.

## Validation

The Phase 11 release must pass:

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_file_references.py
python3 tools/check_release.py --write-manifest
python3 tools/validate_release.py --skip-tests
```

The acceptance criterion is that active documentation, institutional audits and reference checks use the new paths, with historical names retained only in `release/file-rename-map.csv`, `CHANGELOG.md` and phase-history notes.
