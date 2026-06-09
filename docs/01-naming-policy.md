# 01 — Naming policy

This document defines the file-naming rules used by the naming-stable CodeProbe package. The objective is short, representative names without breaking runtime paths, course instructions, release scripts or report documentation.

## Principles

1. **Keep standard names standard.** `README.md`, `LICENSE`, `CHANGELOG.md`, `CONTRIBUTING.md`, `.gitignore` and `.codeprobeignore.example` retain their conventional names.
2. **Number only where sequence matters.** Documents intended to be read in order use a two-digit prefix such as `00-`, `01-`, `02-`. Runtime source files, tests and CLI tools are not numbered.
3. **Use short descriptive names.** Prefer `project-ui.js` to longer implementation-history names; prefer `07-course-integration.md` to a long unnumbered institutional title.
4. **Separate audiences by directory.** Browser assets, runtime code, maintenance tools, educator resources, calibration files and release evidence are kept in separate directories.
5. **Avoid duplicate active paths.** Retired names are not kept as active copies. Historical names belong in `release/file-rename-map.csv`, `CHANGELOG.md`, `docs/00-file-catalogue.md` and `docs/history/`.
6. **Make path changes testable.** Every rename must be reflected in the file catalogue, file-rename map, documentation, browser references, runtime config, release manifest and tests.

## Style rules

| Area | Preferred style | Example |
|---|---|---|
| sequential documentation | two-digit prefix + kebab case | `04-browser-security.md` |
| educator documents | two-digit prefix + audience/action | `05-review-protocol.md` |
| phase history | two-digit prefix + short phase title | `13-final-audit.md` |
| Python modules/scripts | snake case | `analyze_project.py` |
| browser assets | kebab case | `codeprobe-ui.js` |
| JSON/CSV templates | ordered descriptive template name | `01-corpus-manifest-template.csv` |

## Final boundary

The naming migration is complete in v2.2.0. The active path map is `release/file-rename-map.csv`; the human-readable inventory is `docs/00-file-catalogue.md`; the final release boundary is recorded in `docs/15-final-release-audit.md`.

## Acceptance rule for future path changes

A proposed name is accepted only when:

- `release/file-rename-map.csv` records the active path, target path and previous path when applicable;
- `docs/00-file-catalogue.md` reflects the active path;
- active documentation and UI text no longer point to stale paths;
- `tools/check_file_references.py` passes;
- the full release pipeline passes.
