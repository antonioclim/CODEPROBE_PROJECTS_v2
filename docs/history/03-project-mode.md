# Phase 3 changeset — project mode, exclusions and aggregate reporting

Release: `v2.1.3`

## Purpose

Phase 3 turns CodeProbe from a single-file self-check into a project-aware review tool. The main methodological goal is to reduce false positives caused by accidental inclusion of dependencies, starter material, generated files, minified assets, build outputs and documentation.

The project aggregate remains a heuristic concern signal. It is not evidence of misconduct and it is meaningful only after the included and excluded file lists have been reviewed.

## Engine changes

- Added `codeprobe_analyze_project(payload_json)` as a second JSON entry point for Pyodide and local tests.
- Added ZIP unpacking through Python standard-library `zipfile` and `base64`.
- Added multi-file payload support through `files: [{path, content, size_bytes}]`.
- Added deterministic path normalisation for browser and ZIP paths.
- Added automatic `.codeprobeignore` loading when a file with that name is present in the project.
- Added a documented ignore-rule subset:
  - blank lines and comments;
  - `!` negation;
  - leading `/` anchoring;
  - trailing `/` directory patterns;
  - `fnmatch` wildcards, including common `**` patterns.
- Added built-in ignore patterns for typical non-student or non-source artefacts.
- Added minified-asset detection for common JavaScript/CSS bundles.
- Added file-size and file-count limits for project analysis.
- Added per-file exclusion reasons.
- Added project report schema `2.1.3-project`.

## Browser and CLI interface changes

- Added project controls to `app/index.html` for ZIP archives and browser-supported folder uploads.
- Added a smaller dedicated `app/project.html` browser interface for users who want only project mode.
- Added `tools/analyze_project.py` for auditable command-line project reports from folders or ZIP archives.
- Added project-mode calls to the new Python entry point.
- Project mode presents the active payload as a project and reports included and excluded files explicitly.

## Project aggregation

Only files with an applicable AI-style code score contribute to the aggregate. Markdown/documentation and too-small files may be listed but do not contribute by default.

The aggregate is SLOC-weighted with a cap of 500 SLOC per file. This prevents one large file from overwhelming smaller assessed files.

## Validation added

`tests/test_phase3_project_mode.py` covers:

- automatic documentation exclusion;
- dependency exclusion through built-in ignore patterns;
- `.codeprobeignore` file exclusion;
- project-specific ignore rules;
- negated ignore rules;
- ZIP unpacking;
- project schema fields;
- text-report generation.

## Practical effect

Before Phase 3, students had to load only selected files manually. That made accidental inclusion of `node_modules/`, `dist/`, generated files or documentation likely. Phase 3 makes the exclusion process explicit, reproducible and inspectable in the exported report.

## Remaining limitations

- Folder upload in the browser interfaces uses `webkitdirectory`, which is widely available but still browser-specific.
- ZIP analysis is local inside Pyodide, but large archives can be slow.
- The aggregate is not a calibrated probability.
- `.codeprobeignore` intentionally implements a small transparent subset of gitignore semantics, not every edge case of Git's matcher.
- Starter-code detection still depends on path naming or instructor-provided ignore rules.
