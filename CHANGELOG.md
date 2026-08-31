# Changelog

All notable changes to this project will be documented in this file.

The format is based on *Keep a Changelog* and this repository uses semantic-style version tags when releases are made.

## [Unreleased]

### Added

- Add least-privilege GitHub Actions validation across Python 3.10–3.14, with
  current stable Windows and macOS coverage and an aggregate check intended for
  default-branch protection.
- Add an LF checkout policy, an offline dependency-boundary check and an
  automated Git-tree, checkout, archive and release-packet reproducibility gate.
- Make vendored Pyodide bytes fail closed until a complete authenticated runtime
  inventory and verifier are present.

### Fixed

- Require the mandatory unit-test floor before tracked release evidence can be
  refreshed and bind that refresh to the non-evidence tree verified by the
  preceding gate.
- Prepare the complete prospective evidence set before replacement, verify
  detected-failure rollback of bytes and supported metadata and restore before
  propagating an interrupt.
- Make the standalone final audit reject a stale release manifest and remove a
  superseded static reference-audit file that was not generated or verified.
- Validate the browser resource-integrity schema, inventory, paths, sizes,
  hashes and HTML SRI values without accepting out-of-checkout resources.
- Keep deep-tree and hostile-manifest regressions stable across the supported
  Python range and report bounded failing-test identifiers without traceback
  content.
- Reject symbolic links and special filesystem entries before release readers
  run, preventing external targets from entering trusted release evidence or a
  package.
- Verify every authoritative manifest field, canonical path, size and hash
  rather than treating membership and per-file hashes as sufficient.
- Build from a manifest-verified immutable snapshot under a stable archive root,
  independent of the checkout directory name.
- Stage and verify the ZIP and both required sidecars before publication, then
  attempt complete prior-packet rollback after detected in-process failures.
- Normalise the historical CRLF file-rename map so a Windows checkout cannot
  invalidate committed resource-integrity and release evidence.

## [2.2.0] - 2026-05-29

### Changed
- Finalised the naming-stable package layout after the documentation, app, runtime, tool and test migrations.
- Renamed the package navigator to `00-kit-index.md` so it appears first in directory listings and is clearly a reading entry point.
- Moved release evidence into `release/`, including `release/release-manifest.json`, `release/file-rename-map.csv`, `release/final-audit-summary.md` and `release/final-audit-report.json`.
- Renamed the reference checker to `tools/check_file_references.py` to describe its actual responsibility.

### Added
- Final release audit documentation at `docs/15-final-release-audit.md`.
- Phase 13 change record at `docs/history/13-final-audit.md`.
- `tools/check_naming.py` for path-style and retired-path containment checks.
- `tools/final_audit.py` for the final package audit report.
- Automated checks for uncontrolled legacy path references in active documentation, UI, configuration and tooling.

### Verified
- Single-file and project smoke reports remain valid under schema `2.2.0`.
- Browser scripts, Content Security Policy, resource-integrity manifest,
  file-reference audit, naming audit, final package audit, release manifest and
  fixed-metadata packaging under the recorded toolchain all pass.

## [2.1.12] - 2026-05-28

### Changed
- Completed the runtime/UI/CLI/test naming migration planned in Phase 10.
- Moved browser-facing assets into `app/` and renamed them with short role-based names.
- Renamed the Pyodide analysis runtime from `src/engine.py` to `src/codeprobe_runtime.py`.
- Moved project analysis, calibration, local-server, release, comparison and institutional-audit scripts into `tools/`.
- Replaced phase-numbered regression test filenames with short functional names.

### Added
- Phase 12 changeset at `docs/history/12-runtime-app-tools.md`.
- `tools/README.md` and runtime/app/tool naming regression coverage.

### Fixed
- Browser runtime fetch paths, resource-integrity metadata, HTML SRI attributes, release checks and documentation now refer to the final app/runtime/tool layout.

### Validation
- Python, JavaScript, unit-test, browser-resource-integrity, institutional-package, reference-integrity and release-manifest checks pass after the high-risk file moves.

## [2.1.11] - 2026-05-28

### Changed
- Moved and renamed documentation, educator resources and calibration templates according to the Phase 10 naming policy.
- Replaced long or historical active filenames with short, ordered names where an ordered reading path exists.
- Updated active documentation, audit scripts and institutional checks to use the new `docs/`, `educator/` and `calibration/` paths.

### Added
- Phase 11 changeset at `docs/history/11-documentation-resources.md`.
- Reference-integrity coverage for the post-migration documentation and educator-resource layout.

### Validation
- Python, JavaScript, unit-test, institutional-package, reference-integrity and release-manifest checks pass after the documentation/resource migration.

## [2.1.10] - 2026-05-28

### Added

- Naming-policy document at `docs/01-naming-policy.md`.
- Complete file catalogue at `docs/00-file-catalogue.md`.
- Machine-readable migration map at `release/file-rename-map.csv`.
- High-confidence reference checker at `tools/check_file_references.py`.
- Phase 10 reference-integrity regression tests.

### Changed

- Release validation now includes a reference-integrity check before a ZIP is built.
- The institutional audit now requires the naming policy, file catalogue and rename map.
- README and kit index now direct maintainers to the migration-control artefacts before any path-level cleanup.

### Fixed

- Path naming is no longer left implicit: every current release file has a documented proposed final location and migration phase.

## [2.1.9] - 2026-05-28

### Added

- Conservative common-root stripping for hosted/GitHub ZIP exports before `.codeprobeignore` evaluation.
- `input_packaging` metadata in project reports, recording source, detected common root, stripping status and rationale.
- `docs/09-release-integrity.md`, `tools/compare_releases.py` and package-audit sidecars for release-size reconciliation.
- Deterministic release ZIP construction with normalised member timestamps and permissions.
- Phase 9 regression tests for release integrity and GitHub ZIP root handling.

### Changed

- Project reports and text exports now record packaging normalisation explicitly.
- The manual-review layer now surfaces packaging normalisation as a low-level audit item where relevant.
- Release manifests now include `total_source_size_bytes`.

### Fixed

- GitHub-style ZIP exports such as `repo-main/src/app.py` are now analysed as `src/app.py`, so anchored `.codeprobeignore` rules apply as intended.
- Release-size discrepancies are no longer interpreted from visible ZIP size alone; the release workflow now provides member-level accounting.

## [2.1.8] - 2026-05-28

### Added

- Global browser drag-and-drop for single files, multiple files, folders and GitHub-generated ZIP exports.
- Dedicated **Manual review** tab in the main interface and manual-review panel in the project-only interface.
- Structured report fields: `manual_review_guidance`, `risk_zones` and `manual_review_recommendations`.
- Metric-level and project-level risk-zone objects with evidence summaries, interpretation limits and manual actions.
- `docs/07-ui-extension-guide.md` documenting how to add future panels and renderers without changing the deployment model.
- `docs/history/08-dynamic-ui-and-review.md` and Phase 8 regression tests.

### Changed

- Text reports now include a manual-review guidance block after notes and warnings.
- Project reports now distinguish file-risk zones from filtering, calibration and sample-size review issues.
- Browser project intake now uses directory-entry traversal when available and falls back to standard file lists.

### Fixed

- The interface is no longer limited to drag-and-drop inside the editor box; dropping anywhere on the page now opens the appropriate analysis mode.
- Reports are more defensible because the numerical score is accompanied by a concrete human review plan.

## [2.1.6] - 2026-05-28

### Added

- Strict browser-resource layout: `app/codeprobe-ui.js`, `app/project-ui.js`, `app/codeprobe.css`, `app/project.css` and `app/pyodide-loader.js`.
- `app/runtime-config.json` and `app/runtime-config.example.json` for CDN, local and integrity-enforced Pyodide deployment.
- `app/resource-integrity.json` recording SHA-256 and SRI values for local browser assets.
- Optional offline vendor directory documentation under `app/vendor/pyodide/README.md`.
- `docs/04-browser-security.md`, `docs/05-offline-deployment.md` and `docs/history/06-browser-security.md`.
- Browser privacy-wipe control in the main interface.
- Phase 6 browser-security tests covering CSP, external JavaScript, local SRI and runtime configuration.

### Changed

- `index.html` and `project.html` no longer contain inline JavaScript, inline CSS or inline style attributes.
- The browser Content Security Policy no longer uses `unsafe-inline`; it keeps only the Pyodide-related allowances that remain necessary for WebAssembly and runtime loading.
- Pyodide loading now goes through a local runtime loader rather than a hard-coded CDN script tag.
- Release validation now checks external JavaScript files and browser-resource integrity.

### Fixed

- Reduced the classroom deployment trust surface by making the Pyodide CDN/local choice explicit in `runtime-config.json`.
- Added a practical path for offline deployment with a real local SHA-256 digest rather than an invented CDN integrity value.

## [2.1.5] - 2026-05-28

### Added

- Deterministic report metadata for file and project reports: `generated_at_utc`, `engine_fingerprint`, `metric_config_digest`, `metric_role_summary`, `tool_metadata` and compatible `engine_metadata` alias.
- Browser-side SHA-256 engine fingerprinting, using Web Crypto when available, for both the main interface and `project.html`.
- `src/codeprobe_engine/` maintainer support package with API wrappers, metric inventory, shared project-input helpers, release-manifest functions and version constants.
- `tools/check_release.py`, `tools/validate_release.py` and `tools/build_release.py` for repeatable release validation and release ZIP construction.
- `release/release-manifest.json` workflow through `codeprobe_engine.release`.
- `docs/02-architecture.md`, `docs/03-report-schema.md`, `docs/08-release-process.md` and `docs/history/05-release-metadata.md`.
- `tests/test_phase5_release_metadata.py` covering metadata, metric inventory and manifest verification.

### Changed

- `tools/analyze_project.py` and `tools/calibrate_profile.py` now share folder/ZIP payload handling through `codeprobe_engine.project_io`.
- Report schema constants are centralised in the engine and mirrored in `codeprobe_engine.version` for release checks.
- The optimisation roadmap now treats `codeprobe_runtime.py` as a deliberate browser bundle and the support package as the extraction seam, avoiding a hidden build step.

### Fixed

- Release validation now checks Python compilation, unit tests, optional JavaScript syntax, version consistency, smoke reports and manifest integrity.
- Exported reports expose metric-role separation directly, reducing ambiguity between authorship-style, quality, context and documentation signals.

## [2.1.4] - 2026-05-28

### Added

- Course-local calibration profiles using schema `codeprobe-calibration-profile/v1`.
- `tools/calibrate_profile.py` for manifest-driven calibration, JSON/CSV manifests, profile JSON, Markdown summaries, observation CSVs and threshold-sensitivity CSVs.
- `tools/calibrate_corpus.py` as a labelled-folder convenience wrapper for corpora organised as `human/`, `ai/` and optional `hybrid/`.
- `calibration/README.md`, profile templates, example profiles, CSV/JSON manifest templates and `validation_summary_template.md`.
- Optional calibration profile JSON input in the main browser interface and compact project interface.
- `--calibration-profile` option in `tools/analyze_project.py`.
- Report fields for `calibration_profile_id`, `calibration_profile`, `review_policy`, `review_trigger`, `review_trigger_percent`, `review_triggered` and `review_trigger_source`.
- `docs/history/04-calibration.md`.
- `tests/test_phase4_calibration.py` for calibration parsing, trigger reporting and generated profile usability.

### Changed

- The bundled 60% threshold is now described as a provisional review trigger rather than a universal threshold.
- File and project text reports now display the active local review trigger and whether it was reached.
- README, course integration guidance and project notice now explain how a local calibration profile replaces the bundled trigger.

### Fixed

- Reduced ambiguity between score bands and course review triggers by serialising both into exported reports.

## [2.1.3] - 2026-05-28

### Added

- Project mode for ZIP archives and browser-supported folder uploads in the main browser interface, with an additional compact `app/project.html` page.
- Automatic `.codeprobeignore` parsing in project mode, including comments, directory patterns, glob patterns and negated re-inclusions.
- Built-in project exclusions for dependencies, build output, generated artefacts, minified assets, binary files and documentation.
- SLOC-weighted aggregate project reports with per-file weight caps.
- `tools/analyze_project.py` for local command-line folder/ZIP analysis.
- Included-file and excluded-file inventories in JSON and text project reports.
- `tests/test_phase3_project_mode.py` covering ZIP unpacking, ignore rules and project aggregate schema.
- `docs/history/03-project-mode.md`.

### Changed

- The main browser interface now includes project controls while retaining the single-file workflow; a dedicated project browser page is also provided.
- README, course guidance, roadmap and ignore template now describe project-mode analysis rather than manual exclusion only.

### Fixed

- The kit no longer asks users to rely only on manual file selection for multi-file projects; project-mode exclusions are now auditable in the exported report.

## [2.1.2] - 2026-05-28

### Added

- `docs/history/02-parser-and-metrics.md` documenting parser-correctness and false-positive-control changes.
- JavaScript parser regression tests in `tests/test_phase2_javascript_parser.py`.
- False-positive-control tests in `tests/test_phase2_false_positive_controls.py`.
- Report-schema tests in `tests/test_phase2_report_schema.py`.
- `app_name`, `app_version` and `schema_version` fields in the JSON report.

### Changed

- Moved blank-line regularity, function-length regularity, identifier-style regularity and structural self-similarity into the context group by default.
- Expanded JavaScript function extraction to cover async functions, arrow functions, class methods and object-literal methods.
- Updated README and roadmap to identify v2.1.2 as the Phase-2 release.

### Fixed

- Masked JavaScript regex literals before brace matching, preventing regex braces from corrupting function ranges.
- Preserved ordinary division operators during JavaScript scanning.
- Corrected JavaScript function start-line reporting so preceding semicolon or delimiter lines are not absorbed.

## [2.1.1] - 2026-05-28

### Added

- `docs/10-provenance.md` to disclose the assisted-development status of the kit and the human review obligations.
- `docs/11-design-decisions.md` with methodological decisions for threshold language, Markdown handling and quality-signal separation.
- `docs/history/01-stabilisation.md` and `docs/14-optimisation-roadmap.md`.
- `tests/test_phase1_smoke.py` for a small standard-library regression suite.
- Optional local-history toggle in the browser interface; history is disabled by default.
- `--port` and `--no-browser` options in the local helper server.
- Revised student-facing announcement in `educator/`.

### Changed

- Synchronized the engine version with the public repository version line.
- Replaced probability/verdict wording with heuristic concern/reading wording.
- Excluded Markdown metrics from the AI-style code aggregate and reports them as documentation-quality context only.
- Excluded common code-quality practice metrics from the AI-style aggregate to reduce false positives for clean, typed or well-formatted code.
- Corrected lexical entropy from character-level entropy over a concatenated string to normalised token-level entropy.
- Validated JSON metric overrides in the engine; unknown metrics and unsupported keys are now rejected.
- Revised README, course guidance, project notice and disclosure template.

### Fixed

- Removed a duplicate JavaScript metric registry decorator.
- Made the text export label match the Phase-1 terminology.

## [2.1.0] - 2026-03-23

### Added

- Public-repository layout with the application moved into `src/`.
- `docs/` directory for repository media, including an interface preview image.
- `LICENSE`, `CHANGELOG.md` and `CONTRIBUTING.md` for a more complete GitHub-ready project structure.
- In-application **Course use policy** panel describing the formative role of the score and the recommended threshold below 60%.

### Changed

- Updated `README.md` for the `src/` layout and for step-by-step launch instructions on Windows, Linux and macOS.
- Updated course-facing guidance so embedded project repositories can keep CodeProbe isolated in a dedicated folder.

## [2.0.0] - 2026-03-23

### Added

- Transparent browser package with separate `index.html` and `codeprobe_runtime.py` files.
- Support for Python, JavaScript, Bash, C, C++, C# and Markdown.
- Low-level quality metrics for register pressure estimation, stack frame depth, redundant memory access, code elegance and preprocessor hygiene.
- Course-facing templates for disclosure, integration guidance and project notices.
