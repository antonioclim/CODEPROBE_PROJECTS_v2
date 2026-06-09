# Phase 12 changeset — runtime, app, CLI and test naming

Phase 12 activates the higher-risk naming moves that were deliberately postponed until the reference checker and file catalogue existed.

## Completed moves

- Browser files moved from `src/` to `app/`.
- The browser runtime was renamed from `src/engine.py` to `src/codeprobe_runtime.py`.
- Command-line, calibration, release and audit scripts moved from `src/` to `tools/`.
- Test files were renamed with descriptive, phase-independent names.
- `tools/run_local_server.py` now serves the package root and opens `/app/index.html`, allowing the app to fetch `../src/codeprobe_runtime.py`.
- `app/resource-integrity.json`, HTML SRI attributes, release checks and reference checks now target the canonical app/runtime layout.

## Acceptance checks

The phase is accepted only when Python compilation, the full unit-test suite, browser JavaScript syntax checks, browser-resource integrity checks, reference integrity checks and release-manifest validation pass from the renamed paths.
