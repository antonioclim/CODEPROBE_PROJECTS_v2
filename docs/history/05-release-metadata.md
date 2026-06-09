# Phase 5 changeset — architecture, release metadata and validation

- Engine version: `2.1.5`
- File report schema: `2.1.5`
- Project report schema: `2.1.5-project`
- Release type: architecture and release-validation release

Phase 5 does not change the basic classroom interpretation of the score. CodeProbe remains a local, heuristic, formative review aid. It reports AI-style concern signals, quality signals and contextual information; it does not prove AI use, identify a model or certify human authorship.

## Main changes

### 1. Release and report metadata

File and project reports now include deterministic audit metadata:

```json
{
  "generated_at_utc": "...",
  "engine_fingerprint": "sha256:...",
  "metric_config_digest": "sha256:...",
  "metric_role_summary": {"authorship": 4, "quality": 10, "context": 12},
  "tool_metadata": {"app_version": "2.1.5", "methodology": "heuristic-concern-not-authorship-verdict"}
}
```

The metadata is intended to support reproducibility and release audit. It must not be read as additional evidence of student authorship.

### 2. Browser-computed engine fingerprint

The browser interfaces compute a SHA-256 fingerprint of the loaded `codeprobe_runtime.py` source through the Web Crypto API when available. The fingerprint is passed into the analysis payload and recorded in the exported report. Where browser hashing is unavailable, the report records an explicit fallback value rather than pretending that integrity metadata is present.

### 3. Maintainer-facing support package

Phase 5 introduces `src/codeprobe_engine/` as a clean maintenance seam:

```text
src/codeprobe_engine/
├── __init__.py
├── api.py
├── metrics.py
├── paths.py
├── project_io.py
├── release.py
├── version.py
└── README.md
```

The browser-facing runtime remains `src/codeprobe_runtime.py` because a single auditable file is still the simplest and safest Pyodide delivery model for classroom use. The support package removes duplicated CLI helper logic and prepares the project for future modular extraction.

### 4. Shared project-input helpers

`tools/analyze_project.py` and `tools/calibrate_profile.py` now share folder/ZIP payload construction through `codeprobe_engine.project_io`. This reduces the risk that the CLI project analyser and calibration utilities interpret the same input differently.

### 5. Release validation scripts

The release now includes:

```text
tools/check_release.py
tools/validate_release.py
tools/build_release.py
```

`check_release.py` performs Python compilation checks, unit tests, JavaScript syntax checks where Node.js is available, version-consistency checks, smoke analyses, metric-inventory checks and release-manifest verification. `build_release.py` validates the release and builds a ZIP archive.

### 6. Release manifest

`release/release-manifest.json` can be generated with:

```bash
python3 tools/check_release.py --write-manifest
```

The manifest records release file paths, sizes and SHA-256 hashes. This supports institutional archiving and later comparison between the kit used by students and the kit used in review.

## Validation performed for Phase 5

The release was validated with:

```bash
python3 -m py_compile src/codeprobe_runtime.py tools/run_local_server.py tools/analyze_project.py tools/calibrate_corpus.py tools/calibrate_profile.py tools/check_release.py tools/validate_release.py tools/build_release.py src/codeprobe_engine/*.py
python3 -m unittest discover -s tests -v
python3 tools/check_release.py --write-manifest
```

The unit-test suite contains 32 tests after Phase 5. The new tests cover report metadata, metric inventory access and release-manifest verification.

## Known non-goals for Phase 5

Phase 5 does not fully split `codeprobe_runtime.py` into independent scanner/metric/scoring modules. That would make local CLI development cleaner, but it would also complicate the static browser delivery model and require a bundling step. The current compromise keeps `codeprobe_runtime.py` self-contained for students and creates `src/codeprobe_engine/` for maintainers.

Phase 5 also does not claim empirical detector validity. Local calibration remains required for course-specific thresholds, and human review remains required for any consequential interpretation.
