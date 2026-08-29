# CodeProbe architecture

## Design overview

CodeProbe is intentionally conservative in its architecture. The student-facing runtime is a static browser application, while instructor-facing and release-facing workflows use small Python command-line scripts.

```text
app/
├── index.html              # single-file and project browser shell
├── project.html            # compact project-only browser shell
├── codeprobe-ui.js         # main browser UI logic
├── project-ui.js           # compact project UI logic
├── codeprobe.css           # main browser styling
├── project.css             # compact project styling
├── pyodide-loader.js       # runtime Pyodide loader
├── runtime-config.json     # CDN/local Pyodide deployment configuration
└── resource-integrity.json # local SRI and SHA-256 inventory

src/
├── codeprobe_runtime.py    # browser-compatible self-contained analysis engine
└── codeprobe_engine/       # maintainer-facing helper package

tools/
├── analyze_project.py      # local project/ZIP CLI
├── calibrate_profile.py    # manifest-based calibration CLI
├── calibrate_corpus.py     # labelled-corpus calibration helper
├── run_local_server.py     # localhost static server
├── check_release.py        # release validation
├── validate_release.py     # compatibility wrapper for check_release.py
└── build_release.py        # staged release-packet publisher
```

## Why `codeprobe_runtime.py` remains self-contained

The browser interface loads `codeprobe_runtime.py` into Pyodide. A single self-contained engine file has several practical advantages in a university setting:

1. students and instructors can inspect one analysis file without a build step;
2. the browser can run locally from a simple static server;
3. no server-side upload of student code is required;
4. versioned course kits remain easy to archive and compare.

The cost is that `codeprobe_runtime.py` is still large. Phase 5 therefore introduced a support package rather than immediately fragmenting the browser runtime. Phase 6 hardens the browser shell around that bundle by externalising JavaScript/CSS and making Pyodide loading configurable.

## Maintainer support package

`src/codeprobe_engine/` is not a second engine. It is a support layer for local tooling:

| Module | Responsibility |
|---|---|
| `version.py` | version and schema constants for maintenance scripts |
| `api.py` | small JSON wrappers around the browser-compatible engine entry points |
| `metrics.py` | metric inventory for release checks and documentation |
| `project_io.py` | shared folder/ZIP payload construction |
| `release.py` | release-set safety, strict manifest verification and immutable package snapshots |
| `paths.py` | path-normalisation helpers |

This structure reduces duplication while preserving the static browser contract.


## Browser shell and runtime loading

Phase 6 separates the browser shell from the engine:

```text
app/index.html / app/project.html
        ↓
external CSS + external UI JavaScript in app/
        ↓
app/pyodide-loader.js reads app/runtime-config.json
        ↓
Pyodide loads src/codeprobe_runtime.py into the browser runtime
```

The HTML pages contain no inline scripts, inline style blocks or inline style attributes. The Content Security Policy is intentionally stricter than earlier releases, while retaining the Pyodide-related allowances needed for WebAssembly and optional integrity-verified dynamic loading.

## Data flow: single-file browser analysis

```text
source code + filename
        ↓
app/index.html builds payload
        ↓
engine fingerprint is computed in browser when possible
        ↓
codeprobe_analyze(payload_json)
        ↓
file report JSON + text summary
```

## Data flow: project browser analysis

```text
ZIP or folder selection
        ↓
app/index.html or app/project.html builds file list or ZIP payload
        ↓
.codeprobeignore and built-in exclusions are applied by src/codeprobe_runtime.py
        ↓
per-file reports are produced
        ↓
project aggregate + included/excluded file inventory
```

## Data flow: CLI project analysis

```text
folder or ZIP
        ↓
codeprobe_engine.project_io builds payload
        ↓
tools/analyze_project.py calls codeprobe_analyze_project()
        ↓
JSON and/or text reports are written locally
```

## Data flow: calibration

```text
CSV/JSON manifest of labelled samples
        ↓
tools/calibrate_profile.py analyses each sample
        ↓
sensitivity table and observations CSV
        ↓
course-local calibration profile JSON
        ↓
future file/project reports record active review policy
```

## Report metadata

Each report records metadata that helps later audit:

- `generated_at_utc` — when the report was produced;
- `engine_fingerprint` — the SHA-256 fingerprint of the loaded engine where available;
- `metric_config_digest` — digest of the effective metric configuration;
- `metric_role_summary` — count of metrics by role/group;
- `tool_metadata` — version, schema and methodological labels.

These fields support reproducibility. They are not authorship evidence.

## Future extraction path

If a future version moves scanner and metric classes out of `codeprobe_runtime.py`, the support package should become the destination. The recommended order is:

1. extract language detection and scanner helpers;
2. extract report dataclasses and serialisation;
3. extract project-mode file filtering;
4. extract metric specifications;
5. add a small browser bundling step only if it remains transparent and reproducible.

## Institutional distribution layer

Phase 8 adds a distribution layer around the technical engine: `00-kit-index.md`, educator resources, signed-release guidance, release hash guidance and `tools/audit_institutional_pack.py`. These files do not affect metric computation. They ensure that the engine is distributed with the policy, evidence and audit context required for responsible classroom use.

## Phase 8 UI and review-guidance layer

The browser interface is now explicitly panel-based. Summary, manual review, metrics, text, JSON and history panels are separate DOM targets populated by renderer functions in `app/codeprobe-ui.js`. This keeps future functionality additive: a new visual feature should add a panel and renderer rather than rewriting the entire page.

Project intake is also centralised. Drag-and-drop goes through a single pathway that accepts standard `DataTransfer.files` and, where supported by the browser, directory entries from `webkitGetAsEntry`. A single ZIP is treated as project ZIP input; a single non-ZIP file is treated as file input; multiple files or folder entries are treated as project file-list input.

Reports now carry structured manual-review guidance generated by the engine. The UI only renders that data. This matters for defensibility because exported JSON, text reports and the browser view all describe the same review plan.
