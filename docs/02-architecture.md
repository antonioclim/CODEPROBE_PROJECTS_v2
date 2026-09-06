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
├── pyodide-loader.js       # verified runtime loader
├── pyodide-provenance.json # measured core-startup provenance
├── runtime-config.json     # CDN/local runtime and integrity policy
└── resource-integrity.json # local SRI and SHA-256 inventory

src/
├── codeprobe_runtime.py    # browser-compatible self-contained analysis engine
└── codeprobe_engine/
    ├── process_control.py  # bounded process and process-tree boundary
    ├── server.py           # allowlisted local static server
    └── release.py          # release snapshot and publication boundary

tools/
├── analyze_project.py      # local project/ZIP CLI
├── calibrate_profile.py    # manifest-based calibration CLI
├── calibrate_corpus.py     # labelled-corpus calibration helper
├── run_local_server.py     # constrained local application server
├── check_coverage.py       # supported-code line-coverage gate
├── check_pyodide_provenance.py # runtime provenance validator
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

## Maintainer execution boundaries

The browser application does not launch native processes. Maintainer tools that need Git, Python, Node or another local executable use `codeprobe_engine.process_control.run_bounded_process`. The broker prohibits shell execution, limits `stdout` and `stderr` independently, applies a wall-clock deadline and terminates the process tree using a POSIX process group or a Windows Job Object. The dependency checker rejects direct process launch outside that module.

`codeprobe_engine.server` is similarly narrow. It serves only the browser pages, their declared assets, the browser-compatible runtime and an optional versioned Pyodide vendor subtree. Repository documents, tests and release metadata are outside the HTTP allowlist. The reusable factory enforces loopback by default rather than relying on the CLI alone.

## Release publication recovery boundary

`tools/build_release.py` owns release-packet orchestration while
`codeprobe_engine.release` owns the manifest-verified snapshot and archive
semantics. Publication uses a packet-specific JSON lock and a versioned,
fsynchronised transaction journal. The checksum sidecar is withdrawn before
public mutation and installed last as the readiness marker. Recovery compares
public bytes with the recorded new and prior identities, then retains the
complete new packet, restores the prior packet or stops fail-closed on an
unknown concurrent value. The detailed state machine and platform limitations
are defined in `docs/19-release-recovery.md`.

## Coverage extraction seam

Coverage policy and collection live in `tools/check_coverage.py` rather than in the release builder or the analysis engine. This keeps measurement orthogonal to product behaviour. The collector uses `sys.monitoring` to observe executable lines in maintained Python files, while the full test suite, Chromium job and release reproducibility remain separate gates. The sole excluded production path is the coverage driver itself because it must configure the monitor before measurement begins.

## Worker execution boundary

The page controls one cancellable session. Authenticated loader and worker bytes create a classic worker, which alone initialises Pyodide and imports the verified Python engine. The protocol admits only initialisation and fixed file/project operations. Cancellation and timeout terminate the worker; request identity and UI generations exclude late results. See [worker resilience](20-worker-resilience.md).
