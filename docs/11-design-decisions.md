# Design decisions

## DD-001: Concern score rather than probability

The engine does not estimate a calibrated statistical probability. It aggregates heuristic metric scores. For that reason, Phase 1 replaces probability/verdict language with concern/reading language.

## DD-002: 60% as a provisional review trigger

The 60% value is retained as a course-facing default because it was already embedded in the teaching workflow. It is not presented as a universal empirical threshold. Phase 4 introduced local calibration profiles so this value can be replaced per language, assignment type and local student corpus.

## DD-003: Markdown excluded from the AI-style code aggregate

Markdown metrics in this kit describe documentation structure, code-fence density, link density and prose entropy. They are not valid evidence of source-code authorship. Markdown therefore receives a documentation-only profile and no AI-style code score.

## DD-004: Quality practice is not authorship evidence

Clean code can look regular. Type hints, docstrings, consistent indentation, used imports, careful quoting and absence of commented-out code often reflect instruction, linters, formatters or good habits. Phase 1 keeps these metrics visible as quality feedback but excludes them from the AI-style aggregate.

## DD-005: Token entropy correction

The earlier implementation labelled a character-level entropy calculation as lexical entropy. Phase 1 changes this to normalised token-level entropy. The metric remains exploratory and low-weighted.

## DD-006: Local history opt-in

Reports can contain filenames, scores and details that may be sensitive in an academic-integrity context. Phase 1 disables local history by default and requires the user to enable it explicitly.

## DD-007: Configuration override validation

Metric overrides are useful for teaching experiments, but arbitrary JSON keys can make exported reports hard to interpret. Phase 1 validates overrides and rejects unknown metrics or unsupported keys.

## DD-008: Static browser delivery retained

The current deployment model remains a static browser interface plus Python-in-browser engine. This preserves auditability and avoids server-side upload of student code.

## DD-009: JavaScript regex literals must be masked before brace matching

JavaScript regex literals can contain braces and character classes that look like source-code blocks to a simple brace counter. Phase 2 adds a scanner state for regex literals so that function extraction does not misidentify regex syntax as block structure. The scanner remains heuristic; it is a pragmatic classroom analyser, not a full ECMAScript parser.

## DD-010: Formatter-shaped regularity is context, not authorship evidence

Blank-line regularity, similar function lengths, regular identifier style and structural self-similarity can be produced by formatters, style guides, repeated assignment patterns or framework conventions. Phase 2 therefore reports these metrics as context only until local calibration demonstrates discriminative value for a particular course and assignment type.

## DD-011: Project aggregates require auditable exclusions

Single-file analysis is insufficient for realistic student projects because dependencies, generated folders and documentation can distort scores. Phase 3 adds project mode so inclusion and exclusion decisions are recorded in the report rather than being left as undocumented manual choices.

## DD-012: `.codeprobeignore` uses a small transparent subset

The ignore parser intentionally implements a limited, explainable subset of gitignore behaviour. The aim is classroom auditability: a student or instructor should be able to explain why a file was excluded without needing to know every edge case of Git's matcher.

## DD-013: Project aggregation is SLOC-weighted with a cap

Project scoring weights per-file results by source lines of code because a large implementation file carries more evidence than a small helper. A per-file cap prevents one large file from dominating the aggregate and hiding unusual patterns in smaller assessed files.

## DD-014: Calibration profile separated from score calculation

Phase 4 separates the AI-style concern score from the local review trigger. The score remains the metric aggregate. The review trigger is the course policy threshold at which revision, disclosure or discussion is expected. A calibration profile may adjust the trigger and, where justified, metric thresholds or weights, but it does not transform the score into proof of authorship.

## DD-015: Manifest-first calibration

Calibration uses an explicit JSON or CSV manifest rather than implicit folder discovery. This makes sample inclusion auditable: each sample has a path, label, optional language hint, optional kind and notes. The retained `tools/calibrate_corpus.py` file is a convenience helper for simple labelled-folder corpora.

## DD-016: Sensitivity tables matter more than a single threshold

A calibration run exports a threshold-sensitivity view because the practical question is not merely "which number is best?" but how many known-human, AI-generated and hybrid samples would be sent to review at each possible trigger. The final trigger remains an instructor moderation decision, not a mechanical output.

## DD-017: Self-contained browser engine with maintainer extraction seam

Phase 5 keeps `src/codeprobe_runtime.py` as a self-contained browser runtime rather than splitting it immediately into many import-dependent modules. This protects the static Pyodide deployment model and lets students inspect the exact analysis engine without a build step. The new `src/codeprobe_engine/` package is a maintainer-facing extraction seam for CLI helpers, release checks and future modularisation.

## DD-018: Release metadata supports reproducibility, not authorship judgement

Report metadata such as `engine_fingerprint`, `metric_config_digest`, `generated_at_utc` and `tool_metadata` helps establish which kit version and metric configuration produced a report. These fields are audit metadata. They must not be used as evidence that a student did or did not use AI.

## DD-019: Release validation is part of methodological restraint

A kit used in academic-integrity contexts should be reproducible and auditable before it is rhetorically persuasive. Phase 5 therefore adds release checks, smoke reports and a file-hash manifest. The release process is designed to catch version drift, stale documentation, broken browser scripts and missing metadata before distribution.


## DD-020: Browser hardening without hiding the engine

Phase 6 externalises JavaScript and CSS from the HTML files and tightens the Content Security Policy. This reduces the browser attack surface while keeping `codeprobe_runtime.py` readable as the single source of analysis logic. The security work therefore improves packaging discipline without turning the kit into an opaque bundle.

## DD-021: Authenticate the core startup set in both CDN and local modes

CodeProbe requires the same measured Pyodide 0.25.0 core startup bytes regardless of whether they are obtained from jsDelivr or a same-origin vendor directory. The browser validates exact sizes and SHA-256 values before use, then confirms the loaded runtime and Python versions. This keeps CDN availability and offline deployment as operational choices rather than different integrity standards.

The record is intentionally limited to the startup set used by CodeProbe. Optional packages and ecosystem-wide vulnerability status remain outside the claim.

## DD-022: Privacy controls prioritise source-code non-retention

Browser history remains opt-in and stores reports rather than source code. Phase 6 adds a privacy-wipe control because report JSON and text exports can still contain sensitive metadata, filenames and metric details.

## DD-011: Institutional resources belong in the release, not in hidden course notes

Phase 8 adds student, instructor, review, deployment and hash-archiving resources directly to the kit. This prevents an apparently technical score from being separated from the human review process that gives it a defensible educational context.

## DD-012: Reading aliases with backwards-compatible verdict fields

The user-facing language is "reading" rather than "verdict". From v2.1.9, JSON reports include `reading` and `reading_class` aliases while retaining `verdict` and `verdict_class` for compatibility with earlier scripts and test fixtures.

## DD-010: Controlled naming migration before path changes

Phase 10 deliberately adds a catalogue, naming policy, rename map and reference checker before any substantial renaming. This prevents a cosmetic cleanup from breaking the browser runtime, Pyodide engine loading, `.codeprobeignore` handling, calibration tools, course documentation or deterministic release validation.
