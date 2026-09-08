# Report schema notes

## Scope

This document describes the stable report fields that matter for course audit and release comparison. It is not a formal JSON Schema file, but it records the expected structure of CodeProbe `2.2.0` reports.

## File report

A file analysis report has schema version `2.2.0` and includes at least:

```json
{
  "schema_version": "2.2.0",
  "app_version": "2.2.0",
  "filename": "main.py",
  "language": "python",
  "detected_language": "python",
  "input_lines": 120,
  "input_sloc": 92,
  "overall_score": 0.31,
  "verdict": "Moderate AI-style concern — mixed or weak signals",
  "verdict_class": "moderate",
  "reading": "Moderate AI-style concern — mixed or weak signals",
  "reading_class": "moderate",
  "review_trigger": 0.6,
  "review_triggered": false,
  "metrics": [],
  "recommendations": [],
  "generated_at_utc": "2026-05-28T00:00:00Z",
  "engine_fingerprint": "sha256:...",
  "metric_config_digest": "sha256:...",
  "metric_role_summary": {},
  "tool_metadata": {}
}
```

Important interpretation rule: `overall_score` is an AI-style concern score, not a probability. `review_triggered` means that the score crossed the active course review trigger; it does not mean misconduct.

## Project report

A project analysis report has schema version `2.2.0-project` and includes:

```json
{
  "schema_version": "2.2.0-project",
  "app_version": "2.2.0",
  "project_name": "assignment-1",
  "candidate_file_count": 24,
  "included_file_count": 8,
  "excluded_file_count": 16,
  "contributing_file_count": 6,
  "overall_score": 0.27,
  "verdict": "Low AI-style concern",
  "verdict_class": "low",
  "reading": "Low AI-style concern",
  "reading_class": "low",
  "review_trigger": 0.6,
  "review_triggered": false,
  "language_counts": {"python": 6},
  "included_files": [],
  "excluded_files": [],
  "top_concern_files": [],
  "aggregation": {},
  "input_packaging": {
    "source": "zip|file-list",
    "common_root_detected": "repository-main",
    "common_root_stripped": true,
    "common_root_reason": "single common non-source top-level directory; treated as hosted/export ZIP wrapper"
  },
  "generated_at_utc": "2026-05-28T00:00:00Z",
  "engine_fingerprint": "sha256:...",
  "metric_config_digest": "sha256:...",
  "metric_role_summary": {},
  "tool_metadata": {}
}
```

The project aggregate is only as meaningful as its inclusion/exclusion record. Instructors should inspect `included_files`, `excluded_files` and `input_packaging` before interpreting the score. `input_packaging.common_root_stripped` records whether a GitHub/hosted-export wrapper such as `repo-main/` was removed before `.codeprobeignore` evaluation.

## Metadata fields

| Field | Meaning | Authorship evidence? |
|---|---|---:|
| `generated_at_utc` | report generation time in UTC | No |
| `engine_fingerprint` | fingerprint of the loaded `codeprobe_runtime.py` where available | No |
| `metric_config_digest` | digest of the active metric configuration | No |
| `metric_role_summary` | count of configured metrics by group/role | No |
| `tool_metadata` | version, schema and methodological labels | No |
| `engine_metadata` | compatibility alias for tool/engine metadata | No |

## Calibration fields

When a calibration profile is supplied, reports record:

- `calibration_profile_id`;
- `calibration_profile_label`;
- `calibration_profile`;
- `review_policy`;
- `review_trigger`;
- `review_trigger_percent`;
- `review_triggered`;
- `review_trigger_source`.

These fields describe the policy lens used to read the score. They do not convert the score into a statistical probability.

## Backwards compatibility

From v2.2.0 onward, reports include `reading` and `reading_class` as the preferred interpretation fields. The older `verdict` and `verdict_class` keys remain present for compatibility with scripts written before the terminology change was fully reflected in the JSON shape. External scripts should rely on `schema_version` and should not assume that all versions use the same interpretation language. Starting from Phase 1, CodeProbe intentionally uses concern/review terminology rather than probability/verdict terminology.

## Phase 8 manual-review guidance fields

From `2.2.0`, both file and project reports include a structured manual-review layer:

```json
{
  "manual_review_guidance": {
    "scope": "file|project",
    "status": "routine_documentation_only|manual_review_recommended|manual_review_required|not_applicable",
    "status_label": "manual review recommended",
    "defensibility_note": "...",
    "review_trigger_percent": 60.0,
    "review_triggered": false,
    "risk_zones": [],
    "priority_questions": [],
    "recommended_manual_steps": [],
    "evidence_to_request": []
  },
  "risk_zones": [],
  "manual_review_recommendations": []
}
```

These fields are intended for defensible human review. They are not additional proof of AI use. A risk zone identifies where an instructor should inspect code, evidence and explanation; it does not supply a misconduct conclusion.

For file reports, risk zones are usually metric-level objects. For project reports, risk zones may refer to files, input packaging, project filtering, calibration limitations or sample-size limitations. Project risk zones are especially useful for GitHub ZIP exports because they make packaging normalisation and the included/excluded inventory explicit before an aggregate score is interpreted.

## Bounded project-input metadata

Project reports now record the effective hard limits under `input_packaging.limits`. Metadata-only exclusions such as `compression_ratio_exceeded`, `project_total_byte_limit`, `encrypted_zip_entry`, `special_zip_entry` and `nested_ignore_file` are decided before excluded ZIP members are decompressed. The `calibration_scope` field records the report-kind and language domain of the profile that was actually applied.

## Replay and browser exclusion metadata

File and project JSON add `decision_score`, the unrounded value used by the
review comparison. The rounded `overall_score` remains available. New bound
calibration metadata includes `scoring_contract`, `operational` and
`operational_reason`; an absent calibration never becomes a named child policy.
Project-level calibration is not represented as independently validated
file-level calibration.

Metadata-only browser rejections are included in selected-input accounting,
with explicit caller-reported provenance and `browser_` reason prefixes. Unsafe
paths remain independently rejected. These records do not authenticate missing
contents or the selection history. See `docs/22-contract-reconciliation.md`.

## Declared and measured engine provenance

A caller-supplied `engine_fingerprint.value` remains available for compatibility,
but it is not automatically an independently verified identity. When a valid
claim is supplied, `measured_sha256` records the best-effort runtime-file digest
and `matches_loaded_source` records equality (or null when measurement is
unavailable). `declared_source` retains the supplied origin label. A contradictory
or unverifiable verified-origin label is downgraded to `caller-unverified`.
Matching packaged provenance is retained; a manual override remains unverified
even when the digest matches. These JSON fields do not authenticate a caller,
sign a report or prove the state of mutable interpreter memory.

`tool_metadata.python_runtime` reports implementation, version and platform.
Bound calibrated Python analysis requires a successful AST parse, including
project members. Calibration sample scoring enforces the same condition.
Unbound diagnostic analysis retains its warning-bearing fallback. Runtime
metadata are observations, not a universal cross-version equivalence guarantee.

## Python diagnostics and structural metadata

The Python API wrappers return the existing JSON envelope: `report` and `text`
for a file, with the additional `project_report` alias for a project. A returned
diagnostic report does not certify that the source is valid Python.

Unbound analysis catches Python tokenisation and indentation errors explicitly.
The context retains `tokenizer_error` and `ast_error`; reports expose the
corresponding `Tokenizer warning:` and `AST warning:` strings in `warnings`.
Each diagnostic identifies the exception class, line and column when available.
The underlying message is supplied by the actual interpreter and can differ
between Python versions. An unsuccessful parse retains a qualified lexical
fallback, rather than an invented AST. File JSON and text retain these warnings.
Project JSON retains member warnings in `included_files` and promotes parser
diagnostics to path-qualified project warnings, which also appear in project
text and both browser interfaces.

With `require_python_ast: true` or an applied bound calibration profile, an
included Python file must produce an AST. Otherwise analysis raises
`ValueError`; the Python wrappers propagate the refusal and no complete report
envelope is returned. The project CLI reports failure before writing reports.
Calibration sample analysis records an error and aborts profile preparation.
The browser reports a failed operation and accepts no replacement report.
Unbound diagnostic fallback must not be used as evidence that a bound profile
can evaluate the same input.

Python soft keywords are classified by their syntactic role in an accepted AST.
Ordinary identifiers named `match`, `case` or `type` retain their source spelling;
the same words in supported keyword roles are operators. Strings and comments
do not create identifiers. Syntax unsupported by the active interpreter remains
diagnosed; the absence of an AST does not justify discarding every identifier
with a soft-keyword spelling.
The language specification describes these roles in
[Python's soft-keyword rules](https://docs.python.org/3/reference/lexical_analysis.html#soft-keywords).

`FunctionInfo.parameters` is internal structural metadata, ordered as
positional-only parameters, ordinary positional parameters, the variadic
positional parameter, keyword-only parameters then the variadic keyword
parameter. The `/` and bare `*` separators are not parameter names. This restores
signature fidelity without adding a public parameter field or establishing an
effect on an existing score.
The corresponding fields are defined in
[the Python AST argument reference](https://docs.python.org/3/library/ast.html#ast.arguments).

## Python used-import ratio

The public metric remains `used_import_ratio`. For Python its denominator counts
explicit import-binding occurrences, including repeated imports and bindings in
different scopes. Its numerator counts those occurrences with a statically
associated read. Repeated reads of one binding count once. An alias is tracked
under its bound name. A plain assignment target or deletion does not itself
read that binding; augmented assignment can read it before rebinding. A
parameter or another local binding can shadow an outer import. Import, read and
rebinding order matters within a scope.

Function and generator bodies can associate a free-name read with a stable
enclosing import. If that enclosing name is rebound, unknown call or generator
consumption order makes the metric unavailable. A generator's first iterable
is evaluated immediately; its body is deferred. Conditional rebinding in
statements, short-circuit expressions or chained comparisons also requires
unavailable status rather than treating all branches as sequential execution.

The metric's `detail` and `explanation` describe the bounded static analysis.
Where supported scope and ordering rules cannot establish the association, the
metric is unavailable (`applicable: false`), with the limitation recorded. In
particular, recognised direct namespace-access calls, wildcard imports and
unresolved `global`/`nonlocal` interactions must not be presented as resolved
import use.
This is neither a Python interpreter nor a complete name resolver: it does not
prove that an import succeeds, a callable runs or a branch is reachable.
Annotation and type-parameter scopes also require qualification: their evaluation
rules differ across supported interpreter versions, including deferred
annotations in Python 3.14. They cannot automatically be treated as ordinary
immediate reads. See [Python's execution model](https://docs.python.org/3/reference/executionmodel.html).
The current conservative rule makes this metric unavailable for the whole file
when such a scope limitation is found, including an explicit AST annotation or type
parameter even if it appears unrelated to an import. It does not track aliases
of dynamic namespace operations or arbitrary effects of called code.

The internal `AnalysisContext.python_import_usage` record carries `status`,
`imported`, `used`, per-occurrence `bindings` and `limitations`. Compatibility
fields `imported_names` and `used_names` remain available, but their flattened
names are not the metric's denominator or binding-resolution result. The raw
binding inventory is not added to public JSON. Consumers should read the
existing metric applicability, value, detail and explanation fields together.
File text includes these metric fields; project JSON retains them for each
included file.

## Python function complexity and signatures

For Python, `cyclomatic_complexity` reports the mean of CodeProbe's AST decision
counts for inventoried functions. Each function starts at one. Existing node
weights remain: `if`, loops, `with`, `assert`, conditional expressions and
exception handlers add one; a Boolean operation adds the number of operands
minus one; a comprehension adds one plus its filters; non-default match cases
add one. These rules define this implementation's structural count. They do not
establish equivalence to every control-flow graph definition of McCabe
complexity.

Each function's count covers its own body. Bodies of nested functions, lambdas
and classes are excluded from that count. Expressions in nested defaults,
decorators and class bases that are evaluated while defining the nested object
belong to the enclosing callable's count. The function's own defaults and
decorators do not belong to its body count. Nested functions remain separately
inventoried, including asynchronous functions; their source ranges continue to
include decorators. The class-body exclusion is an explicit structural boundary,
even though executing a class definition also executes its class body. It is
not a claim that class construction has no runtime work.

`function_complexity_uniformity` consumes these per-function values.
`FunctionInfo.ast_signature` remains a separate full-subtree node inventory,
including nested structures. Its use by `structural_self_similarity` is not
silently changed to the complexity visitor's scope. Lambdas are excluded from
enclosing complexity bodies but are not added to the named-function inventory.
These features remain qualified structural descriptions, not evidence of
authorship or a demonstrated improvement in detection accuracy.

Python comment masking precomputes line offsets and reuses them for token
coordinates, instead of repeatedly splitting and summing the whole source.
Masking preserves character positions, line classifications and comment text;
normal context construction first normalises newlines. The bounded operation
count concerns this offset work and does not establish a wall-clock guarantee
for the whole parser or browser. Invalid input remains diagnostic fallback;
[the tokenizer documentation](https://docs.python.org/3/library/tokenize.html)
does not promise stable tokenisation of syntactically invalid Python.

## Re-fitting after an engine change

Parser changes alter the measured engine SHA-256 and can alter extracted
features. Updated metric-contract notes can also alter `metric_config_digest`.
An existing bound profile with a different engine or configuration identity is
therefore refused. Changing its digest fields would not establish that its
samples were analysed with the new extraction rules.

Re-fitting requires the original curated samples, declared groups and
fit/evaluation design to be scored with the new engine, followed by review of
the resulting profile and evaluation. Synthetic regression fixtures establish
software behaviour only; they are not a replacement empirical corpus. No
profile migration, new labelled corpus or authorship-validity claim follows
from these structural corrections.
