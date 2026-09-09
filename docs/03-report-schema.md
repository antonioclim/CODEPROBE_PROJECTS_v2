# Report schema notes

CodeProbe v2.2.0 serialises reports as JSON and human-readable text. The JSON report is intended for traceable formative review, not automated disciplinary decisions.

## File report

The canonical file report uses schema `2.2.0`. Important fields include:

- `filename`, `language`, `loc` and `sloc`: source identity and retained line counts. `loc` counts LF-split segments after newline normalisation (empty input gives zero; a final newline adds an empty segment), while `sloc` counts non-blank segments including comments, not executable statements;
- `metrics`: an array of metric records, each with applicability, value, interpretation, weight and role;
- `overall_score`, `overall_percent`, `overall_applicable`, `decision_score`: rounded presentation, applicability and the unrounded review-comparison value;
- `reading` and `reading_class`: preferred interpretation fields;
- `verdict` and `verdict_class`: compatibility aliases, not disciplinary verdicts;
- `review_policy`, `review_trigger`, `review_triggered`: the active policy and inclusive applicable-score comparison;
- `warnings`, `notes`: limitations and explanatory metadata;
- `manual_review_guidance`, `risk_zones`, `manual_review_recommendations`: structured contextual review guidance and an array of recommendation strings;
- `engine_fingerprint`: an object, not a digest string; inspect its availability and provenance;
- `metric_config_digest`: a 64-character lower-case hexadecimal SHA-256 without a `sha256:` prefix, identifying the effective metric configuration;
- `tool_metadata` and `engine_metadata`: tool identity, execution metadata and compatibility alias.

The previous illustrative names `detected_language`, `input_lines`, `input_sloc` and `recommendations` are not the emitted canonical keys. Do not manufacture those fields from a schema example or rename the runtime output to match obsolete documentation. `loc` and `sloc` are integer observations with the conventions above, not necessarily physical-line or executed-statement counts. Read parser qualifications and applicability separately.

## Project report

The canonical project report uses schema `2.2.0-project`. In addition to common score, policy and provenance fields, it includes:

- `project_name`, `language: "project"`: the latter is a report-unit marker, not a programming language;
- `included_file_count`, `excluded_file_count`, `contributing_file_count`, `total_sloc`;
- `included_files`, `excluded_files`: per-member reports or exclusion records;
- `input_packaging`: source-container normalisation, effective limits and intake details;
- `calibration_profile` and `calibration_scope`: active project calibration when supplied;
- project-level manual-review guidance and member-qualified warnings.

The Python API returns a `report`/`text` envelope; the project API additionally retains `project_report` as an alias. The native project CLI writes the project report object directly to its JSON destination. An analysis JSON report is not a calibration profile. Names, timestamps, scores and hashes are input/runtime dependent; consumers should not hard-code an example's incidental values.

### Measured example projections

These are **stable-field projections of reports generated from a synthetic Python fixture**, not complete reports, an empirical corpus or fabricated engine hashes. The file fixture has 23 physical `splitlines()` records including blank lines and a final newline: the retained `loc` convention yields 24 LF-split segments, while `sloc` is 17 non-blank segments. Four ordinary functions make the file aggregate applicable in the tested runtimes. The project contains that one source as `main.py`.

<!-- report-example:file -->
```json
{
  "filename": "example.py",
  "language": "python",
  "loc": 24,
  "sloc": 17,
  "schema_version": "2.2.0",
  "overall_applicable": true
}
```

<!-- report-example:project -->
```json
{
  "project_name": "example-project",
  "language": "project",
  "schema_version": "2.2.0-project",
  "included_file_count": 1,
  "excluded_file_count": 0,
  "contributing_file_count": 1,
  "total_sloc": 17
}
```

The maintained workflow regression generates these reports and verifies their keys, types and values against the projections. It also checks the recommendation-array, fingerprint-object and configuration-digest contracts on the actual reports. It does not create a new wire field or certify every parser input.

## Evidence coverage, roles and contributions

`evidence_coverage` is the canonical name for the existing heuristic category.
`confidence` remains an equal compatibility alias. Neither field is a statistical
confidence interval, probability of authorship, calibration reliability estimate
or guarantee that the observations are correct. The browser labels the category
**Evidence coverage**; JSON, text and both project interfaces retain its basis.

`evidence_coverage_basis` identifies the rule, inputs and decision factors. File
rules retain the existing thresholds: low below 20 SLOC, 120 tokens or three
applicable stylometry-role metrics; high at least 80 SLOC, 500 tokens and six
such metrics; otherwise medium. These role counts are not the configured
contribution count. The file rule does not test every parser warning and can
remain high in a report whose concern aggregate is inapplicable; its basis states
that separation rather than implying universal reliability.

Project coverage is high at 200 total SLOC, at least three contributing files and
no warning present when the category is selected; medium at 80 SLOC and at least
two contributors; otherwise low. `warning_count_at_category_selection` is recorded
before the separate final filtering warning. `report_warning_count` includes the
complete final warnings. Thus a late filtering warning can coexist with the
previously selected high category; the reason is explicit. No confidence rule or
threshold has been silently retuned by the label change.

`metric_role_summary` retains inventory counts by role. A role describes the
metric's intended interpretation, not an absolute contribution ban. The default
effective configuration enables seven concern contributors. A validated custom
positive-weight `contributes_to_ai: true` can include a quality, context or
documentation-role metric; this is a policy override, not validation of that
metric as authorship evidence. `enabled`, `contributes_to_ai` and role are distinct
from whether the metric was actually applicable to the supplied file.

| Metadata layer | Meaning |
|---|---|
| `metric_role_summary.ai_contribution_count` and `.ai_weight_sum` | Nominal enabled contributors with `contributes_to_ai: true` and positive weight, across all roles in the effective configuration. |
| `configured_ai_contributing_metrics`, `configured_ai_contributing_metric_ids`, `configured_ai_weight_sum` | Explicit nominal file/project metadata using that same configuration predicate. |
| File `ai_contributing_metrics`, `ai_contributing_metric_ids`, `effective_ai_weight_sum` | Actual applicable positive-weight contributors admitted into that file's denominator. |
| `overall_applicable` | Whether the separate report eligibility requirements permit an aggregate; it is not implied merely by a non-zero denominator. |

Disabled metrics, zero weights and false contribution flags do not enter the
nominal sum. Native weights retain finite clamping to the existing range; invalid
Boolean flags, non-finite values and unknown roles remain refused. Project JSON
carries its nominal configuration while included child reports carry their
actual file denominators. Project text retains that distinction for each child.
Markdown remains outside the overall code aggregate, and ordinary project
admission still excludes documentation. Enabling an inapplicable metric does not
invent a measured value.

## References and source-level proxies

Metric `detail.references` records descriptive attribution entries with `text`,
`doi`, `url`, `relationship` and `scope`. The relationship is one of `definition`,
`motivation` or `context`: a source can define a family of measures without
validating CodeProbe's particular vocabulary, normalisation, thresholds or
weights. `detail.reference_scope` states that distinction, which text exports
retain. A verified DOI or URL is not evidence that the cited work validates a
review trigger, a hardware claim or authorship detection. The revised reference
metadata does not alter the effective metric configuration digest; the changed
engine file still changes the engine identity and requires refitting bound
profiles.

Applicable memory-related observations additionally carry optional
`measurement_method`, `measurement_unit` and `measurement_domain` metadata.
Their raw proxy values remain visible; the display, explanation and browser
quality panel identify them as **source-level memory proxies**.

| Metric | Declared method and unit | Actual scope |
|---|---|---|
| `register_pressure` | `source_scalar_live_range_proxy` / `estimated_live_scalars/fixed_register_budget` | Maximum estimated per-function peak from admitted scalar declarations, divided by the fixed heuristic budget 13. It is not allocated registers or measured spills. |
| `stack_frame_depth` | `source_stack_layout_proxy` / `weighted_source_stack_proxy` | Existing mixture of assumed local sizes, parameter counts, nesting and a direct-recursion cue. It is not emitted stack-frame bytes or measured call-stack depth. |
| `redundant_memory_access` | `source_index_expression_repeat_proxy` / `repeated_index_expressions/weighted_memory_patterns` | Repeated source index expressions and existing weighted patterns, not dynamic loads/stores, alias analysis or proven redundant instructions. |

The fixed type widths, frame overhead, recursion multiplier and register budget
are assumptions. They are not derived from a target architecture, compiler, ABI,
optimisation level, alias/escape analysis or hardware counters. Dependent parser
features must still be available; an unavailable metric omits measurement
metadata rather than claiming a method produced a zero result. These metrics
keep their existing default quality role. Better source extraction or labels
do not validate their normalisation as an objective quality judgement.

## Metric values and measurement scope

### Cyclomatic observations

The public `cyclomatic_complexity` metric retains three existing calculations,
now explicitly distinguished by optional string fields on an applicable metric
record:

| `measurement_method` | `measurement_unit` | `measurement_domain` |
|---|---|---|
| `python_ast_mean_function_decisions` | `decisions/function` | Python AST-inventoried function bodies under CodeProbe's declared node-count rules. |
| `lexical_mean_function_decisions` | `decisions/function` | Extracted non-Python function intervals under the finite lexical branch-cue rules. |
| `lexical_branch_density` | `branches/20 code lines` | Whole-source lexical branch cues without an available function inventory. This is a density proxy, not a graph cyclomatic number. |

The Python AST calculation is a mean of this implementation's decision counts,
not a claim of equivalence to every McCabe control-flow graph definition. The
non-Python mean also has finite extraction scope; nested callable bodies can
remain in an enclosing lexical count. Without extracted functions, supported
non-Python code retains the existing `branches * 20 / code_line_count` fallback.
The generic branch cues are distinct `if`, `for`, `while`, `case`, `catch`,
`except` and `elif` words plus `&&`, `||` and `?`, outside the masked literal and
comment text. `code_line_count` follows the existing physical line categories:
blank lines and any line identified as a comment line are excluded. A code line
with an inline comment can therefore also be excluded from that retained
 denominator. Python without parsable functions remains unavailable.

For example, function counts 1 and 3 have mean 2 decisions/function; two branch
cues in ten code lines have density 4 branches/20 code lines. These examples do
not make the units interchangeable. Existing raw values and score normalisation
are retained; adding labels alone does not change a score. `value_display` now
includes `decisions/function` or `branches/20 code lines`, so consumers needing
a number should use `value`. `detail` identifies the method, unit and domain. File
JSON/text and project member JSON retain the descriptions; project text includes
each member's applicable cyclomatic observation. Browser displays and exports
consume these same display/detail fields.

The three fields are optional: unrelated and unavailable metric JSON objects
omit them. Internal `MetricResult` defaults them to empty strings. An unavailable
result does not certify a method merely because a language was detected.
Schema versions remain `2.2.0` and `2.2.0-project`.

### Inactive configuration thresholds

`tool_metadata.inactive_thresholds` lists these retained, deprecated keys:

| Dotted metadata name | Formula status |
|---|---|
| `identifier_style.ai_low` | Inactive; identifier style retains its existing fixed component constants. |
| `identifier_style.ai_high` | Inactive; identifier style retains its existing fixed component constants. |
| `line_length_uniformity.ai_high` | Inactive; the formula consumes `ai_low` and `human_high`. |
| `halstead_difficulty.mi_high` | Inactive; the formula consumes `ai_low` and `ai_high`. |

The names abbreviate each metric's `thresholds` object. File and project
`notes`, also rendered in text, explain that these values remain in the
configuration and its digest but do not affect their formulas. This is a note,
not a warning that changes the confidence calculation. Accepted finite numeric
overrides remain compatible; invalid structures, Boolean and non-finite values
remain refused. This list does not claim that arbitrary caller-defined threshold
names have formula consumers.

Changing an inactive value therefore leaves computed metric values/scores
unchanged but changes `metric_config_digest`. That digest identifies the complete
effective configuration, not an equivalence class of scoring formulas. A bound
profile with the former digest is refused even when this particular change
would leave its score unchanged. Deprecation metadata is outside the digested
configuration. See the [calibration guide](06-calibration-guide.md) for replay
and refitting requirements.

### Identifier LTTR and register-pressure quality

`type_token_ratio` reports identifier LTTR as `log(V) / log(N)`, where `N` is the
number of non-empty identifier occurrences and `V` is the number of distinct
spellings among them. Using the same logarithm base in numerator and denominator
gives the same ratio. The existing minimum is 20 occurrences: smaller inputs,
including zero or one, are unavailable before logarithms are evaluated.
At `N = 20, V = 1`, LTTR is exactly 0; at `N = 25, V = 5`, it is 0.5; and at
`N = V = 20`, it is 1. Existing identifier extraction/spelling limits apply.
This arithmetic does not establish length invariance, multilingual linguistic
validity or a validated authorship threshold.

For C/C++, `register_pressure.value` remains the maximum estimated per-function
peak of simultaneously live scalar declarations divided by the fixed budget
13. Its quality score is 1 at or below `low`, interpolates linearly to 0.5 at
`moderate`, then linearly to 0 at 1.25, and stays 0 above that point. Thus higher
estimated pressure never improves this quality score. Defaults remain
`low = 0.50` and `moderate = 0.85`; effective overrides must be finite and satisfy
`0 <= low < moderate < 1.25`. Equal, reversed or out-of-domain anchors are
refused, including when the metric is called directly.

These anchors are explicit heuristic policy. The source-level live ranges and
fixed register budget do not measure compiler allocation, hardware registers or
actual spills. Existing function/declaration availability rules remain; missing
features do not establish zero pressure. This metric retains its quality role
and does not contribute to the default concern aggregate. Neither corrected
arithmetic nor continuous normalisation supplies empirical detector validation.

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

## Language detection and documentation admission

The public `language` field retains the selected analysis
family. It is not a probability estimate, interpreter availability check or
proof that the source is syntactically valid. Single-file precedence is supported
explicit hint, recognised case-insensitive extension, recognised first-line
shebang, then content heuristics; the `.h` C/C++ heuristic is preserved.
The [README detection subset](../README.md#automatic-language-detection) specifies
the exact interpreter names and the deliberately limited `/usr/bin/env` forms.
Unsupported shebang text falls through to content analysis without executing it.

If no positive supported cue is found, the family is `unknown` and `warnings`
retains `The language could not be detected with strong confidence.` File text
includes the same warning. Project `included_files` retains each member's
warning and promotes it with the member path to project `warnings`; project
text consumes that promoted list. Content heuristics can still select a language
after a rejected shebang cue, and their selection
does not certify complete language recognition.

Project admission precedes detection and remains extension-based. The optional
Boolean `include_documentation` admits `.md`, `.markdown`, `.txt`, `.rst` and
`.adoc`, subject to the ordinary ignore, path and resource limits. It does not
admit an extensionless script. Plain text admission does not create a dedicated
reStructuredText/AsciiDoc parser or guarantee documentation-only scoring: its
contents are detected using the same rules. Project code-language hints can
override an admitted member; Markdown/unknown project hints are discarded so
that per-file detection continues. The native CLI exposes admission as
`--include-documentation`. Both browser project interfaces exclude documentation
and offer no documentation opt-in control; a direct worker/API request enabling
documentation is a separate route. Detection operates on supplied text: file
decoding may remove a BOM before detection, while a BOM retained in a raw API
string prevents an offset-zero shebang cue.

## Markdown documentation features

Markdown retains `verdict_class` and `reading_class` = `documentation`,
`overall_applicable: false` and the compatibility numeric placeholder
`overall_score: 0.0`. Consumers must use applicability: that zero is not a
measured absence of authorship concern. Markdown members have no contribution to
the project code aggregate. A project containing only Markdown therefore has
zero contributing files and an inapplicable project code score; its project
reading follows the existing insufficient-evidence contract.

Reports add a `Markdown scope:` warning describing the finite extractor. It is
retained in file JSON/text and single-file browser results, and promoted with
the member path in documentation-enabled native/API project JSON/text.
The scope note qualifies extraction;
it does not suppress the existing documentation metrics. An unclosed supported
fence reaches document end and is not reported as a syntax failure. The same
report/text JSON envelope and schema versions are retained.
Promoted scope and detection warnings enter the existing project-confidence
formula, so its evidence-coverage label can change independently of the concern
score. This does not change weights or thresholds or establish statistical
confidence or authorship accuracy.

`markdown_code_fence_density.detail` records fence block/line counts and density;
`markdown_link_density.detail` records hyperlink count, prose word count and
density. Fence line count includes opener, payload and any accepted closer.
Matched code spans, fenced/indented code and recognised reference definitions
are excluded from hyperlink/prose extraction; images are not hyperlinks.
`markdown_heading_structure.detail` describes the inventoried headings when
enough headings make the metric applicable. Internal `MarkdownInfo.headings`
tuples retain `(level, ordinal, text)`; the ordinal is not a physical line number
and the internal heading/link inventory is not added to public JSON.

The [README Markdown subset](../README.md#markdown-extraction-boundaries) declares
fence delimiters, indentation, code-span matching, single-line setext and flat
reference support, including the 999-character reference-label limit. Full
CommonMark rendering, nested/container syntax, HTML, autolinks and multilingual
linguistic analysis are not established. Correct counts do not independently
validate existing editorial score preferences, thresholds or authorship claims.
Fenced programmes remain data and are never executed or recursively added to
the code aggregate. A new engine still requires a newly bound profile; Markdown
does not bypass engine-identity checks merely because its code score is N/A.

### Descriptive statistics versus editorial preferences

Repeated sibling headings do not reduce `markdown_heading_structure`: the
retained preference is `1 - upward_level_jumps / heading_count`, clamped to the
existing range, and it requires at least two recognised headings. H1/H2/H2/H2
therefore yields 1; H1/H3 yields 0.5. A skipped heading level is not a CommonMark
syntax error. The repeat count may remain in details as a descriptive count.

Fence density is recognised blocks per 100 source lines. An empty or
whitespace-only document has no applicable content denominator and yields N/A;
a non-empty document without fences yields an observed zero. Link density is
recognised hyperlinks per 100 extracted prose tokens: no prose tokens yields
N/A, while non-empty link-free prose yields zero. N/A retains `value: null` and
`applicable: false`; the compatibility score placeholder is not a measurement.
Neither code examples nor hyperlinks are compulsory for a legitimate document.
Their configured score bands are genre-dependent editorial preferences.

Prose entropy is a token-frequency statistic with the existing 40-token minimum.
Permuting the same token multiset leaves it unchanged. It measures neither
logical progression, comprehension nor writing quality. These clarifications do
not extend Markdown parsing, change project admission or enable recursive
analysis of code fences.

## Calibration rates carried into analysis reports

Statistical independence is not established; uncertainty is not estimated.

The public calibration block retains aggregate
`validation.descriptive_review_rates` for `fit`, `evaluation` and `all`.
Each partition states the report unit (`file` or `project`), sample/group counts,
threshold and counts for `human`, `ai_generated`, `hybrid` and pooled `positive`.
Each label has `reviewed`, `eligible`, `sample_count`, `group_count`,
`eligible_group_count` and an unrounded `rate`. A zero denominator gives JSON
`null` and textual N/A, not an observed zero. The positive row overlaps its two
component labels; the all partition pools fit and evaluation and is not an
independent evaluation.

The fit partition alone selects the trigger. Evaluation and pooled counts do
not retune it. `statistical_independence: not_established` and
`uncertainty.status: not_estimated` are explicit. Declared group separation is
not a sampling model; group counts are not effective independent sample sizes.
Historical numeric rate aliases remain for compatibility and may contain zero
for an absent class. Read their `rate_counts` and `legacy_rate_qualification`.
The legacy `independent_holdout` flag refers to separation from selection, not
statistically independent trials or an independent institutional reviewer.
Ordinary analysis exports omit sample observations and the sensitivity grid;
aggregate forwarding is not a promise that user-supplied profile free text is
anonymous. See the [calibration guide](06-calibration-guide.md).

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

## Finite metric extraction

Numeric observations consume recognised literal boundaries, rather than digits
inside identifiers such as `value123`. Generic-language extraction uses the
masked executable view; Python uses numeric AST constant source spans, including
numeric expressions within f-strings. Comments and literal text do not create
numbers. Boolean/string constants are not numeric constants here, and unsupported
numeric forms require unavailable dependent feedback with a diagnostic rather
than a partial numeric match. Python without an AST cannot certify these numeric
observations. Generic masked-language support is decimal/scientific notation
(including `.5` and `3.`) and hexadecimal `0x`/`0X` forms, with admitted attached
`+`/`-` spellings. Numeric suffixes, separators and binary/octal prefixes are
outside that generic subset; a numeric-looking unsupported word is rejected
whole. Python's AST supplies accepted real integer/float source spellings,
including base prefixes and separators accepted by that interpreter; complex
or imaginary constants are unavailable here. Each numeric AST source span must
remain on one physical line. This is a finite lexical/AST subset, not expression
evaluation.

`Numeric literal warning:` records an unavailable numeric vocabulary. It makes
`magic_numbers` and `code_elegance` unavailable; for generic code families it
also makes `lexical_entropy` and `halstead_difficulty` unavailable because their
operand vocabulary is affected. Python's latter two metrics retain their
separate token-stream contract. This warning alone does not add a general
calibration refusal; the existing AST, C-family and script-feature requirements
still apply. File JSON/text retain the warning, and projects promote it with
the member path into project warnings/text.

`magic_numbers` retains its spelling-based exceptions `0`, `1`, `2`, `-1`, `+1`,
`0.0`, `1.0` and `0x0`, and reports non-exempt candidates per 20 code lines.
Equivalent numeric values with other spellings are not automatically exempt.
Corrected token boundaries also feed numeric operands and the literal component
of `code_elegance`; this can change dependent observations without changing the
default metric roles or weights.

For Python, `boilerplate_presence` recognises a main guard only as a direct
module-body `if` with one equality comparison between `__name__` and the constant
`'__main__'`, in either order. It contributes at most one indicator. Module
future imports, an actual module docstring, a recognised first-line Python
shebang and a coding comment in the first two lines remain separate indicators.
An inert string resembling a main guard contributes none. Missing AST makes
this Python metric unavailable.

Python `defensive_programming` counts syntactic cues: `assert`, `raise`, the
named calls `isinstance`, `issubclass`, `len`, `all` and `any`, comparisons with
a direct `None` constant operand, and `if` tests whose outer node is `not`.
Calls and `if` cues are separate occurrences. Text containing these words and a
string containing `None` do not qualify. Missing AST makes the metric
unavailable. These counts do not resolve called functions or prove defensive
intent; for example, a `len` call can serve other purposes.

Python `import_organization` inventories direct module-body import statements.
One initial module docstring is skipped; imports are top-aligned only when all
precede the first non-import statement. Initial future imports are legitimate
members of that block. Local and conditional imports do not enter this module
inventory. Existing sorting uses case-insensitive module-name order, while
grouping concerns physical gaps between complete import statements. These
components are separate from top alignment. Fewer than two module import
statements, or a missing AST, makes this metric unavailable; it is not a complete
import-style linter.

For JavaScript, `used_import_ratio` recognises supported static default,
named/aliased and namespace bindings and associates exact executable identifier
reads outside their declarations. Comments, string/regex contents and longer
lookalike names do not mark a binding used. Detected duplicate, rebound or shadowed
bindings and unsupported binding forms require unavailable feedback with a
qualification. Named imports use identifier spellings, and the module target
must be a string literal. A binding clause through the module literal is bounded
to 2,048 characters after the `import` keyword; unsupported attributes, comments
between `from` and its module literal, or longer clauses are qualified. Dynamic
`import()` and `import.meta` do not introduce static bindings here. Ordinary
member/property names are excluded from binding reads. This is a finite binding
analysis without module resolution,
reachability analysis or arbitrary effects of called code.

`javascript_modern_syntax` counts arrow `=>`, `const`/`let`, interpolated-template,
declaration-destructuring, `...`, `?.` and `??` markers in masked executable code
with exact identifier boundaries. These are marker occurrences, so one
construction can contribute more than one family. Supported template interpolation expressions
remain executable; literal template text is masked. Each template with at least
one interpolation contributes one template marker, including a separately
interpolated nested template. The raw ratio remains
`modern / (modern + var_occurrences + 1)` with its existing normalisation.
Inert arrows, keywords and interpolation-like text do not count.
Dotted member names are excluded from the word markers. Bare object keys are
not fully classified by syntactic role and can still contribute a `const`,
`let` or `var` word marker; this is not complete declaration-role parsing.

For Bash, `nesting_depth` tracks command-position control blocks: `then` and
`do` continue their associated block rather than opening another level.
`elif`/`else` remain in the same conditional; matching terminators unwind the
stack, and command substitutions have separate validated block frames. Quoted
words, escaped characters, comments and here-document payload cannot open a
control block. Detected missing, misplaced or mismatched control tokens make the nesting
observation unavailable. This is finite structural bookkeeping, not execution
or a complete shell grammar.
At most 32 control blocks can be active cumulatively across those frames.
The first excess is diagnostic. `Bash nesting warning:` is retained in file
JSON/text and promoted with the member path to project warnings/text. An applied
bound profile or `require_script_features: true` refuses a detected nesting
issue; ordinary unbound analysis retains the unavailable nesting observation.
These promoted numeric/nesting warnings can affect the existing project
confidence label, independently of a concern-score change.

`bash_quoting_consistency` divides the number of eligible expansions in double
quotes by the number of eligible expansions, counting each occurrence. Five
eligible expansions in one double-quoted string therefore give 5/5, just as five
separately quoted strings do; four quoted and two unquoted give 4/6. The subset
includes simple `$name` and braced forms with an ASCII name
`[A-Za-z_][A-Za-z0-9_]*`, an optional initial `#`, and an optional `#`, `##`, `%`
or `%%` removal suffix whose literal pattern contains no dollar, brace,
backtick or backslash. This recognises a finite spelling subset, without proving
that every combination has meaningful shell semantics.
Single-quoted text, escaped dollars, comments and here-document
payload are excluded. A command substitution uses its own shell quote context.
Positional/special parameters, arithmetic and complex expansions or backticks
do not imply full shell support. Fewer than five eligible expansions remains
unavailable, including a zero denominator.

For C/C++, `preprocessor_hygiene` reads active directives from the masked view.
Here, active means lexically outside comments/literals, not proven active after
evaluating `#if` conditions: apparent directives inside `#if 0` are still lexical
directives. Macro-generated directives and conditional truth are not resolved.
Continued directive lines are joined, including code-token splicing within an
already active directive. Ordinary code-token splicing remains outside the
structural extraction subset. For header extensions `.h`, `.hpp`, `.hxx` and
`.hh`, a guard needs an outer first active `#ifndef NAME`, the matching
`#define NAME` as the next non-empty logical line and its corresponding final
`#endif`; nested conditionals are tracked. Mismatched names and incomplete or
misnested directives cannot establish that paired macro guard. An active unconditional
`#pragma once` follows the same finite guard policy. Original include text is
used for destination style only after an active include directive is found.
Commented directives do not contribute. No preprocessor is executed, macro
expanded or conditional expression evaluated, and this is not a complete
preprocessing translation model.
For other extensions the existing `has_guard: true` convention means that the
header-guard requirement is waived; it is not a detected guard.

## JavaScript and Bash diagnostics

The existing JSON envelope and schema versions are unchanged. JavaScript and
Bash reports use the following `warnings` prefixes:

| Prefix | Meaning |
|---|---|
| `JavaScript scope:` / `Bash scope:` | Describes the finite extraction subset. A scope note alone does not suppress metrics or refuse a calibrated request. |
| `JavaScript warning:` / `Bash warning:` | A detected lexical, executable-feature or function-inventory issue, with a diagnostic code and physical start line. Read its explanation and metric applicability before interpreting a partial result. |
| `Bash nesting warning:` | A detected control-block mismatch or excessive nesting. Unbound nesting is unavailable; strict/bound script analysis refuses it. |

EOF errors also populate the existing internal `tokenizer_error` field. Internal
context records `script_lexically_safe`, `script_feature_issues` and
`script_function_issues`; these do not add public function or token inventories.
Detected unsafe lexical or unsupported executable features make code metrics
unavailable, leaving only `line_length_uniformity`, `blank_line_regularity` and
`indentation_consistency` eligible. The file aggregate is then N/A because fewer
than four contributing metrics can remain. Detected function omissions with safe
lexical boundaries make
`function_length`, `cyclomatic_complexity`, `function_complexity_uniformity`,
`structural_self_similarity` and `code_elegance` unavailable. An unavailable value
is not a measured zero; consumers must read `applicable`, `detail` and
`explanation` together.
Absence of a specific omission warning does not establish a complete callable
inventory; the named-form subset still applies.

The optional request field `require_script_features` is a strict Boolean,
defaulting to false for unbound analysis. True requires available JavaScript/Bash
lexical, executable and function features. An applied bound profile imposes the
same requirement; false cannot override it. Both file and project requests carry
the requirement, including every admitted project member. A recorded feature
issue raises `ValueError` before a complete report envelope is returned.
Calibration sample analysis requests true for both file and project samples;
refusal is a sample error and aborts profile preparation. Python AST and C-family
availability requirements remain separate and unchanged.

Completed file JSON/text retain diagnostics. Project JSON retains member
warnings in `included_files` and promotes them with the member path to project
`warnings`. Project text, the native CLI and both browser interfaces consume the
same promoted list; browser exports retain the report JSON/text. A worker failure
is displayed as a failed operation and does not produce an accepted report; its
error presentation need not expose the internal exception text. Completion of a
warning-bearing unbound report does not establish successful compilation or a
complete inventory.

Promoted scope notes and warnings enter the existing project-confidence
calculation. Its evidence-coverage label can therefore change independently of
the concern score. No weights, thresholds or aggregation rules are retuned by
these extraction changes. Confidence remains a heuristic rather than a
statistical interval or an authorship probability.

| Extraction boundary | Exact bound or qualification |
|---|---|
| JavaScript delimiters | At most 32 active delimiters cumulatively across executable/template-expression/JSX contexts, including open JSX tags. Template `${...}` wrappers do not consume this budget. Unsafe or excessive nesting is diagnostic. |
| JavaScript templates | At most 16 active templates. Text is masked and supported `${...}` expressions remain executable code. |
| JavaScript function headers | At most 2,048 physical characters from the first header character, including `export`/`async` when present, through whitespace before the body-opening brace. Leading whitespace and statement separators are excluded; a truncated header is not accepted as complete. |
| JavaScript function forms | Named declarations, including named exports; function expressions/block-bodied arrows in variable declarations or named object properties; ordinary methods with balanced parameter delimiters. Typed/generic TypeScript headers are qualified omissions. |
| JSX | Simple detected expression spans are qualified and masked, bounded to 65,536 physical characters. The enclosing function is a qualified omission; ordinary following functions can be recovered when boundaries are safe. Unknown, unterminated or excessive spans cannot establish a safe later inventory. |
| JavaScript names | `$`, `_`, `Lu`, `Ll`, `Lt`, `Lm`, `Lo`, `Nl` initially; continuation adds `Mn`, `Mc`, `Nd`, `Pc`, ZWNJ and ZWJ. Source spelling is retained without normalisation or escape decoding. Unsupported forms are diagnosed. |
| Bash command substitutions | Ordinary `$()` in code/double quotes retains child code through 16 active levels. Backticks, process substitutions, arithmetic and complex expansions are qualified. |
| Bash control blocks | At most 32 active control blocks cumulatively across command contexts. Excess or detected mismatches make nesting unavailable and are refused by strict/bound script analysis. |
| Bash parameter masking | At most 32 brace levels while masking parameter text. Nested/complex forms remain qualified within this budget; the limit is not executable-expression support. |
| Bash functions | Brace-delimited `name()`, `function name` and `function name()` forms; names match `[A-Za-z_][A-Za-z0-9_]*`. Names and physical start/end lines are extraction metadata, not shell execution or binding validation. |
| Bash here documents | At most 16 pending documents, 128 characters per quote-removed delimiter and 65,536 physical payload characters including newlines before the terminator. Quoted delimiters and `<<-` leading tabs are recognised. Apparent unquoted executable/complex payload expansions are conservatively qualified, including escaped apparent forms. |

Each first value above a numeric bound is diagnostic. These are CodeProbe
resource boundaries, not limits imposed by ECMAScript or Bash. See the
[README support matrix](../README.md#javascript-and-bash-extraction-boundaries)
for the corresponding language references and qualified syntax.

Coordinates refer to newline-normalised physical source. Masking preserves
positions and supplies structural line categories. Each function's complexity
uses the extracted function's cleaned character interval; stored body/signature
evidence remains original line-based source, which can contain neighbouring same-line content.
The existing metric uses mean per-function complexity when functions are
available and a density fallback otherwise; extraction corrections do not make
those two quantities identical or validate every metric formula. Unicode
database versions can differ between executing Python runtimes. Nested callable
bodies can remain in an enclosing lexical complexity count; this is not a
scope-resolved complexity model.

## C, C++ and C# diagnostics

The existing JSON envelope and report schema versions remain unchanged. These
families add diagnostic strings to `warnings`, with the following prefixes:

| Prefix | Meaning and interpretation |
|---|---|
| `C-family scope:` | The finite extraction contract applies. It identifies excluded forms, including structural features inside C# interpolation expressions. This is a qualification, not a compiler diagnosis. |
| `Tokenizer warning: C-family` | A detected lexical problem prevents a safe structural inventory, for example an unterminated literal, mismatched raw delimiter, excessive nesting or an identifier form outside the admitted subset. Function extraction is suppressed for the file, and dependent metrics are unavailable. |
| `C-family extraction warning:` | A recognised function form, signature or file-scope alias context exceeds the extraction subset. Ordinary supported functions can remain inventoried, but metrics requiring a complete inventory are unavailable. |
| `C-family declaration warning:` | A declaration or local alias cannot be resolved within the bounded declaration subset. Register-pressure and stack-depth proxies are unavailable. |

File JSON and text retain these warnings. Project JSON retains them in each
member's `included_files` entry and promotes them to project `warnings` with the
member path. Project text and both browser interfaces consume that promoted list.
The native project CLI uses the same project report and text formatter; the
Python API and browser worker retain their existing report/text envelopes.
A completed operation means that a diagnostic report was produced, not that
the source compiled or its inventory is complete.

Applying a bound calibration profile requires available C-family lexical,
function and declaration features within this subset, including every admitted
project member. A recorded issue in any of those features raises `ValueError`
before a complete report envelope is returned. A scope message alone does not
trigger that refusal. Unbound analysis can retain a qualified partial report;
it is not evidence that the same input is accepted under a bound profile.
The optional Boolean request field `require_c_family_features` enforces the
same availability requirement without supplying a bound profile. Calibration
sample analysis sets this field for both file and project samples; a refusal
is recorded as a sample error and aborts profile preparation. Its default is
false for unbound diagnostic analysis, and a false value cannot override the
requirement imposed by a bound profile.

Consumers must read `applicable`, `detail` and `explanation` together. An
unavailable metric is not a measured zero. A remaining applicable file or project
score uses the features that remain applicable; it does not reinstate omitted
structural evidence. The main browser's low-level quality card includes only
applicable memory proxies and displays N/A when none apply.

With lexical safety unavailable, only `line_length_uniformity`,
`blank_line_regularity` and `indentation_consistency` remain eligible; the file
aggregate is N/A because fewer than four contributing metrics can remain.
Function-extraction issues make `function_length`, `cyclomatic_complexity`,
`function_complexity_uniformity`, `register_pressure`, `stack_frame_depth`,
`redundant_memory_access` and `code_elegance` unavailable. Declaration issues
make `register_pressure` and `stack_frame_depth` unavailable. A scope message
alone does not suppress metrics. These rules preserve existing weights and
thresholds. Promoted warnings also enter the existing project-confidence
calculation, so the coverage label can change while the concern score stays
the same.

The internal context retains `c_family_lexically_safe`,
`c_family_function_issues` and `c_family_declaration_issues`. Its functions,
parameters and declaration names are extraction metadata; this change does not
add a public JSON inventory of those objects.
Physical line coordinates refer to the newline-normalised source. Comment and
literal masking preserves their positions, including C/C++ continued comments
and C++ raw strings. This does not imply full preprocessing or macro expansion.

| Extraction boundary | Exact bound or qualification |
|---|---|
| Function header | 800 characters from the first non-whitespace character through whitespace before the body-opening `{`; a truncated suffix is not accepted as a complete header. |
| Function forms | Ordinary named functions/methods with brace-delimited bodies; operator overloads and C# expression-bodied members remain qualified omissions. C# lambda arrows also qualify the inventory. |
| C# raw delimiter | 3–16 quote characters; malformed or excessive delimiters are diagnostic. |
| C# interpolation | At most 16 active interpolation expressions, counting the outer expression as one; expression delimiter nesting is bounded to 32 and raw prefix width to 16 dollar signs. Entire interpolated literals, including their expression contents, are masked. Raw opening-brace runs longer than the prefix width and unparenthesised `:` format/conditional suffixes are diagnosed as unsupported. |
| Logical declaration | At most 4,096 characters after stripping surrounding whitespace and before the semicolon; delimiter nesting is bounded to 32. |
| Numeric array extent | At most nine ASCII decimal digits for the size proxy; longer or non-ASCII digit sequences are diagnosed. Extent expressions are not evaluated and retain a variable-extent proxy classification. |
| Typedef inventory | Separate limits of 64 accepted typedef declarations at file scope and within each inventoried function, including nested scopes; repeated declarations count towards the limit. Only preceding simple file-scope aliases in the same file are inherited. Parameters/local objects can shadow aliases and scope exit removes local visibility. Aliases from other functions/files are not used. |
| Identifier spelling | Start: `_`, `Lu`, `Ll`, `Lt`, `Lm`, `Lo`, `Nl`; continuation adds `Mn`, `Mc`, `Nd`, `Pc`. A leading `@` is recognised for C# only and is retained. Escapes and other categories are diagnosed. |

These bounds define CodeProbe's subset, not the limits of the languages. In
particular, retaining lexical spelling does not resolve C# verbatim-name
equivalence or validate the full identifier rules of a C/C++ dialect. No Unicode
normalisation or escape decoding is silently applied to the identifier
inventory. Python runtime versions can use different Unicode databases; tested
cross-runtime examples do not establish agreement for every Unicode character.
See the [README extraction boundaries](../README.md#c-c-and-c-extraction-boundaries)
for supported forms and the associated language references.

The declaration inventory distinguishes `a` and `b` from the initialiser
identifiers `x` and `y` in `int a = x < y, b = 2;`. Correcting those names changes
the inputs to memory proxies. It does not measure actual register allocation,
stack-frame size, memory traffic or authorship, and does not independently
validate the formulas of those metrics.

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

## Consumer type and provenance checks

| Selector | JSON type | Interpretation |
|---|---|---|
| File `language` | string | Detected language, not a success guarantee |
| File `loc`, `sloc` | integer | Normalised LF-split segments and non-blank segments, with the terminal-empty-segment convention described above |
| `manual_review_recommendations` | array of strings | Contextual review steps, not a decision |
| `engine_fingerprint` | object | Availability and provenance must be inspected |
| `engine_fingerprint.available` | Boolean | False means no measured value is available; do not invent one |
| Available `engine_fingerprint.value` | string | SHA-256 digest in hexadecimal, with source qualification |
| `metric_config_digest` | string | 64 lower-case hexadecimal characters without a prefix |
| `calibration_profile.validation` | object | Compact aggregate validation, not individual observations |

Canonical configuration JSON uses sorted keys, comma/colon separators, UTF-8
and unescaped non-ASCII text before SHA-256 hashing. A caller-provided fingerprint
is not automatically a measurement. Contradictory claimed provenance is marked
`caller-unverified`, with `matches_loaded_source` and an independently measured
value when available. No source measurement is represented by `available: false`
and an empty value/reason, not by a fabricated digest.

Compact calibration validation excludes `sample_results`, the full `sensitivity`
grid and identifier mappings. It can retain descriptive reviewed/eligible counts,
separate group counts and the recorded fit/evaluation design. Statistical
independence is not established and uncertainty is not estimated merely because
these fields have valid types. See [the calibration workflow](../calibration/README.md)
for generation, profile scope and refitting rather than hash substitution.
