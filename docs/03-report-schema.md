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

## JavaScript and Bash diagnostics

The existing JSON envelope and schema versions are unchanged. JavaScript and
Bash reports use the following `warnings` prefixes:

| Prefix | Meaning |
|---|---|
| `JavaScript scope:` / `Bash scope:` | Describes the finite extraction subset. A scope note alone does not suppress metrics or refuse a calibrated request. |
| `JavaScript warning:` / `Bash warning:` | A detected lexical, executable-feature or function-inventory issue, with a diagnostic code and physical start line. Read its explanation and metric applicability before interpreting a partial result. |

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
