# S02 measurement specification

## Purpose and claim boundary

This specification operationalises the S01 evidence-bounded review contract. It defines atomic observations, not latent traits and not source-provenance classifications. Passing the conformance suite supports the proposition that the reference implementation follows these counting rules under the declared parser and resource budgets. It does not demonstrate construct validity, educational utility, fairness or transfer across languages and tasks.

## Formal observation object

For source artefact bytes `x`, declared language/configuration `c` and versioned specification `s_i`, the kernel emits an observation `O_i = f_i(x, c; s_i)` with a scalar value or a typed missingness state, measurement scale, unit, entity, source-evidence identifiers, instrumentation identity and residual limitations. `not_applicable`, `insufficient_evidence` and `unavailable` are not numerical zero.

## Retained reference observations

### Source artefact

| Observation | Attribute | Scale | Unit | Oracle |
|---|---|---|---|---|
| `source.byte_count` | number of supplied bytes | ratio | `byte` | `O-IO-BOUNDARY` |
| `source.normalized_codepoint_count` | number of Unicode code points after intake normalisation | ratio | `codepoint` | `O-GEN-LINES` |
| `source.physical_line_count` | number of physical source-line records | ratio | `line` | `O-GEN-LINES` |
| `source.nonblank_line_count` | number of lines containing at least one non-whitespace code point | ratio | `line` | `O-GEN-LINES` |
| `source.blank_line_count` | number of whitespace-only physical lines | ratio | `line` | `O-GEN-LINES` |
| `source.max_line_length_codepoints` | maximum number of code points in one physical line | ratio | `codepoint_per_line` | `O-GEN-LINES` |
| `source.mean_line_length_codepoints` | arithmetic mean of code-point lengths across physical lines | ratio | `codepoint_per_line` | `O-GEN-DISPERSION` |
| `source.population_sd_line_length_codepoints` | population dispersion of physical line lengths | ratio | `codepoint_per_line` | `O-GEN-DISPERSION` |
| `source.line_length_cv` | relative dispersion of physical line lengths | ratio | `dimensionless` | `O-GEN-DISPERSION` |
| `source.trailing_whitespace_line_count` | number of lines ending in one or more spaces or tabs | ratio | `line` | `O-GEN-LINES` |
| `source.mixed_indentation_line_count` | number of non-blank lines whose leading indentation contains both spaces and tabs | ratio | `line` | `O-GEN-LINES` |
| `source.max_blank_line_run_length` | largest number of consecutive blank physical lines | ratio | `line` | `O-GEN-LINES` |

### Python module

| Observation | Attribute | Scale | Unit | Oracle |
|---|---|---|---|---|
| `python.parse_status` | outcome of CPython ast.parse under the executing runtime | nominal | `category` | `O-PY-AST-COUNT` |
| `python.function_definition_count` | number of ast.FunctionDef nodes | ratio | `definition` | `O-PY-AST-COUNT` |
| `python.async_function_definition_count` | number of ast.AsyncFunctionDef nodes | ratio | `definition` | `O-PY-AST-COUNT` |
| `python.class_definition_count` | number of ast.ClassDef nodes | ratio | `definition` | `O-PY-AST-COUNT` |
| `python.import_statement_count` | number of ast.Import and ast.ImportFrom statements | ratio | `statement` | `O-PY-AST-COUNT` |
| `python.imported_binding_count` | number of statically bound names introduced by non-wildcard import aliases | ratio | `binding` | `O-PY-AST-COUNT` |
| `python.wildcard_import_count` | number of from-import statements containing alias name * | ratio | `statement` | `O-PY-AST-COUNT` |
| `python.comment_token_count` | number of tokenize.COMMENT tokens | ratio | `token` | `O-PY-TOKENIZE` |
| `python.comment_physical_line_count` | number of distinct physical lines containing a COMMENT token | ratio | `line` | `O-PY-TOKENIZE` |
| `python.comment_line_proportion` | comment-bearing physical lines divided by physical line count | ratio | `proportion` | `O-PY-TOKENIZE`, `O-GEN-LINES` |
| `python.docstring_eligible_definition_count` | number of class, synchronous-function and asynchronous-function definitions | ratio | `definition` | `O-PY-DOC` |
| `python.docstring_present_definition_count` | number of eligible definitions for which ast.get_docstring(clean=False) is non-null | ratio | `definition` | `O-PY-DOC` |
| `python.docstring_coverage_proportion` | definitions with docstrings divided by eligible definitions | ratio | `proportion` | `O-PY-DOC` |
| `python.annotation_eligible_slot_count` | number of parameter and return slots in function signatures | ratio | `slot` | `O-PY-ANNOTATION` |
| `python.annotation_present_slot_count` | number of eligible slots with an annotation AST node | ratio | `slot` | `O-PY-ANNOTATION` |
| `python.annotation_coverage_proportion` | annotated slots divided by eligible slots | ratio | `proportion` | `O-PY-ANNOTATION` |
| `python.numeric_literal_count` | number of numeric ast.Constant nodes excluding Boolean values | ratio | `literal` | `O-PY-AST-COUNT` |
| `python.exception_handler_count` | number of ast.ExceptHandler nodes | ratio | `handler` | `O-PY-AST-COUNT` |
| `python.raise_statement_count` | number of ast.Raise nodes | ratio | `statement` | `O-PY-AST-COUNT` |

### Python callable

| Observation | Attribute | Scale | Unit | Oracle |
|---|---|---|---|---|
| `python.callable.physical_span_lines` | inclusive physical line span from lineno through end_lineno | ratio | `line` | `O-PY-CALLABLE` |
| `python.callable.decision_point_count` | finite syntactic decision points inside a callable excluding nested definitions | ratio | `decision_point` | `O-PY-CALLABLE` |
| `python.callable.mccabe_complexity` | one plus the S02 decision-point count | ratio | `complexity_unit` | `O-PY-CALLABLE` |
| `python.callable.max_control_nesting_depth` | maximum nesting of finite control-container nodes excluding nested definitions | ratio | `level` | `O-PY-CALLABLE` |

### Markdown document

| Observation | Attribute | Scale | Unit | Oracle |
|---|---|---|---|---|
| `markdown.parse_status` | completion status of the finite S02 Markdown scanner | nominal | `category` | `O-MD-FINITE` |
| `markdown.atx_heading_count` | number of recognised ATX headings outside fenced blocks | ratio | `heading` | `O-MD-FINITE` |
| `markdown.setext_heading_count` | number of recognised one-line Setext headings outside fenced blocks | ratio | `heading` | `O-MD-FINITE` |
| `markdown.fenced_code_block_count` | number of recognised top-level fenced block openers | ratio | `block` | `O-MD-FINITE` |
| `markdown.heading_level_jump_count` | number of adjacent recognised headings whose level increases by more than one | ratio | `transition` | `O-MD-FINITE` |

## Counting, parser and evidence rules

The normative details for each observation are in `research/observation-catalogue.v1.json`. That catalogue defines the entity, attribute, codomain, counting rule, parser scope, applicability states, source-evidence production, nuisance factors, metamorphic expectations, admissible interpretations, prohibited inferences, oracle identifiers and residual limitations. The machine-readable catalogue takes precedence over prose examples.

The S02 kernel supports only `python`, `markdown` and `text`. This is deliberate. Other language families remain on the public v2 route until a later phase supplies equally explicit specifications and oracles. Unsupported declarations are refused rather than guessed.

## Interpretation discipline

Observations are not summed by default. A count or proportion may warrant inspection under a separately governed policy, but it cannot identify an author, determine misconduct or trigger a sanction. Dimension mappings are hypotheses inherited from S01 and remain subject to M01 and E01 evaluation.
