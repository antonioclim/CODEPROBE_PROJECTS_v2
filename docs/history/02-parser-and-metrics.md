# Phase 2 changeset — parser correctness and false-positive control

Phase 2 makes the Phase-1 kit more technically defensible. The emphasis is not on adding more indicators, but on preventing unstable parser behaviour and reducing the risk that disciplined, formatter-shaped student code is misread as AI-style authorship evidence.

## Engine changes

- `APP_VERSION` updated to `2.1.2`.
- JavaScript scanning now includes a regex-literal state.
- Regex literals are masked before brace matching, including common cases such as `/[{}]/g` and `/[.*+?^${}()|[\]\\]/g`.
- Division operators remain visible where the surrounding tokens indicate ordinary arithmetic, for example `return a / b;`.
- JavaScript function extraction now recognises:
  - `function name(...) { ... }`;
  - `async function name(...) { ... }`;
  - `const name = (...) => { ... }`;
  - `const name = async (...) => { ... }`;
  - class methods such as `async run(...) { ... }`;
  - object-literal methods and arrow-valued properties.
- Function start-line calculation now skips delimiters and leading whitespace introduced by matching expressions.
- JSON reports now include `app_name`, `app_version` and `schema_version`.

## Scoring changes

The following metrics are now reported as context only and do not contribute to the AI-style aggregate by default:

- `blank_line_regularity`;
- `function_length`;
- `identifier_style`;
- `structural_self_similarity`.

Rationale: these signals produced false positives on clean, formatter-shaped code and on framework/registry-style implementations. They remain useful for code review, but they need course-local calibration before they can be treated as authorship-style evidence.

## Test-suite changes

Added or updated regression coverage for:

- regex literals containing braces;
- JavaScript arithmetic division versus regex-literal masking;
- JavaScript function extraction across common declarations and methods;
- function start-line accuracy after a preceding semicolon;
- clean JavaScript remaining below the review trigger;
- clean formatter-shaped Python remaining in the low-concern band;
- JSON report version/schema fields;
- rejection of non-numeric threshold overrides.

Run from the repository root:

```bash
python3 -m py_compile src/codeprobe_runtime.py tools/run_local_server.py
python3 -m unittest discover -s tests -v
```

## Remaining limitations

- The JavaScript scanner is still heuristic and is not a full ECMAScript parser.
- JSX/TSX syntax is recognised only through tolerant static cues, not through a compiler-grade parser.
- Phase 2 does not yet implement ZIP/project analysis or automatic `.codeprobeignore` parsing; these remain Phase-3 tasks.
- The threshold model remains uncalibrated until a course-local corpus is built.
