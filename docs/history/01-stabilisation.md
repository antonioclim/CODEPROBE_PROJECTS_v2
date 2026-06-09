# Phase 1 changeset — stabilisation and false-positive reduction

## Objective

Phase 1 makes the existing kit safer to use in a course before deeper architectural refactoring. It focuses on language, scoring hygiene, documentation and small correctness fixes.

## Engine changes

- `APP_VERSION` updated to `2.1.1`.
- Verdict text changed to reading/concern terminology.
- `overall_applicable` added to reports.
- Markdown returns `documentation` reading and `overall_applicable = false`.
- Quality-practice metrics are still reported but no longer contribute to the AI-style aggregate:
  - `magic_numbers`
  - `dead_code_residue`
  - `indentation_consistency`
  - `used_import_ratio`
  - `docstring_coverage`
  - `type_hint_coverage`
  - `javascript_modern_syntax`
  - `bash_quoting_consistency`
  - `import_organization`
  - low-level quality metrics for C/C++/C#
- Ambiguous structural/context metrics are also excluded from the default aggregate until local calibration justifies their use:
  - `error_handling_density`
  - `boilerplate_presence`
  - `cyclomatic_complexity`
  - `halstead_difficulty`
  - `nesting_depth`
  - `defensive_programming`
  - `declarative_ratio`
  - `control_ratio`
- Character-level entropy replaced with normalised token-level entropy.
- JSON configuration overrides are validated.
- Duplicate JavaScript metric registry decorator removed.

## Browser changes

- Summary card renamed to **AI-style concern score**.
- **Verdict** renamed to **Reading**.
- Markdown and insufficient-code cases show `N/A` for the aggregate score.
- Local report history is disabled by default and can be enabled explicitly.
- A conservative Content Security Policy meta tag was added while preserving the inline static-page architecture.

## Documentation changes

- README, course guidance, project notice and disclosure template rewritten to reduce over-claiming.
- Provenance and design-decision documents added.
- Revised LMS/student announcement added under `educator/`.
- `.codeprobeignore.example` clarified as a manual checklist until automatic project mode is implemented.

## Validation performed

- `python3 -m py_compile src/codeprobe_runtime.py tools/run_local_server.py`
- `python3 -m unittest discover -s tests`
- engine smoke checks for Markdown documentation-only handling and quality/context contribution flags

## Remaining limitations

- No multi-file ZIP/project mode yet.
- No automatic `.codeprobeignore` parsing yet.
- No local empirical calibration corpus yet.
- JavaScript scanner still requires deeper treatment of regex literals and complex TypeScript syntax.
- The engine is still monolithic and should be modularised in a later phase.
