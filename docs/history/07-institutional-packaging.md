# Phase 7 changeset — institutional consolidation

- Engine version: `2.1.7`
- File report schema: `2.1.7`
- Project report schema: `2.1.7-project`

## Added

- `KIT_INDEX.md` as the package navigation page at that phase. It was later renamed to `00-kit-index.md` in Phase 13.
- Student, instructor, deployment, review-protocol and submission-evidence resources under `educator/`.
- `docs/13-signed-release-workflow.md` for optional external signing and archival workflow.
- `tools/audit_institutional_pack.py` for institutional-distribution checks.
- Release validation now includes an institutional-package check.
- Report JSON now includes `reading` and `reading_class` aliases while retaining `verdict` and `verdict_class` for backwards compatibility.
- `tests/test_phase7_institutional_packaging.py` covering final documentation, audit checks and reading aliases.

## Changed

- README and optimisation roadmap now describe v2.1.7 as the consolidated institutional release.
- Browser UI code prefers `reading` where available, while remaining compatible with older reports.
- Release process documentation now points to the Phase 7 package names.

## Interpretation boundary

No Phase 8 change makes the score evidentiary on its own. The score remains a heuristic review signal to be interpreted with file scope, development history, tests, disclosure and oral explanation.
