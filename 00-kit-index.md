# CodeProbe kit index

This page is the quickest way to locate the right part of the package. For current package navigation and release audit, start with `docs/01-naming-policy.md`, `docs/00-file-catalogue.md` and `release/file-rename-map.csv`.

## For students

- `app/index.html` — main browser interface for single files, dragged folders and GitHub ZIP project exports.
- `app/project.html` — compact project-only browser interface with ZIP/folder drag-and-drop.
- `educator/01-student-quick-start.md` — one-page use guide.
- `educator/03-student-disclosure-template.md` — disclosure template for AI assistance, design choices, tests and development evidence.
- `.codeprobeignore.example` — starter ignore rules for project mode.

## For instructors

- `educator/07-course-integration.md` — recommended course policy and assessment workflow.
- `educator/04-instructor-checklist.md` — operational checklist before, during and after submission.
- `educator/05-review-protocol.md` — manual review protocol for reports that cross the active trigger.
- `educator/06-evidence-rubric.md` — evidence categories that should accompany any review.
- `educator/02-student-announcement.md` — short LMS announcement text.

## For administrators and local IT support

- `educator/08-deployment-one-page.md` — concise deployment options.
- `docs/04-browser-security.md` — browser security boundary and CSP notes.
- `docs/07-ui-extension-guide.md` — extension points for adding future UI features without making the interface monolithic.
- `docs/05-offline-deployment.md` — local Pyodide deployment notes.
- `docs/13-signed-release-workflow.md` — optional signed-release workflow using the release manifest and external signature tools.
- `docs/15-final-release-audit.md` — final acceptance checks for naming, references and functionality.
- `release/release-manifest.json` — strict package allowlist with canonical paths, sizes and SHA-256 digests.

## For maintainers

- `docs/01-naming-policy.md` — naming rules for the final stable package.
- `docs/00-file-catalogue.md` — current file inventory and final paths.
- `release/file-rename-map.csv` — machine-readable migration map.
- `tools/check_file_references.py` — high-confidence reference and rename-map audit.
- `tools/check_naming.py` — path-style and uncontrolled legacy-reference audit.
- `docs/15-final-release-audit.md` — final acceptance record for the naming-stable package.
- `src/codeprobe_runtime.py` — self-contained browser engine used by Pyodide.
- `src/codeprobe_engine/` — maintainer support package for CLI, release and metadata helpers.
- `tools/check_release.py` — full release validation script.
- `tools/build_release.py` — strict manifest-selected release packet builder.
- `tools/audit_institutional_pack.py` — checks for the institutional distribution pack.
- `tests/` — regression tests across the phased hardening work.

## Interpretation boundary

CodeProbe reports a heuristic AI-style concern score. It does not prove AI authorship, misconduct or independent authorship. Use the report as part of a review packet containing the analysed files, ignored files, repository history, tests, design notes, disclosure and, where needed, an oral code walkthrough.
