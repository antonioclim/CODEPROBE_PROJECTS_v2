# Phase 8 changeset — dynamic UI intake and defensible manual-review guidance

- Engine version: `2.1.8`
- File report schema: `2.1.8`
- Project report schema: `2.1.8-project`

## Purpose

Phase 8 addresses three operational questions that matter in classroom deployment:

1. whether the browser interface can absorb future functions without becoming a single-purpose page;
2. whether students can drag files, folders and GitHub-generated ZIP exports directly into the web interface;
3. whether exported reports are clear enough to support a defensible manual review rather than a numerical judgement.

## Browser interface

The main interface now has a dedicated **Manual review** tab rendered from structured report data. The report tabs remain data-driven through `data-tab` targets, so further panels can be added by creating a tab button, a panel section and a renderer function. The UI remains framework-free to keep the kit auditable in a teaching environment.

Direct drag-and-drop is now global rather than restricted to the editor box. Users may drop:

- one source file for single-file analysis;
- several source files for project analysis;
- a browser-selected folder where the browser exposes relative paths;
- a GitHub-generated ZIP export, such as `repository-main.zip`.

The project-only page has the same ZIP/folder drop pathway.

## Report schema

File and project reports now include:

```json
"manual_review_guidance": {},
"risk_zones": [],
"manual_review_recommendations": []
```

These fields are not extra AI-evidence. They are an evidence-handling layer that tells an instructor what to verify manually.

## Manual-review guidance

The guidance layer contains:

- review status: routine documentation, recommended review, required review or not applicable;
- defensibility note;
- priority questions;
- evidence to request;
- recommended manual steps;
- risk zones tied to metrics, files, project filtering or calibration limitations.

## Defensibility boundary

The new guidance deliberately repeats the institutional interpretation boundary: CodeProbe is a triage and self-review aid. It does not prove AI use, does not prove misconduct and does not certify independent human authorship.
