# UI extension guide

CodeProbe keeps the browser interface deliberately simple: static HTML, external JavaScript, external CSS and a self-contained Python engine loaded through Pyodide. This design is scalable for course-level extensions because new features can be added as isolated panels without changing the analysis engine.

## Current extension points

### Tabs

`app/index.html` defines result panels using matching tab buttons and panel IDs:

```html
<button class="tab-btn" data-tab="tab-review" type="button">Manual review</button>
<section id="tab-review" class="tab-panel">...</section>
```

`app/codeprobe-ui.js` activates panels through the generic `activateTab()` function. A new feature usually needs only one tab button, one panel and one renderer.

### Renderers

The main render pipeline is:

```text
renderReport()
├── renderSummary()
├── renderManualReview()
├── populateProjectFiles() or populateMetrics()
└── update export/history state
```

New panels should follow the same pattern: read structured fields from the JSON report, render them into a dedicated container, and avoid mutating the report itself.

### Project intake

Drag-and-drop is handled by `collectDroppedFiles()`, `filesFromEntry()` and `handleDropDataTransfer()` in `app/codeprobe-ui.js`. The browser first tries the Chromium directory-entry API (`webkitGetAsEntry`) when it is available, then falls back to `DataTransfer.files`. ZIP files are sent as base64 to the engine; folder/file selections are passed as `{path, content, size_bytes}` records.

### Report schema

Features that need to survive export should be added to the JSON report in `src/codeprobe_runtime.py`, then displayed in the UI. Phase 8 uses this method for `manual_review_guidance`, `risk_zones` and `manual_review_recommendations`.

## Constraints worth preserving

- Do not add inline JavaScript or inline CSS; the release checker rejects them.
- Keep browser history optional and disabled by default.
- Keep source code out of local history.
- Prefer structured JSON fields over prose-only report additions.
- Keep score interpretation separate from misconduct judgement.
- Do not make CDN or Pyodide trust assumptions invisible; use `runtime-config.json`.

## Recommended pattern for future features

1. Add data to `src/codeprobe_runtime.py` or to a browser-only state object.
2. Add a tab/panel in `app/index.html` if the feature has persistent visual output.
3. Add a renderer in `app/codeprobe-ui.js`.
4. Add CSS to `app/codeprobe.css`.
5. Add tests for schema, UI hooks and release validation.
6. Refresh `app/resource-integrity.json`, run
   `tools/check_release.py --write-release-evidence`, inspect the evidence diff,
   and then run the read-only `tools/check_release.py` gate.
