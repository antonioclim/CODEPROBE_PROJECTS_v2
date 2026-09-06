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

New panels should follow the same pattern: read structured fields from the JSON report, render them into a dedicated container and avoid mutating the report itself.

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
   `python3 -I -S -B tools/check_release.py --write-release-evidence`, inspect the
   evidence diff and then run the read-only
   `python3 -I -S -B tools/check_release.py` gate.


## Accessibility contract

New controls must have a programmatic name and a visible `:focus-visible` state. Dynamic operational messages belong in the existing polite status regions rather than in transient visual-only text. Numeric score bars must update their visual width and `aria-valuenow`/`aria-valuetext` together; unavailable or inapplicable scores omit `aria-valuenow` and retain an explicit textual state.

The main result selector follows the ARIA tab pattern. Exactly one tab is selected and in the page tab order. Left and Right move cyclically, Home selects the first tab and End selects the last. Inactive panels carry the native `hidden` state as well as the visual class so they are absent from the accessibility tree.

Run the static and real-browser checks after changing the interface:

```bash
python3 -I -S -B -m unittest discover -s tests -p 'test_browser_security.py' -v
node tools/check_browser_accessibility.js
```

The browser gate launches the shipped local server and an installed Chromium-family browser, blocks the external Pyodide CDN and verifies the interface contract without treating successful runtime download as an accessibility prerequisite.

New analysis panels must use the shared worker session, not a page-level Python runtime. Preserve single-flight admission, generation checks, cancellation, deadlines and verified engine identity. Do not add a production debug command that executes arbitrary Python. Extend both the hermetic protocol tests and real Chromium gate for any protocol change.
