# Phase 6 changeset — browser security, privacy controls and deployment hardening

Phase 6 hardens the browser delivery model without changing the underlying interpretation of the score. CodeProbe remains a local, heuristic, formative review aid. It does not prove AI use, identify an LLM, or certify human authorship.

## Security changes

- Inline browser JavaScript has been moved out of `index.html` and `project.html` into `app/codeprobe-ui.js` and `app/project-ui.js`.
- Inline CSS has been moved into `app/codeprobe.css` and `app/project.css`.
- The browser pages now use a stricter Content Security Policy with no `unsafe-inline` directive.
- Local browser assets are loaded with Subresource Integrity attributes.
- `app/resource-integrity.json` records SHA-256 hashes and SRI strings for local browser assets.
- `app/pyodide-loader.js` centralises Pyodide loading and reads `app/runtime-config.json`.
- `app/runtime-config.example.json` documents an offline/integrity-enforced Pyodide configuration.
- `app/vendor/pyodide/README.md` explains where to place a local Pyodide distribution for offline deployment.

## Privacy changes

- Browser history remains disabled by default.
- The main interface now includes **Clear privacy data**, which clears local report history, disables report history, clears the editor/project payload and removes the transient Pyodide payload reference where possible.
- The UI explicitly states the privacy boundary: reports can be stored only when the user opts in; source code is not stored in report history.

## Deployment changes

- `docs/04-browser-security.md` describes the CSP, SRI and Pyodide trust boundary.
- `docs/05-offline-deployment.md` gives a practical offline classroom deployment path.
- Release validation now checks external JavaScript files, local browser-resource integrity and the absence of inline browser code in the two HTML interfaces.

## Non-goals

Phase 6 does not bundle Pyodide. The Pyodide runtime is large and should be supplied by the institution when offline or integrity-enforced deployment is required. The default `runtime-config.json` still uses the Pyodide CDN so the kit works immediately in ordinary local-server use. For high-assurance classroom deployment, switch `runtime-config.json` to local mode and provide the real SHA-256 digest of the exact `pyodide.js` file distributed to students.
