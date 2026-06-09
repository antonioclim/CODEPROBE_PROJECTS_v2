# Browser security model

CodeProbe is a static browser application. The intended classroom deployment is through the local helper server:

```bash
python3 tools/run_local_server.py
```

The server binds to `127.0.0.1` by default. The browser still executes JavaScript locally, loads Pyodide, and runs `codeprobe_runtime.py` inside the Pyodide runtime.

## Content Security Policy

The Phase 6 HTML interfaces use this security posture:

```text
default-src 'self';
script-src 'self' https://cdn.jsdelivr.net blob: 'wasm-unsafe-eval';
connect-src 'self' https://cdn.jsdelivr.net;
worker-src 'self' blob:;
style-src 'self';
img-src 'self' data:;
object-src 'none';
base-uri 'none';
form-action 'none';
frame-ancestors 'none'
```

`wasm-unsafe-eval` is retained because Pyodide needs WebAssembly execution. `blob:` is retained in `script-src` and `worker-src` because integrity-verified dynamic loading and Pyodide worker behaviour may require blob URLs in some browsers.

The two HTML pages intentionally avoid inline JavaScript and inline CSS. This makes the CSP easier to audit and prevents accidental reintroduction of inline event handlers.

## Local Subresource Integrity

The local browser assets have SRI attributes in the HTML files:

```text
codeprobe.css
project.css
pyodide-loader.js
codeprobe-ui.js
project-ui.js
```

The corresponding hashes are recorded in:

```text
app/resource-integrity.json
```

This manifest covers CodeProbe's local browser files. It does not certify the remote Pyodide CDN asset.

## Pyodide trust boundary

By default, `app/runtime-config.json` uses the Pyodide CDN:

```json
{
  "pyodide": {
    "mode": "cdn",
    "loader_url": "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/pyodide.js",
    "index_url": "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/"
  }
}
```

For high-assurance classroom use, use local mode instead:

```json
{
  "pyodide": {
    "mode": "local",
    "local_loader_url": "vendor/pyodide/v0.25.0/full/pyodide.js",
    "local_index_url": "vendor/pyodide/v0.25.0/full/",
    "expected_loader_sha256": "<real SHA-256 hex>",
    "require_integrity": true
  }
}
```

The digest must be computed from the exact `pyodide.js` file distributed to students. Do not copy a digest from another deployment or invent one.

## Browser storage

The application stores no source code in local report history. History is disabled by default and, when enabled, stores the exported report text/JSON. These reports may still contain filenames, scores, metric details and snippets from metric explanations. In sensitive contexts, keep history disabled and use **Clear privacy data** after analysis.
