# Optional offline Pyodide vendor directory

The release does not bundle Pyodide because the upstream runtime is large. For a fully offline classroom deployment, copy the Pyodide 0.25.0 `full/` directory into:

```text
app/vendor/pyodide/v0.25.0/full/
```

Then change `app/runtime-config.json` to:

```json
{
  "pyodide": {
    "mode": "local",
    "local_loader_url": "vendor/pyodide/v0.25.0/full/pyodide.js",
    "local_index_url": "vendor/pyodide/v0.25.0/full/",
    "expected_loader_sha256": "<real SHA-256 hex of pyodide.js>",
    "require_integrity": true
  }
}
```

Do not invent the digest. Compute it from the exact file distributed to
students. The digest covers only the loader, not the complete Pyodide runtime.
The canonical release gate therefore rejects vendored files until the repository
contains and verifies a complete authenticated provenance inventory. Follow
`docs/05-offline-deployment.md` before treating a local deployment as validated.
