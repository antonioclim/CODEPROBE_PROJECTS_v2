# Optional offline Pyodide vendor directory

The release does not bundle Pyodide because the upstream distribution is large. For an offline deployment, copy the Pyodide 0.25.0 `full/` directory into:

```text
app/vendor/pyodide/v0.25.0/full/
```

Set `app/runtime-config.json` to local mode while retaining production integrity:

```json
{
  "pyodide": {
    "mode": "local",
    "version": "0.25.0",
    "local_loader_url": "vendor/pyodide/v0.25.0/full/pyodide.js",
    "local_index_url": "vendor/pyodide/v0.25.0/full/",
    "provenance_url": "pyodide-provenance.json",
    "expected_loader_sha256": "9c79c9999999b15de7587aa220c61d06aa14e76babb75dc50c2f873aa826ad4d",
    "require_integrity": true,
    "verify_core_startup_set": true
  }
}
```

The browser verifies `pyodide.js`, `pyodide-lock.json`, `python_stdlib.zip`, `pyodide.asm.js` and `pyodide.asm.wasm` against `app/pyodide-provenance.json`. Do not replace those values with hashes calculated from an untrusted vendor copy. The local files must match the authenticated upstream bytes.

The provenance record covers the measured core startup set used by CodeProbe. It does not certify every optional package or the complete current vulnerability state. Follow `docs/05-offline-deployment.md`, preserve upstream notices and rerun the canonical release and browser gates before distribution.
