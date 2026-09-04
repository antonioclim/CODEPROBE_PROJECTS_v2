# Offline classroom deployment

The release does not bundle the Pyodide distribution because the complete upstream directory is large. Offline deployment is supported only when the local files match the authenticated Pyodide 0.25.0 startup record shipped in `app/pyodide-provenance.json`.

## 1. Obtain the upstream distribution

Use the Pyodide 0.25.0 `full/` directory from a controlled upstream source and place it under:

```text
app/vendor/pyodide/v0.25.0/full/
```

At minimum, the current CodeProbe startup requires `pyodide.js`, `pyodide-lock.json`, `python_stdlib.zip`, `pyodide.asm.js` and `pyodide.asm.wasm`. Retain the complete `full/` directory when an institutional deployment may load additional standard Pyodide resources.

Maintainers can prepare the exact five-file functional-test fixture from the recorded distribution, or verify an existing source directory, with:

```bash
python3 -I -S -B tools/prepare_pyodide_fixture.py \
  --output-dir /path/outside/the/repository/pyodide-core
```

The command refuses redirects, enforces the recorded byte count while reading and checks every SHA-256 before publishing a fixture file.

## 2. Verify the core startup bytes

The five required files must match the exact sizes and SHA-256 values recorded in `app/pyodide-provenance.json`. The canonical static check is:

```bash
python3 -I -S -B tools/check_pyodide_provenance.py
```

This command validates the provenance record and browser integration. The browser repeats the file verification at startup and uses the resulting verified buffers during bootstrap. Do not edit the recorded values to fit an untrusted local copy; replace the local copy with the measured upstream bytes.

## 3. Select local mode

Change only the deployment mode in `app/runtime-config.json`:

```json
{
  "schema": "codeprobe-runtime-config/v1",
  "production": true,
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

Production mode rejects missing provenance, disabled integrity and disabled core-set verification.

## 4. Refresh tracked integrity and release evidence

Changing `runtime-config.json` or adding vendor files changes the release set. Refresh `app/resource-integrity.json`, then run the independent checks before regenerating tracked release evidence. Finally run:

```bash
python3 -I -S -B tools/check_release.py --require-node --write-release-evidence
python3 -I -S -B tools/check_release.py --require-node
```

A vendored distribution can increase the release packet substantially. Review the manifest, deterministic ZIP size and institutional storage limits before distribution.

## 5. Test without network access

Start the constrained server:

```bash
python3 -I -S -B tools/run_local_server.py
```

Open both browser pages with network access disabled and complete a representative file and project analysis. Confirm that the browser does not request the CDN and that the provenance check succeeds against the same-origin vendor files.

## Assurance boundary

Offline mode removes dependence on CDN availability and mutable future CDN responses. It does not establish that every optional Pyodide package is vulnerability-free, that the upstream build system is reproducible or that a local server is suitable for untrusted multi-user exposure. Preserve upstream notices and licence material for every redistributed component.
