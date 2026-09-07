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

The command verifies the complete provenance schema, a numeric `major.minor.patch` version, an absolute HTTPS distribution URL and the exact five unique core names before creating an output directory. Size fields must be positive integers and SHA-256 fields must contain 64 lower-case hexadecimal digits. Duplicate JSON keys, non-finite numbers and malformed required fields are rejected. The shipped provenance and its recorded values remain authoritative.

To verify local source files and produce a separate JSON report, use distinct source and output directories:

```bash
python3 -I -S -B tools/prepare_pyodide_fixture.py \
  --source-dir /path/to/verified-upstream/full \
  --output-dir /path/to/pyodide-core \
  --json-out /path/to/fixture-summary.json
```

Before the first write, the command checks the complete output set against the provenance, local source artefacts and Python tool/engine source files. A report or fixture destination cannot replace a consumed input or another output through the same path, a resolved alias or an existing hardlink. Conflicting file/directory destinations and symbolic-link output files are also refused. Distinct existing fixture files can be refreshed; using the source directory as the output directory is rejected.

Local artefacts are read through a regular-file descriptor with identity and stability checks before and after reading. Each read is explicitly bounded; growth is detected after at most the recorded size plus one byte has been read, and excess data is rejected before it is accumulated. Symbolic-link and non-regular source files are refused. Network reads retain their recorded-size ceiling and reject an unexpected final URL. Every file must match its exact size and SHA-256 before publication.

The complete JSON report is encoded before publication starts, and output conflicts are checked again before each write. Publication is atomic per file, not a transaction over all five artefacts and the report: a later read or write failure can leave earlier verified artefacts in place. A failure does not publish a success report, but an older report may remain. Re-run the command successfully before using the complete fixture. These checks do not provide a guarantee against every concurrent filesystem replacement or power loss.

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
