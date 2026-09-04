# Runtime integrity and functional browser evidence

## Scope

CodeProbe executes two material runtime layers in the browser: the Pyodide core startup set and `src/codeprobe_runtime.py`. A digest is useful only when the verified bytes are the bytes subsequently consumed. The production path therefore treats verification and consumption as one boundary.

## Pyodide byte binding

`app/pyodide-provenance.json` records exact sizes and SHA-256 values for `pyodide.js`, `pyodide-lock.json`, `python_stdlib.zip`, `pyodide.asm.js` and `pyodide.asm.wasm`. `app/pyodide-loader.js` downloads each artefact once and retains the verified `Uint8Array`.

- `pyodide.js` and `pyodide.asm.js` execute from Blob URLs created from the verified buffers.
- During `loadPyodide()`, exact lockfile, standard-library and WebAssembly requests are answered from cloned copies of the retained verified buffers.
- Any non-GET request or failure to consume a required verified artefact stops startup.
- The original browser `fetch` function is restored after bootstrap.
- Optional packages and an alternative `indexURL`, `lockFileURL` or `stdLibURL` are not accepted by the production entry point.

This prevents a mutable origin from returning a benign first response for verification and a different second response for execution.

## Python-engine byte binding

The loader contains the packaged engine path, size and SHA-256. The same engine record must agree with `app/resource-integrity.json` and the exact tracked file. Both browser interfaces obtain the engine through `CodeProbeRuntime.loadVerifiedEngine()`. Import is permitted only after the fetched same-origin bytes match the recorded size and digest.

The main page retains a manual engine-file control for recovery. The control requires explicit confirmation, labels the engine and report fingerprint `manual-unverified` and does not present the resulting report as packaged CodeProbe evidence.

## Shared source and path identity

Browser file and folder input uses one shared decoder:

1. reject NUL-bearing input as binary;
2. decode strict UTF-8;
3. if strict UTF-8 fails, decode the exact bytes as Latin-1 and emit a warning;
4. normalise line endings to LF.

Project paths use Unicode NFC before portable collision and ignore-rule processing. The Python file-list, ZIP and local-folder paths use the same identity rule. Canonically equivalent names therefore collide instead of being analysed as separate files.

## Required Chromium gate

`tools/prepare_pyodide_fixture.py` prepares an authenticated five-file startup fixture outside the checkout. `tools/check_browser_functional.js` then starts a restricted fixture server and a Chromium-family browser through Chrome DevTools Protocol. The gate:

- performs one real single-file analysis and downloads JSON and text reports;
- performs one real two-file project analysis and downloads JSON and text reports;
- verifies that exported reports carry the packaged engine digest;
- checks Latin-1 decoding and NFC path identity in the live page;
- corrupts every hypothetical second core response and requires the origin to be contacted only once per artefact;
- corrupts the first WebAssembly response and requires fail-closed startup;
- reloads with clean bytes and requires recovery;
- tampers with the Python engine and requires failure before import.

The CI job is required by `Required CI`. It uses an authenticated local fixture so it tests actual Pyodide execution without trusting a mutable second download during bootstrap.

## Assurance limits

The boundary does not prove that Pyodide's upstream build is reproducible, that optional packages are safe, that the CDN will remain available or that the ecosystem has no current vulnerabilities. It also does not validate CodeProbe's AI-style concern score. Those are separate supply-chain, operational and scientific questions.
