# Browser security model

CodeProbe is a static browser application. The intended classroom deployment is through the local helper server:

```bash
python3 -I -S -B tools/run_local_server.py
```

The server binds to `127.0.0.1` by default. The browser still executes JavaScript locally, loads Pyodide, and runs `codeprobe_runtime.py` inside the Pyodide runtime.

## Content Security Policy

The shipped HTML interfaces use this security posture:

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

This manifest covers CodeProbe's packaged browser files. The separate Pyodide provenance manifest authenticates the measured core startup set; neither manifest establishes ecosystem-wide vulnerability status.

## Pyodide trust boundary

The committed production configuration uses Pyodide 0.25.0 and requires integrity verification. `app/pyodide-provenance.json` binds the following core startup artefacts by exact byte size and SHA-256:

- `pyodide.js`;
- `pyodide-lock.json`;
- `python_stdlib.zip`;
- `pyodide.asm.js`;
- `pyodide.asm.wasm`.

The recorded files obtained from `https://cdn.jsdelivr.net/pyodide/v0.25.0/full/` were byte-identical to the corresponding members of the official `pyodide-core-0.25.0.tar.bz2` release asset. The upstream tag is bound to commit `6621b6bca72ed2cc4e9e66ed24783cce0e8dd907`.

Before calling Pyodide, `app/pyodide-loader.js` fetches and verifies the five startup artefacts once. It executes `pyodide.js` and `pyodide.asm.js` from Blob URLs created from the verified buffers. During bootstrap, exact lockfile, standard-library and WebAssembly requests are intercepted and answered from the corresponding verified in-memory buffers, so a later origin response cannot replace the inspected bytes. Startup also fails if Pyodide does not consume each required verified artefact.

The same loader verifies the exact packaged `src/codeprobe_runtime.py` size and SHA-256 before either interface writes or imports the module in Pyodide. `app/resource-integrity.json`, the embedded engine record and the actual file must agree. The main page retains a manual engine-file route only as an explicitly unverified recovery override and marks its report fingerprint accordingly.

This boundary is deliberately narrower than a supply-chain certification. It does not authenticate optional packages not used during CodeProbe startup, upstream build infrastructure, runtime availability or the complete current vulnerability state of the Pyodide ecosystem. A same-origin vendored deployment offers a stronger availability boundary, but it must contain bytes matching the same provenance record. `docs/18-runtime-integrity.md` records the consumption and browser-test contract.

## Local server boundary

`tools/run_local_server.py` uses `codeprobe_engine.server`. The server publishes an explicit application allowlist and never uses repository-root directory serving. It returns no directory listing and rejects noncanonical paths, traversal, links, special files, oversized responses and unsupported methods. Loopback is the default. `--allow-network` is required for a non-loopback bind and does not add authentication, TLS or multi-user isolation.

## Browser storage

The application stores no source code in local report history. History is disabled by default and, when enabled, stores the exported report text/JSON. These reports may still contain filenames, scores, metric details and snippets from metric explanations. In sensitive contexts, keep history disabled and use **Clear privacy data** after analysis.
