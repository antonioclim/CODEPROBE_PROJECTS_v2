# Offline classroom deployment

This release can be used immediately with the Pyodide CDN, but institutional deployments often prefer a fully local runtime. Use the following process.

## 1. Copy Pyodide into the vendor directory

Obtain Pyodide 0.25.0 from the official upstream distribution and copy the `full/` directory to:

```text
app/vendor/pyodide/v0.25.0/full/
```

The directory should contain `pyodide.js`, WebAssembly files and the standard Pyodide support files.

## 2. Compute the loader digest

From the kit root:

```bash
python3 - <<'PY'
from pathlib import Path
import hashlib
path = Path('app/vendor/pyodide/v0.25.0/full/pyodide.js')
print(hashlib.sha256(path.read_bytes()).hexdigest())
PY
```

## 3. Edit `app/runtime-config.json`

Set:

```json
{
  "pyodide": {
    "mode": "local",
    "local_loader_url": "vendor/pyodide/v0.25.0/full/pyodide.js",
    "local_index_url": "vendor/pyodide/v0.25.0/full/",
    "expected_loader_sha256": "<digest from step 2>",
    "require_integrity": true
  }
}
```

## 4. Refresh evidence and run release validation

```bash
python3 tools/check_release.py --write-release-evidence
python3 tools/check_release.py
```

The first command explicitly refreshes the audit reports and release manifest
after the local Pyodide files are added. Inspect the resulting diff. The second
command is the canonical read-only release gate. Large Pyodide files will
increase the ZIP size substantially.

## 5. Distribute the folder or a validated ZIP

A validated release ZIP can be produced with:

```bash
python3 tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0_offline.zip
```

Vendored runtime content must consist of regular files rather than symbolic
links or special filesystem entries. Archive the final ZIP and both required
sidecars in your institutional course repository so students and instructors
use the same runtime.
