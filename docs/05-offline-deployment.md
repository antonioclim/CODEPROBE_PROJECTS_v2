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
python3 -I -S - <<'PY'
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

## 4. Establish the missing provenance boundary

The canonical source release currently rejects vendored runtime bytes and a
production configuration that selects local mode. It does so because the
repository has no authenticated inventory for the complete Pyodide
distribution. The loader digest in step 2 is necessary but does not cover the
WebAssembly and support files loaded later.

Before presenting a local deployment as a validated CodeProbe release, add and
review all of the following:

- the exact upstream release source and its independently authenticated digest
  or signature;
- a complete canonical file inventory with sizes and SHA-256 values;
- the applicable Pyodide and transitive licence notices;
- a dependency-boundary check that verifies every deployed runtime file;
- a live browser test using the local configuration with network access
  disabled.

This repository does not yet ship that attestation. A downstream deployment may
stage the files for controlled local evaluation, but it must not describe the
result as passing the canonical release gate.

## 5. Refresh evidence after attestation support exists

Once the complete inventory and its verifier have been introduced, refresh and
check the tracked evidence:

```bash
python3 -I -S -B tools/check_release.py --write-release-evidence
python3 -I -S -B tools/check_release.py
```

The first command explicitly refreshes the audit reports and release manifest.
Inspect the resulting diff. The second command is the canonical read-only
release gate. Large Pyodide files will increase the ZIP size substantially.

## 6. Distribute the folder or a validated ZIP

A validated release ZIP can be produced with:

```bash
python3 -I -S -B tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0_offline.zip
```

Vendored runtime content must consist of regular files rather than symbolic
links or special filesystem entries. Archive the final ZIP and both required
sidecars in your institutional course repository so students and instructors
use the same runtime.
