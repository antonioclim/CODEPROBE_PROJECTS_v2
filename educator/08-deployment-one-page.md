# One-page deployment guide

## Option A — immediate classroom use

1. Unpack the release ZIP.
2. From the package root, run:

```bash
python3 -I -S -B tools/run_local_server.py
```

3. Open the printed local address.
4. Use `app/index.html` for ordinary use and `app/project.html` for compact project-only use.

This option uses the Pyodide source configured in `app/runtime-config.json`. In the default package this is a pinned CDN URL.

## Option B — institutional/offline deployment

1. Download the pinned Pyodide distribution separately according to `docs/05-offline-deployment.md`.
2. Place it under `app/vendor/pyodide/v0.25.0/full/`.
3. Change `app/runtime-config.json` to local mode.
4. Record the real SHA-256 digest of the local `pyodide.js` file.
5. Run:

```bash
python3 -I -S -B tools/check_release.py --write-release-evidence
python3 -I -S -B tools/check_release.py
```

The first command explicitly refreshes tracked release evidence after the
runtime change. Inspect that diff before using the second, read-only command as
the release gate.

6. Build and archive the institutional release packet:

```bash
python3 -I -S -B tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0_institutional.zip
```

## Minimum publication packet

Publish the following alongside the kit:

- release ZIP;
- generated ZIP SHA-256 sidecar;
- generated ZIP package-audit sidecar;
- `release/release-manifest.json`;
- course-local calibration profile, if used;
- student quick-start guide;
- course policy statement.

## Privacy boundary

The browser interface is designed for local analysis. Local report history is disabled by default and does not store source code. Students can use **Clear privacy data** to remove current browser-side report state.
