# Release hash sheet

This file records how to verify a CodeProbe source release. After exact gate
verification, `release/release-manifest.json` is the committed package allowlist
and records each regular file's size and SHA-256 digest. The final ZIP hash is
recorded outside the ZIP after packaging.

## Source tree manifest

Refresh intentionally after an accepted source change:

```bash
python3 -I -S -B tools/check_release.py --write-release-evidence
```

Inspect the evidence diff, then run the canonical read-only gate:

```bash
python3 -I -S -B tools/check_release.py
```

## Final ZIP hash

`tools/build_release.py` creates two required sidecars beside the ZIP as:

```text
CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt
CodeProbe_Project_Kit_v2.2.0.zip.package_audit.json
```

The ZIP hash cannot be embedded inside the ZIP without changing the ZIP itself.
Keep the generated `.zip.sha256.txt` file with the institutional archive and
course release notes.

## What to archive

- final ZIP;
- final ZIP SHA-256 sidecar;
- final ZIP package-audit sidecar;
- optional detached signature;
- `release/release-manifest.json`;
- active calibration profile, if used;
- calibration validation summary, if used.
