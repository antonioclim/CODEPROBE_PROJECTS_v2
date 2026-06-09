# Release hash sheet

This file records how to verify a CodeProbe source release. The authoritative per-file hashes are in `release/release-manifest.json`; the final ZIP hash is recorded outside the ZIP after packaging.

## Source tree manifest

Refresh before distribution:

```bash
python3 tools/check_release.py --write-manifest
```

Verify after extraction:

```bash
python3 tools/validate_release.py --skip-tests
```

## Final ZIP hash

After building the ZIP, create a sidecar hash file:

```bash
sha256sum CodeProbe_Project_Kit_v2.2.0.zip > CodeProbe_Project_Kit_v2.2.0.zip.sha256
```

The ZIP hash cannot be embedded inside the ZIP without changing the ZIP itself. Keep the sidecar `.sha256` file with the institutional archive and course release notes.

## What to archive

- final ZIP;
- final ZIP SHA-256 sidecar;
- optional detached signature;
- `release/release-manifest.json`;
- active calibration profile, if used;
- calibration validation summary, if used.
