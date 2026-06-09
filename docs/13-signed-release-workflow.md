# Optional signed-release workflow

CodeProbe does not require cryptographic signing, but institutions may want a signed release record for audit. The package provides deterministic file hashes through `release/release-manifest.json`; signing can be performed with institutional tools outside the kit.

## 1. Refresh validation and manifest

```bash
python3 tools/check_release.py --write-manifest
```

## 2. Build the release ZIP

```bash
python3 tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

## 3. Record the ZIP hash

```bash
sha256sum dist/CodeProbe_Project_Kit_v2.2.0.zip > dist/CodeProbe_Project_Kit_v2.2.0.zip.sha256
```

On macOS:

```bash
shasum -a 256 dist/CodeProbe_Project_Kit_v2.2.0.zip > dist/CodeProbe_Project_Kit_v2.2.0.zip.sha256
```

## 4. Sign with the institutional key

Example using GnuPG:

```bash
gpg --detach-sign --armor dist/CodeProbe_Project_Kit_v2.2.0.zip
gpg --detach-sign --armor dist/CodeProbe_Project_Kit_v2.2.0.zip.sha256
gpg --detach-sign --armor release/release-manifest.json
```

The exact key-management policy should be institutional. Do not include private keys in the release package.

## 5. Archive the release packet

Archive:

- release ZIP;
- ZIP SHA-256 file;
- detached signatures;
- `release/release-manifest.json`;
- course-local calibration profile, if used;
- `calibration/reports/` summary, if applicable.

## 6. Verification by a recipient

```bash
sha256sum -c CodeProbe_Project_Kit_v2.2.0.zip.sha256
gpg --verify CodeProbe_Project_Kit_v2.2.0.zip.asc CodeProbe_Project_Kit_v2.2.0.zip
```

After extraction, run:

```bash
python3 tools/validate_release.py --skip-tests
```
