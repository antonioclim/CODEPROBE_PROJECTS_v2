# Optional signed-release workflow

CodeProbe does not require cryptographic signing, but institutions may want a
signed release record for audit. The package provides a strictly verified
per-file membership, size and SHA-256 record through
`release/release-manifest.json`; signing can be performed with institutional
tools outside the kit.

## 1. Refresh evidence and run the read-only gate

```bash
python3 -I -S -B tools/check_release.py --write-release-evidence
python3 -I -S -B tools/check_release.py
```

Inspect the evidence diff between these commands.

## 2. Build the release packet

```bash
python3 -I -S -B tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

## 3. Verify the generated ZIP hash sidecar

The builder writes
`dist/CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt`. From the `dist/`
directory, verify it independently:

```bash
sha256sum -c CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt
```

On macOS:

```bash
shasum -a 256 -c CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt
```

The package-audit sidecar is a required member of the release packet. Retain
`CodeProbe_Project_Kit_v2.2.0.zip.package_audit.json`; it records the
same ZIP name and SHA-256 together with exact member and container accounting.
The checksum is published last and is the packet readiness marker.

## 4. Sign with the institutional key

Example using GnuPG:

```bash
gpg --detach-sign --armor dist/CodeProbe_Project_Kit_v2.2.0.zip
gpg --detach-sign --armor dist/CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt
gpg --detach-sign --armor dist/CodeProbe_Project_Kit_v2.2.0.zip.package_audit.json
gpg --detach-sign --armor release/release-manifest.json
```

The exact key-management policy should be institutional. Do not include private keys in the release package.

## 5. Archive the release packet

Archive:

- release ZIP;
- ZIP SHA-256 file;
- ZIP package-audit file;
- detached signatures;
- `release/release-manifest.json`;
- course-local calibration profile, if used;
- `calibration/reports/` summary, if applicable.

## 6. Verification by a recipient

```bash
sha256sum -c CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt
gpg --verify CodeProbe_Project_Kit_v2.2.0.zip.asc CodeProbe_Project_Kit_v2.2.0.zip
```

On macOS, replace the first command with
`shasum -a 256 -c CodeProbe_Project_Kit_v2.2.0.zip.sha256.txt`.

After extraction, run:

```bash
python3 -I -S -B tools/validate_release.py --skip-tests
```
