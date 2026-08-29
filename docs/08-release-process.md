# Release process

## 1. Update versioned files

Before building a release, update:

- `src/codeprobe_runtime.py`;
- `src/codeprobe_engine/version.py`;
- `README.md`;
- `CHANGELOG.md`;
- browser titles in `app/index.html` and `app/project.html`;
- local SRI attributes in the browser HTML if browser assets changed;
- `app/resource-integrity.json` if `codeprobe_runtime.py`, browser JS/CSS or runtime config changed;
- any relevant phase changeset under `docs/`.

## 2. Run release checks

From the repository root:

```bash
python3 tools/check_release.py
```

This is the canonical read-only gate. It does not write bytecode, audit reports
or the release manifest into the source tree. A normal Git clone and an exact
`git archive` export must produce the same semantic check results when the same
supported toolchain and a byte-preserving checkout configuration are used.

This runs:

- Python compilation checks;
- unit-test discovery;
- JavaScript syntax checking through Node.js when available;
- browser CSP and local SRI checks;
- browser-resource integrity checks;
- version-consistency checks;
- file and project smoke analyses;
- metric-inventory checks;
- verification of the committed audit reports and release manifest.

After an intentional source change, refresh the tracked release evidence with:

```bash
python3 tools/check_release.py --write-release-evidence
```

The refresh is attempted only after the other checks pass. Each evidence file
uses atomic replacement, the manifest is written last and post-write
verification must pass. A detected generation failure triggers restoration of
the previous bytes; if restoration itself encounters an I/O error, the command
reports that rollback is incomplete. `--write-manifest` remains a compatibility
alias, but it is not the canonical spelling. Missing tracked audit artefacts are
treated as a fail-closed condition rather than bootstrapped from an incomplete
release set.

For a faster pre-commit pass:

```bash
python3 tools/check_release.py --skip-tests
```

Machine-readable results may be requested with `--json-out`, but that explicit
diagnostic output must be placed under `dist/` or outside the checkout. The tool
rejects destinations inside the release set because they would immediately make
the committed manifest stale.

## 3. Inspect `release/release-manifest.json`

The release manifest records each file path, file size and SHA-256 digest. It is intended for audit and institutional archiving. If a distributed release is later questioned, the manifest helps establish which exact files were shipped.

## 4. Build the release ZIP

```bash
python3 tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

The builder runs the complete read-only gate against the committed evidence,
then writes the ZIP and its external sidecars. It does not refresh tracked
source-tree evidence. If validation fails, package construction is not started.
Transactional replacement of the ZIP and its sidecars remains a separate
packaging-hardening concern.

## 5. Post-build smoke use

Open the browser kit through the local server:

```bash
python3 tools/run_local_server.py
```

Then verify manually:

1. `index.html` loads the engine;
2. single-file analysis returns a report;
3. project ZIP/folder analysis lists included and excluded files;
4. the exported JSON contains `engine_fingerprint`, `metric_config_digest` and `tool_metadata`;
5. local report history remains opt-in;
6. **Clear privacy data** clears the editor/report state and local history;
7. if using offline deployment, `runtime-config.json` points to the local Pyodide path and contains the real loader digest.

## 6. Archival recommendation

For course use, archive the exact release ZIP, the SHA-256 of that ZIP and the calibration profile used for the course. Keep the local validation summary beside the profile. Do not rely on a generic threshold without recording the local policy decision.

## Institutional release packet

For course publication, archive the following together:

- the release ZIP produced by `tools/build_release.py`;
- the ZIP SHA-256 sidecar file;
- `release/release-manifest.json`;
- optional detached signatures, if institutional policy requires signing;
- active course-local calibration profile and validation summary, if used;
- the student quick-start and course policy notice.

See `docs/13-signed-release-workflow.md` and `docs/12-release-hash-sheet.md` for the optional signing and hash-recording procedure.


From v2.2.0, `tools/build_release.py` writes `.zip.sha256.txt` and `.zip.package_audit.json` sidecars. Use these sidecars rather than visible ZIP size when reconciling release artefacts.
