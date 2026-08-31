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
python3 -I -S -B tools/check_release.py
```

This is the canonical read-only gate. It does not write bytecode, audit reports
or the release manifest into the source tree. A normal Git clone and an exact
`git archive` export must produce the same semantic check results when the same
supported toolchain and a byte-preserving checkout configuration are used.

This runs:

- release-set safety checks that reject symbolic links and non-regular files
  before later readers are invoked;
- the standard-library dependency boundary and immutable workflow action pins;
- Python compilation checks;
- unit-test discovery, only after the dependency boundary succeeds;
- JavaScript syntax checking through Node.js when available;
- browser CSP and local SRI checks;
- browser-resource integrity checks;
- version-consistency checks;
- file and project smoke analyses;
- metric-inventory checks;
- exact verification of the committed audit reports and release manifest.

A dependency-boundary failure prevents the checkout's unit tests from running.
The gate reports that test step as skipped while the remaining non-test checks
continue to provide additional diagnostics.

After an intentional source change, refresh the tracked release evidence with:

```bash
python3 -I -S -B tools/check_release.py --write-release-evidence
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
python3 -I -S -B tools/check_release.py --skip-tests
```

Machine-readable results may be requested with `--json-out`, but that explicit
diagnostic output must be placed under `dist/` or outside the checkout. The tool
rejects destinations inside the release set because they would immediately make
the committed manifest stale.

### CI parity gate

CI runs the canonical gate with `--require-node` across the supported Python
matrix. It never uses `--write-release-evidence`: stale evidence must fail rather
than be repaired by automation. A separate job runs:

```bash
python3 -I -S -B tools/check_release_reproducibility.py
```

That command requires a clean Git commit. It compares the committed tree with
normalised LF and forced-CRLF checkouts and an exact Git export, then builds and
compares the mandatory ZIP and both sidecars. It invokes the fast gate inside
its isolated candidate trees to avoid recursively starting the full test suite.
The exact workflow matrix and repository rules are defined in
`docs/16-ci-and-repository-controls.md`.

## 3. Inspect `release/release-manifest.json`

The release manifest is the explicit package allowlist. Verification requires
the exact schema, application name and version, canonical ordered relative paths,
file count, aggregate size, per-file sizes and SHA-256 digests and the canonical
manifest digest. Duplicate JSON keys, duplicate paths, traversal paths, excluded
locations and unrecognised fields fail closed. The manifest itself and every
listed source must be a regular file rather than a symbolic link or special
filesystem entry. Current regular-file membership must match the manifest
exactly; an extra or missing release file fails verification.

## 4. Build the release ZIP

```bash
python3 -I -S -B tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

The builder runs the complete read-only gate against the committed evidence,
captures immutable bytes for every manifest-listed file and for the verified
manifest itself, then builds the ZIP only from that snapshot. The archive root
is `CodeProbe_Project_Kit_v2.2.0/`, independent of both the checkout directory
and output ZIP basename.
Output inside the checkout is allowed only under `dist/`; an external output is
also permitted. The builder rejects non-`.zip` names, output target symbolic
links, special files and hard links that alias source files.

The ZIP, SHA-256 sidecar and package-audit sidecar form one required release
packet. All three are created and checked in a private same-filesystem staging
directory. When replacement is required, existing targets are backed up, then
the ZIP and package audit are replaced before the checksum readiness marker. A detected in-process write,
sync or verification failure attempts to restore the complete prior packet. If
rollback is incomplete, the command returns non-zero and retains its recovery
directory.

This is not a power-loss or `SIGKILL`-atomic three-file transaction: ordinary
filesystems cannot replace three independent names as one atomic operation. An
uncatchable interruption can leave staging or lock debris and may require
operator recovery. Consumers must treat the checksum sidecar as the readiness
marker and verify it before using the ZIP. Byte-for-byte ZIP reproducibility is
bounded to identical source bytes and the same supported Python/zlib toolchain.
Windows does not expose the same directory `fsync` durability primitive used on
POSIX systems, so the tool does not claim equivalent rename durability there.
Run validation and evidence refresh in a quiescent checkout. The safety precheck
is not a sandbox against another process that already has write access to the
tree. Package construction is insulated from later source changes only after
the immutable snapshot has been captured.

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
7. if using offline deployment, `runtime-config.json` points to the local
   Pyodide path and contains the real loader digest;
8. if using offline deployment, the complete local runtime matches its
   authenticated file inventory and licence record;
9. if using offline deployment, the inventory verifier passes and a live browser
   test succeeds with network access disabled, as required by
   `docs/05-offline-deployment.md`.

## 6. Archival recommendation

For course use, archive the exact release ZIP, the SHA-256 of that ZIP and the calibration profile used for the course. Keep the local validation summary beside the profile. Do not rely on a generic threshold without recording the local policy decision.

## Institutional release packet

For course publication, archive the following together:

- the release ZIP produced by `tools/build_release.py`;
- the ZIP SHA-256 sidecar file;
- the `.zip.package_audit.json` sidecar file;
- `release/release-manifest.json`;
- optional detached signatures, if institutional policy requires signing;
- active course-local calibration profile and validation summary, if used;
- the student quick-start and course policy notice.

See `docs/13-signed-release-workflow.md` and `docs/12-release-hash-sheet.md` for the optional signing and hash-recording procedure.


From v2.2.0, `tools/build_release.py` writes required `.zip.sha256.txt` and
`.zip.package_audit.json` sidecars. Keep the three files together and use their
content rather than visible ZIP size when reconciling release artefacts.
