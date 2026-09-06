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
- browser-resource and Pyodide core-startup provenance checks;
- supported-code coverage policy validation;
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

The refresh is attempted only after every mandatory check, including the unit
tests, runs and passes. The complete prospective evidence set is prepared before
the first replacement. Each evidence file uses atomic replacement with its
candidate receipt recorded before the rename, the manifest is written last and
post-write verification must pass. A detected generation failure triggers
verified restoration of the previous bytes, supported mode and modification
time. If restoration encounters an I/O error or a concurrent change, the
command reports that rollback is incomplete. `--write-manifest` remains a compatibility
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

### Supported-code coverage

Canonical CI runs the complete suite under the pinned Python 3.14.7 coverage policy:

```bash
python3 -I -S -B tools/check_coverage.py \
  --json-out /path/outside/the/checkout/codeprobe-supported-coverage.json
```

The output is diagnostic and must remain outside the release set. Overall, root and selected high-risk file floors are weighted by executable lines. Lowering a floor or adding an exclusion is a policy change that requires explicit review.

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

## 4. Build and recover the release packet

Before building or signing a packet, clear any interrupted publication for the
same output target:

```bash
python3 -I -S -B tools/build_release.py \
  --recover-only \
  --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

A normal build also runs this recovery step before validating the current
checkout. The explicit command is useful after a terminated process and before
an institutional signing workflow.

Build the packet with:

```bash
python3 -I -S -B tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

The builder runs the complete read-only gate against the committed evidence,
captures immutable bytes for every manifest-listed file and for the verified
manifest itself, then builds the ZIP only from that snapshot. The archive root
is `CodeProbe_Project_Kit_v2.2.0/`, independent of both the checkout directory
and output ZIP basename. Output inside the checkout is allowed only under
`dist/`; an external output is also permitted. The builder rejects non-`.zip`
names, output target symbolic links, special files and hard links that alias
source files.

The ZIP, SHA-256 sidecar and package-audit sidecar form one logical release
packet. They are prepared and verified in a private same-filesystem transaction
directory. Before any public packet member changes, the publisher records a
strict, versioned transaction journal and withdraws the checksum readiness
marker. It installs the ZIP, package audit and checksum in that order, recording
and synchronising each transition. The checksum is therefore present only for a
fully installed packet.

At the start of publication, or when `--recover-only` is used, the publisher
validates the lock and journal and compares the actual public bytes with the
recorded new and prior packet identities. It then either retains a complete new
packet, restores the complete prior packet, restores absence after an
interrupted first publication or stops fail-closed without overwriting an
unknown concurrent change. Recovery is itself journalled and may be repeated
after a second abrupt termination.

Do not remove a retained lock or transaction directory manually. A fail-closed
result preserves that evidence because it cannot prove that overwriting the
public paths is safe. Use the reported path for diagnosis. See
`docs/19-release-recovery.md` for the journal schema, state machine, operator
procedure and adversarial test matrix.

The protocol provides deterministic recovery from abrupt process termination
on the supported CI platforms. It does not make three independent names
atomically replaceable and does not claim universal power-loss durability.
Windows does not expose the same directory `fsync` primitive used on POSIX, so
the Windows assurance is deliberately limited to process-crash recovery and
conservative fail-closed handling. Byte-for-byte ZIP reproducibility remains
bounded to identical source bytes and the supported Python/zlib toolchain.

Consumers must treat the checksum sidecar as the readiness marker and verify it
before using the ZIP. Run publication in a quiescent output directory: the
transaction detects observed unknown changes but is not an authorisation
boundary against another process that already has write access.

## 5. Post-build smoke use

Open the browser kit through the local server:

```bash
python3 -I -S -B tools/run_local_server.py
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
