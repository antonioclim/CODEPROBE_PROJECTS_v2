# Release publication recovery

## 1. Purpose and assurance boundary

`tools/build_release.py` publishes a logical three-file packet:

```text
<release>.zip
<release>.zip.package_audit.json
<release>.zip.sha256.txt
```

No portable filesystem operation can replace all three names atomically. The
publisher therefore uses a durable transaction journal and treats the checksum
sidecar as the public readiness marker. A packet is ready only when all three
files are present, the checksum sidecar is installed last and independent
verification succeeds.

The protocol is designed to recover deterministically after abrupt process
termination, including `SIGKILL` or `os._exit`, on the operating systems covered
by the CI matrix. It does not claim storage-controller atomicity, protection
against torn writes outside the host operating-system contract or identical
power-loss durability on every filesystem.

## 2. Transaction layout

For an output named `CodeProbe_Project_Kit_v2.2.0.zip`, publication uses:

```text
.CodeProbe_Project_Kit_v2.2.0.zip.publish.lock
.CodeProbe_Project_Kit_v2.2.0.zip.transaction-<32-hex-id>/
```

The lock is a strict JSON document that binds the transaction identifier,
process identifier, hostname, application version and packet basename. The
private transaction directory contains:

```text
journal.json
public-mutation.started
new/
backup/
install/
```

`new/` holds the complete verified candidate packet. `backup/` holds the prior
public packet when one existed. `install/` is used for same-filesystem atomic
replacement of individual packet members. `public-mutation.started` is written
and synchronised before the first public path is changed.

The journal schema is `codeprobe-release-publication-journal/v1`. Unknown
fields, duplicate JSON keys, unsafe paths, inconsistent target names, invalid
hashes, mismatched application versions and lock/journal ownership mismatches
are rejected.

## 3. Durable state machine

The journal records the following states:

```text
prepared
readiness_withdrawn
zip_installed
audit_installed
checksum_installed
committed
rollback_started
rollback_zip_restored
rollback_audit_restored
rollback_checksum_restored
rolled_back
```

Every state transition is written through an atomic control-file replacement
and synchronised before the next public mutation. The checksum sidecar is
removed before the ZIP or package-audit file can change and is installed last.
Consequently, a consumer that requires the checksum sidecar cannot mistake a
known intermediate state for a ready packet.

## 4. Automatic recovery

Normal publication calls recovery before validating the current source tree or
building a new packet. This ordering matters: an interrupted transaction must
be recoverable even when the current checkout or release manifest has changed
since the interrupted process began.

Recovery classifies each public target by exact bytes and supported metadata as
one of:

- the new transaction value;
- the recorded prior value;
- absent, where the target did not previously exist;
- unknown.

The resulting behaviour is conservative:

| Observed state | Recovery action |
|---|---|
| Complete new packet, including a valid checksum readiness marker | Retain the new packet and remove the private transaction state |
| Mixture containing only recorded new and prior values | Restore the complete prior packet |
| Interrupted first publication containing only new values and absent prior targets | Remove the partial packet and restore complete absence |
| Unknown or concurrently modified public value | Stop fail-closed and retain all recovery evidence |
| Live local lock owner | Refuse concurrent recovery or publication |
| Stale lock owned by a dead local process | Recover from the validated journal |
| Lock naming a different host | Stop fail-closed because liveness cannot be established safely |
| Missing or invalid journal after public mutation was authorised | Stop fail-closed and retain the transaction directory |
| More than one non-empty transaction directory for the packet | Stop fail-closed |
| Empty legacy staging directory | Remove it |
| Non-empty unrecognised legacy staging directory | Retain it and stop fail-closed |

Rollback is journalled as well. If the recovery process is itself terminated,
a later invocation resumes from the observed bytes and validated journal rather
than assuming that the first rollback completed.

## 5. Operator command

Run recovery without building a new packet:

```bash
python3 -I -S -B tools/build_release.py \
  --recover-only \
  --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

The `--out` value must be identical to the interrupted publication target. For
the default output, `--out` may be omitted.

A successful recovery prints one of the explicit recovery statuses and exits
zero. A fail-closed result exits non-zero and reports the retained recovery
path. Do not delete the lock or transaction directory manually: those files
contain the only durable evidence needed to distinguish a recoverable packet
from an unrelated concurrent modification.

After recovery, run the canonical read-only gate before building, signing or
distributing a packet:

```bash
python3 -I -S -B tools/check_release.py
```

## 6. Consumer rule

A recipient must not use a ZIP merely because the ZIP path exists. The release
is ready only when:

1. the ZIP, checksum sidecar and package-audit sidecar are all present;
2. the checksum sidecar verifies the ZIP independently;
3. the package-audit sidecar names the same ZIP and digest;
4. the extracted kit passes the documented isolated validation command.

The recipient validation command is:

```bash
python3 -I -S -B tools/validate_release.py --skip-tests
```

## 7. Test evidence and limitations

`tests/test_release_recovery.py` and
`tests/test_release_crash_driver.py` exercise abrupt termination after lock
creation, transaction creation, journal preparation, readiness withdrawal, each
public member installation and commit recording. They also cover repeated
recovery after interruption during rollback, first-publication recovery, live
and foreign-host locks, duplicate JSON keys, orphan transaction directories,
unknown concurrent public changes and the public `--recover-only` route.

The fault hook is a private callable supplied explicitly by the test driver. It
is not enabled by an environment variable and is not reachable through the
normal command-line interface.

On POSIX systems the implementation synchronises control files, packet files
and directories where the platform exposes the required primitive. Python's
portable Windows interface does not expose an equivalent directory `fsync`, so
the supported Windows claim is deterministic process-crash recovery and
conservative fail-closed behaviour, not identical hardware power-loss
semantics.

## Recognised identity overlap

A public member can match both recorded prior and candidate new identities.
Classification preserves that overlap instead of inventing an external change.
The recognised partial-packet rebuild route repairs missing members without
weakening unknown-concurrent-state refusal or checksum-last readiness.
Interrupted repair either retains a complete new packet or restores its
recorded prior state, which can itself be partial. The tests and limits are
described in `docs/22-contract-reconciliation.md`.
