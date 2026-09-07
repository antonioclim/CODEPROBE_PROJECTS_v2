# Scoring, input and publication contracts

## Scope

This note defines the contracts repaired after the Phase 4G targeted re-audit.
Passing software tests establishes the exercised behaviour, not empirical
LLM-code detection, authorship attribution, anonymity or readiness for a
misconduct decision. Existing licensing, attribution and promotion restrictions
are unchanged.

## One effective scoring configuration

New calibration profiles carry a `codeprobe-scoring-contract/v1` record with
`base_profile`, `engine_sha256` and `metric_config_digest`. Calibration scoring
uses the manifest metric overrides, or the replacement override supplied through
`--config`, before both fitting and held-out evaluation. The profile binds that
same merged configuration. Application checks the actual loaded engine source
rather than trusting a caller-provided fingerprint.

The public file/project entry points select the bound base mode when `profile`
is omitted. An explicit conflicting mode, changed effective overrides, changed
engine identity or incompatible report-kind/language scope is rejected. The
native project CLI leaves the mode unspecified by default so a bound profile can
select it. Browser selectors are explicit: choose the bound mode or application
will refuse the mismatch. An identical redundant override remains permissible.

Legacy manually supplied profiles without a scoring contract remain compatible
with the older provisional policy route. They do not acquire verified replay
provenance merely by parsing. Refit an old generated profile before relying on
its recorded evaluation: the implementation cannot reconstruct its omitted
historical scoring configuration. A matching digest is an identity check, not a
signature or proof that the supplied evaluation data are authentic.

`overall_score` retains its rounded display/compatibility representation.
`decision_score` records the unrounded numerical value used by the review
comparison and by new calibration fitting. Observation CSVs include it too.
Threshold selection compares unrounded counts/rates; rounded reporting values
cannot make an otherwise ineligible candidate satisfy the target. The native
and browser regression compares the same generated profile and fixture with a
numerical tolerance of 1e-12, plus exact configuration/engine identities. This is
a particular replay test, not a cross-platform theorem for every input.

## Feasibility and operational status

Selection still uses only the fit partition and the existing threshold grid.
The profile declares `validation.target_met`, `grid_feasible`,
`evaluation_target_met` and `target_status`. Evaluation results do not alter the
selected threshold. Grid infeasibility is not impossibility over every real
threshold or future corpus.

When the fit target is not met, `operational` is false and
`operational_reason` identifies `fit-target-unmet`. The fallback threshold and
actual rates remain available for diagnosis, but the public application entry
points refuse the draft. Summaries assembled from unbound numerical scores are
also non-operational. Operational means replayable under this software policy;
it does not establish an adequate sample size, successful external validation
or approval for high-stakes use. Small-partition warnings remain mandatory.

## Input generations and immutable report identity

Every asynchronous file, ZIP or directory intake obtains a generation before
reading. A replacement, cancellation, privacy wipe or teardown invalidates that
generation. Each asynchronous completion checks ownership before changing the
editor, project payload, status or loading controls. Old errors and old
`finally` blocks are subject to the same rule. The manual-engine bundle cache
also checks ownership after reading and hashing: a late read cannot restore a
wiped cache.

A new selection invalidates the prior report before any read completes.
Language, scoring-mode, configuration, calibration and editor changes invalidate
pending/current reports. Export names come from the accepted report, not a
mutable later selection. The compact interface additionally verifies the
returned project name against its request and stores the accepted export name.
A failed or cancelled replacement does not silently resurrect an old report.

This protects the maintained event paths. It is not a defence against arbitrary
same-origin script modification or a hostile manually substituted engine. DOM,
File and interpreter doubles in `tools/check_input_contracts.js` control event
order. The separate Chromium functional gate exercises real DOM events and
File objects with controlled read completion, actual authenticated Pyodide and
downloaded reports.

## Selected-input accounting

A browser-preexcluded item remains in the bounded file-list payload as:

```json
{
  "path": "oversized.py",
  "size_bytes": 1000001,
  "intake_rejection": {"reason": "file_too_large"}
}
```

Allowed reasons are `file_too_large`, `project_total_byte_limit`,
`unsupported_file_type`, `unreadable_file` and `unsafe_path`. Non-negative safe
integer sizes, bounded path text, a strict rejection record and absent/empty
content are required. Rejected file contents are not read solely to report the
exclusion. The engine applies its own path safety checks, then records the
reason with a `browser_` prefix, except independently unsafe paths. Rejected
ignore files never supply ignore rules.

These are explicitly caller-reported exclusions: neither contents nor claimed
sizes are independently inspected. The record can explain why selected input
was not analysed; it cannot authenticate what the caller originally selected.
Existing entry, byte, archive and path limits still apply. A selection rejected
as a whole does not produce a successful partial report.

An absent calibration is represented as absent. A project-level calibration is
not copied into children as though each child had an independently calibrated
file policy. Root project policy and child provisional policy remain distinct;
engine/configuration identity still describes the actual scoring computation.

## Recognised prior/new publication overlap

Public packet member classification derives new/prior membership from one
coherent content/metadata read. A member matching both identities is `both`,
which satisfies a requirement for either recognised value. Unknown bytes or
metadata do not become recognised by this rule. The three-member checksum-last
protocol and versioned journal are unchanged.

Rebuilding unchanged source after one or more packet members have disappeared
can therefore repair the recognised partial packet. Interrupted repair restores
the recorded prior partial state or retains a complete verified new packet.
The regression covers all seven non-empty missing-member subsets, interruption
after six publication states for each singly missing member and a genuine
unknown concurrent modification. Unknown changes retain recovery evidence and
fail closed; locks are not deleted to make a failed check pass. These tests do
not prove universal power-loss durability or protection from an actor with
write access to the publication directory.

## Maintained regression entry points

Run the ordinary complete gate:

```bash
python3 -I -S -B tools/check_release.py --require-node
```

`tests/test_contract_repairs.py` covers native calibration replay, configuration
incompatibility, feasibility, absent calibration, rejected-input metadata and
publication overlap. It also invokes the deterministic JavaScript input/export
scenarios. `tools/check_browser_functional.js` adds real-engine input-accounting
and calibration replay to its existing response-integrity, cancellation,
timeout, download and recovery checks. No coverage threshold or excluded
production path is relaxed by these repairs.

## Parser qualification and calibration

Engine and configuration equality alone do not establish parser equivalence.
A real-runtime synthetic qualification compared native CPython 3.14.7 with
Pyodide 0.25.0 / CPython 3.11.3 in Node. A module containing `type UserId = int`
scored 0.26544846394872545 natively and 0.25648308345270704 in WebAssembly, where
an AST warning was emitted and applicable metrics decreased from 24 to 18.
Both decisions remained below the fitted 0.27 trigger. The common-syntax
control agreed within 1e-12. These fixtures are not empirical authorship data.

Calibration fitting/evaluation and bound Python replay now require a successful
AST parse; project members use the same requirement without acquiring fictional
per-file calibration provenance. Unbound diagnostics retain fallback warnings.
This is a capability boundary, not a blanket version-equality restriction.
Accepted syntax may still differ semantically between runtimes: universal replay
is not claimed. Refit existing bound profiles after the engine changes rather
than editing their engine digests. Maintained real-browser tests exercise the
common-syntax replay and rejection of this modern syntax in pinned Pyodide.

## Raw browser intake versus filtered source budgets

Folder selection and ZIP intake do not consume an identical budget. The browser
counts decoded candidate bytes before every engine-side documentation exclusion.
The raw folder ceiling is 20,000,000 bytes. Twenty 1,000,000-byte text documents
plus a 165-byte source exceed it: documentation encountered first can exhaust
the allowance, while source encountered first can be analysed. The rejected
source remains in the exported exclusion inventory. A ZIP can filter documents
before charging its assessable-source budget. Selection order and route can
therefore matter above the raw ceiling; route invariance is not promised.
Inspect exclusions and `overall_applicable`: false is not a zero-concern score.
No ceiling has been raised and rejected contents are not read merely to report
rejection. Select the assessed source subset when preparing a bounded input.

## Report destinations and partial-write boundary

The native analysis CLI preflights JSON/text destinations against each other,
the project/ZIP and any explicit configuration, calibration or ignore input.
Reports must be outside the input project tree, including new report paths.
Existing hard-linked destinations and leaf links/reparse points are rejected;
canonicalised parent aliases cannot redirect a report into the input tree.
Destination directories must already exist. These checks happen before analysis
and are repeated before publication. Prepare both reports in private temporary
files and use individual atomic replacements. A failed later replacement may
leave the earlier report updated: this is not a two-file transaction, a lock
against other directory writers or a guarantee against power loss. Run in a
quiescent destination directory. Detected conflicts return exit code 2 without
altering the prior destination or input bytes.

## Privacy erasure when browser storage is unavailable

Clear privacy data invalidates input generations, cancels the worker, clears
source/configuration/report state and disables local history before requesting
persistent erasure. Each history key is attempted independently; a thrown getter,
failed removal or failed read-back produces a visible persistence-uncertainty
message. Session clearing does not prove that persistent reports were erased.
A storage refusal at initial page setup leaves history disabled. Storage-fault
regressions use explicitly injected failures; they do not assert that every
browser emits each tested exception. Real Chromium qualification retains the
HTTP delivery and authenticated Pyodide worker and exercises clean retries.

## Finite numeric configuration and strict generated JSON

Effective metric weights, thresholds and review-policy numbers must convert to
finite binary floating-point values. Reject NaN, infinity and exponent/integer
overflow before clamping or fitting; a JSON parse-constant hook alone cannot
catch overflowing exponents such as 1e309. Finite weight clamping, threshold
semantics, display rounding and unrounded decision scores are unchanged.
Generated runtime reports and calibration profiles reject non-finite values
rather than emitting non-standard JSON constants. Calibration serialises the
profile before creating output directories/files. This guard does not promise
unbounded precision or prohibit ordinary finite underflow. Successfully written
non-operational diagnostic profiles retain the documented generation exit-code
policy; non-finite configuration is a different, rejected condition.

## Calibration input protection and individual file publication

The manifest CLI and folder wrapper share a preparation stage. The wrapper
builds its generated manifest in memory with an explicit corpus base; it does
not publish that manifest before validating the complete request. Preparation
applies configuration overrides before scoring and retains the existing bound
engine/configuration replay contract and shared JSON/CSV sample identifiers.

All destinations are checked together: profile JSON, observation CSV,
sensitivity CSV, Markdown summary and, for the wrapper, generated manifest.
Canonical names use Unicode NFC and case folding. Existing physical file
identities are compared across destinations and against the input manifest,
explicit configuration, file/ZIP samples and every project file actually read,
including `.codeprobeignore`. The bounded reader collects these identities
during its verified reads; it does not export them in reports or perform a
second project traversal. A required physical identity that is unavailable
causes rejection. Outputs inside a project sample tree are also refused.

Existing destination leaves must be ordinary files, with symlinks, reparse
points and special files refused. Parent aliases, including system directory
aliases, remain usable after canonicalisation. The existing bounded, no-follow
input rules remain in force.

Every output is fully serialised and encoded as UTF-8 before output directories
or temporary files are created. Invalid Unicode scalars are rejected with an
output-specific diagnostic. Complete bytes are staged in exclusively created,
private sibling files on each destination's filesystem, flushed and synced.
Consumed input identities and the complete destination set are checked again
before individual replacements. Preflight, encoding or staging failure
publishes no files; owned temporary files are cleaned up, and cleanup failures
are reported explicitly. Directories created for staging may remain.

Each successful replacement installs one complete file. Failure between
replacements is reported as partial publication with the completed paths; it
can leave an incomplete set of updated outputs. This is not a transaction
across paths, a global rollback, a power-loss durability guarantee or protection
against every concurrent change by a hostile directory writer. Use quiescent
input and destination trees. Generation success and technical replay eligibility
do not establish label validity, independent sampling or empirical accuracy.

## Bounded control reads and strict input values

The native project CLI accepts at most 262,144 bytes for an explicit metric
configuration and 4,000,000 bytes for a calibration profile. Both inputs use the
stable regular-file reader, strict UTF-8 decoding and a JSON object parser that
rejects duplicate keys and non-finite numbers, including overflowing exponents.
Invalid limits and control inputs are rejected before folder inventory or ZIP
intake. A valid generated profile must still match the current engine and
effective configuration; changing its recorded digest is not recalibration.
The derived folder or ZIP name remains the default unless explicitly replaced.

Recovery control files pass their existing 262,144-byte ceiling into the release
reader before it reads the body. The local server likewise passes its existing
public-resource ceiling. An oversized descriptor is rejected before the first
body read. If the file grows during reading, at most the ceiling plus one byte
is consumed before rejection. The extra byte detects overflow and is never
accepted as content. Zero-byte and exact-ceiling regular reads retain their
documented behaviour, together with identity and ancestry checks. Release
snapshot callers that omit the optional ceiling retain their existing size
policy; this change does not impose a new universal release-file limit.

Both project-reader opens request `O_NONBLOCK` where the platform provides it,
then verify a regular descriptor and its identity. The second open has the same
checks as the first. This permits rejection of a substituted special descriptor
without a blocking FIFO open on supported platforms. It is not a deadline for
ordinary filesystem I/O or a guarantee against every concurrent replacement.
Platforms without that flag retain the descriptor and identity checks. Tests
using substituted metadata describe that simulation explicitly; they do not
establish an observed special-file race or hang.

The public file, project and metadata JSON entry points require object roots.
They reject ambiguous JSON and invalid field types before analysis. Source text
and filenames must be strings; project file entries must be objects with text
fields of the declared types. Boolean switches require JSON Booleans. Missing
fields retain their existing defaults, and null remains valid for optional UI
controls. Metadata retains its omitted/empty-text default but no longer hides
malformed JSON by returning default metadata. Unknown fields remain ignored.
Supplied configuration and calibration-policy aliases are validated even when
their values would otherwise be bypassed by a fallback expression. Invalid
configuration does not silently produce a default report.

Project integer limits share one conversion policy between the native reader
and runtime. Integers, finite integral floats and the decimal integer strings
previously accepted by Python remain compatible, including signs, surrounding
whitespace and digit separators. Fractional values, Boolean values, non-finite
numbers and arbitrary coercible objects are rejected before resource access.
The existing inclusive minimum and maximum values remain in force; a zero-byte
reader ceiling is valid while project allocation limits require positive values.
All eight project limits are validated before collection, including a finite
compression ratio between 1 and 1,000 with the existing default of 100.

File and project report aliases, text output, configuration digests and bound
profile replay remain unchanged. Browser transport serialises objects; raw JSON
parser checks and worker transport checks are therefore separate tests in the
authenticated Pyodide browser gate. Input checks establish exercised software
contracts, not authenticity of submitted metadata or empirical detection quality.
