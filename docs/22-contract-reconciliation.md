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
