
# Report-schema migration and legacy compatibility

## 1. Migration objective

Migration exists to preserve inspectable historical evidence, not to claim equivalence between v2.2.0 outputs and the v3 construct. The legacy report may be read, fingerprinted and decomposed into raw observations, but scalar and provenance-oriented semantics are not promoted into the new schema.

## 2. Compatibility model

The migration command produces `codeprobe-legacy-migration-envelope/v1`. It does not produce a complete `codeprobe-review-report/v3`, because a legacy report lacks the specification versions, applicability states, construct mapping and traceable actions required by v3.

The source file remains unchanged. The envelope records:

- detected source schema and report kind;
- SHA-256 of canonical source content, explicitly labelled with `source_digest_scope: canonical_json`;
- `non_equivalent: true`;
- safe scalar leaves preserved as archival, unmapped legacy values rather than promoted observations;
- semantic fields discarded from interpretation;
- warnings that block causal or provenance reinterpretation.

## 3. Field-level decisions

| Legacy field or family | Migration disposition | Reason |
|---|---|---|
| raw metric value | Preserve as `archival_unmapped_value` when structurally safe | May support later specification mapping |
| metric applicability or warning | Preserve when present | Needed to avoid treating missingness as zero |
| `overall_score` | Record in `discarded_semantics`, not as evidence | No validated common unit or v3 equivalent |
| `verdict` / concern band | Discard from interpretation | Adjudicative and tied to the old scalar |
| `review_trigger` | Discard from interpretation | Old threshold cannot become a v3 action policy |
| `ai_*`, authorship-like fields | Discard and warn | Outside the declared construct |
| human / AI-generated / hybrid labels | Refuse as policy-evaluation input | Provenance labels are not default v3 targets |
| engine and input fingerprint | Preserve when independently parseable | Supports provenance, not semantic equivalence |

## 4. State machine

A legacy input follows one of four states:

1. `RECOGNISED_READ_ONLY` — source schema is known and a digest is computed;
2. `RAW_OBSERVATIONS_PRESERVED` — safe metric-like values are retained without v3 interpretation;
3. `SEMANTICS_DISCARDED_WITH_AUDIT` — scalar, verdict and provenance-like fields are listed explicitly;
4. `REFUSED` — the input is ambiguous, malformed or accompanied by a provenance-labelled policy profile.

There is no `FULLY_MIGRATED_EQUIVALENT` state.

## 5. Determinism

Canonical JSON uses UTF-8, sorted keys and compact separators. The source digest is independent of incidental whitespace in a parsed JSON document. The migration result is deterministic for the same parsed report and policy input.

## 6. Backward reading versus forward writing

Legacy compatibility is read-only. New software must not emit v2 reports and must not mutate old reports in place. v3 output is written only after the S02 observation catalogue and S04 interpretation profile are implemented.

## 7. Refusal conditions

The migration tool fails closed when:

- the source root is not a JSON object;
- duplicate or non-finite JSON values are supplied;
- a policy profile contains default provenance labels;
- the source schema is absent and the structure is too ambiguous for a safe envelope;
- an output path aliases the source path.

S03 must extend these controls with bounded file reading and filesystem identity checks before public release.
