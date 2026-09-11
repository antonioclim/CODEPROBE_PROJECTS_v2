
# A01-F007 — non-scalar acceptance contract

## Historical problem

The historical acceptance condition treated a weighted scalar as the primary integration object. Under the evidence-bounded redesign, that condition is scientifically incompatible with the core construct.

## Replacement acceptance predicates

A future runtime satisfies the S01 replacement only when all predicates hold on the exact candidate:

1. **Vector-first output** — the core report contains dimensions and observation references but no report-level scalar, verdict or global band.
2. **Typed missingness** — an inapplicable or unavailable observation cannot be encoded as zero and cannot improve a dimension.
3. **Non-compensation** — no core operation allows evidence in one dimension to cancel evidence in another.
4. **Traceability** — each interpretation and action resolves to existing observations and source evidence.
5. **Reversibility** — every suggested change is explicitly reversible and may be declined without changing the observation record.
6. **Legacy non-equivalence** — v2 scalar fields are preserved only in a migration audit and are not mapped to v3 dimensions.
7. **Negative semantics** — authorship probability, misconduct verdict, compulsory review and sanction-trigger fields are rejected.
8. **Determinism** — canonical serialisation and content digest are stable for identical deterministic content.
9. **Cross-route agreement** — browser and native routes emit equivalent deterministic contract content after S04–S05 implementation.
10. **Exact-candidate CI** — phase tests pass on the commit actually proposed for integration.

## S01 disposition

S01 completes the contract rewrite and prototype enforcement. It does not close A01-F007 because the v2.2.0 runtime still emits the legacy scalar and S04 has not implemented the new composition layer.

Formal status after S01:

`OPEN_CONTRACT_REWRITTEN_IMPLEMENTATION_PENDING_S04`
