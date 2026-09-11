
# CodeProbe research contract

This directory records the normative research-facing contract for the evidence-bounded redesign. The material is versioned separately from the v2.2.0 runtime because S01 defines the construct before S02 changes the measurement kernel and before S04–S05 replace the current report composition and interfaces.

The documents are normative for the research candidate in the following order:

1. `01-construct-map.md` — observation, interpretation, action and non-inference architecture;
2. `02-terminology-policy.md` — names required in schemas, APIs, CLI, UI, documentation and tests;
3. `03-report-schema-migration.md` — legacy compatibility and explicit non-equivalence;
4. `04-scalar-and-aggregation-decision.md` — removal of the default global scalar;
5. `05-formative-policy-evaluation.md` — redesign of policy evaluation away from provenance labels;
6. `06-claim-boundary.md` — executable claim tiers and prohibited consequential uses;
7. `07-a01-f007-acceptance-contract.md` — replacement for the historical scalar-centred acceptance condition.

Machine-readable counterparts live under `research/` and `schemas/`. `research/schema-index.v1.json` binds every prototype schema to a unique identifier and status. They are checked by `tools/check_s01_construct_contract.py` and `tests/test_s01_construct_contract.py`.

## Status boundary

S01 establishes a scientifically coherent v3 contract. It does not claim that the existing v2.2.0 runtime already implements the contract. The old report and calibration formats remain legacy inputs only. S02, S04 and S05 must implement and validate the contract before it can become the public default.

## Immutable evidence and mutable responses

Generated feedback actions belong to the deterministic report. Acceptance, decline or deferral is represented by the separate `codeprobe-feedback-response/v1` schema and cannot alter the report digest.
