
# Terminology policy for the evidence-bounded redesign

## 1. Normative rule

Names are part of the measurement instrument. A disclaimer cannot repair a schema, button or command whose ordinary meaning invites a stronger interpretation. S01 therefore treats terminology as an executable contract across schema, API, CLI, UI, documentation and tests.

## 2. Default vocabulary

| Legacy expression | v3 default | Decision |
|---|---|---|
| `overall_score` | `review_evidence.dimensions` | No direct equivalent |
| AI-style concern | dimension-specific review evidence | Prohibited as the default construct |
| verdict | bounded interpretation | Remove adjudicative language |
| review trigger | dimension-specific action policy | No silent migration |
| low/moderate/elevated/high global bands | typed applicability and source-local interpretation | Remove global bands |
| human / AI-generated / hybrid label | separately supplied process-evidence declaration, when authorised | Prohibited as default policy labels |
| calibration profile | policy-evaluation profile | Legacy term remains only in v2 compatibility documentation |
| manual review required | review question available | Remove compulsory language |
| score | atomic value or evidence profile | Reserved for an explicitly defined measure, never the report as a whole |

The machine-readable registry is `research/terminology-registry.v1.json`.

## 3. Schema and API rules

The v3 core schema must not contain identifiers such as `overall_score`, `review_trigger`, `ai_probability`, `authorship_probability`, `human_likelihood`, `misconduct_verdict` or `sanction_trigger`.

The following are required:

- `observations` for atomic measurements;
- `review_evidence.dimensions` for the vector profile;
- `feedback_actions` for immutable, traceable and reversible review questions;
- a separate feedback-response record for mutable learner or reviewer acknowledgement;
- `non_inferences` for explicit boundaries;
- `legacy_compatibility.non_equivalent = true` when historical semantics are mentioned.

Legacy identifiers may appear only inside documentation, tests or migration records that explicitly identify them as deprecated, prohibited or non-equivalent.

## 4. CLI rules

The future v3 CLI shall use verbs that describe operations rather than adjudications. Candidate forms include:

```text
codeprobe observe FILE
codeprobe review FILE
codeprobe review-project DIRECTORY
codeprobe migrate-legacy REPORT.json
codeprobe validate-policy PROFILE.json
```

The CLI must not expose a default `detect`, `classify-author`, `misconduct`, `verdict` or `sanction` operation. A policy option controls feedback selection, not provenance classification.

## 5. UI rules

The future UI will present:

- Review evidence;
- Observations and scope;
- Review dimensions;
- Review questions;
- Limitations and unavailable evidence;
- Export evidence report.

It will not centre a global progress bar, probability-like percentage, traffic-light provenance band or compulsory review message. S05 must test comprehension, keyboard use, screen-reader naming and the visibility of limitations.

## 6. Documentation rules

Affirmative product claims must remain within tiers 0–2 of `research/claim-policy.v1.json`. Terms concerning source provenance or misconduct may be used only to state explicit non-inferences, describe legacy behaviour or document a prohibited use.

## 7. Test rules

Negative tests are first-class acceptance evidence. At minimum, tests must show that:

- forbidden identifiers are rejected recursively;
- an authorship-like probability field cannot enter a v3 report;
- a compulsory review or sanction action is rejected;
- required non-inferences cannot be omitted;
- a legacy scalar is not mapped to a v3 dimension;
- provenance-labelled legacy policy profiles are refused rather than silently reinterpreted.

## 8. Naming stability

The v3 schema major version marks a semantic break. Names may still be refined before F01, but any change must update the registry, migration table, schemas, tests and claim policy as one transaction.
