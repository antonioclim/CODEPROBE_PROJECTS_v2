
# Formative policy evaluation without provenance labels

## 1. Target redesign

The legacy workflow tunes thresholds using labels such as human, AI-generated or hybrid. These labels are neither required nor appropriate for the default evidence-bounded product. The v3 target is the quality of the review process and its actions.

## 2. Candidate evaluation targets

A policy-evaluation record may address:

- **action correctness** — whether the cited evidence actually warrants the review question;
- **actionability** — whether a reviewer or learner can act on the suggestion;
- **revision quality** — whether an accepted revision improves a predeclared rubric criterion;
- **uptake** — whether the action is accepted, declined or judged inapplicable;
- **burden** — time, cognitive demand and interruption cost;
- **false prompting** — actions surfaced when evidence is insufficient or irrelevant;
- **coverage** — relevant rubric concerns for which the system supplies a traceable action;
- **equity and subgroup behaviour** — differences across tasks, languages, experience groups and accessibility needs, when ethically and statistically supported.

None is a proxy for source provenance.

## 3. Proposed policy-evaluation profile

A future profile may include:

```json
{
  "schema": "codeprobe-policy-evaluation-profile/v1",
  "scope": {
    "review_dimensions": ["structural_complexity_dispersion"],
    "languages": ["python"],
    "task_families": ["introductory-algorithms"]
  },
  "target": "action_correctness",
  "decision_rule": {
    "surface_when": "mapped_observation_set_satisfies_named_rule"
  },
  "evidence": {
    "study_id": "real-identifier-required",
    "estimator": "predeclared",
    "uncertainty": "required"
  }
}
```

The example is a schema sketch, not a completed study or an approved policy.

## 4. Process evidence remains separate

A learner may voluntarily supply declarations, history, test evolution or design notes under an authorised protocol. Such process evidence is stored in a separate record with provenance and scope. It is not inferred from code and is not used as a hidden origin label for the default review policy.

## 5. Leakage and generalisation controls

M02 must define task, repository, template and near-duplicate grouping before policy evaluation. E01–E02 must separate development and evaluation data, report uncertainty and analyse nuisance factors. No performance number is allowed until the target, split, estimator and exclusion rules are locked.

## 6. Legacy profile handling

A legacy profile containing provenance categories is not silently translated. The migration tool refuses it and explains that the v3 policy target is non-equivalent. Raw historical files may be archived independently, but they do not become v3 policy evidence.

## 7. Consequence rule

Even a well-performing feedback policy does not determine misconduct or author identity. Utility evidence supports only the intended formative action in the studied population and context.

## Policy traceability

Every generated action references a `policy_rule_id` declared by the report policy catalogue. Evaluation estimates apply to that rule and scope, not to a global suspicion threshold.
