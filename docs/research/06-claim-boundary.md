
# Executable claim boundary

## 1. Claim tiers

The claim policy defines five tiers.

| Tier | Claim type | Current status |
|---|---|---|
| 0 | deterministic source observation | permitted when the metric specification and source trace are available |
| 1 | bounded review interpretation | permitted when mapped evidence, applicability and limitations are present |
| 2 | reversible feedback action | permitted when the action is traceable, feasible and non-compulsory |
| 3 | educational utility or consequence | withheld until an authorised study supports the exact claim |
| 4 | provenance, misconduct or sanction inference | outside the default product purpose |

## 2. Required non-inferences

Every v3 report must include four explicit statements:

1. The report does not estimate or classify source-code authorship.
2. The report does not determine misconduct, cheating or independent work.
3. The report does not recommend or trigger disciplinary sanctions.
4. Code-derived observations do not establish why a code property is present.

Omitting any statement is a schema-level failure.

## 3. Claim–evidence monotonicity

A stronger claim requires at least as much evidence as a weaker claim and may require qualitatively different evidence. Passing software tests can support deterministic execution claims. It cannot support construct validity, pedagogical utility or provenance inference.

## 4. Language enforcement

The check tool scans machine-readable keys and new public contract documents. Prohibited terms may appear only in explicit legacy, refusal or non-inference contexts. Test fixtures may contain invalid examples, but successful v3 outputs may not.

## 5. Publication boundary

Until E01–E02 are complete, manuscript language is restricted to design, implementation and computational-conformance claims actually supported by evidence. No participant, effect, accuracy, generalisation or fairness result may be anticipated as if observed.
