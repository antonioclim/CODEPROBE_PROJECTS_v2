
# Decision record: scalar removal and future aggregation

## Decision

The core v3 report has **no global scalar**. The default output is a Review Evidence Vector whose dimensions retain separate observation references, applicability and limitations. Legacy scalar fields are accepted only in a read-only migration envelope marked non-equivalent.

## Measurement rationale

A weighted sum requires more than arithmetic availability. It requires commensurable representations, a defensible common target, stable transformations and a justified compensation rule. The current metric families concern unlike attributes and use unlike scales. A global sum therefore creates an order that is not established by the construct.

For illustration, let \(m_1\) and \(m_2\) represent unrelated attributes. A sum

\[
S = w_1 m_1 + w_2 m_2
\]

allows a decrease in \(m_1\) to compensate for an increase in \(m_2\). That compensation has no substantive meaning unless an explicit decision model and evidence justify the trade. Further, admissible transformations of ordinal or proxy measures can change \(S\) and its ordering. The apparent precision is therefore stronger than the representation.

## Operational consequences

The following are absent from the core schema:

- a report-level score;
- global low/moderate/elevated/high bands;
- a global review threshold;
- a probability-like percentage;
- a verdict.

A dimension may contain multiple atomic values, but it does not receive a default numeric grade in S01. Missing or unsupported evidence is typed and visible.

## Optional future aggregation gate

S04 may propose a tightly scoped optional index only if all of the following are met:

1. a named decision and intended population are specified;
2. component scales and permissible transformations support the operation;
3. the compensation or non-compensation rule is substantively justified;
4. uncertainty, missingness and nuisance sensitivity are represented;
5. ablation and external validation show incremental utility over the vector;
6. the index cannot be interpreted as authorship, misconduct or sanction evidence.

Any such index must live in an extension namespace, remain off by default and use a new schema version. S01 does not pre-authorise it.

## Comparison semantics

The v3 core permits only:

- equality of deterministic observations under the same specification;
- within-dimension comparison when the metric catalogue declares commensurability;
- set-based comparison of warranted actions;
- no cross-dimension ranking of people, projects or reports.

## Disposition of historical A01-F007

The old acceptance contract tested scalar aggregation. S01 replaces it with the contract in `07-a01-f007-acceptance-contract.md`. The historical finding remains open until S04 implements the v3 composition rule and exact candidate CI passes.
