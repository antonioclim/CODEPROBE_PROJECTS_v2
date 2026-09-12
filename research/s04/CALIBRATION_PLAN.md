# Prospective formative calibration design

Author: Antonio Clim. Status: design and admission interface only. Empirical calibration: **not established**.

## Purpose and absence register

The proposed targets concern whether a reversible review question is warranted and useful, not who wrote the source. No authorised calibration dataset, participant study, ethics decision, external preregistration, rater dataset or empirical calibration estimate is supplied in S04. The corresponding machine-readable references are null in `calibration-design.v1.json`. Synthetic fixtures verify software contracts; they are not substitutes for such evidence. This document is not the complete M01/M02 protocol or an instruction to collect data.

The distinction between a correct computation and a justified interpretation/use follows the argument-based separation developed by Kane (2013). In this project, the resulting design decision is to withhold unlicensed construct interpretations, rather than attach a confidence label to an unsupported inference. This methodological reference does not validate CodeProbe.

## Proposed unit, decisions and reference assessment

The prospective analysis unit is an eligible entity-rule opportunity nested within its source artefact and declared contributor/lineage group. Report rule and task-family strata separately. Retain the original value, applicability, policy threshold set, possible predicates, optional question and evidence references. Do not treat repeated transformations or repeated runtime executions as independent cases.

Before collecting or inspecting evaluation outcomes, M01/M02 must specify a sampling frame, permission and privacy arrangements, a blinded reference-assessment codebook, adjudication of disagreement and the permitted meaning of correct, feasible, unwarranted and uncertain. Reference assessment must not simply restate the threshold rule. A review question can be syntactically triggered yet inappropriate for the task. Refactoring feasibility, preservation of behaviour, cohesion and time cost require their own assessment. No rater agreement coefficient, sample size, power or approval is invented here.

## Four estimands to lock before empirical evaluation

| Target | Prospective numerator and denominator | Required qualification |
|---|---|---|
| Action correctness | Correct and feasible surfaced questions / all independently assessed surfaced questions, by rule and task family | Report disagreements and unassessable questions; do not silently remove them |
| False prompting | Unwarranted surfaced questions / all independently assessed surfaced questions | Not an authorship or misconduct false-positive rate |
| Coverage | Non-abstaining interpretations / all eligible entity-rule pairs | Report unavailable, unsupported and absent entities separately; no favourable zero imputation |
| Burden | Reviewer time and rejected-question burden per artefact under the selected profile | Uptake or faster completion alone is not evidence of learning or net benefit |

A prospective codebook must make clear whether correctness and false prompting are complementary; they need not be, because uncertain, infeasible and unassessable cases may remain distinct. Report rule-specific denominators. Profiles must not collapse the four targets into an unexplained scalar utility. A matched or appropriately controlled comparison with observation-only feedback may later be justified, but it is not performed in S04. A future educational-effect study requires a separate design and outcome specification.

## Partitioning and leakage controls

The executable manifest interface requires three split roles: training, tuning and evaluation. Partition before selecting thresholds or consulting evaluation outcomes. Raw content hashes, normalised content hashes, declared lineage groups and contributor groups cannot cross splits. Evaluation labels must remain sealed, and the frozen profile SHA-256 must match the caller's expected digest. Outcome values, approval assertions and origin-classification targets are not accepted by this interface. Task families seen only in evaluation are disclosed rather than silently pooled into a supported domain.

Kapoor and Narayanan (2023) document leakage as a source of overoptimistic ML-based scientific conclusions. The project-specific precaution here is stricter provenance and split admission, even though S04 does not fit an ML classifier. Passing the manifest checks does not prove that declared groups are truthful or that unknown near-duplicates, concealed contributor relationships and evaluation contamination are absent. An independent corpus audit and a recorded permission decision remain necessary.

`admit_manifest` returns `structural_checks_passed_only`, `empirical_calibration=not_established` and `authorisation=not_verified_by_this_interface`. It is deliberately unable to mark a profile empirically calibrated. An admitted synthetic manifest is only a conformance fixture. Within-split repetition is allowed and remains a dependence for later analysis; it is not counted as an independent sample.

## Analysis, sensitivity and stopping rules

The present threshold sets are illustrative predeclared policies. Sensitivity over these sets is deterministic: a question is withheld when its truth depends on the selected threshold. The set is neither a confidence interval nor a sampling distribution. Future empirical work must lock tuning rules, a separate evaluation role, cluster-aware uncertainty, handling of missing outcomes, multiplicity, stopping criteria and acceptable burden before unsealing labels. No confidence interval or population error rate is calculated from the 504 boundary fixtures or the 369 interpretation executions.

Future threshold tuning must preserve every tested policy candidate, avoid using evaluation labels to choose cut-offs and report trade-offs among false prompting, coverage and burden. Unsupported strata must remain abstaining until their evidence is assessed. Rejection of a proposed use is a legitimate outcome; the programme does not guarantee empirical benefit.

## References (APA 7th edition; DOI and metadata checked 12 September 2026)

| Reference | Verified primary source and role |
|---|---|
| Kane, M. T. (2013). Validating the interpretations and uses of test scores. *Journal of Educational Measurement, 50*(1), 1–73. https://doi.org/10.1111/jedm.12000 | Wiley publisher record and abstract; distinction between computation, interpretation and use |
| Kapoor, S., & Narayanan, A. (2023). Leakage and the reproducibility crisis in machine-learning-based science. *Patterns, 4*(9), Article 100804. https://doi.org/10.1016/j.patter.2023.100804 | Publisher record, PubMed and Princeton author-institution record; leakage controls as methodological rationale |
