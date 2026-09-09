# CodeProbe local validation summary template

This is an uncompleted record template, not a validation result or approval.

Course / assignment:
Language and report unit (choose one: file or project):
Prepared by / date:
Profile ID / engine SHA-256 / metric configuration digest:
Corpus provenance and access restrictions:

## Selection and separation

Fit/evaluation assignment method and declared group definition:
Duplicate and shared-template controls:
Target human review rate and fit-only selection rule:
Fit-selected trigger:
Evidence that evaluation did not influence selection:
Technical replay status (`operational` and reason):

Technical replay eligibility is not institutional approval. Group-exclusive
separation does not establish statistical independence or representative
sampling. Record uncertain or missing provenance rather than inferring it.

## Descriptive counts at the fit-selected trigger

Populate the table from `validation.descriptive_review_rates`, not from an
unqualified legacy zero. Use N/A when eligible = 0 and retain 0/n when n > 0.
The pooled positive row overlaps AI-generated and hybrid; the all partition
pools fit and evaluation and is not an independent evaluation.

| Partition | Label | Unit | Samples | Distinct groups | Eligible groups | Reviewed | Eligible | Rate |
|---|---|---|---:|---:|---:|---:|---:|---:|
| fit | human | | | | | | | |
| fit | ai_generated | | | | | | | |
| fit | hybrid | | | | | | | |
| fit | positive (pooled) | | | | | | | |
| evaluation | human | | | | | | | |
| evaluation | ai_generated | | | | | | | |
| evaluation | hybrid | | | | | | | |
| evaluation | positive (pooled) | | | | | | | |
| all (pooled) | human | | | | | | | |
| all (pooled) | ai_generated | | | | | | | |
| all (pooled) | hybrid | | | | | | | |
| all (pooled) | positive (pooled) | | | | | | | |

Statistical independence: not established by the software.
Uncertainty: not estimated by the software.
Any separately justified sampling model and uncertainty analysis, with evidence:

Do not substitute the group count for an effective sample size or manufacture
an interval from a Bernoulli assumption. These are descriptive review rates,
not authorship accuracy estimates.

## Exclusions and sensitivity

Record excluded starter code, dependencies, generated files, duplicates,
unreadable inputs and inapplicable reports, with reasons. Attach the fit-only
sensitivity CSV and the evaluation summary. Preserve their separate roles.

## Institutional decision (to be completed by the responsible person)

Decision: approved / provisional / rejected / not decided:
Decision-maker and date:
Rationale, permitted use, review procedure and safeguards:
Changes requiring a fresh calibration or approval:

An empty decision field is not approval. Preserve the original generated
profile; do not rewrite it to imply a review that did not occur.

## Caveat to students

The calibrated trigger is a formative review trigger, not proof of misconduct
or a certificate of independent authorship. Evidence coverage is a separate
heuristic label, not statistical confidence. A low score is not an exemption
from explaining and validating the submitted work.
