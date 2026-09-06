# CodeProbe legacy lineage and retirement assessment

Scope: evidence-bounded comparison of the fixed snapshots below. Authorship and
citation corrections are subsequent documentation changes, not a new empirical
benchmark or a rewrite of either snapshot. Prepared 6 September 2026.

## 1. Scope and identity

The inspected public legacy snapshot is `e7a1778b789c98c6c2029d8cfa85184757731ecf` in
`https://github.com/antonioclim/CODEPROBE_PROJECTS_v1`. The inspected successor snapshot is `3fe84e86d72876f674f37c152bc0cefe23500e29` in
`https://github.com/antonioclim/CODEPROBE_PROJECTS_v2`. The former tree lists 14 files; the latter contains 149.
Counts describe packaging, not software quality or predictive accuracy.

The legacy repository suffix `v1` must not be confused with its internal software
version: its `src/engine.py` declares `APP_VERSION = "2.0.0"`, and its README
is headed “CodeProbe v2”. The successor engine and report line is 2.2.0.
Neither repository is an empirical benchmark merely because it contains code.

## 2. Executive judgement

The successor is materially more developed as a research-software and formative
review system. Its maintained testing, input controls, calibration contract,
provenance, worker cancellation and release evidence address substantive
engineering concerns. They do not measure the accuracy of AI-authorship
inference. Retiring the legacy edition is defensible as an author maintenance
and risk-control decision, but the retirement explanation must not manufacture
a quantified benchmark or imply that every erroneous judgement is now fixed.

## 3. The reported error rate

Antonio Clim reports errors exceeding 30% in some prior assessments of research
works or projects involving the legacy version. The report is important as a
reason for precaution; it is not independently substantiated by the available
source-tree and documentation evidence.

To interpret 30%, one needs the evaluated unit, number evaluated, number judged
erroneous, direction of each error, threshold and comparison standard. Error among
all projects, error among flagged projects, false-positive rate among genuine
human work and a percentage-point score discrepancy are different quantities.
The phrase cannot be converted into “accuracy below 70%”, “false-positive rate
over 30%” or “v2 has reduced errors by 30%” without the corresponding data.

The workflow is also unspecified. These versions inspect source text and limited
Markdown context, not arbitrary research-paper DOCX/PDF content. A reported use
in evaluating research works may refer to associated code or manual extraction;
that workflow must not be invented from the wording alone.

A defensible public notice should attribute the observation to the maintainer,
state that the denominator and benchmark have not been supplied, distinguish it
from software regression tests and avoid claims of a measured v2 improvement.
Existing affected decisions should be reconsidered on independent evidence,
not by automatically applying another unvalidated score to the same work.

## 4. Evidence-grounded comparison

| Dimension | Legacy distribution | Successor distribution | Critical interpretation |
|---|---|---|---|
| Identity | Repository suffix v1; internal engine 2.0.0; README calls it v2 | Engine/schema line 2.2.0 | Name both repository and exact commit to prevent mistaken comparisons. |
| Language coverage | Python, JavaScript, Bash, C, C++, C# and Markdown already listed | Same broad families, with more explicit extension and parser qualifications | Do not present the same language names as newly implemented coverage. |
| Interpretation | Engine verdicts include low/moderate/elevated/very-high probability wording | Concern/review-signal language and explicit non-probability limits | Probability language in a heuristic without measured calibration is unjustified. Changing wording improves honesty, not accuracy by itself. |
| Course guidance | README warns against proof-of-misconduct interpretation, but also asks students to aim below 60% and revise above it | More explicit provisional policy and scope limits | The predecessor had warnings; it did not have no safeguards at all. Mandatory threshold-driven revision nevertheless risks rewarding score optimisation rather than learning. |
| Project handling | Single engine, HTML page and small server in the visible source; ignore file described as manual checklist | Explicit project APIs/CLI, bounded ZIP/folder admission, exclusions and report inventories | A larger tree is not a proof; the concrete implemented workflows and their tests matter. |
| Calibration | No dedicated calibration tool/corpus directory or maintained test directory in the inspected tree | Group-exclusive fit/evaluation, replay-bound engine/configuration and operational status | Reproducible threshold selection does not establish external validity or rule out dataset shift. |
| Provenance | Minimal package metadata compared with the successor | Measured engine/configuration identities, separation from caller declarations and report/input identity | Integrity tells a reader which algorithm ran, not whether its inference is scientifically valid. |
| Browser resilience | Monolithic legacy HTML/engine arrangement | Authenticated terminable worker, limits, cancellation and retry controls | These are meaningful reliability measures; no new legacy real-browser execution is claimed here. |
| Dependency and privacy controls | Legacy README declares a CDN runtime and short browser history | Explicit pinned runtime integrity, opt-in history and tested clearing failure paths | Local execution is not a complete privacy or vulnerability assessment. |
| Release process | No checked-in release/CI/test structure in the inspected legacy tree | Manifest, packet checks, crash-recovery and canonical CI | Absence of checked-in tests does not prove that no author ever tested v1. |
| Citation | No CITATION.cff in the inspected v1 tree | A CFF exists but incorrectly names only a collective entity for this request | Correct named scholarly attribution to Antonio Clim without erasing historical licence notices. |
| Maintainer documentation | Generic contribution guide | Extensive guide, but previously no explicit named author/maintainer | Contributing describes a process; name Antonio clearly instead of treating it as a fabricated contributor census. |

## 5. Why the legacy claims warrant criticism

The inspected engine uses probability labels while its documentation describes
heuristic source-pattern analysis. No labelled validation corpus, confusion
matrix or calibration study is supplied in that legacy tree. Thus a numerical
output must not be interpreted as a posterior probability that an author used
AI. Even mathematically well-defined metrics can correlate with task templates,
style requirements, language conventions or formatting instead of origin.

The instruction to revise work until a score falls below 60% also changes the
optimisation target: students can be driven towards satisfying an unvalidated
proxy. That is an assessment-design concern independently of whether a particular
individual decision was correct. The existing caution against automatic sanctions
should be acknowledged, but it does not turn the threshold into a validated one.

The lack of a maintained test and release-control structure visible in v1 makes
its assurances much harder to inspect and reproduce. It does not establish that
the code is wholly broken, malicious or worthless. The successor should preserve
useful ideas and document actual repaired behaviours rather than treating the
predecessor as a caricature.

## 6. Residual weaknesses in the successor

The present evidence supports improved engineering, not a numerical comparison
of classifier performance. The same broad metric families and language heuristics
retain construct-validity and domain-shift questions. Language admission does not
mean standards-complete parsing, type analysis or programme semantics. Markdown
handling does not add Word/PDF extraction. The frozen Pyodide dependency, resource
limits and platform-specific paths need ongoing maintenance.

A real predictive study would require authorised samples with reliable provenance,
a stated target, partitioning by author/task/project where relevant, untouched
external evaluation, thresholds fixed before evaluation and uncertainty estimates.
Data obtained after users revised their work to satisfy the score must not be
silently treated as an independent validation set. Synthetic tests remain
software probes and cannot estimate human false-positive rates.

## 7. Retirement and preservation

The maintainer's plan is to withdraw public access to v1. This document does not perform or certify that administrative change. Record the effective date and
commit when it actually occurs. Preserve an evidentiary copy, exact source hashes,
known release metadata and the reasoning for retirement before removing access.

Retirement should reduce confusion, not obstruct correction or reproducibility.
A durable notice in the successor should retain the old repository identifier,
last assessed commit and a neutral explanation. Archiving a public legacy record
or leaving a minimal redirect notice can be preferable to making an unexplained
link disappear; that choice remains the owner's. Existing distributed copies,
licence notices and third-party records are not erased by a visibility change.
No permission revocation or legal clearance is asserted here.

## 8. Authorship and citation

The author has explicitly requested attribution as Antonio Clim. The current CFF uses
structured `given-names` = `Antonio` and `family-names` = `Clim`, with software type,
version, genuine release date and repository/release URLs. Do not add a DOI,
ORCID, institutional endorsement or article that has not been established.

The 2.2.0 release citation concerns the release actually published. Documentation
and CFF corrections on main are later changes and must not be described as bytes
already present in the old ZIP. Existing MIT notices remain unchanged. GitHub
Actions uploading an asset is not the intellectual authorship of the software.

## 9. Source links and limits of this document

- Legacy inventory: https://github.com/antonioclim/CODEPROBE_PROJECTS_v1/tree/e7a1778b789c98c6c2029d8cfa85184757731ecf
- Legacy engine: https://github.com/antonioclim/CODEPROBE_PROJECTS_v1/blob/e7a1778b789c98c6c2029d8cfa85184757731ecf/src/engine.py
- Legacy README: https://github.com/antonioclim/CODEPROBE_PROJECTS_v1/blob/e7a1778b789c98c6c2029d8cfa85184757731ecf/README.md
- Successor snapshot: https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/tree/3fe84e86d72876f674f37c152bc0cefe23500e29
- Existing citation metadata: https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/blob/3fe84e86d72876f674f37c152bc0cefe23500e29/CITATION.cff
- Existing contribution guide: https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/blob/3fe84e86d72876f674f37c152bc0cefe23500e29/CONTRIBUTING.md
- Published version: https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/releases/tag/v2.2.0
- CFF specification/schema: https://github.com/citation-file-format/citation-file-format/tree/1.2.0
- GitHub citation documentation: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files

This comparison uses the explicitly retrieved repository inventory, code excerpts,
documentation and recorded successor verification, not a newly completed exhaustive
execution audit of both versions. It must not be labelled a replicated >30% error
study. Further measurements, if obtained, must be added with inputs, exact methods
and outputs rather than retrospectively inferred from this narrative.
