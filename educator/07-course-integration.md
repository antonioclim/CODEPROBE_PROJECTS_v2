# Course integration guide

This guide is for instructors who want to embed CodeProbe in a programming assignment, capstone project or bachelor-level thesis workflow.

## Intended use

CodeProbe is a formative self-review instrument. It can help students identify code that appears overly templated, overly explanatory, unusually regular or insufficiently revised after AI assistance. It should not be used as a disciplinary detector.

The current terminology is deliberately conservative:

- **AI-style concern score**, not probability;
- **reading**, not verdict;
- **review trigger**, not proof;
- **quality/context feedback**, not authorship evidence;
- **calibration profile**, not universal detector.

## Recommended policy

Use the following model unless your institution already has a stricter policy.

1. Students run CodeProbe locally before submission.
2. They analyse only assessed source files they authored.
3. They exclude starter code, generated files, dependencies, minified assets, build output and documentation; in project mode this should be done through `.codeprobeignore` and verified in the excluded-file list.
4. An applicable result at or above the active local review trigger prompts inspection and explanation. Revise for identified issues; require disclosure under the course policy, not as a mechanical inference from a score.
5. Persistent concern is checked through repository history, tests, design notes and oral explanation.

## Reading class, trigger and teaching action

Use the active `reading_class`, `review_policy`, `review_triggered` and applicability fields in the report. A reading class describes a numerical band. The trigger is a separate inclusive comparison against the **unrounded** applicable score. Neither field prescribes a mark, a penalty or a compulsory reduction in the score.

The following are exact boundary examples for the **bundled provisional policy only**, not a second teaching policy. They apply to eligible file and project aggregates.

| Exact unrounded percentage | Active reading class | Trigger reached? |
|---:|---|---|
| 28% | `moderate` | No |
| 48% | `elevated` | No |
| 50% | `elevated` | No |
| 60% | `elevated` | Yes |
| 68% | `high` | Yes |
| 75% | `high` | Yes |

The lower boundary belongs to the new class: below 28% is low, 28% to below 48% moderate, 48% to below 68% elevated and 68% upwards high. Review is triggered at **score >= 0.60**, so exactly 60% qualifies. A rounded display of 60.0% does not necessarily establish equality; the emitted Boolean and `decision_score` retain the actual comparison. An N/A result has no applicable numeric interpretation and is not proof of independent authorship.

For a compatible local profile, read its active values instead. For example, a separately identified illustrative policy with class boundaries 10%, 20% and 30% and a trigger of 50% would classify exactly 50% as high and trigger review. This example explains policy replacement; it is not a fitted or recommended policy.

At a triggered result, inspect the relevant code, metrics, exclusions and limitations, then ask for an explanation supported by ordinary development evidence. Revise only for an identified issue. A non-triggered result does not dispense with the usual quality expectations or course disclosure policy. The objective is explainable work, not score minimisation.

## Course-local calibration workflow

Curate a private corpus for one report kind and assignment family. File profiles require one detected language; project profiles use the `project` scope marker and do not calibrate each constituent file. Use explicit group identifiers for related authors, submissions or templates and keep groups out of both partitions simultaneously. Record the basis for each declared human, generated or hybrid label.

Follow the [calibration workflow and single-line commands](../calibration/README.md). Copy a file-only or project-only JSON/CSV template to a private workspace before replacing its placeholder paths. Each illustrates four records with human and positive observations in `fit` and `evaluation`; four records demonstrate plumbing, not statistical sufficiency. The folder wrapper treats admitted files as separate observations and does not infer groups from nested directories. Use an explicit manifest when files are related.

Run the commands from the kit root with `-I -S -B`, keep calibration outputs outside samples and create the project report directory before application. The old ignored `--min-per-class-for-language` option has been removed; delete it from scripts rather than assuming it enforced a minimum. The existing balance, grouping and small-partition checks remain.

Review fit/evaluation sample and group counts, missing denominators, threshold sensitivity, applicability and the scoring contract. Fresh UUID4 tokens hide direct identifiers in new observations, not relationships implied by scores or free text. Preserve private manifests separately. Do not interpret successfully written diagnostics as approval: an unmet fit target produces a non-operational draft. The shipped profile template and example are also explicitly non-operational.

Generate a file profile for file analysis, and a project profile for project analysis. Publish only a scope-compatible profile following a separately recorded institutional decision. Engine/configuration changes require refitting from the curated corpus, not a hand-edited digest. Review evaluation results without using them to select a substitute threshold under the original protocol.

## Short statement for a module handbook

> Students must run CodeProbe locally on the source code they authored for the project before submission. The AI-style concern score is a formative review signal, not proof of misconduct. The bundled 60% trigger is provisional; the active trigger may be replaced by a course-local calibration profile. An applicable result at or above the active trigger prompts code inspection and explanation. Revise only for identified issues and provide the disclosure required by the course policy, independently of the score, describing any AI assistance, what was retained, what was rewritten and how correctness was validated. Final academic judgement, where needed, will be based on the report together with repository history, intermediate commits, tests, design notes and an oral code walkthrough. Starter code, third-party libraries, generated files, minified assets, build output and documentation must be excluded.

## Student workflow

1. Open CodeProbe from the provided `codeprobe/` folder.
2. For one file, load only the authored source file. For a whole project, use **Open project ZIP** or **Open folder** and provide a `.codeprobeignore` where needed.
3. Paste a calibration profile JSON only if your instructor provides one.
4. Run the analysis.
5. In project mode, check the included-file and excluded-file inventories before reading the aggregate score.
6. Read the score, active review trigger, notes, warnings and individual metrics.
7. Treat quality/context metrics as improvement advice, not as evidence of AI authorship.
8. If an applicable score is at or above the active review trigger, inspect the indicated code and discuss the evidence. Re-run after justified changes; do not edit merely to lower the score.
9. Export the report only if required.
10. Complete `educator/03-student-disclosure-template.md` when the course disclosure policy requires it; a score neither proves nor disproves AI assistance.

## Instructor workflow

1. Place the kit in a dedicated `codeprobe/` folder.
2. Publish the short project notice from `educator/09-project-kit-notice.md`.
3. State explicitly which files should be checked and which should be excluded. Provide a course-specific `.codeprobeignore` where starter code or scaffold folders have predictable names.
4. Decide whether to use the bundled provisional trigger or an approved course-local calibration profile.
5. Require students to inspect the project-mode excluded-file list before submitting a report.
6. Require normal evidence of development: commits, tests and design notes.
7. For elevated results, request explanation rather than imposing an automatic judgement.
8. Record any manual review decision separately from the tool output.

## Project-mode guidance

Project mode is the preferred route for multi-file submissions because the exported report records:

- the number of candidate files received;
- the files actually analysed;
- the files excluded before analysis;
- the reason for each exclusion;
- the SLOC-weighted aggregate score and the per-file reports;
- the active calibration profile and review trigger.

For institutional use, instructors should prepare a module-specific `.codeprobeignore` covering starter folders and scaffold files. Students should not edit ignore rules to hide assessed source files. Students should explain both exclusions and any negated rule that re-includes a file; negation is not itself an exclusion.

## Evidence model for manual review

A proportionate review should combine:

- CodeProbe text or JSON report;
- commit history and intermediate snapshots;
- a short AI-use disclosure;
- tests and validation logs;
- design notes or sketches;
- an oral walkthrough of the submitted code.

The oral walkthrough should focus on specific implementation decisions, edge cases, defects fixed during development and tests written by the student.

## What not to do

- Do not analyse the entire repository without checking the project-mode inclusion/exclusion lists.
- Do not include dependencies, generated folders or instructor starter code.
- Do not treat a single score as a misconduct finding.
- Do not infer that a low score proves independent authorship.
- Do not compare students using Markdown scores; Markdown supplies descriptive statistics and configured editorial preferences, not a validated quality judgement.
- Do not call a course-local trigger empirical unless the validation summary is retained and reviewed.

## Minimal repository layout

```text
project-root/
├── codeprobe/
│   ├── .codeprobeignore.example
│   ├── app/
│   ├── src/
│   ├── tools/
│   ├── educator/
│   ├── calibration/
│   ├── docs/
│   └── README.md
├── src/
├── tests/
└── README.md
```

## Recommended assignment wording

> Before final submission, run CodeProbe on the source files you wrote for this assignment. For a multi-file project, use project mode and check that `.codeprobeignore` excludes starter code, libraries, generated files, minified assets, build output and documentation. The aim is not to obtain the lowest possible number, but to submit coherent, purposeful code that you understand and can defend. An applicable score at or above the active trigger prompts inspection and explanation, not compulsory score reduction. Revise for identified issues and follow the course disclosure policy independently of the score. The tool is a self-check; final academic reading depends on the submitted code, development evidence and your explanation.

## Interpretation and reference limits

The visible **Evidence coverage** category describes source quantity, metric
availability and selected warnings under fixed heuristic rules. The historical
JSON name `confidence` is retained only for compatibility. Neither the category
nor a well-formed report is a probability or a guarantee of correctness.

The default score uses seven configured contributors. A custom positive-weight
contribution in a quality, context or documentation role is a policy choice,
not new evidence of authorship. Examine the nominal and per-file eligible
weights and the applicability of the aggregate. Markdown remains excluded from
the code aggregate. Memory-related feedback describes source cues: it does not
measure allocated registers, emitted stack frames or safe optimisation.

Calibration summaries separate fit, evaluation and pooled observations and show
reviewed/eligible counts, declared groups and file/project units. Missing classes
have unavailable rates, not measured zero rates. Statistical independence is
not established and uncertainty is not estimated. Technical `operational`
status does not approve use in a course; a named institutional decision belongs
in the separately completed validation summary. Evaluation must not be used to
retune the fit-selected trigger without a new declared protocol.

The references below provide educational, policy or authorship-research
background. They do not validate the CodeProbe implementation, manual weights,
review bands or a language-independent detection rate. The runtime separately
labels metric references by definition, motivation or context. A real DOI is
not evidence that a paper supports an unrelated software claim.

## Academic background

| APA 7 reference | DOI |
|---|---|
| Dalalah, D., & Dalalah, O. M. A. (2023). The false positives and false negatives of generative AI detection tools in education and academic research: The case of ChatGPT. *The International Journal of Management Education, 21*(2), 100822. | https://doi.org/10.1016/j.ijme.2023.100822 |
| Krsul, I., & Spafford, E. H. (1997). Authorship analysis: Identifying the author of a program. *Computers & Security, 16*(3), 233-257. | https://doi.org/10.1016/S0167-4048(97)00005-9 |
| Nicol, D. J., & Macfarlane-Dick, D. (2006). Formative assessment and self-regulated learning: A model and seven principles of good feedback practice. *Studies in Higher Education, 31*(2), 199-218. | https://doi.org/10.1080/03075070600572090 |
| Wang, H., Dang, A., Wu, Z., & Mac, S. (2024). Generative AI in higher education: Seeing ChatGPT through universities' policies, resources and guidelines. *Computers & Education: Artificial Intelligence, 7*, 100326. | https://doi.org/10.1016/j.caeai.2024.100326 |

## Release and report metadata

From v2.1.9 onward, exported reports include engine and metric-configuration metadata. These fields are useful when checking which kit version produced a report, especially if several course profiles are used. They are not extra authorship evidence and should not be interpreted as proof of AI use or proof of independent authorship.
