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
4. A result above the active local review trigger leads to revision and disclosure, not an automatic penalty.
5. Persistent concern is checked through repository history, tests, design notes and oral explanation.

## Interpretation bands

| AI-style concern score | Teaching interpretation | Recommended action |
|---:|---|---|
| 0-50% | Low concern under the bundled policy | No special action beyond normal submission evidence |
| >50-60% | Borderline under the bundled policy | Student self-review; check comments, naming, repetition and structure |
| >60-75% | Elevated concern under the bundled policy | Revision, re-run and short disclosure where required |
| >75% | High concern | Manual review with commits, tests and oral walkthrough |
| N/A | Not applicable | Too little code or documentation-only profile |

The 60% threshold is a bundled provisional review trigger. It should not be presented as an empirically universal boundary. When a course-local profile is supplied, the report records the active trigger and whether it was reached.

## Course-local calibration workflow

Phase 4 introduced a standard-library calibration CLI. A defensible workflow is:

1. Assemble a private labelled corpus for each course/assignment/language.
2. Exclude starter code, templates, libraries and generated files from the calibration corpus.
3. Record every sample in a JSON or CSV manifest with its label, optional language hint, optional kind and notes.
4. Run `tools/calibrate_profile.py` with the manifest and target false-positive review rate.
5. Inspect the generated Markdown validation summary, especially sample counts, score distributions and sensitivity table.
6. Approve, revise or reject the generated JSON profile.
7. Provide the approved profile to students or use it only during instructor-side review.

Example:

```bash
python3 tools/calibrate_profile.py \
  --manifest calibration/01-corpus-manifest-template.json \
  --out-dir calibration/profiles/intro-python-2026 \
  --target-fpr 10
```

Explicit-output alternative:

```bash
python3 tools/calibrate_profile.py \
  --manifest calibration/01-corpus-manifest-template.csv \
  --profile-id intro-python-2026-project1-v1 \
  --label "Intro Python 2026 Project 1" \
  --target-fpr 10 \
  --profile-out calibration/profiles/intro-python-2026-profile.json \
  --summary-out calibration/reports/intro-python-2026-validation.md \
  --csv-out calibration/reports/intro-python-2026-observations.csv \
  --sensitivity-out calibration/reports/intro-python-2026-sensitivity.csv
```

Use the profile in project analysis:

```bash
python3 tools/analyze_project.py \
  --folder path/to/project \
  --calibration-profile calibration/profiles/intro-python-2026-profile.json \
  --json-out report.json \
  --text-out report.txt
```

## Short statement for a module handbook

> Students must run CodeProbe locally on the source code they authored for the project before submission. The AI-style concern score is a formative review signal, not proof of misconduct. The bundled 60% trigger is provisional; the active trigger may be replaced by a course-local calibration profile. A result above the active trigger requires revision and, where requested, a short disclosure describing any AI assistance, what was retained, what was rewritten and how correctness was validated. Final academic judgement, where needed, will be based on the report together with repository history, intermediate commits, tests, design notes and an oral code walkthrough. Starter code, third-party libraries, generated files, minified assets, build output and documentation must be excluded.

## Student workflow

1. Open CodeProbe from the provided `codeprobe/` folder.
2. For one file, load only the authored source file. For a whole project, use **Open project ZIP** or **Open folder** and provide a `.codeprobeignore` where needed.
3. Paste a calibration profile JSON only if your instructor provides one.
4. Run the analysis.
5. In project mode, check the included-file and excluded-file inventories before reading the aggregate score.
6. Read the score, active review trigger, notes, warnings and individual metrics.
7. Treat quality/context metrics as improvement advice, not as evidence of AI authorship.
8. If the score is above the active review trigger, revise the code and re-run the tool.
9. Export the report only if required.
10. Complete `educator/03-student-disclosure-template.md` if AI assistance was used or the score remains elevated.

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

For institutional use, instructors should prepare a module-specific `.codeprobeignore` covering starter folders and scaffold files. Students should not edit ignore rules to hide assessed source files. If a file is excluded through negation or re-inclusion, the student should be able to explain why.

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
- Do not compare students using Markdown scores; Markdown is documentation-quality context only.
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

> Before final submission, run CodeProbe on the source files you wrote for this assignment. For a multi-file project, use project mode and check that `.codeprobeignore` excludes starter code, libraries, generated files, minified assets, build output and documentation. The aim is not to obtain the lowest possible number, but to submit coherent, purposeful code that you understand and can defend. A score above the active review trigger requires revision and, where requested, a short disclosure. The tool is a self-check; final academic reading depends on the submitted code, development evidence and your explanation.

## Academic background

| APA 7 reference | DOI |
|---|---|
| Dalalah, D., & Dalalah, O. M. A. (2023). The false positives and false negatives of generative AI detection tools in education and academic research: The case of ChatGPT. *The International Journal of Management Education, 21*(2), 100822. | https://doi.org/10.1016/j.ijme.2023.100822 |
| Krsul, I., & Spafford, E. H. (1997). Authorship analysis: Identifying the author of a program. *Computers & Security, 16*(3), 233-257. | https://doi.org/10.1016/S0167-4048(97)00005-9 |
| Nicol, D. J., & Macfarlane-Dick, D. (2006). Formative assessment and self-regulated learning: A model and seven principles of good feedback practice. *Studies in Higher Education, 31*(2), 199-218. | https://doi.org/10.1080/03075070600572090 |
| Wang, H., Dang, A., Wu, Z., & Mac, S. (2024). Generative AI in higher education: Seeing ChatGPT through universities' policies, resources and guidelines. *Computers & Education: Artificial Intelligence, 7*, 100326. | https://doi.org/10.1016/j.caeai.2024.100326 |

## Release and report metadata

From v2.1.9 onward, exported reports include engine and metric-configuration metadata. These fields are useful when checking which kit version produced a report, especially if several course profiles are used. They are not extra authorship evidence and should not be interpreted as proof of AI use or proof of independent authorship.

