# Manual review protocol for triggered reports

This protocol applies when a CodeProbe report crosses the active review trigger or when an instructor has independent reasons to request clarification.

## Step 1 — Check scope before interpreting the score

Confirm that the analysed project excluded starter code, libraries, generated files, minified assets, build output and documentation. Inspect `included_files`, `excluded_files`, `.codeprobeignore` and the Phase 8 `risk_zones` before reading the aggregate score. For GitHub ZIP exports, verify that the top-level repository folder did not hide or duplicate the assessed source tree.

## Step 2 — Separate signal types

Read authorship-style metrics separately from quality, context and documentation metrics. A clean structure, consistent indentation, type hints, modern syntax or well-used imports are not misconduct evidence.

## Step 3 — Compare against process evidence

Review commit history, intermediate versions, tests, design notes and any disclosure. Look for consistency between the submitted code and the student's documented development process.

## Step 4 — Conduct a focused oral walkthrough

Start with the files and metrics listed in `manual_review_guidance.risk_zones`, then select one ordinary low-concern file for contrast. Ask the student to explain:

- why the structure was chosen;
- how edge cases are handled;
- what bugs were encountered;
- how tests validate the behaviour;
- which AI suggestions, if any, were rejected or rewritten.

## Step 5 — Record the outcome

Record the review outcome as a human academic judgement. The CodeProbe score is one artefact in the review packet; it is not the conclusion.

## Step 6 — Feed back into calibration

Where institutional policy permits, anonymise and archive borderline examples for future calibration. Do not store private source code in calibration corpora without appropriate permission.

## Interpretation boundary

The CodeProbe score is a review signal, not proof of misconduct and not a certificate of independent authorship.
