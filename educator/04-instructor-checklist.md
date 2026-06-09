# Instructor checklist

## Before releasing the kit

- Confirm that the distributed ZIP hash matches the hash sheet or institutional archive.
- Decide whether the bundled 60% trigger will be used or replaced by a course-local calibration profile.
- Publish the LMS announcement from `educator/02-student-announcement.md`.
- Provide a course-specific `.codeprobeignore` example when projects contain known starter folders or framework files.
- State that CodeProbe is a formative review tool, not an automatic misconduct detector.

## During the project period

- Encourage students to run the tool before final submission and to revise code for clarity, not merely to minimise the score.
- Remind students that generated files, dependencies, documentation and starter code must be excluded.
- Ask students using AI assistance to keep prompts, accepted/rejected suggestions and final design decisions in a short disclosure.

## At submission

Request, where appropriate:

- exported CodeProbe JSON or text report;
- `.codeprobeignore` used for project analysis;
- repository commit history or development log;
- test evidence;
- completed disclosure template if AI assistance was used;
- short design note explaining architecture and non-trivial implementation choices.

## When a report crosses the active review trigger

- Do not use the score alone as evidence of misconduct.
- Check included and excluded files first, then read `manual_review_guidance.risk_zones` and `manual_review_recommendations`.
- Compare the report with the student's commits, tests and design notes.
- Ask for an oral walkthrough of the highest-concern file/metric plus one ordinary file for contrast, focusing on design decisions, edge cases and debugging decisions.
- Record the review outcome separately from the CodeProbe score.

## After the course

- Archive anonymised calibration candidates if institutional policy permits.
- Revisit the local review trigger before the next iteration of the course.
- Keep the exact ZIP hash and release manifest used for that cohort.

## Interpretation boundary

The CodeProbe score is a review signal, not proof of misconduct and not a certificate of independent authorship.
