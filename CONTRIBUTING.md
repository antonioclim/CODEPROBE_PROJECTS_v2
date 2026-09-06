# Contributing to CodeProbe

## Author and maintainer

**Antonio Clim** ([`@antonioclim`](https://github.com/antonioclim)) is the author
and maintainer identified for this project. Contribution proposals, technical
changes and documentation corrections are reviewed through the repository's
issues and pull requests. GitHub's automated committer labels do not identify
the scholarly author of the software.

This guide is a contribution process, not a claim that every past byte has a
single legal origin. Retain applicable copyright notices, the MIT licence and
accurate provenance. Do not manufacture co-authors or erase real contributions.
Accepted contributions should be credited according to their documented scope.

## Scope and scientific restraint

Contributions should improve correctness, robustness, security, usability,
transparent methodology or documentation. CodeProbe is an inspectable formative
static-analysis tool, not a validated disciplinary detector. A score is not an
AI-authorship probability. Do not add a metric merely because it detects clean,
well-documented or stylistically consistent code.

A lower score after a code change is not proof of greater human authorship.
A higher score is not proof of misconduct. Clearly distinguish measured software
behaviour, assumptions, synthetic test fixtures and empirical findings. Claims
about error rates require a specified corpus, reference labels, denominator,
threshold, unit of analysis and uncertainty analysis. Do not recast the author's
legacy-use observation as a published validation study.

## Before implementing a change

Read README.md, SECURITY.md, docs/11-design-decisions.md and the documentation
for the affected boundary. State the problem, expected behaviour and a small
reproducer in an issue or PR. Use formal British English for project material.
Make a focused branch from the current main commit; inspect concurrent changes
before proposing integration. Never force-push over another person's work.

The browser runtime must remain inspectable and standard-library-only on the
Python side. Preserve authenticated runtime/worker/engine loading, bounded input,
terminable analysis and local processing. No remote upload of analysed source,
reports or filenames is introduced merely to simplify a feature. Do not turn
an explicitly unverified manual engine override into an authenticated route.

## Tests and release evidence

Run commands from a complete checkout, with a supported Python and Node runtime:

```bash
python3 -I -S -B tools/check_release.py --require-node
```

The canonical gate is read-only. A source change makes committed release
evidence stale. After implementing the change and its regressions, refresh
evidence only through the guarded complete gate, then verify it again:

```bash
python3 -I -S -B tools/check_release.py --require-node --write-release-evidence
python3 -I -S -B tools/check_release.py --require-node
```

Inspect the evidence diff. Do not edit a digest to conceal a failure, reduce a
coverage floor, remove an assertion or add an exclusion merely to obtain PASS.
Tests for a defect should fail on the old behaviour and pass after its repair.
Report the platform, exact source commit, executed cases and justified skips.
Synthetic labels do not become observations of human authorship.

The standalone reproducibility gate requires a clean Git commit:

```bash
python3 -I -S -B tools/check_release_reproducibility.py
```

Use the pinned runtime for coverage enforcement and the documented real-browser
harnesses for changes affecting browser behaviour. A mock-only result must not
be represented as a Chromium/Pyodide execution. Keep diagnostic outputs outside
the tracked source. Changes to browser/runtime bytes require corresponding
integrity metadata and SRI updates, verified by the existing controls.

## Documentation and attribution

Keep input formats, parser limitations, output schemas and commands consistent
with implementation. Preserve the distinction between bundled teaching documents
and formats the engine can actually read. Update examples when behaviour changes;
identify placeholders and pseudocode rather than claiming they were executed.

Use CITATION.cff for machine-readable software authorship. Cite the exact release
or commit used. Changing citation metadata does not rewrite an earlier release
or transfer copyright. Keep discussion of the legacy repository factual,
version-specific and linked to preserved evidence rather than personal criticism.

## Privacy and security reports

Follow SECURITY.md for security-sensitive issues. Never upload student source,
identified reports, credentials or private evaluation records to a public issue.
Provide a minimal authorised or synthetic reproducer. Any institutional data
collection, retention or participant consent is a separate decision, not an
assumption granted by this contribution guide.

## Acceptance and release

Antonio Clim reviews the proposed scope, implementation, evidence and attribution.
Normal pull-request integration requires the appropriate CI results for the exact
head and a fresh ref check. A contributor does not approve their own PR as an
independent reviewer; do not invent review approvals.

A contribution may be accepted without creating a release. Do not overwrite an
existing tag or published asset, change repository visibility, invite
collaborators, alter licensing or deploy the application without the maintainer's
specific authorisation. No numerical error-rate claim is established merely by
passing the software test suite.
