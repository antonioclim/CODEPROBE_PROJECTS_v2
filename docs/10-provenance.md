# AI assistance and provenance

This kit has a hybrid provenance. LLM assistance was used in the broader drafting, review and improvement process, including analysis of terminology, documentation and refactoring risks. The final responsibility for interpretation, deployment and course policy remains with the instructor or maintainer using the kit.

## What this disclosure means

The presence of LLM assistance in the construction process does not invalidate the kit. It does mean that the kit should be treated as an inspectable teaching artefact rather than as an opaque authority. Every release should therefore include:

- readable source code;
- documented scoring assumptions;
- tests for release-relevant behaviour;
- cautious score terminology;
- clear false-positive warnings;
- human review before high-stakes use.

## Human-review requirements

Before using this version in a module, the maintainer should verify that:

1. the version shown in `src/codeprobe_runtime.py` matches `CHANGELOG.md`;
2. Markdown files return a documentation-only profile;
3. quality metrics do not contribute to the AI-style concern score;
4. the tool is introduced as a formative self-check;
5. students are told which files to exclude;
6. local report history is disabled unless explicitly enabled.

## Known provenance-sensitive areas

The following areas should be reviewed carefully in later phases because they are susceptible to LLM-style over-regularity or over-confidence:

- repeated metric-class boilerplate in `src/codeprobe_runtime.py`;
- threshold values that are not yet calibrated on a local course corpus;
- explanatory text that may sound more precise than the empirical validation permits;
- broad claims about AI-fingerprint detection;
- Markdown/prose analysis, which is not currently suitable for code-authorship decisions.

## Responsible use statement

CodeProbe is a local static-analysis aid. It reports signals associated with code style, structure and quality. It does not prove AI use, does not identify a particular model and does not certify human authorship. The appropriate use is revision, reflection and proportionate review.

## Phase-2 validation note

The Phase-2 release adds parser-focused tests and false-positive-control tests. In particular, clean formatter-shaped Python and JavaScript fixtures are used to verify that regular naming, regular function lengths and structural similarity are not treated as default authorship evidence.

## Phase-3 validation note

The Phase-3 release adds project-mode code paths and tests. These changes are provenance-sensitive because automatic exclusion can materially alter the reported score. For this reason the exported project report records candidate counts, included files, excluded files and exclusion reasons. A human maintainer should review these lists before treating the aggregate as meaningful.

## Phase-4 validation note

The Phase-4 release adds calibration profiles and sensitivity reporting. These features reduce reliance on a generic trigger, but they also introduce a new responsibility: the profile must be backed by a documented local corpus. A generated profile without its validation summary is policy metadata, not empirical evidence. The report therefore records the active calibration profile, the review trigger and whether the trigger was reached.

## Phase-5 validation note

The Phase-5 release adds release metadata, an engine fingerprint, a metric-configuration digest, a maintainer support package and release-validation scripts. These additions reduce provenance ambiguity by making the distributed kit easier to identify and compare. They do not make the detector more evidentially decisive; they make the toolchain more auditable.

Before distributing this phase, maintainers should explicitly refresh tracked
evidence with `python3 -I -S -B tools/check_release.py --write-release-evidence`,
inspect the diff, run the read-only `python3 -I -S -B tools/check_release.py` gate and archive the
resulting ZIP and both required sidecars with any course-local calibration
profile.


## Phase-6 validation note

The Phase-6 release hardens browser delivery and privacy controls. Inline JavaScript and CSS have been moved to external resources, the CSP no longer permits `unsafe-inline`, local browser assets carry SRI attributes and the Pyodide runtime source is made explicit through `runtime-config.json`. These changes reduce packaging ambiguity; they do not make AI-use detection more certain.

Before distributing this phase, maintainers should explicitly refresh tracked
evidence with `python3 -I -S -B tools/check_release.py --write-release-evidence`,
inspect the diff, run the read-only `python3 -I -S -B tools/check_release.py` gate, inspect
`app/runtime-config.json` and decide whether the course will use the default CDN
mode or an institutionally supplied local Pyodide runtime.

## Phase 8 consolidation note

The final package includes explicit operational resources for students, instructors and administrators. This is part of the provenance strategy: the kit should not appear as a black-box detector, but as a documented review workflow with visible assumptions, release hashes, calibration guidance and human-review safeguards.

## Phase 10 provenance note

The naming migration was treated as a maintainability and auditability task rather than a stylistic rewrite. The release keeps active paths unchanged while adding an explicit map from current names to proposed final names. Future path moves must pass the reference checker and release validation.

## Phase 4C–4D execution and evidence note

The audit branch adds three independently reviewable engineering boundaries: an allowlisted local server, one bounded process broker and a measured Pyodide core-startup provenance record. It also adds version-pinned supported-code coverage with nonzero weighted floors. These controls improve reproducibility and failure containment. They do not validate the scientific accuracy of AI-style authorship inference, certify every optional Pyodide package or establish that no software defect remains.

The coverage result is tied to a specific interpreter and test suite. The Pyodide record is tied to exact startup bytes and the official 0.25.0 core release. Future runtime upgrades require new measurements rather than copying old digests.
