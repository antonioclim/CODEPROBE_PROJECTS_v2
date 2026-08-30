# 15 — Final release audit

This document records the v2.2.0 naming-stable release boundary. It is an internal audit note, not an authorship-classification claim.

## Stable package areas

- repository-root policy files, including `.gitattributes` and `.gitignore`.
- `.github/` — least-privilege continuous-integration configuration.
- `app/` — static browser interface, CSS/JS assets, runtime configuration and Pyodide vendor placeholder.
- `src/` — Pyodide-compatible Python runtime and maintainer support package.
- `tools/` — command-line analysis, calibration, local serving, release building and audits.
- `docs/` — numbered technical documentation, visual assets and chronological phase history.
- `educator/` — student and instructor course resources.
- `calibration/` — corpus manifests, profile templates and validation-report placeholders.
- `release/` — release evidence, including `release/file-rename-map.csv` and `release/release-manifest.json`.
- `tests/` — behaviour-focused regression tests.

## Final audit checks

The canonical read-only release gate verifies:

1. release-set regular-file safety before any later reader is invoked;
2. Python compilation for runtime, support package, tools and tests;
3. unit-test discovery;
4. JavaScript syntax for the browser scripts;
5. CSP, inline-code and local SRI checks for the browser pages;
6. browser-resource integrity for local assets and the auditable runtime;
7. version consistency across runtime, UI, documentation and changelog;
8. file and project smoke reports;
9. institutional distribution artefact presence;
10. high-confidence Markdown/HTML file references;
11. file-rename-map coverage and retired active-path containment;
12. the standard-library dependency boundary, Pyodide configuration consistency
    and immutable GitHub Action references;
13. exact verification of the committed audit reports and every authoritative
    release-manifest field, membership, size and SHA-256 value, without
    rewriting them.

After that gate passes, `tools/build_release.py` captures the manifest-listed
files and verified manifest as an immutable snapshot, then constructs a
fixed-metadata ZIP under the canonical versioned root. It stages and verifies
the ZIP and both required sidecars before publishing them with detected-failure
rollback. It consumes, but does not rewrite, the tracked release evidence. Byte
identity is claimed only for identical snapshot bytes under the same supported
Python/zlib toolchain. The three public path replacements are not claimed to be
atomic across a power loss or uncatchable process exit.

CI runs the complete gate across Python 3.10–3.14 on Linux and the current
stable interpreter on Windows and macOS. A separate integration gate compares
the exact Git tree, normalised checkouts, a Git archive and the three-file
packet. `Required CI` is the stable aggregate check intended for the
default-branch ruleset. The hosted runner image remains mutable and the external
Pyodide distribution is not reported as vulnerability-audited.

## Interpretation boundary

CodeProbe reports a heuristic AI-style concern score. The score can guide revision and manual review, but it does not prove AI authorship, misconduct or independent authorship. Any triggered case must be read together with the analysed files, excluded-file inventory, repository history, tests, design notes, disclosure and, where required, an oral walkthrough.

## Release status boundary

The v2.2.0 layout defines the naming-stable candidate boundary. A particular
commit is releasable only when the canonical read-only gate passes in both a
fresh clone and an exact Git export under the same supported toolchain and a
byte-preserving checkout configuration, the checkout remains byte-identical
after validation, the package is built from the exact verified head and
`Required CI` succeeds for that head. The branch rules described in
`docs/16-ci-and-repository-controls.md` must be verified independently because a
committed workflow cannot enable repository settings. Future
features should extend the existing directories rather than reintroducing
unnumbered documentation, phase-numbered test filenames, ambiguous runtime
paths or duplicate active release manifests.
