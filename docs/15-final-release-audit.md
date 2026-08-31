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

The canonical read-only release gate is
`python3 -I -S -B tools/check_release.py`. It verifies:

1. release-set regular-file safety before subsequent check functions and readers are invoked;
2. the standard-library dependency boundary, Pyodide configuration consistency
   and immutable GitHub Action references;
3. Python compilation for runtime, support package, tools and tests;
4. unit-test discovery, only when the dependency boundary succeeds;
5. JavaScript syntax for the browser scripts;
6. CSP, inline-code and local SRI checks for the browser pages;
7. browser-resource integrity for local assets and the auditable runtime;
8. version consistency across runtime, UI, documentation and changelog;
9. file and project smoke reports;
10. institutional distribution artefact presence;
11. high-confidence Markdown/HTML file references;
12. file-rename-map coverage and retired active-path containment;
13. exact verification of the committed audit reports and every authoritative
    release-manifest field, membership, size and SHA-256 value, without
    rewriting them.

If check 2 fails, the gate reports unit-test discovery as skipped so untrusted
checkout code is not executed. Trusted static checks still run to provide the
remaining policy diagnostics.

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
