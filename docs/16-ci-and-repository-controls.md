# Continuous integration and repository controls

This document defines the automated repository checks and the branch controls
that should enforce them. It does not claim that a mutable hosted runner is a
reproducible operating-system image or that static checks replace browser,
scientific or security validation.

## Continuous-integration scope

`.github/workflows/ci.yml` runs for pull requests targeting `main`, pushes to
`main`, version-like tags and manual dispatches. Pull requests do not receive a
write-capable token. The workflow does not use `pull_request_target`, caches,
uploaded artefacts or a self-hosted runner. It receives only the
automatic read-only token described below and does not request user-configured
repository or environment secrets.

The validation matrix covers the inferred Python 3.10 syntax floor through the
current stable Python series. Linux runs every supported minor series, while the
current stable interpreter is also exercised on Windows and macOS.

| Runner | Architecture | Exact Python versions |
|---|---|---|
| `ubuntu-24.04` | x64 | 3.10.21, 3.11.16, 3.12.14, 3.13.15 and 3.14.7 |
| `windows-2025` | x64 | 3.14.7 |
| `macos-15` | ARM64 | 3.14.7 |

Every validation job installs Node.js 24.20.0 and requires the three browser
scripts to pass `node --check`. A missing Node executable is an error in CI even
though the local developer gate may report that optional check as skipped.

The workflow records the effective Python, Node.js, Git and zlib versions. The
runner labels remain mutable GitHub-hosted images, so these logs delimit the
environment actually tested.

## Checkout and release reproducibility

`.gitattributes` fixes detected text files to LF, disables content-changing Git
filters and substitutions and explicitly protects the current binary formats.
CI stages a no-op renormalisation and fails if the resulting index differs from
the committed tree.

`tools/check_release_reproducibility.py` then compares the exact Git tree with
clean LF and forced-CRLF checkouts and a safely extracted `git archive` export.
It compares path membership, entry types, sizes and SHA-256 values, runs the
read-only release gate in each source and builds the same three-file release
packet from each source. The ZIP, checksum sidecar and package-audit sidecar must
be byte-identical within that recorded Python/zlib toolchain.

This is a same-toolchain test. It does not assert that different zlib versions,
compressor implementations or hosted-runner images emit the same DEFLATE
bitstream.

## Dependency boundary

CodeProbe currently has no Python or JavaScript package manifest or lockfile.
Its Python code uses the standard library and repository-local modules. Node.js
is used only for syntax checking. Consequently, `pip-audit` and `npm audit` have
no declared dependency graph to inspect; running them against the hosted runner
would audit CI tooling rather than CodeProbe.

`tools/check_dependency_boundary.py` instead verifies the present offline
contract: no undeclared package manifest or PEP 723 dependency block, no
third-party Python import, no standard-library shadow module, no unapproved or
missing source-tree entry, no vendored dependency tree, no package-manager
reference in executable workflow fields, no unapproved literal or simply
constructed browser-runtime location and no mutable GitHub Action reference.
Remote executable HTML attributes are forbidden and CSP source lists accept
only the repository's exact local keywords, schemes and Pyodide origin. The
check also verifies the consistency of the declared Pyodide version and paths.
The Python check performs bounded, scope-aware static evaluation of constant
child-process commands. The browser and workflow checks recognise deliberately
narrow lexical forms and reject security-sensitive YAML or JavaScript forms
that they cannot prove safe. These controls are regression policy, not semantic
parsers for arbitrary Python, JavaScript or shell and not a substitute for
reviewing executable changes.

CI's inline toolchain probes use `python -I -S -`. Repository release tools and
their child gate, builder and unittest commands use the canonical
`python -I -S -B` invocation. Isolated mode and disabled automatic `site`
initialisation keep ambient import paths, site-packages and `sitecustomize`
hooks out of the release process before tool code starts. Repository paths are
then appended after the interpreter's standard-library paths. The unittest
child removes every ambient `PYTHON*` variable from its explicit environment.

The dependency boundary runs immediately after release-set safety and before
Python compilation or unit-test discovery. A boundary failure reports unit
tests as skipped, so untrusted checkout tests are not executed, while the
remaining non-test checks continue to provide additional diagnostics. The
boundary also rejects top-level standard-library shadow modules. Together these
controls prevent checkout or ambient modules from pre-empting the gate's own
standard-library imports before the inventory check runs.

The default browser mode still loads Pyodide 0.25.0 from jsDelivr without a
complete authenticated distribution inventory. This gate does not report that
external runtime as vulnerability-audited or provenance-verified. Those tasks
require an upstream advisory review, complete runtime hashes, licence evidence
and a live browser test. Until that inventory exists, the gate rejects vendored
runtime bytes and a production configuration that selects local mode.

## Action and token controls

Remote actions are pinned to verified full commit SHAs, with the corresponding
verified tag retained as a comment:

| Action | Immutable commit | Corresponding verified tag |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 |
| `actions/setup-python` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | v7.0.0 |
| `actions/setup-node` | `820762786026740c76f36085b0efc47a31fe5020` | v7.0.0 |

Checkout credentials are not persisted. Validation and reproducibility jobs
receive only `contents: read`; the aggregate `Required CI` job receives no
repository permission. An action-pin update must be reviewed together with its
upstream release rather than merged automatically.

## Required GitHub ruleset

After `Required CI` has appeared for this repository, configure the
default branch through **Settings → Rules → Rulesets → New branch ruleset**:

1. name the ruleset `Protect main` and set enforcement to `Active`;
2. target the repository default branch;
3. restrict branch deletion and block force pushes;
4. require a pull request before merging;
5. require conversation resolution;
6. require the `Required CI` status check and require the branch to be up
   to date before merging;
7. leave the bypass list empty for ordinary work;
8. retain ordinary merge commits, because the audit history does not require a
   linear-history rule.

With one active maintainer, set required approving reviews to zero so the owner
is not placed in an impossible self-approval state. Increase this to one and
dismiss stale approvals after an independent maintainer is formally available.
Do not require signed commits until a signing method is configured and verified;
turning that rule on first would block the current unsigned maintenance path.

The committed workflow defines the required check but cannot itself enable the
GitHub ruleset. Repository settings must be verified separately after the rule
is applied.


## Real-browser accessibility job

The `Browser accessibility (Chromium)` job runs on Ubuntu with the same pinned checkout, Python and Node setup actions as the other CI jobs. It invokes `node tools/check_browser_accessibility.js`, which uses only Node's standard modules and the runner's installed Chromium-family browser. The gate inspects the browser accessibility tree and exercises keyboard interaction through the Chrome DevTools Protocol. It deliberately blocks the external Pyodide CDN so a remote runtime outage cannot make an accessibility regression appear to pass or fail.

The aggregate `Required CI` job depends on this browser job. A skipped, cancelled or failed browser run therefore prevents the aggregate check from succeeding.
