# S03: finite robustness and computational validity

Author: Antonio Clim.

This candidate extends the exact S02 measurement kernel, not the public v2.2.0 product. It provides a deterministic finite experiment and corrective implementation changes. It does not establish construct validity, educational utility, fairness, cross-language generalisation, origin classification or misconduct detection. No source fixture is executed.

## Authority and prospective limits

The baseline is commit `dee3bdd9bae60b3fb7b6db9c1106306b83f36cb5`, tree `567af91fc8b79274edfcc690ce0a58725d4e4e75`. The earlier hash-only anchor at `7fceee8042f18fc6110ebc2dd6dc9d504e9f8683` is preserved. Its protocol bytes and subsequent local outcomes were not recovered. The complete replacement `resumption-protocol.v1.json` was persisted at `ef45fe8d20fe74a0e888e8dae4e6fe374c659aee` before measurements in the resumed execution. Deviation D-S03-001 prohibits representing this as the original protocol, uninterrupted prospective history or external preregistration.

The protocol SHA-256 is `e5ee95190a74e9f84e12450cd2b27dc3a2ac241409e5b41c384a7f920123c6e0`. The eight hypotheses and their tolerances are immutable. Supplementary tests and fixture corrections are separately identified in the experiment register.

## Reproduction

Run `python -I -S -B tools/check_s03_robustness.py --output <outside-source-directory>` from an exact Git checkout. No third-party Python package is required. The checker runs S01/S02 regression, S03 corrective controls, the 2,000-case experiment, 41 adversarial probes and three runtime-grammar frontier checks. It retains every generated input, full measurement output, discrepancy, refusal and resource-worker outcome outside the source tree. The corpus manifest distinguishes unique case identifiers from unique byte payloads and from independent observations.

The baseline can be reproduced by exporting its exact Git tree and passing that directory to `tools/run_s03_robustness.py --root <baseline> --output <baseline-evidence>`. Do not pass `--strict` when reproducing the known failing baseline. The S03 generator, oracle and locked protocol remain those of this candidate. A positive acceptance result requires `--strict` for the corrected implementation and the separate regression checks.

## Evidence and interpretation

The completed local baseline produced 197 failed assertions across 95 case identifiers. All eight finite metamorphic hypotheses nevertheless passed: metamorphic success alone did not establish correctness. Differential Markdown cases and adversarial ownership, codomain, adapter and resource probes exposed six root defect categories. Three supplementary entity/scope substitutions were also retained. Corrections do not erase these observations.

`experiment-register.v1.json` is an explicitly pre-CI local evidence snapshot. It is not a declaration of remote closure. Acceptance requires the exact source commit, SHA-specific CI and the verified phase audit. The CI workflow assesses Ubuntu 24.04 with Python 3.10.21 and 3.14.7, Windows 2025 x64 with Python 3.14.7 and macOS 15 ARM64 with Python 3.14.7. Ubuntu uses x64. The comparison job checks the actual bytes of the shared 80-case core, source hashes and corpus identities. Grammar-frontier changes and OS-specific resource/symlink limitations are reported separately.

The measurements are dependent synthetic observations, not a representative sample. No population error rate, confidence interval or p-value follows from these counts. The formatter is a finite token-spacing transformation, not a general guarantee about every formatter. Independent AST traversal shares CPython's front-end; analytic generator counts provide a separate but finite oracle.

No product, kernel or catalogue version is changed. Contract version 1.1.0 is not a unique build identifier: use the exact Git commit and file hashes. ME-015 is defined in `error-register-extension.v1.json`; the existing error register is preserved. The historical ME-008 terminology collision is explicitly carried to S04.

Nineteen historical findings are individually reconciled without artificial closure. The historical ledger remains 80 CLOSED / 31 OPEN of 111. `A01-F003` remains P1 OPEN/PARTIALLY_IMPLEMENTED. Catching recoverable Python exceptions is not universal process containment, and internal evidence consistency is not a signed attestation of authentic measurement. Browser, release, canonical coverage and distribution paths are not validated by native-kernel tests.

A disclosed late fault-injection regression preserves the existing unavailable callable-span fallback (ME-013) under the new evidence-scope validation. Corrective unit tests now number 19. The retained pre-fix failure is supplemental, not part of the original baseline 197. CI logs export compact cell evidence alongside full uploaded artefacts.
