# Security policy

## Supported state

CodeProbe is presently a development candidate. No public release is supported until the repository's release gate records a `GO` decision for an exact commit.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use GitHub's private **Report a vulnerability** or draft security-advisory facility for this repository when it is available. If that facility is unavailable, contact the repository owner privately through the contact route shown on the `@antonioclim` GitHub profile and include `CodeProbe security report` in the subject or first line.

Include the affected commit, entry point, minimal reproduction, expected impact and any evidence that the issue is exploitable. Do not include student source code, personal data, access tokens or confidential institutional material.

## Response and disclosure

Receipt is not a promise of a particular remediation date. Reports are triaged according to reproducibility, affected trust boundary and impact. A coordinated disclosure date must be agreed before public discussion. Security fixes must pass the canonical exact-head CI and the release gate before promotion.

## Scope limits

A CodeProbe score is heuristic evidence for formative review. It is not an authorship determination, disciplinary finding or validated forensic classifier. Reports that concern only disagreement with a score, without a software or data-integrity defect, are not security vulnerabilities.
