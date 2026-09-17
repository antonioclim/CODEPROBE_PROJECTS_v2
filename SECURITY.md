# Security policy

## Scope and reporting

CodeProbe is a formative code-review tool, not an authorship detector or a basis for a misconduct finding. This audit snapshot is not an approval for institutional production deployment. Its source, runtime configuration and exact commit must be considered together.

The repository is maintained through `@antonioclim`. Report non-sensitive, reproducible defects through this repository's issue tracker. Do not attach student code, personal identifiers, credentials, private repositories or an exploitable disclosure to a public issue. A confidential reporting channel and private vulnerability reporting have not been verified as enabled; this file does not claim otherwise. Establish a confidential channel with the maintainer before sharing sensitive details. No response-time or remediation-time service level is promised by this policy.

A useful report identifies the exact commit, operating system, browser/Python versions, expected behaviour, observed behaviour and a minimal non-sensitive reproducer. Hashes can identify a test artefact without publishing its contents. Do not test systems without permission.

## Trust boundaries

The browser imports the bundled Python engine only after checking its packaged SHA-256 identity. The five pinned Pyodide startup artefacts are verified and the verified bytes are bound to bootstrap consumption. The analysis worker entry is hash-checked; the loader bytes included in the worker are fetched with the page's Subresource Integrity value. A changed response is not accepted merely because a preceding response was valid.

Both browser interfaces run Python in a dedicated worker. Cancellation, execution failure and deadlines dispose of that worker. There is no fallback to execution on the page. This is an execution-isolation boundary for responsiveness, **not a security sandbox for a malicious runtime**. The explicit manual engine override remains unverified executable code and should not be used with sensitive inputs. A compromised origin, browser extension, modified HTML trust anchor or actor able to rewrite the complete package remains outside the digest boundary.

Analysis inputs are treated as source text, not programs to execute. Source files and ZIPs have intake budgets. Native subprocesses use the bounded process broker. The local server publishes an allowlist, not the whole checkout. No source upload is required by the normal analysis path; downloading the CDN runtime still discloses ordinary network metadata to its provider.

## Evidence-contract implementation boundary

The bounded evidence-contract modules inspect admitted source and JSON bytes without launching submitted programmes. `src/codeprobe_interpretation.py` does not launch Git or infer repository identity from a parent checkout. It records a deterministic admitted-file-set identity, while exact release commit and tree anchors are supplied by an external provenance receipt after the integration commit exists. This avoids an unbounded process dependency and an impossible self-referential commit claim.

The evidence-contract route is a scientific and provenance boundary, not a security sandbox. A hostile Python runtime, modified package, compromised filesystem or actor able to replace the trusted source set remains outside its guarantees. Its source-localisation coordinates and review opportunities do not establish authorship, intent or misconduct.

## Supported snapshot and incident handling

The tested browser dependency remains Pyodide 0.25.0. Pinning and byte verification do not establish that this old runtime is free of vulnerabilities or supported upstream. See [the runtime lifecycle](docs/21-runtime-lifecycle.md) and [worker boundaries](docs/20-worker-resilience.md). Optional runtime packages are outside the approved dependency graph.

For a suspected integrity failure, stop using the affected snapshot, retain its commit and hashes and reproduce with non-sensitive data. Do not bypass a failing digest or enable optional downloads to obtain a green result. A runtime upgrade requires a new provenance inventory and all acceptance gates. Release recovery is documented in [the recovery guide](docs/19-release-recovery.md); do not delete ambiguous transaction evidence.

This policy, `CODEOWNERS` and passing CI do not enforce default-branch protection. Effective repository rules, contribution ownership, licensing decisions and independent scientific validation remain separate questions.
