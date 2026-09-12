# Measurement error and typed missingness

## Core distinction

The absence of an observed property is not equivalent to inability to observe that property. S02 distinguishes true zero from `not_applicable`, `insufficient_evidence` and `unavailable`.

## Error classes

The normative register is `research/measurement-error-register.v1.json`. It separates intake and decoding errors, parser errors, unsupported syntax, finite-budget refusal, environment drift, approximation, instrumentation defects, true absence and insufficient evidence.

## Propagation rule

A failure is propagated only to observations that depend on the failed component. For example, a Python syntax error makes AST-dependent counts unavailable, while generic source counts and any successfully tokenised comment observations retain their own states. A failed denominator produces `insufficient_evidence`, not zero.

## Reporting rule

Every unavailable or insufficient observation carries a stable reason code and a human-readable reason. The kernel never uses missingness to improve a profile and never imputes absent evidence into an aggregate score.

## Residual risks

The bounded file reader reduces symlink and race risks but is not a universal filesystem proof. CPython AST and tokenisation semantics can drift across versions. S02 CI therefore uses both the oldest and newest supported endpoints, while S03 and release gates must detect semantic drift before integration.
