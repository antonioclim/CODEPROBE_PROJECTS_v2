# Oracle hierarchy and conformance design

## Rationale

A test that reuses the production formula can reproduce the same mistake. S02 therefore assigns every retained observation to at least one explicit oracle class and records residual dependence.

## Hierarchy

1. **Independent reference implementation** — a separately written calculation with a different decomposition.
2. **Worked-example oracle** — a finite, manually inspectable example with a declared expected value.
3. **Metamorphic oracle** — an invariant or equivariant relation under a controlled transformation.
4. **Cross-route oracle** — agreement between kernel output, S01 adapter and catalogue contract.
5. **Structural oracle** — uniqueness, ownership, cardinality and referential integrity.
6. **Boundary and negative oracles** — exact acceptance/refusal behaviour at resource and syntax boundaries.
7. **Cross-version determinism** — exact output comparison at the supported Python endpoints.
8. **Bounded-rationale status** — a transparent marker where an adequately independent oracle is not yet available.

`research/oracle-hierarchy.v1.json` is normative. No oracle class is treated as evidence of empirical construct validity.

## Conformance matrix

The matrix covers normal, boundary, malformed, scope-boundary, unsupported-syntax and resource-exhaustion cases. It also includes path-renaming, newline, BOM, alpha-renaming and comment-insertion relations. S03 will widen this into systematic metamorphic testing; E01 will evaluate nuisance sensitivity and redundancy on an empirical corpus.

## Independence caveats

The production and reference implementations share the Python interpreter, Unicode database and AST semantics. Agreement therefore localises many implementation errors but cannot establish language-independent truth. Where both routes depend on `ast.parse`, the shared dependency is stated rather than hidden.
