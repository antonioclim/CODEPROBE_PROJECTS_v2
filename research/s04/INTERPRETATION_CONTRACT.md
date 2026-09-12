# S04 interpretation contract, version 1.0.0

Author: Antonio Clim. Status: implemented native contract; empirical interpretation validity is not established.

## 1. Typed evidence and the inferential boundary

The input is an immutable byte string, an exact declared language (`python`, `markdown` or `text`), `source_inspection` task context, path metadata and an explicitly selected profile identifier plus canonical profile digest. The unchanged S03 kernel performs bounded intake and measurement. S04 checks catalogue cardinality and creates a separate `codeprobe-interpretation-capsule/v1` object. It never accepts a caller's arbitrary observations as an authentic measurement.

Five S01 candidate dimensions remain `insufficient_evidence` with `no_licensed_mapping`. Structural evidence is a series of separate callable observations, not an aggregate or dispersion estimator. Parser status is a qualification of the route, not a judgement of source quality. For plain text, structural interpretation is `not_applicable`; Python syntax failure makes it `unavailable`; a parsed file without callable entities gives `insufficient_evidence`. These dimension states are distinct from the four unchanged observation applicability states. A present item retains the original state, reason and evidence identifiers. Missing series and missing callable metrics produce explicit absences, never zero values or favourable judgements.

## 2. Policy semantics

For non-negative integer observation x and ordered threshold set L <= N <= U, the predicate at threshold t is x > t. S04 reports:

| Condition | Policy outcome | Optional opportunity |
|---|---|---|
| x <= L | `no_rule_trigger` | None; this is not a quality certification |
| L < x <= U | `abstain`, `boundary_sensitive` | None, even when x > N |
| x > U | `review_opportunity`, stable over the declared set | One controlled, reversible inspection question |

`nominal_predicate` records x > N without overriding abstention. The possible predicate set is not a probability distribution. Thresholds are illustrative choices locked before S04 evaluation; no optimum, universal convention or empirical calibration is claimed. Degenerate L=N=U is permitted and still obeys strict greater-than semantics. Counts cannot be Boolean, negative or fractional.

| Profile | McCabe complexity L/N/U | Control nesting L/N/U | Callable physical span L/N/U |
|---|---|---|---|
| observation-only | No rule | No rule | No rule |
| structural-review | 8 / 10 / 12 | 2 / 3 / 4 | 40 / 60 / 80 |
| structural-review-conservative | 14 / 16 / 18 | 4 / 5 / 6 | 80 / 100 / 120 |

For example, complexity 11 exceeds the regular nominal threshold but produces abstention; 12 also abstains, whereas 13 permits an optional branching inspection. Under the conservative profile, 13 does not trigger that rule. This disagreement is policy dependence, not measurement noise or an empirical probability. No rule suppresses an opportunity from another rule. A long function can remain an inspection opportunity even when its branching and nesting do not trigger their rules.

The only permitted actions are controlled branching, nesting and function-span inspection questions. All preserve behaviour and domain cohesion as trade-offs. No automatic rewrite, grading operation or sanction is performed. Profiles have a closed field/rule vocabulary; the native API does not execute arbitrary policy code or accept unconstrained policy text.

## 3. Output fields and identity

The capsule's exact top-level fields are `schema`, `contract_version`, `measurement_specification`, `build`, `profile`, `context`, `measurement`, `composition_rule`, `dimensions`, `empirical_calibration`, `non_inferences` and `digest`.

`measurement` retains the complete unchanged S03 result. `measurement_specification` states the kernel contract version and catalogue digest. `build` separates the admitted 15-component file-set digest, each component hash, actual Git anchor commit/tree, checkout state and runtime identity. Specification version 1.1.0 is not an implementation identifier. Untracked or modified source is marked `working_tree`, while an export without its own Git worktree is `unversioned_source` with no fabricated commit/tree. A parent directory's Git repository is not inherited as the export identity.

The component inventory includes executable interpretation contracts and the eight inherited components on which the capsule depends. Their S03 hashes are checked on import. The inventory includes its own bytes in the computed digest without embedding that digest in itself. Tests, workflow and explanatory prose are outside this component digest; the whole-candidate Git tree identifies them. Component changes after module admission are rejected. These checks describe admitted file consistency, not authentic authorship, a signed attestation or integrity in a hostile Python process.

`profile` retains identifier, semantic version and the SHA-256 of canonical UTF-8 JSON: sorted keys, compact separators, Unicode retained and non-finite numbers rejected. Its identity is separate from the build and the source/evidence hashes. The complete report digest covers all fields except the digest itself. Runtime and path differences therefore need not preserve full capsule identity.

Each dimension carries status, basis, interpretation, limitations, an uncertainty object, items and explicit absences. Each item carries the rule and observation identifiers, the exact observation record reference, entity and source-evidence references, value, applicability, source-qualified condition, decision, optional opportunity and uncertainty. Opportunities never replace the evidence or its limitations.

## 4. Uncertainty is not a score

Each dimension and item distinguishes the finite computational contract, parser/runtime dependence, policy sensitivity and unestablished empirical calibration. A measurement interval is `null` with `not_estimated`, not [0,0], 100% confidence or a posterior probability. Dimension-level limitations do not deny available item evidence. Missingness, policy sensitivity and an unestimated numerical error distribution are different conditions and must remain distinguishable in S05.

The S04 finite invariance experiment compares a deliberately restricted decision projection. Path, LF/CRLF, leading BOM, alpha-renaming, leading comments and token spacing preserve the tested structural policy projections for the finite fixtures. The byte count, source hash, coordinates, metadata, build and complete report digest may change. Alpha-renaming can be an identity transform when a fixture has no generated identifier. These comparisons are not universal guarantees about transformations, formatters or all programming languages.

## 5. Compatibility migration

`migrate_condition(namespace, code)` requires an exact source-qualified pair. Its 27 entries distinguish the original measurement-error register from kernel exceptions and kernel observation reasons. The raw legacy code remains visible alongside the new condition identifier.

ME-008 in a kernel exception means unsupported language; ME-008 in the legacy register describes a finite Markdown subset limitation. ME-013 in an observation denotes an unavailable callable span; ME-013 in the legacy register describes a bounded syntactic complexity convention. Unqualified or unknown pairs are rejected rather than guessed. S03 error codes, tests and locked protocol bytes are unchanged. This is an explicit new-boundary compatibility mapping, not proof that every historical consumer has migrated.

## 6. Admission and replay

`verify_capsule` remeasures caller-supplied source bytes with independently supplied language, profile digest, task context and path. It requires exact canonical equality with the resulting capsule. Altering a value, evidence, context, claim, policy or build and recomputing the transported digest does not pass replay. Same-runtime and same-build replay is intended; cross-runtime equivalence is assessed separately by the restricted finite projection, never used to authenticate a report.

External JSON parsing has a four-million-byte limit, explicit duplicate-key and non-finite-number rejection, maximum depth 64 and maximum 200,000 visited value nodes. Parsing still occurs before the explicit depth walk; this is not an OS memory-containment mechanism. The inherited source limit is one million bytes. Interpretation refuses more than 4,096 callable observation records instead of truncating them. Leaf and parent symlink components are not admitted. These are bounded API controls, not a guarantee against native parser crashes or process-wide exhaustion.

## 7. S05 integration obligations

The new capsule is not certified against the old S01 complete-report schema. S05 must define and test any mapping, namespace, coordinate and ownership changes explicitly. It must preserve abstention, evidence references, profile/build identity and the five withheld dimensions in browser/CLI/report presentation; test accessibility and misleading favourable displays; handle source paths as potentially sensitive metadata; and keep feedback responses outside immutable measurement evidence. This phase neither implements nor claims that integration.
