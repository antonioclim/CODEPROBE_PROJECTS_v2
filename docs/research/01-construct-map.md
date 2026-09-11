
# Construct map: from source bytes to bounded review action

## 1. Purpose

CodeProbe v3 is designed as an evidence-bounded formative-review system. Its object is not the origin of source code. Its object is a set of inspectable properties of supplied bytes, the limits under which those properties were extracted and reversible review actions that those properties may warrant.

The construct is defined before the measurement kernel is altered so that implementation choices can be tested against an explicit interpretation-and-use argument rather than retrofitted to existing outputs.

## 2. Formal separation of layers

Let \(x\) denote the supplied source artefact, \(c\) the declared analysis configuration and \(s_i\) the versioned specification for observation \(i\). An atomic observation is:

\[
O_i = f_i(x, c; s_i)
\]

where the codomain includes an atomic scalar value, a measurement scale, a unit, a typed applicability state, stable source-evidence identifiers, instrumentation identity and a limitation record. It does **not** include a cause, author or disciplinary interpretation.

For a candidate review dimension \(d\), CodeProbe forms an evidence set rather than a scalar:

\[
E_d = \{(O_i, q_i, \ell_i) : i \in M_d\}
\]

where \(M_d\) is an explicit mapping, \(q_i\) is the observation qualification and \(\ell_i\) is the limitation. The complete review profile is the vector:

\[
\mathbf{E}(x) = (E_1, E_2, \ldots, E_D)
\]

No default function \(g(\mathbf{E}) \rightarrow \mathbb{R}\) is defined. Reports therefore have no total order by default. Comparison is valid only within a declared dimension and only when the underlying specifications, applicability and nuisance conditions are commensurable.

A bounded interpretation \(I_d(E_d)\) may state that a named region warrants inspection under a named policy. A feedback action \(A_j\) must reference the observations that warrant it:

\[
A_j = h_j(E_d, \text{policy}_j)
\]

and must remain specific, feasible and reversible. The inverse causal step

\[
\mathbf{E}(x) \Rightarrow \text{who or what produced } x
\]

is outside the model and is represented as a prohibited inference rather than as an unreported latent output.

## 3. Five invariants

### 3.1 Causal abstention

Observing a property does not identify its cause. Formatting, templates, domain conventions, experience, collaboration, automated assistance and ordinary refactoring can produce overlapping surface patterns. CodeProbe therefore reports the property and its extraction scope only.

### 3.2 Typed applicability

`observed`, `not_applicable`, `insufficient_evidence` and `unavailable` are explicit states. The latter three are not numerical zero. A parser failure cannot be converted into low concern, a missing observation cannot improve a profile and an unsupported construct cannot be treated as absence of the property.

### 3.3 Non-compensation

Evidence in one dimension cannot cancel evidence in another. Clear documentation does not make an untested failure path disappear, and low structural complexity does not repair dependency provenance. The core schema has no weighted sum for this reason.

### 3.4 Traceable and reversible action

Every generated feedback item must link to observations in its own dimension, source-evidence identifiers owned by those observations, a policy rule, an explanation, expected benefit, trade-offs and a reversible suggested change. Learner or reviewer acknowledgement is stored separately so it cannot mutate the deterministic evidence report. The reviewer may accept, decline or mark the action inapplicable without changing the observations.

### 3.5 Explicit legacy non-equivalence

Legacy scalar fields may be read to support archival continuity, but they are not translated into v3 dimensions. A migration envelope records their source digest, preserves raw atomic values where possible and lists discarded semantics.

## 4. Candidate dimensions

The seven dimensions in `research/construct-map.v1.json` are working hypotheses:

- structural complexity and dispersion;
- clarity and naming evidence;
- documentation–implementation alignment;
- defensive explicitness and failure handling;
- repetition, redundancy and maintainability signals;
- project intake and dependency hygiene;
- parser scope and unsupported-construct burden.

They are not asserted latent variables. S02 must specify every retained observation. M01 must test content representation. E01 must evaluate redundancy, nuisance sensitivity and dimensional behaviour. A dimension may be merged, split, renamed or abandoned if the evidence does not support it.

## 5. Construct-map completeness rule

Every dimension entry must contain:

1. observable families;
2. allowed interpretations;
3. permitted actions;
4. prohibited inferences;
5. nuisance factors;
6. metamorphic expectations;
7. an evidence gate.

An entry missing any element is incomplete and cannot support public output.

## 6. Consequence boundary

The system may help a learner or reviewer inspect source code. It cannot establish misconduct, cheating, independent work or source provenance. It cannot trigger a sanction. Any institutional decision must rely on an independently governed process and evidence outside the code-derived report.
