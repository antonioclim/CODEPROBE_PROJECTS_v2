# Browser-runtime lifecycle

The browser runtime is controlled by `app/pyodide-support-policy.json`. The policy is deliberately separate from provenance:

- provenance identifies the exact bytes approved for the pinned runtime;
- lifecycle metadata records when that pin was reviewed, when the next review is due and whether it may support a public release.

The present Pyodide 0.25.0 pin is classified as a reproducible, legacy development runtime. It is not approved for a public CodeProbe release. A measured upgrade must repeat provenance capture, browser functional testing, accessibility testing, report-equivalence checks and exact-head CI.

The lifecycle check is date-sensitive and fails after `next_review_by`. It does not assert that no vulnerability advisory exists. Advisory review is an explicit human task and must cite current upstream and vulnerability-database evidence at the time of a release decision.
