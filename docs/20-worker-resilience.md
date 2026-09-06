# Browser worker resilience

## Execution and integrity

Each page creates one analysis session with at most one active operation. Both interfaces use `CodeProbeRuntime.createAnalysisSession()`. The session fetches the loader with the SRI digest from the already loaded HTML script element and authenticates `analysis-worker.js` against the loader's embedded size and SHA-256 record. A classic worker is created from those verified bytes. The worker uses the existing verified Pyodide startup and Python-engine loading boundary; it does not import an unchecked network script. All temporary script Blob URLs are revoked.

Only initialisation and the fixed file/project analysis operations are accepted. The protocol contains no arbitrary Python-expression operation. Submitted code is data for the analysis engine. The explicitly approved manual engine override is an exception for executable engine code, is limited to 1 MB and remains labelled `manual-unverified` in report fingerprints. The page itself cannot initialise Pyodide through the shared runtime entry point.

The worker removes its Python payload global in a `finally` block after each completed analysis. An interrupted worker is terminated instead of being reused. This is not a promise of forensic memory erasure, prevention of all JavaScript interoperability or a sandbox against a malicious replacement engine.

## Deadlines, cancellation and stale results

Initialisation has a 60,000 ms deadline including authenticated script fetch, Pyodide bootstrap and engine import. Analysis has a 30,000 ms deadline. The session API accepts shorter positive deadlines, never a longer deadline than these maxima. The watchdog runs on the page, outside synchronous Python. A timeout aborts pending bootstrap fetches, terminates the worker and rejects the operation. Cancelling through either page's **Cancel analysis** button has the same disposal semantics. Leaving the page also disposes of its worker.

A new request is rejected while another request is active; work is not queued without a bound. Request identifiers and worker identity reject late responses from an old operation. Each UI also records a generation, clears exports before analysis and accepts no report from a cancelled generation. A retry creates a fresh interpreter. No main-thread fallback is permitted.

Browser timer suspension, process starvation and operating-system scheduling mean these are watchdog deadlines, not hard real-time or universal wall-clock guarantees. Worker termination is not a promise of a bounded browser-process memory footprint. Browser crashes remain possible under environmental resource exhaustion.

## Intake and rendering bounds

Browser single-file loading is limited to 1 MB; submitted editor text must fit 1 MB when encoded as UTF-8. Project file, total byte, entry and ZIP budgets remain enforced. Dropped-directory traversal counts all entries, including directories, stops beyond 2,000 entries or depth 32 and has a 10-second callback/enumeration budget. Large fragments above 50,000 characters are displayed without regular-expression syntax highlighting.

The protocol caps serialised request text at 24,000,000 characters and response text at 16,000,000 characters. Limits on JSON characters are distinct from source-file byte limits. Main-thread input preparation, structured cloning, JSON serialisation/parsing and report rendering remain bounded work on the page, not worker operations. This implementation does not claim zero UI pauses for every legal input or device.

## Verification contract

`tools/check_worker_protocol.js` uses explicit Worker test doubles to check deterministic races, timeout disposal, single-flight admission, bootstrap integrity failure and malformed results. It is not evidence of a real Python interpreter. `tests/test_worker_contract.py` invokes those scenarios and checks the source boundary and export identifiers.

The required Chromium functional gate separately loads authenticated Pyodide, performs real file/project analyses and downloads their reports. Its legal stress input is 20,000 repeated Python function definitions below 1 MB, not an artificial infinite loop or an unverified engine. It checks UI heartbeat during acknowledged execution, cancellation, blocked stale exports, a clean retry, an actual short execution deadline and a second retry in both interfaces. Tampered worker bytes and a changed second loader response must fail before interpreter bootstrap. Existing core/engine tamper and exact-consumption checks remain required.

A passing test proves the tested scenario on its recorded environment. It does not establish asymptotic parser safety, branch/mutation coverage, WCAG certification or scientific validity of the score.

## Design sources

The worker execution model and termination behaviour follow the WHATWG HTML living standard, Workers section: https://html.spec.whatwg.org/multipage/workers.html. The pinned runtime's worker integration is documented at https://pyodide.org/en/0.25.0/usage/webworker.html. These are implementation references, not evidence that this repository passed its gates; gate logs must refer to the resulting exact tree.

## Intake ownership and report invalidation

Worker-message ownership alone does not protect asynchronous file intake. File,
ZIP and directory reads now carry a generation through successful and failed
completion; only the current owner changes page state or loading controls.
Cancellation, wipe, replacement and teardown invalidate pending reads and
manual-engine caching. Selection and setting changes invalidate reports before
reading or analysing replacements. Export identity belongs to the accepted
report, not a later input selection. See `docs/22-contract-reconciliation.md`
for the event-order and real-browser regression contracts.
