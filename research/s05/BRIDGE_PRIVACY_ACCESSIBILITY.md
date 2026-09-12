# S05 native-to-standalone report bridge

Author: Antonio Clim. Contract version: 1.0.0. This document defines the implementation boundary; it is not an empirical evaluation or a conformance certificate.

## Routes and schema precedence

The new route is `codeprobe_report_cli generate` -> `codeprobe-review-bundle/v1` JSON -> standalone `report.html` -> `codeprobe-feedback-journal/v1` response export. `render` replays a transported bundle against independently supplied source bytes, language, explicit profile ID/digest and privacy options before producing HTML. `verify` and `check-feedback` expose the same native replay boundary. No network service is started. No source fixture is executed.

The bundle retains the entire unchanged S04 capsule, an independent S05 presentation file-set identity, an explicit privacy disposition and an optional normalised-source snapshot. Its digest covers all fields other than the digest itself. It is NOT a S01 `codeprobe-review-report/v3` instance. Existing consumers must dispatch on the new exact schema identifier and reject unknown identifiers. S01 action/response vocabulary is reused only where stated; a journal is not renamed a S01 response. Feedback has its own schema and cannot be stored in measurement fields.

The native renderer replays the capsule and the complete bundle. HTML is a presentation snapshot, not a source authenticator and not a general capsule importer. Modifying an HTML file can change what a reader sees; rechecking its JSON bundle and original source in the same admitted build/runtime is the verification route. Browser test projections exclude runtime identity only for comparisons and are never validation interfaces.

All seven dimensions, the five withheld mappings, observation applicability, decision sensitivity, absences and non-inferences remain explicit. No-rule-trigger means only that the selected illustrative predicate did not trigger; it is never a quality certification. A stable review opportunity is optional and does not establish a defect. There is no global score, count-based risk badge or compensatory aggregation.

## Evidence and source display

Each rendered item retains its exact record reference, rule and evidence IDs. An opportunity instance is bound to bundle digest, record reference and rule ID. Evidence navigation uses one-based inclusive physical-line spans after UTF-8 BOM/newline normalisation. C0-C0 are inherited line-span sentinels: no character/token precision is claimed. Whole-artefact evidence on empty input represents empty input, not a fabricated physical line. Source text is absent by default. Optional source display provides line anchors and displays potentially misleading controls as escaped Unicode code points; the JSON snapshot, where explicitly included, preserves the actual normalised text.

The HTML uses ordinal callable labels instead of raw function names. Complete JSON capsules still contain source-derived identifiers, hashes and coordinates. These can reveal information or enable linkage. Path minimisation is not anonymisation. An explicit path-disclosure option supplies actual path metadata before measurement; no post-hoc rewrite invalidates capsule identity.

## Privacy and persistence

The native application uses installed Python and local files; Git identity inspection is local. The standalone reader embeds its CSS and JavaScript and uses a hash-based Content Security Policy. It does not request a CDN, Pyodide, network API, telemetry, service worker or application storage. Development and CI dependency/browser acquisition are separate network events, not runtime source processing. The old hosted/Pyodide application remains unchanged and must not inherit these claims.

Generation creates an explicitly requested output directory outside the repository and refuses an existing destination. Outputs are report.json and report.html, with restrictive POSIX modes where available; Windows permission inheritance is not a POSIX confidentiality guarantee. A process or filesystem crash can leave an incomplete directory. Treat only a successful terminal result as completion and inspect remaining files after an error. Arbitrary hostile filesystem races and whole-process containment are not proven.

Feedback controls hold responses only in active page state. Export creates a user-requested JSON file; its blob URL is revoked. Clear resets active controls and response state. Page lifecycle events also clear active controls where delivered. Downloads, the original report/source files, browser restoration, caches, swap, backups, extensions and screenshots are outside secure-erasure claims. The HTML visibly discloses this limitation. Users should not enter secrets in rationales.

## Accessibility boundary

Use semantic headings, fieldset/legend groups, explicit labels, readable state text, visible focus, keyboard evidence navigation, live status/error messages and responsive wrapping. Test actual Chromium at 320 and desktop CSS pixels, keyboard transitions, focus targets, text labels and contrast of the chosen colours. Automated checks are scoped evidence, not a WCAG 2.2 conformance certificate, manual screen-reader assessment or participant study. Other browsers and assistive technologies remain untested unless a named run supplies evidence.

Technical basis: W3C WCAG 2.2, Recommendation 12 December 2024, https://www.w3.org/TR/WCAG22/; MDN Content-Security-Policy, https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy. Consulted 12 September 2026. These normative/technical documents have no DOI and are not empirical evidence of CodeProbe validity.

## Explicit residual work

Legacy Pyodide acquisition, SRI loader retries, the legacy Chromium harness, public-product distribution, release gates and integration into main are not executed or repaired by this alternative standalone route. Keep their inherited findings open. A01-F003 remains open. M01 must describe the actual finite software and the interpretation/use argument; no study or calibration is initiated here.
