# S05: native reporting, offline review and separate feedback

Author and maintainer: Antonio Clim.

The exact S04 base is `03163d557969d49c53a43ed5805733b13c4a1950`. The full prospective acceptance contract is committed at `cbc7ea89d89fbdac6569c2dbd2b058c9e85cc42d`, before S05 evaluation. All inherited source files remain unchanged. This route is a research candidate, not the public v2.2.0 product, a completed legacy Pyodide migration or a S01 complete-report instance.

## An executable alternative browser pathway

Installed Python performs bounded native measurement and interpretation. The CLI produces `report.json` and a standalone `report.html`. Open the latter in a browser: no server, CDN, browser Python runtime, extension or installation is required by the generated reader. The reader cannot measure a new project by itself. It presents the admitted report and exports a separate feedback journal. It neither uploads data nor imports arbitrary capsules as verified reports.

To list the three admitted profile identifiers and canonical digests, run:

```text
python -I -B tools/codeprobe_s05.py profiles
```

For a new report, replace the two paths and the digest copied from that output:

```text
python -I -B tools/codeprobe_s05.py generate --source SOURCE.py --language python --profile structural-review --profile-sha PROFILE_SHA256 --output-dir NEW_DIRECTORY_OUTSIDE_REPOSITORY
```

The output directory must not exist; its parent must exist. No existing report is overwritten. Paths containing symlinks are rejected. By default a neutral source label is supplied before measurement and literal source is omitted. `--include-source` includes normalised source explicitly; `--disclose-path` includes the actual path. Neither the default JSON nor its source-derived identifiers/hashes is anonymous. Keep the complete report and feedback private where appropriate. No scientific or disciplinary conclusion follows from a successful command.

`verify` takes the same source, language, profile and privacy options plus `--bundle report.json`. `render` additionally takes a new output directory. `check-feedback` takes `--bundle report.json` and `--feedback codeprobe-feedback.json`. All replay against independently supplied source/context in the same admitted build/runtime. A new runtime, modified source or build may invalidate exact replay; do not bypass that refusal by rewriting metadata. The HTML itself remains an unauthenticated presentation snapshot.

## Interpretation and navigation

All seven candidate dimensions are visible, including five explicit withheld mappings. Policy-dependent abstention is not an error or a favourable verdict. No rule trigger is not evidence of quality. Evidence links navigate owned, one-based inclusive normalised line spans. C0-C0 fields are sentinels, not precise token coordinates. Source excerpts exist only when explicitly included; empty input does not create a fictitious source line. Full S04 measurement and interpretation remain in JSON without relabelling the bundle as a S01 report.

Optional responses are bound to exact report and opportunity identities. No response changes the measurement or the interpretation. Export writes a user-requested JSON file. Clear removes active response values and revokes generated object URLs; downloaded files, original reports, operating-system or browser traces and backups remain outside secure-erasure guarantees. Rationales are not a place for secrets.

## Reproduction and limitations

From a clean exact candidate checkout, `python -I -S -B tools/check_s05_reporting.py --output OUTSIDE_DIRECTORY` runs inherited S01/S02 checks, the 19 S03 corrective tests, the 46 S04 tests, the 36 S05 tests and 54 finite reports from 18 sources and three profiles. It does not rerun complete historical S03/S04 experiments merely for reassurance. Full generated inputs, bundles, HTML, independent view projections, discrepancies and logs are retained.

The test-only browser requirements pin the version used in local development. The CI browser command installs that Playwright release's matching Chromium, records actual versions and runs `tools/check_s05_browser.py` on the exact candidate. Default transport is `file`: it tests actual local-file loading and reload. The local development browser policy blocked both file and loopback navigation. Local `--transport dom` therefore injects the same report bytes into an allowed blank page and tests DOM interactions only; it does not establish actual file navigation or reload. No administrator policy was disabled. Final acceptance requires separate actual-file CI evidence. The optional loopback transport is an in-process bounded test fixture, not a product server.

Automated Chromium checks include labels, keyboard focus, evidence navigation, source escaping, response admission/export/retry/clear, no-JavaScript readability, 320-pixel reflow, selected text contrast and CSP negative controls. They are not a WCAG certificate, a manual screen-reader assessment or general browser coverage. The pinned browser differs from the local system Chromium; evidence names the actual browser in each run.

`development-register.v1.json` preserves failures and corrective/supplementary changes. Final closure requires SHA-specific CI and the separately verified phase audit. Empirical calibration, educational utility, fairness, construct validity, authorship inference and universal containment remain unestablished. The 111-entry historical ledger is not reduced by this alternative route.
