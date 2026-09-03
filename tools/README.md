# Command-line and release tools

This folder contains project analysis, calibration, validation and release utilities. Common entry points are `tools/run_local_server.py`, `tools/analyze_project.py`, `tools/check_release.py` and `tools/build_release.py`.


`tools/check_naming.py` validates the naming policy, ordered documentation paths and uncontrolled retired-path references. It is run by `tools/check_release.py`.

`tools/check_dependency_boundary.py` checks the standard-library-only Python contract, direct process-launch prohibition, Pyodide configuration and immutable GitHub Action pins. Native commands are permitted only through `codeprobe_engine.process_control`. The Pyodide check authenticates the measured core startup set but does not claim an ecosystem-wide vulnerability audit.

`tools/check_release_reproducibility.py` is the standalone CI integration gate
for exact Git-tree, LF/forced-CRLF checkout, `git archive` and three-file packet
parity. It uses `--skip-tests` only inside isolated candidate trees; CI runs the
full canonical gate immediately before starting this integration check.

`tools/build_release.py` packages only the immutable snapshot authorised by the
strict release manifest. It stages and verifies the required ZIP, checksum and
package audit before publication, then attempts to restore the prior packet
after a detected publication failure. This is not an atomic or crash-recovery
guarantee for three paths.


## Supported-code coverage

```bash
python -I -S -B tools/check_coverage.py \
  --json-out /path/outside/the/checkout/codeprobe-supported-coverage.json
```

The policy is pinned to Python 3.14.7, runs the complete suite and enforces weighted overall, root and high-risk file floors. The JSON output is diagnostic and must remain outside the checkout.

## Local application server

`tools/run_local_server.py` serves only the browser application's declared resources. It does not provide repository directory indexes. Loopback is the default; `--allow-network` is an explicit exposure override, not an authentication mechanism.

## Browser accessibility gate

```bash
node tools/check_browser_accessibility.js
```

This command starts the shipped local server and a Chromium-family browser, then verifies accessible names, live regions, progressbar state, focus visibility and keyboard-operated result tabs through the Chrome DevTools Protocol. It has no npm dependency and fails when no supported browser is available.
