# 17 — Supported-code coverage

## Purpose

CodeProbe measures executable-line coverage for maintained Python code under `src/` and `tools/`. This is a non-regression control. It is not branch, condition or mutation coverage and it does not establish exhaustive testing or defect absence. Browser JavaScript is exercised separately by the required Chromium job.

## Measurement model

`tools/check_coverage.py` validates `tools/coverage-policy.json`, discovers every in-scope Python file and runs the complete `unittest` suite under the pinned Python 3.14.7 runtime. CPython's `sys.monitoring` API records line events only for the declared production files. After a bytecode line location is observed once, its event is disabled because repeated execution adds cost but no coverage information.

This design replaced an earlier `sys.settrace` prototype. A deliberately deep syntax test caused the conventional tracer to disable itself, silently underreporting every later test. The monitoring-based collector is independent of `sys.settrace`, applies to threads in the same interpreter and has a regression that clears `sys.settrace` before a following covered test.

Coverage is weighted by executable lines. A small file cannot compensate numerically for a poorly exercised large module merely by reporting a high percentage.

## Enforced floors

The initial floors are set several percentage points below the measured passing candidate. The margin accommodates harmless Python line-table differences while still detecting material loss.

| Scope | Floor |
|---|---:|
| Overall maintained Python | 72% |
| `src/` | 69% |
| `tools/` | 75% |
| `src/codeprobe_engine/process_control.py` | 58% |
| `src/codeprobe_engine/server.py` | 87% |
| `src/codeprobe_engine/release.py` | 81% |
| `src/codeprobe_engine/project_io.py` | 65% |
| `src/codeprobe_runtime.py` | 68% |
| `tools/build_release.py` | 75% |
| `tools/check_dependency_boundary.py` | 85% |
| `tools/check_pyodide_provenance.py` | 68% |
| `tools/check_release.py` | 79% |
| `tools/check_release_reproducibility.py` | 50% |
| `tools/final_audit.py` | 90% |

The Python 3.14.7 hosted-runner measurement used to ratify these floors reported 74.29% overall, 71.52% for `src/` and 76.99% for `tools/`. `tools/build_release.py` measured 77.72%; its 75% ratchet therefore retains a 2.72 percentage-point margin rather than relying on the higher result observed under a different interpreter.

The policy also requires at least 369 discovered tests. A lower test count fails before coverage is accepted. The coverage module defers access to `sys.monitoring` until measurement begins, so the ordinary release gate remains importable on the supported Python 3.10–3.13 validation interpreters while the dedicated coverage job stays pinned to Python 3.14.7.

## Deliberate limitations

- Python child processes are not merged into the in-process measurement. Their observable behaviour is checked by process-containment, release and reproducibility integration tests.
- Browser JavaScript is not included in the Python denominator.
- Operating-system-specific paths that cannot execute on the Linux coverage runner remain subject to the required Windows and macOS validation jobs.
- The coverage driver is the sole excluded production file because it performs policy validation and configures the monitor before measurement begins.
- A percentage cannot demonstrate test quality. Material fixes still require behavioural regressions.

## Policy changes

Lowering a floor, reducing the minimum test count or adding an exclusion is a policy change. It must identify the lost coverage and provide replacement evidence where practicable. Moving code into an excluded path or adding trivial assertions solely to raise a percentage is not acceptable.

## Command

```bash
python -I -S -B tools/check_coverage.py \
  --json-out /path/outside/the/repository/codeprobe-supported-coverage.json
```

The diagnostic JSON must be written outside the checkout. Raw monitoring data and coverage directories are not release artefacts.
