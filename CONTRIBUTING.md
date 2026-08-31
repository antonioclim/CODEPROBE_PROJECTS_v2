# Contributing

Thank you for considering a contribution to CodeProbe.

## Scope

CodeProbe is a browser-based heuristic static-analysis tool for teaching use. Contributions should improve correctness, robustness, transparency, pedagogy or documentation without turning the tool into a disciplinary detector.

The architecture should remain transparent:

- `app/index.html` and `app/project.html` provide browser shells;
- `app/codeprobe-ui.js`, `app/project-ui.js` and the CSS files provide the browser application layer;
- `app/pyodide-loader.js` and `app/runtime-config.json` control CDN/local Pyodide loading;
- `src/codeprobe_runtime.py` provides the Python analysis engine executed through Pyodide;
- course-facing documents explain responsible academic use.

## Principles

1. Prefer evidence over persuasive language.
2. Treat the score as a concern signal, not as a probability.
3. Keep quality/context metrics separate from authorship-style concern unless there is a documented reason not to.
4. Avoid non-standard Python dependencies in the engine.
5. Keep analysed code local to the student's machine.

## Before opening a pull request

1. Read `README.md`, `CHANGELOG.md` and `docs/11-design-decisions.md`.
2. Keep user-facing text in British English.
3. Preserve backward compatibility for existing supported languages where possible.
4. Add or update tests for every release-relevant metric or scoring change.
5. Update the documentation whenever thresholds, terminology, metric roles or supported languages change.

## Python engine expectations

- Use only the Python standard library.
- Keep helper functions small and testable.
- Explain methodological compromises in comments only where the compromise affects interpretation.
- Add references for new metrics where appropriate.
- Do not add a metric to the AI-style aggregate merely because it identifies clean or high-quality code.

## Browser interface expectations

- Keep the dark theme and responsive layout coherent.
- Avoid dependencies beyond Pyodide unless the change is documented and justified.
- Do not reintroduce inline JavaScript, inline CSS or inline style attributes in the browser HTML.
- If browser assets or `codeprobe_runtime.py` change, refresh `app/resource-integrity.json` and local SRI attributes.
- Do not send analysed source code to remote services.
- Do not reintroduce Base64-packed execution patterns.
- Keep local report history optional and clearly labelled.

## Recommended validation before submission

```bash
python3 -m py_compile src/codeprobe_runtime.py tools/run_local_server.py
python3 -m unittest discover -s tests
```

Then launch the browser interface:

```bash
python3 tools/run_local_server.py --no-browser
```

Check at least one representative file for every language family affected by the change.

## Pull request checklist

- [ ] User-visible terminology remains cautious and non-punitive.
- [ ] New or changed metrics declare their group and contribution status.
- [ ] Quality/context-only metrics do not inflate the AI-style concern score.
- [ ] Markdown remains documentation-only unless a future calibrated method is explicitly added.
- [ ] Tests pass with the standard-library test runner.
- [ ] `CHANGELOG.md` is updated.

## Security and privacy notes

Avoid any change that uploads analysed code, reports or filenames to an external service. The current default network dependency is the Pyodide runtime configured in `app/runtime-config.json`; institutional deployments may switch this to a local vendor copy with a real SHA-256 digest.

## Release validation

Before proposing or distributing a release candidate, run:

```bash
python3 -I -S -B tools/check_release.py
```

This read-only gate validates Python syntax, the unit-test suite, external
browser-script syntax where Node.js is available, browser CSP/SRI hygiene,
resource-integrity metadata, version consistency, smoke reports and committed
release evidence. It also verifies the declared standard-library dependency
boundary and immutable GitHub Action pins. CI invokes the gate with
`--require-node`, so JavaScript syntax cannot be reported as skipped there. If a
deliberate change requires refreshed evidence, run
`python3 -I -S -B tools/check_release.py --write-release-evidence` only after the other
checks pass. A change that modifies metric semantics, report shape or project
filtering should add or update a regression test.

Before proposing a release-boundary change, also run:

```bash
python3 -I -S -B tools/check_release_reproducibility.py
```

This standalone integration gate requires a clean Git commit. It compares
normalised checkouts and an exact Git export, then requires their complete
release packets to be byte-identical under the active Python/zlib toolchain.
The GitHub Actions matrix and repository-control requirements are documented in
`docs/16-ci-and-repository-controls.md`.


## Institutional release checks

Before proposing a packaged release, run:

```bash
python3 tools/audit_institutional_pack.py
python3 -I -S -B tools/check_release.py
```

Do not remove or weaken the student, instructor, review and deployment guidance unless the course policy is updated at the same time.
