# Project repository notice

Place the kit in a dedicated `codeprobe/` directory and link to its README. Students should analyse only the assessed source they authored, not the kit itself, starter code, dependencies, generated files, minified assets or build output. Documentation is outside the code aggregate. The included/excluded inventories must be checked before interpreting a project score.

## Local launch

From the project root containing `codeprobe/`, run the following single-line command. `python` must resolve to the intended supported Python 3 interpreter; where it is named `python3`, replace only that word. Keep isolation and site suppression enabled. The `-u` option makes printed startup URLs immediately visible when output is redirected; `--no-browser` leaves opening the page to you.

<!-- workflow-command:server -->
```console
python -I -S -B -u codeprobe/tools/run_local_server.py --no-browser
```

Open the **actual URL printed after `Open:`**, or the one after `Project:` for the compact project interface. The default server binds an available port on `127.0.0.1`; do not assume a fixed port or open `/app/index.html` without its printed host and port. Press Ctrl+C in the terminal when finished. See [the kit quick start](../README.md#quick-start) for the standalone-kit directory and explicit-port alternatives.

## Interpretation

The aim is coherent, purposeful and explainable code, not the lowest possible number. An applicable score at or above the active trigger prompts inspection and explanation. Revise only for an identified issue and make disclosures under the course policy, independently of the score. This is a review signal, not proof of misconduct. Under the bundled provisional policy, 50% is elevated without reaching the trigger; exactly 60% reaches it. A compatible local profile can replace both the bands and trigger. Non-applicable is not a certificate of independent authorship.

The shipped calibration templates and example profiles are illustrations, not an approved corpus or usable course policy. Generate and review a scope-compatible file or project profile using [the calibration workflow](../calibration/README.md). `operational: true` is technical replay eligibility, not institutional approval. Keep private corpus and observation records outside the student repository.

Final academic reading should use the actual code, normal commit history, tests, design notes and the student's explanation. From v2.1.9 onward, exported engine/configuration metadata help identify the analysis configuration; they are not additional authorship evidence.
