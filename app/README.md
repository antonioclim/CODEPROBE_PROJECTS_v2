# Browser application

This folder contains the static browser interface. Use `app/index.html` for ordinary single-file and project analysis, and `app/project.html` for the compact project-only interface. The browser loads `../src/codeprobe_runtime.py` through Pyodide and reads configuration from `app/runtime-config.json`.

`analysis-worker.js` implements the fixed analysis protocol. It is authenticated and loaded by `pyodide-loader.js`; both interfaces use its terminable session. Python must not execute on the page.
