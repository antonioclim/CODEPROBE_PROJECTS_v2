# `codeprobe_engine` support package

CodeProbe still ships `src/codeprobe_runtime.py` as a single-file browser runtime because Pyodide can load it transparently and students can audit it without a build step. This package is the maintainer-facing extraction seam for local tooling: API wrappers, metric inventories, path helpers, project-input helpers and release-manifest logic live here so that future engine modules can be introduced without changing the browser contract.

Current rule: browser-facing analysis remains in `codeprobe_runtime.py`; release and CLI support may use this package.
