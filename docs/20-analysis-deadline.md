# Browser analysis deadline

CodeProbe installs a worker-backed interrupt deadline through `app/analysis-watchdog.js`. A Web Worker sets Pyodide's shared interrupt buffer independently of the browser main thread. This allows an overlong Python call, including a non-terminating loop, to be interrupted even while the UI thread is occupied.

Production configuration requires cross-origin isolation, `SharedArrayBuffer`, Web Workers and Pyodide's interrupt-buffer API. The canonical local server emits the required isolation headers. When the deadline boundary cannot be installed, production startup fails closed rather than silently running unbounded analysis.

The deadline is a containment mechanism, not a guarantee of continuously smooth rendering. The current architecture still performs accepted analysis on the main thread. Interactive cancellation can be serviced only when the event loop regains control, while the independent deadline remains enforceable throughout the call.
