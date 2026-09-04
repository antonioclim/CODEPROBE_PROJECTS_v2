(function () {
  "use strict";

  const DEFAULT_DEADLINE_MS = 8000;
  const MINIMUM_DEADLINE_MS = 100;
  const MAXIMUM_DEADLINE_MS = 60000;
  const INTERRUPT_SIGNAL = 2;
  const attached = new WeakMap();

  class AnalysisDeadlineError extends Error {
    constructor(message, options = {}) {
      super(message);
      this.name = "AnalysisDeadlineError";
      this.deadline_ms = options.deadline_ms || null;
      this.elapsed_ms = options.elapsed_ms || null;
      this.cause = options.cause;
    }
  }

  function positiveDeadline(value) {
    const rendered = Number(value);
    if (!Number.isSafeInteger(rendered) || rendered < MINIMUM_DEADLINE_MS || rendered > MAXIMUM_DEADLINE_MS) {
      throw new Error(
        `Analysis deadline must be an integer between ${MINIMUM_DEADLINE_MS} and ${MAXIMUM_DEADLINE_MS} milliseconds.`
      );
    }
    return rendered;
  }

  function createTimerWorker() {
    const source = `
      "use strict";
      let timer = null;
      let activeId = 0;
      function clearActive() {
        if (timer !== null) clearTimeout(timer);
        timer = null;
        activeId = 0;
      }
      self.onmessage = event => {
        const data = event.data || {};
        if (data.command === "start") {
          clearActive();
          activeId = data.id;
          const view = new Int32Array(data.buffer);
          timer = setTimeout(() => {
            if (activeId !== data.id) return;
            Atomics.store(view, 0, ${INTERRUPT_SIGNAL});
            Atomics.notify(view, 0);
            self.postMessage({ command: "expired", id: data.id });
          }, data.deadline_ms);
        } else if (data.command === "stop" && data.id === activeId) {
          clearActive();
        } else if (data.command === "close") {
          clearActive();
          self.close();
        }
      };
    `;
    const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    try {
      return new Worker(url, { name: "codeprobe-analysis-watchdog" });
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  function interruptUnavailableReason() {
    if (!window.crossOriginIsolated) return "the page is not cross-origin isolated";
    if (typeof SharedArrayBuffer !== "function") return "SharedArrayBuffer is unavailable";
    if (typeof Worker !== "function") return "Web Workers are unavailable";
    return "the Pyodide runtime does not expose setInterruptBuffer";
  }

  function attach(runtime, options = {}) {
    if (!runtime || typeof runtime.runPython !== "function") {
      throw new Error("A live Pyodide runtime is required for analysis deadline control.");
    }
    if (attached.has(runtime)) return attached.get(runtime).publicApi;

    const deadlineMs = positiveDeadline(options.deadline_ms || DEFAULT_DEADLINE_MS);
    const required = options.require_interrupt_buffer !== false;
    const supported = Boolean(
      window.crossOriginIsolated &&
      typeof SharedArrayBuffer === "function" &&
      typeof Worker === "function" &&
      typeof runtime.setInterruptBuffer === "function"
    );
    if (!supported && required) {
      throw new Error(`Analysis deadline containment is unavailable because ${interruptUnavailableReason()}.`);
    }

    if (!supported) {
      const unsupportedApi = Object.freeze({
        supported: false,
        deadline_ms: deadlineMs,
        cancelCurrent() { return false; },
        close() {},
        getState() { return Object.freeze({ active: false, expired: false, supported: false }); }
      });
      attached.set(runtime, { publicApi: unsupportedApi });
      return unsupportedApi;
    }

    const interruptView = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
    runtime.setInterruptBuffer(interruptView);
    const worker = createTimerWorker();
    const originalRunPython = runtime.runPython.bind(runtime);
    const originalRunPythonAsync = typeof runtime.runPythonAsync === "function"
      ? runtime.runPythonAsync.bind(runtime)
      : null;
    let nextId = 1;
    let current = null;

    worker.addEventListener("message", event => {
      const data = event.data || {};
      if (current && data.command === "expired" && data.id === current.id) {
        current.expired = true;
      }
    });

    function begin() {
      if (current) throw new Error("Nested CodeProbe analyses are not permitted.");
      const operation = {
        id: nextId++,
        started: performance.now(),
        expired: false,
      };
      current = operation;
      Atomics.store(interruptView, 0, 0);
      worker.postMessage({
        command: "start",
        id: operation.id,
        deadline_ms: deadlineMs,
        buffer: interruptView.buffer,
      });
      return operation;
    }

    function finish(operation) {
      worker.postMessage({ command: "stop", id: operation.id });
      Atomics.store(interruptView, 0, 0);
      const elapsed = performance.now() - operation.started;
      if (current === operation) current = null;
      return elapsed;
    }

    function translate(error, operation, elapsed) {
      const rendered = String(error && (error.stack || error.message) ? (error.stack || error.message) : error);
      if (operation.expired || /KeyboardInterrupt|interrupted|SIGINT/i.test(rendered)) {
        return new AnalysisDeadlineError(
          `Analysis exceeded the ${deadlineMs} ms execution deadline and was interrupted.`,
          { deadline_ms: deadlineMs, elapsed_ms: Math.round(elapsed), cause: error }
        );
      }
      return error;
    }

    runtime.runPython = function codeProbeBoundedRunPython(...args) {
      const operation = begin();
      try {
        return originalRunPython(...args);
      } catch (error) {
        const elapsed = finish(operation);
        throw translate(error, operation, elapsed);
      } finally {
        if (current === operation) finish(operation);
      }
    };

    if (originalRunPythonAsync) {
      runtime.runPythonAsync = async function codeProbeBoundedRunPythonAsync(...args) {
        const operation = begin();
        try {
          return await originalRunPythonAsync(...args);
        } catch (error) {
          const elapsed = finish(operation);
          throw translate(error, operation, elapsed);
        } finally {
          if (current === operation) finish(operation);
        }
      };
    }

    const publicApi = Object.freeze({
      supported: true,
      deadline_ms: deadlineMs,
      cancelCurrent() {
        if (!current) return false;
        Atomics.store(interruptView, 0, INTERRUPT_SIGNAL);
        Atomics.notify(interruptView, 0);
        return true;
      },
      close() {
        if (current) this.cancelCurrent();
        worker.postMessage({ command: "close" });
        worker.terminate();
      },
      getState() {
        return Object.freeze({
          active: Boolean(current),
          expired: Boolean(current && current.expired),
          supported: true,
          deadline_ms: deadlineMs,
        });
      }
    });
    attached.set(runtime, { publicApi, worker, interruptView });
    return publicApi;
  }

  window.CodeProbeAnalysisWatchdog = Object.freeze({
    AnalysisDeadlineError,
    attach,
    defaults: Object.freeze({
      deadline_ms: DEFAULT_DEADLINE_MS,
      minimum_deadline_ms: MINIMUM_DEADLINE_MS,
      maximum_deadline_ms: MAXIMUM_DEADLINE_MS,
    }),
  });
})();
