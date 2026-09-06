"use strict";

// This entry is concatenated with SRI-authenticated loader bytes by the page.
// Only two fixed analysis entry points are exposed; source is data, not a script.
(() => {
  let runtime = null;
  let fingerprint = null;
  let busy = false;
  const MAX_PAYLOAD = 24000000;
  const MAX_RESULT = 16000000;

  async function initialise(manual) {
    if (runtime) throw new Error("The worker has already been initialised.");
    runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
    let bundle;
    if (manual !== null) {
      if (!manual || !(manual.bytes instanceof Uint8Array) || manual.bytes.length > 1000000) {
        throw new Error("Invalid explicitly unverified engine override.");
      }
      const bytes = manual.bytes;
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      const value = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
      fingerprint = { algorithm: "sha256", value, available: true, scope: "src/codeprobe_runtime.py", source: "manual-unverified" };
      bundle = { copyBytes: () => bytes };
    } else {
      bundle = await self.CodeProbeRuntime.loadVerifiedEngine();
      fingerprint = bundle.fingerprint;
    }
    runtime.FS.writeFile("codeprobe_runtime.py", bundle.copyBytes());
    runtime.runPython("import codeprobe_runtime");
    return { fingerprint, bootstrap: self.CodeProbeRuntime.getBootstrapConsumption(), isolated: true };
  }

  function analyse(message) {
    if (!runtime || !["file", "project"].includes(message.kind)) throw new Error("Worker is not ready for this operation.");
    if (typeof message.payloadJson !== "string" || message.payloadJson.length > MAX_PAYLOAD) throw new Error("Invalid payload.");
    const payload = JSON.parse(message.payloadJson);
    payload.engine_fingerprint = fingerprint;
    runtime.globals.set("payload_json", JSON.stringify(payload));
    try {
      const command = message.kind === "project"
        ? "codeprobe_runtime.codeprobe_analyze_project(payload_json)"
        : "codeprobe_runtime.codeprobe_analyze(payload_json)";
      const text = runtime.runPython(command);
      if (typeof text !== "string" || text.length > MAX_RESULT) throw new Error("Invalid or oversized analysis result.");
      return text;
    } finally {
      runtime.globals.delete("payload_json");
    }
  }

  self.onmessage = async event => {
    const message = event.data;
    if (!message || !Number.isSafeInteger(message.id) || message.id <= 0) return;
    if (busy) { self.postMessage({ id: message.id, error: true }); return; }
    busy = true;
    try {
      let result;
      if (message.type === "init") result = JSON.stringify(await initialise(message.manual));
      else if (message.type === "analyse") {
        self.postMessage({ id: message.id, started: true });
        result = analyse(message);
      }
      else throw new Error("Unsupported worker operation.");
      self.postMessage({ id: message.id, result });
    } catch (_) {
      // Exceptions can contain source fragments or local identifiers.
      self.postMessage({ id: message.id, error: true });
    } finally {
      busy = false;
    }
  };
})();
