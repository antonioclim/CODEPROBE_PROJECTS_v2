#!/usr/bin/env node
"use strict";

// Deterministic event-order regressions. These use shipped application code
// with DOM, File and interpreter doubles, not a real browser or Pyodide.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ROOT = path.resolve(__dirname, "..");
let scenarios = 0;

function section(source, first, next) {
  const start = source.indexOf(first);
  const end = source.indexOf(next, start + first.length);
  assert(start >= 0 && end > start, `Missing maintained application boundary: ${first}`);
  return source.slice(start, end);
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function file(name, content = "print('fixture')\n") {
  const bytes = new TextEncoder().encode(content);
  return { name, size: bytes.length, arrayBuffer: async () => bytes.buffer };
}
function delayedFile(name) {
  const read = deferred();
  return { read, file: { name, size: 17, arrayBuffer: () => read.promise } };
}
function elements() {
  const nodes = new Map(), blobs = new Map(), downloads = [];
  function element(id) {
    if (nodes.has(id)) return nodes.get(id);
    const node = {
      value: /profile/i.test(id) ? "default" : "", disabled: false, textContent: "", style: {}, handlers: {},
      classList: { add() {}, remove() {}, toggle() {} },
      setAttribute() {}, removeAttribute() {}, replaceChildren() {}, remove() {},
      addEventListener(event, handler) { this.handlers[event] = handler; },
      click() {
        if (id === "anchor") downloads.push({ name: this.download, blob: blobs.get(this.href) });
        else return this.handlers.click?.({ target: this });
      }
    };
    nodes.set(id, node);
    return node;
  }
  const dom = {
    nodes, downloads, element,
    els: new Proxy({}, { get: (_target, key) => element(key) }),
    document: { getElementById: element, addEventListener() {}, body: { appendChild() {} }, createElement: () => element("anchor") },
    URL: { createObjectURL(blob) { const id = `blob:${blobs.size}`; blobs.set(id, blob); return id; }, revokeObjectURL() {} }
  };
  element("calibrationProfile").value = "";
  element("languageSelect").value = "python";
  return dom;
}
function runtime() {
  return {
    normaliseProjectPath(value) { if (String(value).includes("..")) throw new Error("unsafe path"); return value; },
    decodeSourceBytes(bytes) { return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes), warning: "" }; },
    collectDroppedFiles: async data => data.files,
  };
}
function compact() {
  const dom = elements(), calls = [], api = runtime(), events = {};
  const session = {
    ready: false, pending: null,
    isReady() { return this.ready; },
    cancel() { this.ready = false; },
    async initialise() { this.ready = true; return { fingerprint: { source: "test-double" } }; },
    async analyse(kind, payload) {
      calls.push(payload);
      if (this.pending) await this.pending.promise;
      return { project_report: { project_name: payload.project_name, overall_percent: 20, included_file_count: 1 }, text: `Report for ${payload.project_name}` };
    }
  };
  api.createAnalysisSession = () => session;
  const context = vm.createContext({ console, TextEncoder, Uint8Array, ArrayBuffer, Blob, btoa,
    document: dom.document, URL: dom.URL, window: { CodeProbeRuntime: api, addEventListener: (name, callback) => { events[name] = callback; } } });
  vm.runInContext(fs.readFileSync(path.join(ROOT, "app/project-ui.js"), "utf8"), context);
  return { ...dom, context, calls, api, session, events, state: vm.runInContext("state", context) };
}
function main() {
  const source = fs.readFileSync(path.join(ROOT, "app/codeprobe-ui.js"), "utf8");
  const dom = elements(), api = runtime();
  const appState = { busy: false, generation: 0, loadingInput: false, currentReport: null, currentProjectReport: null,
    workerSession: null, engineFailed: false, engineBundle: null, localEngineFile: null, fileWarnings: [] };
  const context = vm.createContext({ console, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, Blob, btoa, DOMException,
    appState, els: dom.els, window: { CodeProbeRuntime: api, crypto: crypto.webcrypto },
    MAX_BROWSER_PROJECT_TEXT_BYTES: 1000000, MAX_BROWSER_PROJECT_ZIP_BYTES: 8000000,
    MAX_BROWSER_PROJECT_TOTAL_BYTES: 20000000, MAX_BROWSER_PROJECT_ENTRIES: 2000, MAX_BROWSER_DROP_FILES: 2000,
    localStorage: { removeItem() {} }, HISTORY_KEY: "history", HISTORY_ENABLED_KEY: "enabled",
    updateEditorMeta() {}, scheduleHighlight() {}, syncEditorScroll() {}, markReportStale() {}, renderHistory() {},
    renderList() {}, setProgressBar() {}, setEngineBadge() {}, showEngineLoader() {},
    setStatus(text) { dom.els.status.textContent = text; },
    setBusy(value) { appState.busy = value; dom.els.analyzeBtn.disabled = value || appState.loadingInput; dom.els.cancelBtn.disabled = !(value || appState.loadingInput); },
    defaultFileNameForLanguage: () => "fragment.py"
  });
  const code = [
    section(source, "    async function sha256Bytes(bytes)", "    async function getEngineFingerprint()"),
    section(source, "    function looksBinary(bytes)", "    function assertPlainObject("),
    section(source, "    function arrayBufferToBase64(", "    function getConfigOverrideObject()"),
    section(source, "    function cancelAnalysis()", "    async function initEngine()"),
    section(source, "    function clearReport()", "    function handleHistoryClick("),
    section(source, "    function isZipLikeFile(", "    els.openBtn.addEventListener"),
    section(source, "    els.languageSelect.addEventListener(\"change\"", "    els.editor.addEventListener(\"scroll\"")
  ].join("\n");
  vm.runInContext(code, context);
  return { ...dom, context, api, state: appState };
}
async function check(name, operation) {
  await operation();
  scenarios += 1;
  console.log(`[PASS] input-contract: ${name}`);
}
const bytes = text => new TextEncoder().encode(text).buffer;

async function run() {
  for (const event of ["wipe", "cancel", "replacement", "editor", "configuration"]) {
    await check(`main delayed file cannot survive ${event}`, async () => {
      const f = main(), late = delayedFile("private.py");
      const pending = f.context.handleFile(late.file);
      if (event === "wipe") f.context.clearPrivacyData();
      if (event === "cancel") f.context.cancelAnalysis();
      if (event === "replacement") await f.context.handleFile(file("latest.py", "latest"));
      if (event === "editor") { f.els.editor.value = "typed"; f.els.editor.handlers.input(); }
      if (event === "configuration") f.els.configOverride.handlers.input();
      late.read.resolve(bytes("PRIVATE_SYNTHETIC_SOURCE"));
      await pending;
      assert.equal(f.els.editor.value, event === "replacement" ? "latest" : event === "editor" ? "typed" : "");
      assert.equal(f.state.currentReport, null);
      assert.equal(f.els.exportJsonBtn.disabled, true);
    });
  }
  await check("main superseded read cannot publish an error or finish another read", async () => {
    const f = main(), a = delayedFile("a.py"), b = delayedFile("b.py");
    const first = f.context.handleFile(a.file), second = f.context.handleFile(b.file);
    const status = f.els.status.textContent;
    a.read.reject(new Error("obsolete read error")); await first;
    assert.equal(f.els.status.textContent, status);
    assert.equal(f.els.analyzeBtn.disabled, true);
    b.read.resolve(bytes("latest")); await second;
    assert.equal(f.els.editor.value, "latest");
    assert.equal(f.els.analyzeBtn.disabled, false);
  });
  for (const kind of ["zip", "folder"]) {
    await check(`main ${kind} read cannot restore a wiped payload`, async () => {
      const f = main(), late = delayedFile(kind === "zip" ? "private.zip" : "private.py");
      const pending = kind === "zip" ? f.context.handleProjectZip(late.file) : f.context.handleProjectFiles([late.file]);
      f.context.clearPrivacyData(); late.read.resolve(bytes("private")); await pending;
      assert.equal(f.state.projectPayload, null);
      assert.equal(f.els.editor.value, "");
    });
  }
  await check("main pending manual engine cannot restore a wiped engine cache", async () => {
    const f = main(), late = delayedFile("engine.py");
    f.state.localEngineFile = late.file;
    const pending = f.context.getEngineBundle();
    const rejected = assert.rejects(pending, { name: "AbortError" });
    f.context.clearPrivacyData(); late.read.resolve(bytes("print('private engine')")); await rejected;
    assert.equal(f.state.engineBundle, null);
    assert.equal(f.state.engineFingerprint, null);
    assert.equal(f.state.localEngineFile, null);
  });
  await check("main cancelled directory enumeration cannot dispatch late files", async () => {
    const f = main(), late = deferred();
    f.api.collectDroppedFiles = () => late.promise;
    const pending = f.context.handleDropDataTransfer({});
    f.context.clearPrivacyData(); late.resolve([file("old.py", "old")]); await pending;
    assert.equal(f.els.editor.value, ""); assert.equal(f.state.projectPayload, null);
  });
  for (const kind of ["zip", "folder"]) {
    for (const action of ["replace", "cancel", "pagehide"]) {
      await check(`compact ${kind} ${action} invalidates a pending read`, async () => {
        const f = compact(), late = delayedFile(kind === "zip" ? "old.zip" : "old.py");
        const pending = kind === "zip" ? f.context.loadZip(late.file) : f.context.loadFolder([late.file]);
        if (action === "replace") await f.context.loadZip(file("latest.zip"));
        else if (action === "pagehide") f.events.pagehide();
        else f.context.cancelAnalysis();
        late.read.resolve(bytes("old")); await pending;
        assert.equal(f.state.payload?.project_name || null, action === "replace" ? "latest" : null);
      });
    }
  }
  await check("compact older error/finally cannot finish a newer read", async () => {
    const f = compact(), a = delayedFile("a.zip"), b = delayedFile("b.zip");
    const first = f.context.loadZip(a.file), second = f.context.loadZip(b.file);
    const status = f.els.status.textContent;
    a.read.reject(new Error("obsolete failure")); await first;
    assert.equal(f.els.status.textContent, status); assert.equal(f.els.analyseBtn.disabled, true);
    b.read.resolve(bytes("latest")); await second;
    assert.equal(f.state.payload.project_name, "b"); assert.equal(f.els.analyseBtn.disabled, false);
  });
  await check("compact new input invalidates the prior report before reading", async () => {
    const f = compact();
    await f.context.loadZip(file("alpha.zip")); await f.context.analyse();
    f.els.exportJsonBtn.click();
    assert.equal(f.downloads[0].name, "alpha.json");
    const late = delayedFile("beta.zip"), pending = f.context.loadZip(late.file);
    f.els.exportJsonBtn.click(); assert.equal(f.downloads.length, 1);
    late.read.resolve(bytes("beta")); await pending;
    f.els.exportJsonBtn.click(); assert.equal(f.downloads.length, 1);
    await f.context.analyse(); f.els.exportJsonBtn.click();
    const saved = f.downloads[1];
    assert.equal(saved.name, "beta.json"); assert.equal(JSON.parse(await saved.blob.text()).project_name, "beta");
  });
  for (const control of ["profileSelect", "calibrationProfile"]) {
    await check(`compact ${control} invalidates existing and pending reports`, async () => {
      const f = compact();
      await f.context.loadZip(file("alpha.zip")); await f.context.analyse();
      f.els[control].handlers.input();
      assert.equal(f.state.json, ""); assert.equal(f.els.exportJsonBtn.disabled, true);
      f.session.pending = deferred();
      const running = f.context.analyse();
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(f.state.busy, true);
      f.els[control].handlers.change(); f.session.pending.resolve(); await running;
      assert.equal(f.state.json, ""); assert.equal(f.els.exportJsonBtn.disabled, true);
    });
  }
  await check("compact superseded directory enumeration cannot dispatch old files", async () => {
    const f = compact(), late = deferred();
    f.api.collectDroppedFiles = () => late.promise;
    const pending = f.context.handleDroppedProject({});
    await f.context.loadZip(file("latest.zip"));
    late.resolve([file("old.py")]); await pending;
    assert.equal(f.state.payload.project_name, "latest");
  });
  for (const factory of [main, compact]) {
    await check(`${factory.name} retains oversized/unreadable/unsafe metadata without reading rejected bytes`, async () => {
      const f = factory(); let read = 0;
      const items = [file("main.py"), { name: "oversized.py", size: 1000001, arrayBuffer: async () => { read += 1; throw new Error("must not read"); } },
        { name: "unreadable.py", size: 2, arrayBuffer: async () => { throw new Error("unreadable"); } }, file("../unsafe.py")];
      if (factory === main) await f.context.handleProjectFiles(items); else await f.context.loadFolder(items);
      const payload = f.state.projectPayload || f.state.payload;
      assert.equal(payload.files.length, 4); assert.equal(read, 0);
      assert.equal(payload.files[1].intake_rejection.reason, "file_too_large");
      assert.equal(payload.files[2].intake_rejection.reason, "unreadable_file");
      assert.equal(payload.files[3].intake_rejection.reason, "unsafe_path");
      assert.equal(payload.files[1].content, undefined);
    });
  }
  for (const fault of ["healthy", "getter", "first-removal", "second-removal", "verification"]) {
    await check(`privacy wipe clears session and rejects late input under ${fault}`, async () => {
      const f = main(), late = delayedFile("private.py");
      const pending = f.context.handleFile(late.file);
      let calls = 0, cancellations = 0;
      f.state.workerSession = {cancel() { cancellations += 1; }};
      f.els.editor.value = "PRIVATE_SOURCE";
      f.els.configOverride.value = "private config";
      f.els.calibrationProfile.value = "private profile";
      f.els.historyEnabled.checked = true;
      Object.defineProperty(f.context, "localStorage", {configurable: true, get() {
        if (fault === "getter") throw new Error("synthetic storage refusal");
        return {removeItem() {
          calls += 1;
          if ((fault === "first-removal" && calls === 1) || (fault === "second-removal" && calls === 2)) throw new Error("synthetic removal refusal");
        }, getItem() { return fault === "verification" ? "retained" : null; }};
      }});
      const generation = f.state.generation;
      f.context.clearPrivacyData();
      late.read.resolve(bytes("LATE_PRIVATE_SOURCE")); await pending;
      assert(f.state.generation > generation);
      assert.equal(cancellations, 1);
      assert.equal(f.els.editor.value, "");
      assert.equal(f.els.configOverride.value, "");
      assert.equal(f.els.calibrationProfile.value, "");
      assert.equal(f.els.historyEnabled.checked, false);
      assert.equal(f.state.projectPayload, null);
      assert.equal(f.els.exportJsonBtn.disabled, true);
      assert.match(f.els.status.textContent, fault === "healthy" ? /local storage\.$/ : /could not be verified/);
      if (fault !== "getter") assert.equal(calls, 2);
    });
  }
  console.log(`[PASS] input-contracts: ${scenarios} hermetic event-order and export scenarios`);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
