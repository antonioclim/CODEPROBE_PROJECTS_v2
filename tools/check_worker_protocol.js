#!/usr/bin/env node
"use strict";

// Hermetic protocol tests. The real Python/worker behaviour is tested separately
// by check_browser_functional.js; these doubles make race ordering repeatable.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ROOT = path.resolve(__dirname, "..");
const loader = fs.readFileSync(path.join(ROOT, "app", "pyodide-loader.js"), "utf8");
const entry = fs.readFileSync(path.join(ROOT, "app", "analysis-worker.js"));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function fixture() {
  const instances = [];
  let respond = (worker, message) => worker.reply({ id: message.id, result: JSON.stringify(message.type === "init" ? { fingerprint: { source: "packaged-verified" } } : { report: { value: 7 } }) });
  let tamper = false;
  let networkFailure = false;
  const signals = [];
  class Worker {
    constructor(url) { this.url = url; this.terminated = false; this.messages = []; instances.push(this); }
    postMessage(message) { this.messages.push(message); queueMicrotask(() => respond(this, message)); }
    reply(message) { if (this.onmessage) this.onmessage({ data: message }); }
    terminate() { this.terminated = true; }
  }
  const context = vm.createContext({
    console, TextDecoder, TextEncoder, Uint8Array, ArrayBuffer, Blob, URL,
    Response, Request, AbortController, setTimeout, clearTimeout, Worker,
    crypto: crypto.webcrypto,
    location: { origin: "http://localhost", href: "http://localhost/app/index.html" },
    document: {
      baseURI: "http://localhost/app/index.html",
      querySelector: () => ({ src: "http://localhost/app/pyodide-loader.js", integrity: "sha256-" + crypto.createHash("sha256").update(loader).digest("base64") }),
    },
    async fetch(url, options) {
      signals.push(options.signal);
      if (networkFailure) throw new Error("network unavailable");
      const bytes = url.endsWith("analysis-worker.js") ? (tamper ? Buffer.from("tampered") : entry) : Buffer.from(loader);
      return new Response(bytes);
    },
  });
  vm.runInContext(loader, context, { filename: "pyodide-loader.js" });
  return {
    api: context.CodeProbeRuntime, instances, signals,
    session: context.CodeProbeRuntime.createAnalysisSession(),
    setResponder(value) { respond = value; },
    tamper() { tamper = true; },
    failNetwork() { networkFailure = true; },
  };
}

async function run() {
  let count = 0;
  async function test(name, operation) {
    await operation(); count += 1; console.log(`[PASS] worker-protocol: ${name}`);
  }
  await test("cancellation during a manual-engine read prevents later worker startup", async () => {
    const ui = fs.readFileSync(path.join(ROOT, "app", "codeprobe-ui.js"), "utf8");
    const begin = ui.indexOf("    async function initEngine() {");
    const end = ui.indexOf("    async function analyzeNow() {", begin);
    assert.ok(begin >= 0 && end > begin);
    let releaseRead;
    const reading = new Promise(resolve => { releaseRead = resolve; });
    let initialisations = 0;
    const state = { generation: 0, localEngineFile: {}, workerSession: null, enginePromise: null };
    const context = vm.createContext({
      appState: state, els: { contextText: {} },
      setBusy() {}, setEngineBadge() {}, showEngineLoader() {},
      getEngineBundle: () => reading,
      window: { CodeProbeRuntime: { createAnalysisSession: () => ({
        isReady: () => false,
        initialise: async () => { initialisations += 1; return { fingerprint: { source: "manual-unverified" } }; },
      }) } },
    });
    vm.runInContext(ui.slice(begin, end) + "\nglobalThis.start = initEngine;", context);
    const pending = context.start();
    state.generation += 1;
    releaseRead({ copyBytes: () => new Uint8Array([1]) });
    await pending;
    assert.equal(initialisations, 0, "cancelled file reading must not start an interpreter afterwards");
  });
  await test("main-thread Python is refused", async () => {
    const f = fixture(); await assert.rejects(f.api.loadVerifiedPyodide(), /dedicated analysis worker/);
  });
  await test("authenticated worker bootstrap and warm reuse", async () => {
    const f = fixture(); await f.session.initialise();
    assert.equal(f.session.isReady(), true);
    const result = await f.session.analyse("file", { code: "x = 1" });
    assert.equal(result.report.value, 7);
    await f.session.initialise(); assert.equal(f.instances.length, 1); f.session.cancel();
  });
  await test("invalid operation and deadline are rejected", async () => {
    const f = fixture(); await f.session.initialise();
    await assert.rejects(f.session.analyse("script", {}), /Unsupported/);
    for (const value of [0, -1, NaN, Infinity, 30001]) await assert.rejects(f.session.analyse("file", {}, value), /deadline/);
    f.session.cancel();
  });
  await test("oversized legal-shaped payload is rejected before dispatch", async () => {
    const f = fixture(); await f.session.initialise();
    await assert.rejects(f.session.analyse("file", { code: "x".repeat(24000001) }), /budget/);
    assert.equal(f.instances[0].messages.length, 1); f.session.cancel();
  });
  await test("duplicate operations cannot queue or replace the active request", async () => {
    const f = fixture(); await f.session.initialise(); f.setResponder(() => {});
    const first = f.session.analyse("file", {}); const rejection = assert.rejects(first, { name: "AbortError" });
    await assert.rejects(f.session.analyse("project", {}), { name: "BusyError" });
    f.session.cancel(); await rejection;
    assert.equal(f.session.isBusy(), false); assert.equal(f.instances[0].terminated, true);
  });
  await test("execution acknowledgement is distinct from result acceptance", async () => {
    const f = fixture(); await f.session.initialise();
    f.setResponder((w, m) => { w.reply({ id: m.id, started: true }); });
    const first = f.session.analyse("file", {}); const rejection = assert.rejects(first, { name: "AbortError" });
    await pause(0); assert.equal(f.session.isExecuting(), true);
    f.session.cancel(); await rejection; assert.equal(f.session.isExecuting(), false);
  });
  await test("timeout terminates the worker rather than abandoning a promise", async () => {
    const f = fixture(); await f.session.initialise(); f.setResponder(() => {});
    await assert.rejects(f.session.analyse("file", {}, 10), { name: "TimeoutError" });
    assert.equal(f.instances[0].terminated, true); assert.equal(f.session.isReady(), false);
  });
  await test("startup deadline also aborts bootstrap and terminates", async () => {
    const f = fixture(); f.setResponder(() => {});
    await assert.rejects(f.session.initialise(null, 10), { name: "TimeoutError" });
    assert.ok(f.signals.some(signal => signal && signal.aborted));
    assert.ok(f.instances.every(worker => worker.terminated));
  });
  await test("stale worker replies cannot replace a new generation", async () => {
    const f = fixture(); await f.session.initialise(); f.setResponder(() => {});
    const old = f.instances[0];
    const first = f.session.analyse("file", {}); const rejection = assert.rejects(first, { name: "AbortError" });
    f.session.cancel(); await rejection;
    f.setResponder((w, m) => { old.reply({ id: m.id, result: '{"poison":true}' }); w.reply({ id: m.id, result: '{"fresh":true}' }); });
    const metadata = await f.session.initialise(); assert.equal(metadata.fresh, true); assert.equal(metadata.poison, undefined);
    assert.equal(f.instances.length, 2); f.session.cancel();
  });
  await test("wrong request identifiers are ignored", async () => {
    const f = fixture(); await f.session.initialise();
    f.setResponder((w, m) => { w.reply({ id: m.id - 1, result: '{"poison":true}' }); w.reply({ id: m.id, result: '{"fresh":true}' }); });
    const value = await f.session.analyse("file", {}); assert.equal(value.fresh, true); assert.equal(value.poison, undefined); f.session.cancel();
  });
  await test("malformed result stops the worker and admits no report", async () => {
    const f = fixture(); await f.session.initialise(); f.setResponder((w, m) => w.reply({ id: m.id, result: "not json" }));
    await assert.rejects(f.session.analyse("file", {}), { name: "WorkerError" }); assert.equal(f.instances[0].terminated, true);
  });
  await test("oversized result stops the worker", async () => {
    const f = fixture(); await f.session.initialise(); f.setResponder((w, m) => w.reply({ id: m.id, result: " ".repeat(16000001) }));
    await assert.rejects(f.session.analyse("file", {}), { name: "WorkerError" }); assert.equal(f.instances[0].terminated, true);
  });
  await test("worker errors reject the active request", async () => {
    const f = fixture(); await f.session.initialise(); f.setResponder(w => w.onerror());
    await assert.rejects(f.session.analyse("file", {}), { name: "WorkerError" }); assert.equal(f.session.isBusy(), false);
  });
  await test("tampered worker source cannot be constructed", async () => {
    const f = fixture(); f.tamper(); await assert.rejects(f.session.initialise(), /mismatch/); assert.equal(f.instances.length, 0);
  });
  await test("failed bootstrap leaves no worker or pending operation", async () => {
    const f = fixture(); f.failNetwork(); await assert.rejects(f.session.initialise(), /network/);
    assert.equal(f.instances.length, 0); assert.equal(f.session.isBusy(), false);
  });
  await test("drop enumeration rejects oversized root selections", async () => {
    const f = fixture();
    await assert.rejects(f.api.collectDroppedFiles({files:{length:2001}}), /Too many/);
  });
  await test("drop enumeration counts directories and bounds large batches", async () => {
    const f = fixture();
    const root = {isDirectory:true, name:"root", createReader:() => ({readEntries:resolve => resolve(new Array(2000).fill({isDirectory:true}))})};
    await assert.rejects(f.api.collectDroppedFiles({items:[{kind:"file", webkitGetAsEntry:() => root}]}), /budget/);
  });
  await test("deep directory-only input is bounded", async () => {
    const f = fixture();
    const directory = depth => ({isDirectory:true, name:"nested", createReader() { let done=false; return {readEntries(resolve) { if(done) resolve([]); else {done=true; resolve(depth ? [directory(depth-1)] : []);} }}; }});
    await assert.rejects(f.api.collectDroppedFiles({items:[{kind:"file", webkitGetAsEntry:() => directory(40)}]}), /depth budget/);
  });
  await test("dropped file identity is canonical and preserved", async () => {
    const f = fixture(); const file={name:"cafe\u0301.py"};
    const result=await f.api.collectDroppedFiles({items:[{kind:"file", webkitGetAsEntry:() => ({isFile:true, file:resolve => resolve(file)})}]});
    assert.equal(result.length,1); assert.equal(result[0]._codeprobeRelativePath,"café.py");
  });
  await test("unreadable dropped entries fail instead of disappearing", async () => {
    const f=fixture();
    await assert.rejects(f.api.collectDroppedFiles({items:[{kind:"file", webkitGetAsEntry:() => ({isFile:true, file:(_resolve,reject) => reject(new Error("unreadable entry"))})}]}), /unreadable/);
  });
  console.log(`[PASS] worker-protocol: ${count} hermetic scenarios; Worker is a protocol double, not a Pyodide execution fixture`);
}

if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { run };
