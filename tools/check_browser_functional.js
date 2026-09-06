#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const TIMEOUT_MS = 120_000;
const CORE_NAMES = Object.freeze([
  "pyodide.js",
  "pyodide-lock.json",
  "python_stdlib.zip",
  "pyodide.asm.js",
  "pyodide.asm.wasm",
]);
const PUBLIC_EXACT = new Set([
  "/app/index.html",
  "/app/project.html",
  "/app/codeprobe.css",
  "/app/project.css",
  "/app/pyodide-loader.js",
  "/app/analysis-worker.js",
  "/app/codeprobe-ui.js",
  "/app/project-ui.js",
  "/app/runtime-config.json",
  "/app/resource-integrity.json",
  "/app/pyodide-provenance.json",
  "/src/codeprobe_runtime.py",
]);
const MIME_TYPES = Object.freeze({
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".py": "text/x-python; charset=utf-8",
  ".wasm": "application/wasm",
  ".zip": "application/zip",
});
const processes = new Set();

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(error => error ? reject(error) : resolve(port));
    });
  });
}

function executableOnPath(name) {
  if (name.includes(path.sep) || (path.sep === "\\" && name.includes("/"))) {
    try {
      fs.accessSync(name, fs.constants.X_OK);
      return name;
    } catch (_) {
      return null;
    }
  }
  for (const directory of String(process.env.PATH || "").split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.join(directory, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch (_) {
      continue;
    }
  }
  return null;
}

function findBrowser() {
  const configured = process.env.CODEPROBE_BROWSER;
  if (configured) {
    const resolved = executableOnPath(configured);
    assert(resolved, `CODEPROBE_BROWSER is not executable: ${configured}`);
    return resolved;
  }
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"]) {
    const resolved = executableOnPath(name);
    if (resolved) return resolved;
  }
  throw new Error("No supported Chromium-family browser was found on PATH.");
}

function stopProcess(child) {
  if (!child || child.exitCode !== null || child.killed) return;
  try { child.kill("SIGTERM"); } catch (_) { /* best effort */ }
}

function cleanup() {
  for (const child of processes) stopProcess(child);
}

process.once("exit", cleanup);
process.once("SIGINT", () => { cleanup(); process.exit(130); });
process.once("SIGTERM", () => { cleanup(); process.exit(143); });

async function waitForJson(url, timeout = TIMEOUT_MS) {
  const deadline = Date.now() + timeout;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { cache: "no-store" });
      if (response.ok) return await response.json();
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw new Error(`Endpoint did not become ready: ${lastError || "timeout"}`);
}

async function messageText(data) {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  if (data && typeof data.text === "function") return await data.text();
  return String(data);
}

class CdpConnection {
  constructor(url) {
    this.url = url;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    assert(typeof WebSocket === "function", "Node.js global WebSocket support is required.");
    this.socket = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("CDP connection timed out")), TIMEOUT_MS);
      this.socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
      this.socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("CDP connection failed")); }, { once: true });
    });
    this.socket.addEventListener("message", async event => {
      let payload;
      try { payload = JSON.parse(await messageText(event.data)); }
      catch (_) { return; }
      if (!payload.id || !this.pending.has(payload.id)) return;
      const pending = this.pending.get(payload.id);
      this.pending.delete(payload.id);
      clearTimeout(pending.timer);
      if (payload.error) pending.reject(new Error(`${pending.method}: ${payload.error.message}`));
      else pending.resolve(payload.result || {});
    });
  }

  send(method, params = {}, sessionId = undefined) {
    assert(this.socket && this.socket.readyState === WebSocket.OPEN, "CDP WebSocket is not open.");
    const id = this.nextId++;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer, method });
      this.socket.send(JSON.stringify(message));
    });
  }

  close() {
    if (this.socket && this.socket.readyState <= WebSocket.OPEN) this.socket.close();
  }
}

async function evaluate(cdp, sessionId, expression) {
  const outcome = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  }, sessionId);
  if (outcome.exceptionDetails) {
    const exception = outcome.exceptionDetails.exception || {};
    const detail = exception.description || exception.value || outcome.exceptionDetails.text || "unknown error";
    throw new Error(`Browser evaluation failed: ${detail}`);
  }
  return outcome.result ? outcome.result.value : undefined;
}

async function waitForExpression(cdp, sessionId, expression, timeout = TIMEOUT_MS) {
  const deadline = Date.now() + timeout;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      if (await evaluate(cdp, sessionId, expression)) return;
      lastError = null;
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  const detail = lastError ? `; last error: ${lastError.message || lastError}` : "";
  throw new Error(`Browser condition timed out: ${expression}${detail}`);
}

async function waitForFile(filePath, timeout = TIMEOUT_MS) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath) && !fs.existsSync(`${filePath}.crdownload`)) return;
    await delay(100);
  }
  throw new Error(`Download did not complete: ${filePath}`);
}

function copyFixtureTree(destination, pyodideDirectory) {
  fs.cpSync(ROOT, destination, {
    recursive: true,
    filter(source) {
      const relative = path.relative(ROOT, source);
      if (!relative) return true;
      const first = relative.split(path.sep)[0];
      return !new Set([".git", "dist", "__pycache__"]).has(first) && !relative.endsWith(".pyc");
    },
  });
  const vendor = path.join(destination, "app", "vendor", "pyodide", "v0.25.0", "full");
  fs.mkdirSync(vendor, { recursive: true });
  for (const name of CORE_NAMES) {
    const source = path.join(pyodideDirectory, name);
    assert(fs.statSync(source).isFile(), `Pyodide fixture is missing ${name}`);
    fs.copyFileSync(source, path.join(vendor, name));
  }
  const configPath = path.join(destination, "app", "runtime-config.json");
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  config.pyodide.mode = "local";
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function safePathname(rawUrl) {
  const parsed = new URL(rawUrl, "http://127.0.0.1");
  let pathname;
  try { pathname = decodeURIComponent(parsed.pathname); }
  catch (_) { return null; }
  if (pathname === "/") pathname = "/app/index.html";
  if (!pathname.startsWith("/") || pathname.includes("\\") || pathname.includes("\0")) return null;
  const parts = pathname.slice(1).split("/");
  if (parts.some(part => !part || part === "." || part === "..")) return null;
  return pathname;
}

function createFixtureServer(root) {
  const state = {
    counts: new Map(),
    tamperEngine: false,
    tamperCore: "",
    tamperWorker: false,
    tamperLoaderSecond: false,
    reset({ tamperEngine = false, tamperCore = "", tamperWorker = false, tamperLoaderSecond = false } = {}) {
      this.counts.clear();
      this.tamperEngine = tamperEngine;
      this.tamperCore = tamperCore;
      this.tamperWorker = tamperWorker;
      this.tamperLoaderSecond = tamperLoaderSecond;
    },
    count(pathname) { return this.counts.get(pathname) || 0; },
  };
  const server = http.createServer((request, response) => {
    const pathname = safePathname(request.url || "/");
    if (!pathname || request.method !== "GET") {
      response.writeHead(pathname ? 405 : 400, { "Content-Type": "text/plain; charset=utf-8" });
      response.end(pathname ? "Method not allowed.\n" : "Invalid request.\n");
      return;
    }
    const vendorPrefix = "/app/vendor/pyodide/v0.25.0/full/";
    if (!PUBLIC_EXACT.has(pathname) && !pathname.startsWith(vendorPrefix)) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Resource not found.\n");
      return;
    }
    const relative = pathname.slice(1);
    const filePath = path.resolve(root, ...relative.split("/"));
    if (!filePath.startsWith(`${path.resolve(root)}${path.sep}`)) {
      response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Invalid request.\n");
      return;
    }
    let content;
    try { content = fs.readFileSync(filePath); }
    catch (_) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Resource not found.\n");
      return;
    }
    const count = state.count(pathname) + 1;
    state.counts.set(pathname, count);
    const basename = path.basename(pathname);
    if (CORE_NAMES.includes(basename) && (count > 1 || (state.tamperCore === basename && count === 1))) {
      content = Buffer.from(content);
      content[0] ^= 0xff;
    }
    if (pathname === "/src/codeprobe_runtime.py" && (state.tamperEngine || count > 1)) {
      content = Buffer.concat([content, Buffer.from("\n# integrity tamper\n", "utf8")]);
    }
    if ((pathname === "/app/analysis-worker.js" && state.tamperWorker) ||
        (pathname === "/app/pyodide-loader.js" && state.tamperLoaderSecond && count > 1)) {
      content = Buffer.concat([content, Buffer.from("\nself.workerTamperExecuted = true;\n", "utf8")]);
    }
    const type = MIME_TYPES[path.extname(pathname).toLowerCase()] || "application/octet-stream";
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Length": String(content.length),
      "Content-Security-Policy": "default-src 'self'; script-src 'self' blob: 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self' blob:; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      "Content-Type": type,
      "X-Content-Type-Options": "nosniff",
    });
    response.end(content);
  });
  return { server, state };
}

async function createSession(cdp, url) {
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  await cdp.send("Page.enable", {}, sessionId);
  await cdp.send("Runtime.enable", {}, sessionId);
  await cdp.send("Network.enable", {}, sessionId);
  const result = await cdp.send("Page.navigate", { url }, sessionId);
  if (result.errorText) throw new Error(`Browser navigation failed: ${result.errorText}`);
  await waitForExpression(cdp, sessionId, "document.readyState === 'complete'");
  return { targetId, sessionId };
}

async function closeSession(cdp, session) {
  try { await cdp.send("Target.closeTarget", { targetId: session.targetId }); }
  catch (_) { /* best effort */ }
}

function assertSingleVerifiedRequests(state) {
  for (const name of CORE_NAMES) {
    const pathname = `/app/vendor/pyodide/v0.25.0/full/${name}`;
    assert(state.count(pathname) === 1, `${name} reached the origin ${state.count(pathname)} time(s); verified bytes were not bound to consumption`);
  }
  assert(state.count("/src/codeprobe_runtime.py") === 1, "the packaged Python engine was fetched more than once");
}

async function testMainAnalysis(cdp, baseUrl, downloads, state, engineDigest) {
  state.reset();
  const session = await createSession(cdp, `${baseUrl}/app/index.html`);
  try {
    await waitForExpression(cdp, session.sessionId, "document.getElementById('statusText').textContent === 'The analysis engine is ready.'");
    assertSingleVerifiedRequests(state);
    const sharedContracts = await evaluate(cdp, session.sessionId, `(() => {
      const decoded = window.CodeProbeRuntime.decodeSourceBytes(new Uint8Array([99, 97, 102, 233]));
      return {
        text: decoded.text,
        encoding: decoded.encoding,
        warning: decoded.warning,
        path: window.CodeProbeRuntime.normaliseProjectPath('demo/cafe\u0301.py'),
        engineCopyLength: window.CodeProbeRuntime.getPackagedEngineRecord().size_bytes,
      };
    })()`);
    assert(sharedContracts.text === "café", "shared browser decoding did not preserve Latin-1 bytes");
    assert(sharedContracts.encoding === "latin-1" && sharedContracts.warning, "Latin-1 fallback was not reported");
    assert(sharedContracts.path === "demo/café.py", "shared browser path identity is not NFC-normalised");
    assert(sharedContracts.engineCopyLength > 250000, "packaged engine record is unexpectedly small");
    await evaluate(cdp, session.sessionId, `(() => {
      const editor = document.getElementById('editor');
      editor.value = 'def add(left: int, right: int) -> int:\\n    return left + right\\n\\nprint(add(2, 3))\\n';
      editor.dispatchEvent(new Event('input', { bubbles: true }));
      document.getElementById('analyzeBtn').click();
    })()`);
    await waitForExpression(cdp, session.sessionId, "document.getElementById('statusText').textContent === 'Analysis completed.'");
    const result = await evaluate(cdp, session.sessionId, `(() => {
      const report = JSON.parse(document.getElementById('jsonReport').value);
      return {
        reportKind: report.report_kind,
        language: report.language,
        schema: report.schema_version,
        fingerprint: report.engine_fingerprint && report.engine_fingerprint.value,
        textLength: document.getElementById('textReport').value.length,
        jsonLength: document.getElementById('jsonReport').value.length,
        exportJsonDisabled: document.getElementById('exportJsonBtn').disabled,
        exportTextDisabled: document.getElementById('exportTextBtn').disabled,
      };
    })()`);
    assert(result.reportKind === "file", "main browser report_kind is not file");
    assert(result.language === "python", "main browser analysis did not identify Python");
    assert(result.schema === "2.2.0", "main browser report schema is unexpected");
    assert(result.fingerprint === engineDigest, "main browser report does not carry the verified engine digest");
    assert(result.textLength > 100 && result.jsonLength > 100, "main browser report outputs are unexpectedly empty");
    assert(!result.exportJsonDisabled && !result.exportTextDisabled, "main browser exports did not become available");

    fs.rmSync(downloads, { recursive: true, force: true });
    fs.mkdirSync(downloads, { recursive: true });
    await cdp.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads, eventsEnabled: true });
    await evaluate(cdp, session.sessionId, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click();");
    const jsonPath = path.join(downloads, "fragment.json");
    const textPath = path.join(downloads, "fragment.txt");
    await Promise.all([waitForFile(jsonPath), waitForFile(textPath)]);
    const exported = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
    assert(exported.report_kind === "file", "downloaded main JSON is not a file report");
    assert(exported.engine_fingerprint.value === engineDigest, "downloaded main JSON lost the verified engine digest");
    assert(fs.readFileSync(textPath, "utf8").length > 100, "downloaded main text report is empty");
  } finally {
    await closeSession(cdp, session);
  }
}

async function testProjectAnalysis(cdp, baseUrl, downloads, state, engineDigest) {
  state.reset();
  const session = await createSession(cdp, `${baseUrl}/app/project.html`);
  try {
    await waitForExpression(cdp, session.sessionId, "document.getElementById('folderInput') !== null");
    await evaluate(cdp, session.sessionId, `(() => {
      const transfer = new DataTransfer();
      const first = new File(['def square(value):\\n    return value * value\\n'], 'alpha.py', { type: 'text/x-python' });
      const second = new File(['def cube(value):\\n    return value * value * value\\n'], 'beta.py', { type: 'text/x-python' });
      transfer.items.add(first);
      transfer.items.add(second);
      const input = document.getElementById('folderInput');
      input.files = transfer.files;
      Object.defineProperty(input.files[0], '_codeprobeRelativePath', { value: 'demo/alpha.py', configurable: true });
      Object.defineProperty(input.files[1], '_codeprobeRelativePath', { value: 'demo/beta.py', configurable: true });
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    await waitForExpression(cdp, session.sessionId, "document.getElementById('status').textContent.startsWith('Loaded folder: 2 text file(s)')");
    await evaluate(cdp, session.sessionId, "document.getElementById('analyseBtn').click()");
    await waitForExpression(cdp, session.sessionId, "document.getElementById('status').textContent === 'Project analysis completed.'");
    assertSingleVerifiedRequests(state);
    const result = await evaluate(cdp, session.sessionId, `(() => {
      const report = JSON.parse(document.getElementById('jsonReport').value);
      return {
        reportKind: report.report_kind,
        schema: report.schema_version,
        included: report.included_file_count,
        fingerprint: report.engine_fingerprint && report.engine_fingerprint.value,
        textLength: document.getElementById('textReport').value.length,
      };
    })()`);
    assert(result.reportKind === "project", "project browser report_kind is not project");
    assert(result.schema === "2.2.0-project", "project browser report schema is unexpected");
    assert(result.included === 2, `project browser analysed ${result.included} files instead of two`);
    assert(result.fingerprint === engineDigest, "project browser report does not carry the verified engine digest");
    assert(result.textLength > 100, "project browser text report is unexpectedly empty");

    fs.rmSync(downloads, { recursive: true, force: true });
    fs.mkdirSync(downloads, { recursive: true });
    await cdp.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: downloads, eventsEnabled: true });
    await evaluate(cdp, session.sessionId, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click();");
    const jsonPath = path.join(downloads, "demo.json");
    const textPath = path.join(downloads, "demo.txt");
    await Promise.all([waitForFile(jsonPath), waitForFile(textPath)]);
    const exported = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
    assert(exported.report_kind === "project", "downloaded project JSON is not a project report");
    assert(exported.engine_fingerprint.value === engineDigest, "downloaded project JSON lost the verified engine digest");
    assert(fs.readFileSync(textPath, "utf8").length > 100, "downloaded project text report is empty");
  } finally {
    await closeSession(cdp, session);
  }
}


async function testTamperedCoreFailsClosedAndReloadRetries(cdp, baseUrl, state) {
  state.reset({ tamperCore: "pyodide.asm.wasm" });
  const failed = await createSession(cdp, `${baseUrl}/app/index.html?core-tamper=1`);
  try {
    await waitForExpression(cdp, failed.sessionId, "document.getElementById('engineBadge').textContent === 'Initialisation failed'");
    const outcome = await evaluate(cdp, failed.sessionId, `({
      status: document.getElementById('statusText').textContent,
      disabled: document.getElementById('analyzeBtn').disabled,
    })`);
    assert(outcome.status === "The in-browser Python engine could not be loaded.", "tampered core did not reach the explicit failure state");
    assert(outcome.disabled, "tampered core did not fail closed");
    assert(state.count("/app/vendor/pyodide/v0.25.0/full/pyodide.asm.wasm") === 1, "tampered core was fetched repeatedly");
    assert(state.count("/src/codeprobe_runtime.py") === 0, "the Python engine was fetched after core integrity failure");
  } finally {
    await closeSession(cdp, failed);
  }

  state.reset();
  const retried = await createSession(cdp, `${baseUrl}/app/index.html?core-retry=1`);
  try {
    await waitForExpression(cdp, retried.sessionId, "document.getElementById('statusText').textContent === 'The analysis engine is ready.'");
    assertSingleVerifiedRequests(state);
  } finally {
    await closeSession(cdp, retried);
  }
}

async function testTamperedEngineFailsClosed(cdp, baseUrl, state) {
  state.reset({ tamperEngine: true });
  const session = await createSession(cdp, `${baseUrl}/app/index.html?engine-tamper=1`);
  try {
    await waitForExpression(cdp, session.sessionId, "document.getElementById('engineBadge').textContent === 'Initialisation failed'");
    const outcome = await evaluate(cdp, session.sessionId, `({
      status: document.getElementById('statusText').textContent,
      disabled: document.getElementById('analyzeBtn').disabled,
      loaderVisible: !document.getElementById('loadEngineBtn').classList.contains('hidden'),
    })`);
    assert(outcome.status === "The in-browser Python engine could not be loaded.", "tampered engine did not reach the explicit failure state");
    assert(outcome.disabled && outcome.loaderVisible, "tampered engine did not fail closed");
    assert(state.count("/src/codeprobe_runtime.py") === 1, "tampered engine was fetched repeatedly");
  } finally {
    await closeSession(cdp, session);
  }
}


// Large but legal source, below the browser's 1 MB file limit. No synthetic
// worker delay, production test hook or unverified Python engine is used.
const LEGAL_BUSY_SOURCE = "def transform(value):\n    return value + 1\n".repeat(20000);

async function loadProjectFixture(cdp, sessionId, content) {
  await evaluate(cdp, sessionId, `(() => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([${JSON.stringify(content)}], 'busy.py', {type:'text/x-python'}));
    const input = document.getElementById('folderInput');
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', {bubbles:true}));
  })()`);
  await waitForExpression(cdp, sessionId, "document.getElementById('status').textContent.startsWith('Loaded folder: 1 text file(s)')");
}

async function testWorkerResponsiveness(cdp, baseUrl, fixtureState, compact) {
  fixtureState.reset();
  const session = await createSession(cdp, `${baseUrl}/app/${compact ? 'project' : 'index'}.html?resilience=1`);
  const id = session.sessionId;
  const active = compact ? "state.workerSession" : "appState.workerSession";
  const analyseId = compact ? "analyseBtn" : "analyzeBtn";
  const statusId = compact ? "status" : "statusText";
  try {
    if (compact) {
      await loadProjectFixture(cdp, id, LEGAL_BUSY_SOURCE);
    } else {
      await waitForExpression(cdp, id, "appState.workerSession?.isReady()");
      await evaluate(cdp, id, `document.getElementById('editor').value = ${JSON.stringify(LEGAL_BUSY_SOURCE)}; document.getElementById('editor').dispatchEvent(new Event('input', {bubbles:true}));`);
    }
    await evaluate(cdp, id, `(() => {
      window.resilienceTicks = 0;
      window.resilienceTimer = setInterval(() => { if (${active}?.isExecuting()) window.resilienceTicks += 1; }, 25);
      document.getElementById('${analyseId}').click();
    })()`);
    await waitForExpression(cdp, id, `${active}?.isExecuting()`, 60000);
    await waitForExpression(cdp, id, "window.resilienceTicks >= 3", 5000);
    const start = Date.now();
    const cancelled = await evaluate(cdp, id, `(() => {
      document.getElementById('cancelBtn').click();
      clearInterval(window.resilienceTimer);
      return {busy:${active}.isBusy(), ready:${active}.isReady(), status:document.getElementById('${statusId}').textContent,
        disabled:document.getElementById('exportJsonBtn').disabled, hasPagePython:typeof window.pyodide !== 'undefined' || typeof window.loadPyodide !== 'undefined'};
    })()`);
    assert(Date.now() - start < 5000, "page cancellation was not responsive under a legal Python workload");
    assert(!cancelled.busy && !cancelled.ready && cancelled.disabled && !cancelled.hasPagePython, "cancellation retained a live worker, report export or page Python interpreter");
    assert(cancelled.status.includes("cancelled"), "cancel action did not produce an explicit status");
    await delay(150);
    assert(await evaluate(cdp, id, "document.getElementById('exportJsonBtn').disabled"), "late cancelled result enabled report export");

    // A fresh worker is an intentional clean bootstrap, not a second response
    // inside one bootstrap. Reset the adversarial fixture's request generation.
    fixtureState.reset();
    if (compact) await loadProjectFixture(cdp, id, "def square(value):\n    return value * value\n");
    else await evaluate(cdp, id, "document.getElementById('editor').value = 'def square(value):\\n    return value * value\\n';");
    await evaluate(cdp, id, `document.getElementById('${analyseId}').click()`);
    await waitForExpression(cdp, id, `document.getElementById('${statusId}').textContent === '${compact ? 'Project analysis completed.' : 'Analysis completed.'}'`);
    assertSingleVerifiedRequests(fixtureState);

    // Exercise an actual short deadline while the verified interpreter is warm.
    const timed = await evaluate(cdp, id, `(() => {
      let ticks = 0;
      const timer = setInterval(() => { ticks += 1; }, 10);
      const start = performance.now();
      return ${active}.analyse('file', {code:${JSON.stringify(LEGAL_BUSY_SOURCE)}, filename:'deadline.py', language_hint:'python'}, 100)
        .then(() => ({accepted:true}), error => ({accepted:false, name:error.name, elapsed:performance.now()-start, ticks, ready:${active}.isReady()}))
        .finally(() => clearInterval(timer));
    })()`);
    assert(!timed.accepted && timed.name === "TimeoutError" && !timed.ready, "verified legal workload did not terminate at the requested deadline");
    assert(timed.ticks > 0 && timed.elapsed < 5000, "deadline delivery blocked the page");
    fixtureState.reset();
    const retry = await evaluate(cdp, id, `(() => ${active}.initialise().then(() => ${active}.analyse('file', {code:'def add(a, b):\\n    return a + b\\n', filename:'retry.py', language_hint:'python'})))()`);
    assert(retry.report && retry.report.engine_fingerprint.source === "packaged-verified", "deadline retry did not use a fresh authenticated interpreter");
    assertSingleVerifiedRequests(fixtureState);
    console.log(`[PASS] browser-resilience: ${compact ? 'project' : 'main'} UI heartbeat, execution cancellation, clean retry, deadline and second retry`);
  } finally { await closeSession(cdp, session); }
}

async function testTamperedWorkerBootstrap(cdp, baseUrl, fixtureState) {
  for (const options of [{tamperWorker:true}, {tamperLoaderSecond:true}]) {
    fixtureState.reset(options);
    const session = await createSession(cdp, `${baseUrl}/app/index.html?worker-tamper=1`);
    try {
      await waitForExpression(cdp, session.sessionId, "document.getElementById('engineBadge').textContent === 'Initialisation failed'");
      assert(await evaluate(cdp, session.sessionId, "document.getElementById('analyzeBtn').disabled && document.getElementById('exportJsonBtn').disabled"), "tampered bootstrap was not fail-closed");
      for (const name of CORE_NAMES) assert(fixtureState.count(`/app/vendor/pyodide/v0.25.0/full/${name}`) === 0, "tampered worker began fetching the Python runtime");
    } finally { await closeSession(cdp, session); }
  }
  console.log("[PASS] browser-resilience: tampered worker entry and changed second loader response refused before interpreter bootstrap");
}


// Real DOM/File events with deliberately controlled I/O completion. Analysis
// and exported reports still use the authenticated Pyodide interpreter.
async function testInputReportContracts(cdp, baseUrl, downloads, fixtureState, compact) {
  fixtureState.reset();
  const session = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?input-contracts=1`);
  const id = session.sessionId;
  const statusId = compact ? "status" : "statusText";
  const button = compact ? "analyseBtn" : "analyzeBtn";
  try {
    if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()");
    await evaluate(cdp, id, `(() => {
      window.contractBytes = Uint8Array.from(atob("UEsDBBQAAAAIAHYnJl2Js2mnTgAAAJEAAAAHAAAAbWFpbi5weUtJTVNITEnRyElNK9FRKMpMzyjRtOJSAIKi1JLSojwFkISCNkSGiysFqDy3NKcksyCnkoAeLRQ9iZl5GqiK4MaArDfUUTDS1FEw1uQCAFBLAQIUAxQAAAAIAHYnJl2Js2mnTgAAAJEAAAAHAAAAAAAAAAAAAACAAQAAAABtYWluLnB5UEsFBgAAAAABAAEANQAAAHMAAAAAAA=="), value => value.charCodeAt(0));
      window.selectContractZip = (name, delayed) => {
        const transfer = new DataTransfer();
        transfer.items.add(new File([window.contractBytes], name, {type:'application/zip'}));
        const input = document.getElementById('${compact ? "zipInput" : "projectZipInput"}');
        input.files = transfer.files;
        if (delayed) Object.defineProperty(input.files[0], 'arrayBuffer', {value: () => new Promise(resolve => {window.finishContractRead = () => resolve(window.contractBytes.buffer.slice(0));})});
        input.dispatchEvent(new Event('change', {bubbles:true}));
      };
    })()`);
    if (compact) {
      await evaluate(cdp, id, "window.selectContractZip('alpha.zip', false)");
      await waitForExpression(cdp, id, "document.getElementById('status').textContent === 'Loaded ZIP: alpha.zip.'");
      await evaluate(cdp, id, "document.getElementById('analyseBtn').click()");
      await waitForExpression(cdp, id, "document.getElementById('status').textContent === 'Project analysis completed.'");
      await evaluate(cdp, id, "window.selectContractZip('beta.zip', true)");
      assert(await evaluate(cdp, id, "document.getElementById('exportJsonBtn').disabled && document.getElementById('exportTextBtn').disabled && state.json === ''"), "loading beta retained alpha's export");
      await evaluate(cdp, id, "window.finishContractRead()");
      await waitForExpression(cdp, id, "document.getElementById('status').textContent === 'Loaded ZIP: beta.zip.'");
      assert(await evaluate(cdp, id, "document.getElementById('exportJsonBtn').disabled"), "unanalyzed beta enabled an export");
      await evaluate(cdp, id, "document.getElementById('analyseBtn').click()");
      await waitForExpression(cdp, id, "document.getElementById('status').textContent === 'Project analysis completed.'");
      fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
      await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
      await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click()");
      await waitForFile(path.join(downloads, "beta.json"));
      const report = JSON.parse(fs.readFileSync(path.join(downloads, "beta.json"), "utf8"));
      assert(report.project_name === "beta", "beta download carries a stale project identity");
      await evaluate(cdp, id, "document.getElementById('profileSelect').dispatchEvent(new Event('change', {bubbles:true}))");
      assert(await evaluate(cdp, id, "document.getElementById('exportJsonBtn').disabled && state.json === ''"), "settings change retained a prior report");
      await evaluate(cdp, id, "window.selectContractZip('old.zip', true); window.selectContractZip('latest.zip', false)");
      await waitForExpression(cdp, id, "document.getElementById('status').textContent === 'Loaded ZIP: latest.zip.'");
      await evaluate(cdp, id, "window.finishContractRead()");
      await delay(50);
      assert(await evaluate(cdp, id, "state.payload.project_name === 'latest'"), "older ZIP replaced the last selection");
    } else {
      await evaluate(cdp, id, `(() => {
        const input = document.getElementById('fileInput'), transfer = new DataTransfer();
        transfer.items.add(new File(['SYNTHETIC_PRIVATE_SOURCE'], 'private.py'));
        input.files = transfer.files;
        Object.defineProperty(input.files[0], 'arrayBuffer', {value: () => new Promise(resolve => {window.finishPrivateRead = () => resolve(new TextEncoder().encode('SYNTHETIC_PRIVATE_SOURCE').buffer);})});
        input.dispatchEvent(new Event('change', {bubbles:true}));
        document.getElementById('privacyWipeBtn').click();
        window.finishPrivateRead();
      })()`);
      await delay(50);
      assert(await evaluate(cdp, id, "document.getElementById('editor').value === '' && appState.currentReport === null && appState.engineBundle === null"), "late input resurrected wiped data");
      fixtureState.reset();
    }
    await evaluate(cdp, id, `(() => {
      const transfer = new DataTransfer();
      transfer.items.add(new File([${JSON.stringify("def add(left, right):\n    return left + right\n\ndef multiply(left, right):\n    return left * right\n\ndef main():\n    return multiply(add(1, 2), 3)\n")}], 'main.py'));
      transfer.items.add(new File([new Uint8Array(1000001)], 'oversized.py'));
      const input = document.getElementById('folderInput'); input.files = transfer.files;
      window.rejectedContentReads = 0;
      Object.defineProperty(input.files[0], '_codeprobeRelativePath', {value:'accepted/main.py'});
      Object.defineProperty(input.files[1], '_codeprobeRelativePath', {value:'accepted/oversized.py'});
      Object.defineProperty(input.files[1], 'arrayBuffer', {value: async () => {window.rejectedContentReads += 1; throw new Error('Rejected content must remain unread');}});
      input.dispatchEvent(new Event('change', {bubbles:true}));
    })()`);
    await waitForExpression(cdp, id, `${compact ? "state" : "appState"}.loadingInput === false && !document.getElementById('${button}').disabled`);
    await evaluate(cdp, id, `document.getElementById('${button}').click()`);
    await waitForExpression(cdp, id, `document.getElementById('${statusId}').textContent === 'Project analysis completed.'`);
    const observed = await evaluate(cdp, id, `(() => ({report:JSON.parse(document.getElementById('jsonReport').value), rejectedReads:window.rejectedContentReads}))()`);
    assert(observed.rejectedReads === 0, "browser read prefiltered content");
    assert(observed.report.included_file_count === 1 && observed.report.excluded_file_count === 1, "selected input accounting does not reconcile");
    assert(observed.report.excluded_files.some(item => item.path.endsWith('oversized.py') && item.reason === 'browser_file_too_large'), "browser exclusion metadata disappeared in the real engine");
    for (const child of observed.report.included_files) assert(!child.calibration_profile_id, "uncalibrated child declares a calibration identity");
    console.log(`[PASS] browser-input-contracts: ${compact ? "compact" : "main"} intake ownership, report invalidation and real-engine exclusion accounting`);
  } finally { await closeSession(cdp, session); }
}

// Real HTTP-delivered UI and authenticated worker, with explicit storage-fault
// injection and controlled completion of a real File read. No worker double.
async function testPrivacyStorageFailures(cdp, baseUrl, fixtureState) {
  for (const fault of ["getter", "first-removal", "second-removal", "verification"]) {
    fixtureState.reset();
    const session = await createSession(cdp, `${baseUrl}/app/index.html?storage-fault=${fault}`);
    const id = session.sessionId;
    try {
      await waitForExpression(cdp, id, "appState.workerSession?.isReady()");
      const outcome = await evaluate(cdp, id, `(() => {
        const input = document.getElementById('fileInput'), transfer = new DataTransfer();
        transfer.items.add(new File(['SYNTHETIC_PRIVATE_SOURCE'], 'private.py'));
        input.files = transfer.files;
        Object.defineProperty(input.files[0], 'arrayBuffer', {value: () => new Promise(resolve => {
          window.finishFaultRead = () => resolve(new TextEncoder().encode('LATE_PRIVATE_SOURCE').buffer);
        })});
        input.dispatchEvent(new Event('change', {bubbles:true}));
        document.getElementById('editor').value = 'PRIVATE_SOURCE';
        document.getElementById('configOverride').value = '{}';
        document.getElementById('calibrationProfile').value = '{}';
        document.getElementById('historyEnabled').checked = true;
        const descriptor = Object.getOwnPropertyDescriptor(window, 'localStorage');
        let calls = 0;
        Object.defineProperty(window, 'localStorage', {configurable:true, get() {
          if (${JSON.stringify(fault)} === 'getter') throw new DOMException('Synthetic refusal', 'SecurityError');
          return {removeItem() {
            calls += 1;
            if ((${JSON.stringify(fault)} === 'first-removal' && calls === 1) ||
                (${JSON.stringify(fault)} === 'second-removal' && calls === 2)) throw new Error('Synthetic removal refusal');
          }, getItem() { return ${JSON.stringify(fault)} === 'verification' ? 'retained' : null; }};
        }});
        const generation = appState.generation;
        try { document.getElementById('privacyWipeBtn').click(); }
        finally {
          if (descriptor) Object.defineProperty(window, 'localStorage', descriptor);
          else delete window.localStorage;
        }
        window.finishFaultRead();
        return {generation, calls};
      })()`);
      await delay(50);
      const result = await evaluate(cdp, id, `({
        cleared: document.getElementById('editor').value === '' && document.getElementById('configOverride').value === '' && document.getElementById('calibrationProfile').value === '',
        generation: appState.generation, ready: appState.workerSession.isReady(), busy: appState.workerSession.isBusy(),
        disabled: document.getElementById('exportJsonBtn').disabled,
        history: document.getElementById('historyEnabled').checked,
        status: document.getElementById('statusText').textContent
      })`);
      assert(result.cleared && !result.ready && !result.busy && result.disabled && !result.history,
        "storage refusal prevented session teardown or a late read restored input");
      assert(result.generation > outcome.generation && result.status.includes('could not be verified'),
        "failed persistent erasure lacks an honest status or generation invalidation");
      if (fault !== 'getter') assert(outcome.calls === 2, "first storage error prevented the second erasure attempt");
      fixtureState.reset();
      await evaluate(cdp, id, `document.getElementById('editor').value = ${JSON.stringify("def square(value):\n    return value * value\n")}; document.getElementById('analyzeBtn').click()`);
      await waitForExpression(cdp, id, "document.getElementById('statusText').textContent === 'Analysis completed.'");
      assertSingleVerifiedRequests(fixtureState);
      console.log(`[PASS] privacy-storage: ${fault}; session cleared, late read refused, uncertainty reported and authenticated retry passed`);
    } finally { await closeSession(cdp, session); }
  }
}

function nativeReplayFixture() {
  const script = `import argparse, json, pathlib, sys, tempfile
sys.path[:0] = [str(pathlib.Path(sys.argv[1]) / 'src'), str(pathlib.Path(sys.argv[1]) / 'tools')]
import calibrate_profile
code = ${JSON.stringify("def add(left, right):\n    return left + right\n\ndef multiply(left, right):\n    return left * right\n\ndef main():\n    return multiply(add(1, 2), 3)\n")}
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    samples = []
    for index, (label, split) in enumerate((('human','fit'),('ai','fit'),('human','evaluation'),('ai','evaluation'))):
        name = 'sample-' + str(index) + '.py'
        (root / name).write_text(code, encoding='utf-8')
        samples.append(dict(path=name, label=label, split=split, group='g-' + str(index), kind='file'))
    manifest = root / 'manifest.json'
    manifest.write_text(json.dumps(dict(samples=samples, metric_overrides={'line_length_uniformity':{'weight':1.0}})), encoding='utf-8')
    result = calibrate_profile.run_calibration(argparse.Namespace(manifest=str(manifest), root=None, profile='strict', target_fpr=.1, config=None, out_dir=str(root/'output')))
    print(json.dumps(dict(code=code, profile=result['profile'], decision_score=result['results'][0]['decision_score'])))
`;
  const child = childProcess.spawnSync("python", ["-I", "-S", "-B", "-c", script, ROOT], {encoding:"utf8", timeout:30000, maxBuffer:1024*1024});
  assert(child.status === 0, `native calibration fixture failed: ${child.stderr || child.error}`);
  return JSON.parse(child.stdout);
}
async function testNativeBrowserReplay(cdp, baseUrl, fixtureState) {
  const expected = nativeReplayFixture();
  fixtureState.reset();
  const session = await createSession(cdp, `${baseUrl}/app/index.html?replay-contract=1`);
  try {
    await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()");
    const result = await evaluate(cdp, session.sessionId, `appState.workerSession.analyse('file', ${JSON.stringify({filename:"replay.py",code:expected.code,calibration_profile:expected.profile})})`);
    assert(result.report.profile === "strict", "browser ignored the bound scoring mode");
    // Native libm and WebAssembly implementations can differ in their last bits.
    assert(Math.abs(result.report.decision_score - expected.decision_score) < 1e-12, "native and browser scoring disagree");
    assert(result.report.metric_config_digest === expected.profile.scoring_contract.metric_config_digest, "browser used a different effective configuration");
    assert(result.report.engine_fingerprint.value === expected.profile.scoring_contract.engine_sha256, "browser used a different engine");
    const invalid = await evaluate(cdp, session.sessionId, `appState.workerSession.analyse('file', ${JSON.stringify({filename:"replay.py",code:expected.code,profile:"default",calibration_profile:expected.profile})}).then(() => false, () => true)`);
    assert(invalid, "browser accepted a conflicting explicit scoring mode");
    console.log("[PASS] browser-calibration-contract: native fitted strict/override configuration replayed in authenticated Pyodide; conflicting mode refused");
  } finally { await closeSession(cdp, session); }
}


function nativeParserFixtures() {
  const script = "import argparse, hashlib, json, pathlib, platform, sys, tempfile\nsys.path[:0] = [str(pathlib.Path(sys.argv[1]) / 'src'), str(pathlib.Path(sys.argv[1]) / 'tools')]\nimport calibrate_profile\ncode = 'type UserId = int\\n\\ndef lookup(name: str) -> UserId:\\n    \"\"\"Resolve a key.\"\"\"\\n    data = {\"a\": 1, \"b\": 2}\\n    return data.get(name, 0)\\n\\ndef increase(value: UserId) -> UserId:\\n    \"\"\"Increase the value.\"\"\"\\n    if value < 0:\\n        return 0\\n    return value + 1\\n\\ndef reduce(value: UserId) -> UserId:\\n    \"\"\"Reduce the value.\"\"\"\\n    if value > 0:\\n        return value - 1\\n    return 0\\n\\ndef combine(left: UserId, right: UserId) -> UserId:\\n    \"\"\"Combine the values.\"\"\"\\n    return increase(left) + reduce(right)\\n'\ncases = []\nfor syntax, text in [('modern', code), ('common', code.replace('type UserId = int', 'UserId = int', 1))]:\n    for kind in ('file', 'project'):\n        with tempfile.TemporaryDirectory() as directory:\n            root = pathlib.Path(directory)\n            samples = []\n            for index, (label, split) in enumerate((('human','fit'),('ai','fit'),('human','evaluation'),('ai','evaluation'))):\n                name = 'sample-' + str(index) + ('.py' if kind == 'file' else '')\n                item = root / name\n                if kind == 'project':\n                    item.mkdir()\n                    item /= 'main.py'\n                item.write_text(text, encoding='utf-8')\n                samples.append(dict(path=name, label=label, split=split, group='g-' + str(index), kind=kind))\n            manifest = root / 'manifest.json'\n            manifest.write_text(json.dumps(dict(samples=samples)), encoding='utf-8')\n            result = calibrate_profile.run_calibration(argparse.Namespace(manifest=str(manifest), root=None, profile='default', target_fpr=.1, config=None, out_dir=str(root/'output')))\n            payload = dict(calibration_profile=result['profile'])\n            if kind == 'file':\n                payload.update(filename='parser.py', code=text)\n            else:\n                payload.update(project_name='parser', files=[dict(path='main.py', content=text)])\n            cases.append(dict(syntax=syntax, kind=kind, payload=payload, source_sha256=hashlib.sha256(text.encode()).hexdigest(), decision_score=result['results'][2]['decision_score']))\nprint(json.dumps(dict(native_python=platform.python_version(), cases=cases)))\n";
  const child = childProcess.spawnSync("python", ["-I", "-S", "-B", "-c", script, ROOT], {encoding:"utf8", timeout:30000, maxBuffer:1024*1024});
  assert(child.status === 0, `native parser fixtures failed: ${child.stderr || child.error}`);
  return JSON.parse(child.stdout);
}

async function testParserReplayBoundary(cdp, baseUrl, fixtureState) {
  const expected = nativeParserFixtures();
  fixtureState.reset();
  const session = await createSession(cdp, `${baseUrl}/app/index.html?parser-contract=1`);
  const observations = [];
  try {
    await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()");
    for (const item of expected.cases) {
      // A terminated interpreter starts a new authenticated request generation.
      if (!await evaluate(cdp, session.sessionId, "appState.workerSession.isReady()")) fixtureState.reset();
      await evaluate(cdp, session.sessionId, "appState.workerSession.initialise()");
      assertSingleVerifiedRequests(fixtureState);
      if (item.syntax === "modern") {
        const refusal = await evaluate(cdp, session.sessionId, `appState.workerSession.analyse(${JSON.stringify(item.kind)}, ${JSON.stringify(item.payload)}).then(() => ({rejected:false}), error => ({rejected:true, name:error.name, message:error.message}))`);
        assert(refusal.rejected && refusal.name === "WorkerError", `calibrated ${item.kind} did not reject unsupported syntax`);
        assert(refusal.message === "The analysis worker rejected the operation.", "worker error leaked interpreter details");
        assert(!await evaluate(cdp, session.sessionId, "appState.workerSession.isReady()"), "failed worker remained reusable");
        observations.push({syntax:item.syntax, kind:item.kind, source_sha256:item.source_sha256, result:"refused", error:refusal.name});
        if (item.kind === "file") {
          fixtureState.reset();
          await evaluate(cdp, session.sessionId, "appState.workerSession.initialise()");
          assertSingleVerifiedRequests(fixtureState);
          const diagnostic = {...item.payload}; delete diagnostic.calibration_profile;
          const fallback = await evaluate(cdp, session.sessionId, `appState.workerSession.analyse('file', ${JSON.stringify(diagnostic)})`);
          assert(fallback.report.warnings.some(message => message.includes("AST warning")), "unbound parser fallback lost its warning");
          assert(!fallback.report.calibration_profile_id, "unbound parser fallback acquired calibration provenance");
        }
        continue;
      }
      const result = await evaluate(cdp, session.sessionId, `appState.workerSession.analyse(${JSON.stringify(item.kind)}, ${JSON.stringify(item.payload)})`);
      const report = item.kind === "file" ? result.report : result.project_report;
      assert(Math.abs(report.decision_score - item.decision_score) < 1e-12, "common-syntax native/browser replay differs");
      const provenance = report.engine_fingerprint;
      assert(provenance.source === "packaged-verified" && provenance.matches_loaded_source === true, "normal browser provenance degraded");
      assert(provenance.measured_sha256 === item.payload.calibration_profile.scoring_contract.engine_sha256, "measured browser engine disagrees with bound contract");
      const runtime = report.tool_metadata.python_runtime;
      assert(runtime.platform === "emscripten" && runtime.version.startsWith("3.11."), "unexpected pinned parser runtime");
      observations.push({syntax:item.syntax, kind:item.kind, source_sha256:item.source_sha256, native_score:item.decision_score, wasm_score:report.decision_score, runtime, measured_sha256:provenance.measured_sha256});
    }
    console.log("[PASS] parser-replay-boundary: " + JSON.stringify({native_python:expected.native_python, observations}));
  } finally { await closeSession(cdp, session); }
}

async function main() {
  const pyodideDirectory = path.resolve(String(process.env.CODEPROBE_PYODIDE_FIXTURE_DIR || ""));
  assert(process.env.CODEPROBE_PYODIDE_FIXTURE_DIR, "CODEPROBE_PYODIDE_FIXTURE_DIR is required.");
  for (const name of CORE_NAMES) assert(fs.existsSync(path.join(pyodideDirectory, name)), `missing fixture: ${name}`);

  const working = fs.mkdtempSync(path.join(os.tmpdir(), "codeprobe-functional-"));
  const fixtureRoot = path.join(working, "kit");
  const downloads = path.join(working, "downloads");
  const userData = path.join(working, "chrome-profile");
  copyFixtureTree(fixtureRoot, pyodideDirectory);
  const engineDigest = sha256File(path.join(fixtureRoot, "src", "codeprobe_runtime.py"));

  const { server, state } = createFixtureServer(fixtureRoot);
  const serverPort = await freePort();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(serverPort, "127.0.0.1", resolve);
  });
  const baseUrl = `http://127.0.0.1:${serverPort}`;

  const browser = findBrowser();
  const debugPort = await freePort();
  const browserLog = [];
  const chrome = childProcess.spawn(browser, [
    "--headless=new",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-sync",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-proxy-server",
    "--no-sandbox",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${userData}`,
    "about:blank",
  ], { stdio: ["ignore", "pipe", "pipe"] });
  processes.add(chrome);
  chrome.stdout.on("data", chunk => browserLog.push(String(chunk)));
  chrome.stderr.on("data", chunk => browserLog.push(String(chunk)));

  let cdp = null;
  try {
    const version = await waitForJson(`http://127.0.0.1:${debugPort}/json/version`);
    assert(version.webSocketDebuggerUrl, "Chrome did not expose a DevTools WebSocket URL.");
    cdp = new CdpConnection(version.webSocketDebuggerUrl);
    await cdp.connect();
    await testMainAnalysis(cdp, baseUrl, downloads, state, engineDigest);
    await testProjectAnalysis(cdp, baseUrl, downloads, state, engineDigest);
    await testTamperedCoreFailsClosedAndReloadRetries(cdp, baseUrl, state);
    await testTamperedEngineFailsClosed(cdp, baseUrl, state);
    await testWorkerResponsiveness(cdp, baseUrl, state, false);
    await testWorkerResponsiveness(cdp, baseUrl, state, true);
    await testTamperedWorkerBootstrap(cdp, baseUrl, state);
    await testInputReportContracts(cdp, baseUrl, downloads, state, false);
    await testInputReportContracts(cdp, baseUrl, downloads, state, true);
    await testPrivacyStorageFailures(cdp, baseUrl, state);
    await testNativeBrowserReplay(cdp, baseUrl, state);
    await testParserReplayBoundary(cdp, baseUrl, state);
    const browserVersion = childProcess.spawnSync(browser, ["--version"], { encoding: "utf8" });
    const renderedVersion = String(browserVersion.stdout || browserVersion.stderr || browser).trim();
    console.log(`[PASS] browser-functional: verified Pyodide and engine bytes drove real analyses (${renderedVersion})`);
    console.log("[PASS] browser-functional: file and project JSON/text exports were downloaded and validated");
    console.log("[PASS] browser-functional: each core artefact reached the origin once; a hostile second response was never consumed");
    console.log("[PASS] browser-functional: a tampered core artefact failed closed and a clean reload recovered");
    console.log("[PASS] browser-functional: a tampered Python engine failed before import");
  } catch (error) {
    console.error(`[FAIL] browser-functional: ${error && error.stack ? error.stack : error}`);
    if (browserLog.length) console.error(`browser log:\n${browserLog.join("").slice(-8_000)}`);
    process.exitCode = 1;
  } finally {
    if (cdp) cdp.close();
    stopProcess(chrome);
    processes.delete(chrome);
    await new Promise(resolve => server.close(resolve));
    try { fs.rmSync(working, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }
}

main().catch(error => {
  console.error(`[FAIL] browser-functional: ${error && error.stack ? error.stack : error}`);
  cleanup();
  process.exitCode = 1;
});
