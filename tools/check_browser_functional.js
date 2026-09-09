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
    this.attachedTargets = new Map();
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
      if (payload.method === "Target.attachedToTarget") {
        this.attachedTargets.set(payload.params.sessionId, {
          parentSessionId: payload.sessionId,
          targetInfo: payload.params.targetInfo,
        });
        return;
      }
      if (payload.method === "Target.detachedFromTarget") {
        this.attachedTargets.delete(payload.params.sessionId);
        for (const [id, pending] of this.pending) {
          if (pending.sessionId !== payload.params.sessionId) continue;
          this.pending.delete(id);
          clearTimeout(pending.timer);
          pending.reject(new Error(`${pending.method}: CDP target detached`));
        }
        return;
      }
      if (!payload.id || !this.pending.has(payload.id)) return;
      const pending = this.pending.get(payload.id);
      if (payload.sessionId !== pending.sessionId) return;
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
      this.pending.set(id, { resolve, reject, timer, method, sessionId });
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
    return expected;
  } finally { await closeSession(cdp, session); }
}

// Raw JSON is checked in the already authenticated worker's real interpreter.
// The public worker transport normalises JSON and exposes no metadata operation,
// so its reachable field checks are recorded separately below.
async function testStrictJsonContracts(cdp, baseUrl, fixtureState, engineDigest) {
  const deadline = Date.now() + 300000;
  async function bounded(operation) {
    const remaining = deadline - Date.now();
    assert(remaining > 0, "strict JSON browser contract exceeded its 300-second budget");
    let timer;
    try {
      return await Promise.race([
        operation(),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("strict JSON browser contract exceeded its 300-second budget")), remaining); }),
      ]);
    } finally { clearTimeout(timer); }
  }
  await bounded(() => cdp.send("Target.setDiscoverTargets", {discover:true}));
  const previous = new Set((await bounded(() => cdp.send("Target.getTargets"))).targetInfos.map(item => item.targetId));
  fixtureState.reset();
  const pageUrl = `${baseUrl}/app/index.html?strict-json-contract=1`;
  const session = await bounded(() => createSession(cdp, pageUrl));
  let workerSession = null;
  try {
    await bounded(() => waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()"));
    assertSingleVerifiedRequests(fixtureState);
    // Dedicated-worker renderer channels are reported through the owning page.
    // Discovery alone can expose a browser-side target without a usable channel.
    await bounded(() => cdp.send("Target.setAutoAttach", {
      autoAttach:true, waitForDebuggerOnStart:false, flatten:true,
      filter:[{type:"worker"}, {exclude:true}],
    }, session.sessionId));
    let targets = [], workers = [], attachments = [];
    const discoveryDeadline = Math.min(deadline, Date.now() + 5000);
    do {
      targets = (await bounded(() => cdp.send("Target.getTargets"))).targetInfos;
      workers = targets.filter(item => item.type === "worker" && !previous.has(item.targetId) && item.parentId === session.targetId);
      attachments = [...cdp.attachedTargets.entries()].filter(([, item]) =>
        item.parentSessionId === session.sessionId && workers.some(worker => worker.targetId === item.targetInfo.targetId));
      if (workers.length && attachments.length) break;
      await bounded(() => delay(100));
    } while (Date.now() < discoveryDeadline);
    console.log("[INFO] browser-strict-json-targets: " + JSON.stringify({page_target_id:session.targetId, targets:targets.map(item => ({id:item.targetId, type:item.type, url:item.url, parent:item.parentId, opener:item.openerId, existed:previous.has(item.targetId)}))}));
    assert(workers.length === 1, "the owned page did not expose exactly one new child worker after bounded discovery");
    const worker = workers[0];
    if (worker.openerId) assert(worker.openerId === session.targetId, "worker opener differs from the owned page");
    assert(attachments.length === 1, "the owned worker did not expose exactly one page-attached CDP session");
    const [attachedSessionId, attachment] = attachments[0];
    assert(attachment.targetInfo.type === "worker" && attachment.targetInfo.parentId === session.targetId,
      "worker attachment differs from the owned child target");
    workerSession = attachedSessionId;
    await bounded(() => cdp.send("Runtime.enable", {}, workerSession));
    const workerBase = await bounded(() => evaluate(cdp, workerSession, "self.CODEPROBE_BASE_URL"));
    assert(workerBase === pageUrl, "attached worker does not carry the owned page's bootstrap URL");
    const script = `def _codeprobe_strict_json_fixture():
    import json, sys
    module = sys.modules['codeprobe_runtime']
    entries = [('file', module.codeprobe_analyze), ('project', module.codeprobe_analyze_project), ('metadata', module.codeprobe_engine_metadata)]
    positives = []
    metadata = None
    for kind, entry in entries:
        result = json.loads(entry('{}'))
        if kind == 'metadata':
            metadata = result
            assert result['file_report_schema_version'] == '2.2.0'
        else:
            assert result['report']['report_kind'] == kind
            assert result['report']['profile'] == 'default'
            assert isinstance(result['text'], str) and len(result['text']) > 100
            if kind == 'file':
                assert result['report']['filename'] == 'fragment.py'
            else:
                assert result['report'] == result['project_report']
                assert result['report']['included_file_count'] == 0
        positives.append(dict(kind=kind, case='empty-object-defaults', result='accepted'))
    invalid = []
    cases = [('null-root', 'null'), ('array-root', '[]'), ('scalar-root', '"scalar"'), ('duplicate-key', '{"duplicate":1,"duplicate":2}'), ('nonfinite-number', '{"value":NaN}')]
    for kind, entry in entries:
        for label, raw in cases:
            try:
                entry(raw)
            except (ValueError, TypeError) as error:
                invalid.append(dict(kind=kind, case=label, result='refused', error=type(error).__name__))
            else:
                raise AssertionError(kind + ' accepted ' + label)
    return json.dumps(dict(positives=positives, invalid=invalid, runtime=metadata['python_runtime'], measured_sha256=metadata['engine_fingerprint']['value']), allow_nan=False)
_codeprobe_strict_json_fixture()
`;
    const direct = await bounded(() => evaluate(cdp, workerSession, `(async () => {
      const runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
      try { return JSON.parse(runtime.runPython(${JSON.stringify(script)})); }
      finally { runtime.globals.delete('_codeprobe_strict_json_fixture'); }
    })()`));
    assert(direct.runtime.platform === "emscripten" && direct.runtime.version.startsWith("3.11."), "raw JSON checks did not run in pinned Pyodide");
    assert(direct.measured_sha256 === engineDigest, "raw JSON checks used a different engine source");
    assert(direct.positives.length === 3 && direct.invalid.length === 15, "raw JSON matrix is incomplete");
    assertSingleVerifiedRequests(fixtureState);
    console.log("[PASS] browser-strict-json-direct: " + JSON.stringify({ownership:{page_target_id:session.targetId, worker_target_id:worker.targetId, worker_parent_id:worker.parentId, worker_url:worker.url, bootstrap_url:workerBase}, ...direct}));

    const code = "def add(left, right):\n    return left + right\n";
    const valid = [
      {kind:"file", payload:{filename:"accepted.py", code, language_hint:"auto", profile:null, config_override:{}}},
      {kind:"project", payload:{project_name:"accepted", files:[{path:"accepted.py", content:code}], language_hint:"auto", profile:null, config_override:{}, include_documentation:false}},
    ];
    for (const item of valid) {
      const result = await bounded(() => evaluate(cdp, session.sessionId, `appState.workerSession.analyse(${JSON.stringify(item.kind)}, ${JSON.stringify(item.payload)})`));
      assert(result.report.report_kind === item.kind && result.report.profile === "default", "valid worker payload lost its report kind or default profile");
      assert(result.report.engine_fingerprint.value === engineDigest && result.report.engine_fingerprint.source === "packaged-verified", "valid worker payload lost authenticated engine provenance");
      assert(typeof result.text === "string" && result.text.length > 100, "valid worker payload lost its text report");
      if (item.kind === "project") {
        assert(JSON.stringify(result.report) === JSON.stringify(result.project_report), "worker project report alias differs");
        assert(result.report.included_file_count === 1, "valid worker project lost its supplied file");
      }
    }
    const invalid = [
      {label:"file-code-type", kind:"file", payload:{code:17}},
      {label:"config-object-type", kind:"file", payload:{code, config_override:[]}},
      {label:"documentation-boolean-type", kind:"project", payload:{files:[], include_documentation:"false"}},
      {label:"project-content-type", kind:"project", payload:{files:[{path:"bad.py", content:17}]}},
      {label:"fractional-file-limit", kind:"project", payload:{files:[], max_files:1.9}},
      {label:"nonfinite-compression-ratio", kind:"project", payload:{files:[], max_compression_ratio:"nan"}},
    ];
    const observations = [];
    for (const item of invalid) {
      if (!await bounded(() => evaluate(cdp, session.sessionId, "appState.workerSession.isReady()"))) {
        fixtureState.reset();
        await bounded(() => evaluate(cdp, session.sessionId, "appState.workerSession.initialise()"));
      }
      assertSingleVerifiedRequests(fixtureState);
      const refusal = await bounded(() => evaluate(cdp, session.sessionId, `appState.workerSession.analyse(${JSON.stringify(item.kind)}, ${JSON.stringify(item.payload)}).then(() => ({rejected:false}), error => ({rejected:true, name:error.name, message:error.message}))`));
      assert(refusal.rejected && refusal.name === "WorkerError", `${item.label} was not refused through the worker`);
      assert(refusal.message === "The analysis worker rejected the operation.", "invalid payload exposed interpreter details");
      assert(!await bounded(() => evaluate(cdp, session.sessionId, "appState.workerSession.isReady()")), "invalid payload left a reusable worker");
      observations.push({kind:item.kind, case:item.label, result:"refused", error:refusal.name});
    }
    console.log("[PASS] browser-strict-json-worker: " + JSON.stringify({positive_cases:valid.length, observations, qualification:"Raw roots, duplicate keys, numeric NaN and metadata were tested directly in the authenticated interpreter; the worker transports serialised objects."}));
  } finally {
    if (workerSession) {
      try { await cdp.send("Target.detachFromTarget", {sessionId:workerSession}, session.sessionId); }
      catch (_) { /* the worker is deliberately terminated after a refusal */ }
    }
    await closeSession(cdp, session);
    await cdp.send("Target.setDiscoverTargets", {discover:false});
  }
}

// Real File/DOM/controller/worker/Pyodide paths. Entry callbacks and the one
// returned-identity fault below are controlled fixtures, not OS drag claims.
async function testIntakeContracts(cdp, baseUrl, downloads, fixtureState, compact, engineDigest) {
  const deadline = Date.now() + 300000;
  const observations = [];
  async function caseWithinBudget(name, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "intake browser group exceeded its 300-second budget");
    const started = Date.now();
    let timer;
    try {
      await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`intake case timed out: ${name}`)), remaining);
      })]);
      observations.push({case:name, result:"PASS", elapsed_ms:Date.now() - started});
      console.log("[PASS] browser-intake-case: " + JSON.stringify({ui:compact ? "compact" : "main", ...observations[observations.length - 1]}));
    } finally { clearTimeout(timer); }
  }
  fixtureState.reset();
  const session = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?intake-i06=1`);
  const id = session.sessionId;
  const active = compact ? "state" : "appState";
  const button = compact ? "analyseBtn" : "analyzeBtn";
  const status = compact ? "status" : "statusText";
  const folderName = compact ? "intake" : "selected-files";
  const noAcceptedReport = compact
    ? "state.json === '' && document.getElementById('jsonReport').value === ''"
    : "appState.currentReport === null && document.getElementById('jsonReport').value === '{}'";
  const text = "# café\ndef add(left, right):\n    return left + right\n\ndef multiply(left, right):\n    return left * right\n\ndef main():\n    return multiply(add(1, 2), 3)\n";
  const latin = [...Buffer.from(text.replace(/\n/g, "\r\n"), "latin1")];
  const utf8 = [...Buffer.from(text.replace(/\n/g, "\r\n"), "utf8")];
  const warning = "Decoded as latin-1; review the file encoding.";
  async function selectFiles(files, single = false) {
    await evaluate(cdp, id, `(() => {
      const transfer = new DataTransfer();
      for (const item of ${JSON.stringify(files)}) {
        const file = new File([new Uint8Array(item.bytes)], item.name, {type:'text/x-python'});
        if (item.path) Object.defineProperty(file, '_codeprobeRelativePath', {value:item.path, configurable:true});
        transfer.items.add(file);
      }
      const input = document.getElementById('${single ? "fileInput" : "folderInput"}');
      input.files = transfer.files;
      input.dispatchEvent(new Event('change', {bubbles:true}));
    })()`);
    await waitForExpression(cdp, id, `${active}.loadingInput === false`, 60000);
  }
  async function analyse(single = false) {
    await evaluate(cdp, id, `document.getElementById('${button}').click()`);
    await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === '${single ? "Analysis completed." : "Project analysis completed."}'`, 60000);
    return await evaluate(cdp, id, `({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, dom:document.body.textContent})`);
  }
  async function download(name, report, requiredText) {
    fs.rmSync(downloads, {recursive:true, force:true});
    fs.mkdirSync(downloads, {recursive:true});
    await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
    await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
    const jsonPath = path.join(downloads, `${name}.json`), textPath = path.join(downloads, `${name}.txt`);
    await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
    assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(report), "downloaded JSON differs from the accepted report");
    assert(fs.readFileSync(textPath, "utf8").includes(requiredText), "downloaded text lost the intake contract");
  }
  function checkProvenance(report, encoding, hasWarning) {
    const provenance = report.intake_provenance;
    assert(provenance && provenance.source === "caller-reported", "intake provenance is absent or represented as authenticated");
    assert(provenance.encoding === encoding && provenance.normalisation === "newlines", "intake encoding or normalisation differs from the CRLF fixture");
    assert(Array.isArray(provenance.warnings) && provenance.warnings.length === (hasWarning ? 1 : 0), "intake warning count differs");
    if (hasWarning) {
      assert(provenance.warnings[0] === warning, "Latin-1 intake warning changed");
      assert(report.warnings.some(item => item.includes(warning)), "report warnings lost the caller-reported decoding warning");
    } else assert(!report.warnings.some(item => item.includes("latin-1")), "valid UTF-8 acquired a false decoding warning");
  }
  try {
    if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
    if (!compact) {
      for (const item of [{label:"latin1", bytes:latin, encoding:"latin-1"}, {label:"utf8", bytes:utf8, encoding:"utf-8"}]) {
        await caseWithinBudget(`single-${item.label}-report-and-downloads`, async () => {
          await selectFiles([{name:`${item.label}.py`, bytes:item.bytes}], true);
          assert(await evaluate(cdp, id, `document.getElementById('editor').value === ${JSON.stringify(text)}`), "single controller did not retain the exact decoded and normalised text");
          const result = await analyse(true);
          checkProvenance(result.report, item.encoding, item.label === "latin1");
          assert(result.report.engine_fingerprint.value === engineDigest, "single intake report used different engine bytes");
          if (item.label === "latin1") assert(result.dom.includes(warning) && result.text.includes(warning), "single UI or text report lost decoding warning");
          await download(item.label, result.report, item.label === "latin1" ? warning : "utf8.py");
        });
      }
    }
    await caseWithinBudget("folder-latin1-utf8-report-and-downloads", async () => {
      await selectFiles([{name:"latin1.py", path:"intake/latin1.py", bytes:latin}, {name:"utf8.py", path:"intake/utf8.py", bytes:utf8}]);
      const payload = await evaluate(cdp, id, `${compact ? "state.payload" : "appState.projectPayload"}`);
      assert(payload.files.length === 2 && payload.files.every(item => item.intake_provenance), "controller payload lost decoding provenance");
      assert(payload.files.every(item => item.content === text), "folder payload differs from the independently decoded and normalised fixture");
      assert(payload.project_name === folderName, "annotated file-list project name differs from its controller contract");
      const result = await analyse();
      assert(result.report.included_file_count === 2, "folder intake did not analyse both valid text files");
      checkProvenance(result.report.included_files.find(item => item.path.endsWith("latin1.py")), "latin-1", true);
      checkProvenance(result.report.included_files.find(item => item.path.endsWith("utf8.py")), "utf-8", false);
      assert(result.text.includes(warning) && result.dom.includes(warning), "project UI or text report lost decoding warning");
      await download(folderName, result.report, warning);
    });
    await caseWithinBudget("caller-reported-warning-rendered-as-text", async () => {
      const marker = '<b id="intake-provenance-marker">caller message</b>';
      await evaluate(cdp, id, `(() => {
        const payload = ${compact ? "state.payload" : "appState.projectPayload"};
        payload.files[0].intake_provenance = {encoding:'latin-1', normalisation:'none', warnings:[${JSON.stringify(marker)}]};
      })()`);
      const result = await analyse();
      assert(result.report.included_files[0].intake_provenance.source === "caller-reported", "warning was attributed to an authenticated source");
      assert(result.dom.includes(marker) && result.text.includes(marker), "caller-reported warning was erased");
      assert(await evaluate(cdp, id, "document.getElementById('intake-provenance-marker') === null"), "caller-reported warning became a DOM element");
      await download(folderName, result.report, marker);
    });
    await caseWithinBudget("full-bounded-nul-screen-and-exclusion-inventory", async () => {
      const positions = [0, 4095, 4096, 5000];
      const files = [{name:"valid.py", path:"nul/valid.py", bytes:utf8}];
      for (const position of positions) {
        const bytes = new Array(5001).fill(35); bytes[position] = 0;
        files.push({name:`nul-${position}.py`, path:`nul/nul-${position}.py`, bytes});
      }
      const decoded = await evaluate(cdp, id, `(${JSON.stringify(files.slice(1))}).map(item => {
        try { window.CodeProbeRuntime.decodeSourceBytes(new Uint8Array(item.bytes)); return {name:item.name, refused:false}; }
        catch (error) { return {name:item.name, refused:true, message:error.message}; }
      })`);
      assert(decoded.length === 4 && decoded.every(item => item.refused && item.message.includes("NUL")), "full bounded decoder accepted a NUL position");
      await selectFiles(files);
      const result = await analyse();
      assert(result.report.included_file_count === 1 && result.report.excluded_file_count === 4, "NUL inventory does not reconcile");
      for (const position of positions) assert(result.report.excluded_files.some(item => item.path.endsWith(`nul-${position}.py`) && item.reason === "browser_undecodable_text"), `NUL ${position} lost its exclusion reason`);
    });
    for (const [name, project] of [[".zip", "project"], ["ordinary.zip", "ordinary"]]) {
      await caseWithinBudget(`zip-name-${name}-accepted-and-exported`, async () => {
        await evaluate(cdp, id, `(() => {
          const bytes = Uint8Array.from(atob('UEsDBBQAAAAIAHYnJl2Js2mnTgAAAJEAAAAHAAAAbWFpbi5weUtJTVNITEnRyElNK9FRKMpMzyjRtOJSAIKi1JLSojwFkISCNkSGiysFqDy3NKcksyCnkoAeLRQ9iZl5GqiK4MaArDfUUTDS1FEw1uQCAFBLAQIUAxQAAAAIAHYnJl2Js2mnTgAAAJEAAAAHAAAAAAAAAAAAAACAAQAAAABtYWluLnB5UEsFBgAAAAABAAEANQAAAHMAAAAAAA=='), value => value.charCodeAt(0));
          const transfer = new DataTransfer(); transfer.items.add(new File([bytes], ${JSON.stringify(name)}, {type:'application/zip'}));
          const input = document.getElementById('${compact ? "zipInput" : "projectZipInput"}'); input.files = transfer.files;
          input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, `${active}.loadingInput === false`, 60000);
        const result = await analyse();
        assert(result.report.project_name === project && result.report.included_file_count === 1, "ZIP name fallback differs or lost its member");
        await download(project, result.report, project);
      });
    }
    await caseWithinBudget("wrong-returned-project-identity-refused", async () => {
      await evaluate(cdp, id, `(() => {
        const actual = ${active}.workerSession;
        window.intakeWrongIdentityResponses = 0;
        window.restoreIntakeSession = () => { ${active}.workerSession = actual; };
        ${active}.workerSession = {...actual, async analyse(kind, payload) {
          const result = await actual.analyse(kind, payload);
          window.intakeWrongIdentityResponses += 1;
          window.intakeIdentityOriginalDigest = result.report.engine_fingerprint.value;
          result.report.project_name = 'unrelated-project';
          if (result.project_report) result.project_report.project_name = 'unrelated-project';
          return result;
        }};
        document.getElementById('${button}').click();
      })()`);
      await waitForExpression(cdp, id, `window.intakeWrongIdentityResponses === 1 && ${active}.busy === false`, 60000);
      assert(await evaluate(cdp, id, `window.intakeIdentityOriginalDigest === ${JSON.stringify(engineDigest)} && document.getElementById('${status}').textContent.includes('failed; no report was accepted')`), "identity refusal did not follow an authenticated analysis and explicit failure state");
      assert(await evaluate(cdp, id, `document.getElementById('exportJsonBtn').disabled && document.getElementById('exportTextBtn').disabled && (${noAcceptedReport})`), "wrong report identity remained exportable");
      await evaluate(cdp, id, "window.restoreIntakeSession()");
    });
    await caseWithinBudget("drop-all-valid-all-null-and-mixed-permutations", async () => {
      const outcome = await evaluate(cdp, id, `(async () => {
        const a = new File(['# a'], 'a.py'), b = new File(['# b'], 'b.py');
        function item(file, valid, repeated = false) { return {kind:'file', webkitGetAsEntry:() => valid ? {isFile:true, name:file.name, file(resolve) {resolve(file); if (repeated) resolve(file);}} : null}; }
        const cases = [];
        for (const flags of [[true,true], [false,false], [true,false], [false,true]]) {
          const transfer = {items:[item(a,flags[0]),item(b,flags[1])],files:[a,b],types:['Files']};
          try { const files = await window.CodeProbeRuntime.collectDroppedFiles(transfer); cases.push({flags, names:files.map(file => file.name), error:null}); }
          catch (error) { cases.push({flags, names:[], error:error.message}); }
        }
        try {
          const files = await window.CodeProbeRuntime.collectDroppedFiles({items:[item(a,true,true)],files:[a],types:['Files']});
          cases.push({case:'repeated-callback', names:files.map(file => file.name), error:null});
        } catch (error) { cases.push({case:'repeated-callback', names:[], error:error.message}); }
        window.intakeMixedDrop = {items:[item(a,true),item(b,false)],files:[a,b],types:['Files']};
        const event = new Event('drop', {bubbles:true,cancelable:true});
        Object.defineProperty(event, 'dataTransfer', {value:window.intakeMixedDrop}); document.dispatchEvent(event);
        return cases;
      })()`);
      for (const item of outcome.slice(0, 2)) assert(!item.error && item.names.length === 2 && new Set(item.names).size === 2, "complete drop selection lost or duplicated a file");
      assert(outcome.length === 5, "drop callback matrix is incomplete");
      for (const item of outcome.slice(2)) assert(item.error && item.names.length === 0, "mixed entry selection or repeated callback returned an accepted inventory");
      await waitForExpression(cdp, id, `${active}.loadingInput === false`, 60000);
      assert(await evaluate(cdp, id, `${compact ? "state.payload" : "appState.projectPayload"} === null && document.getElementById('exportJsonBtn').disabled && (${noAcceptedReport})`), "mixed drop left a partial analysable project or prior report");
    });
    if (!compact) {
      for (const provenance of [{encoding:"invented", normalisation:"none", warnings:[]}, {encoding:"utf-8", normalisation:"none", warnings:"invented"}]) {
        await caseWithinBudget(`malformed-provenance-${typeof provenance.warnings === "string" ? "warnings" : "encoding"}`, async () => {
          if (!await evaluate(cdp, id, "appState.workerSession.isReady()")) {
            fixtureState.reset(); await evaluate(cdp, id, "appState.workerSession.initialise()");
          }
          const result = await evaluate(cdp, id, `appState.workerSession.analyse('file', ${JSON.stringify({filename:"bad-metadata.py", code:text, intake_provenance:provenance})}).then(() => ({accepted:true}), error => ({accepted:false,name:error.name}))`);
          assert(!result.accepted && result.name === "WorkerError", "malformed intake provenance was accepted by the authenticated worker");
          assert(!await evaluate(cdp, id, "appState.workerSession.isReady()"), "malformed intake provenance left a reusable worker");
        });
      }
    }
    console.log("[PASS] browser-intake-i06: " + JSON.stringify({ui:compact ? "compact" : "main", engine_sha256:engineDigest, observations, qualification:"Real Chromium File/DOM, authenticated worker/Pyodide and downloaded exports; controlled entry callbacks and one returned-identity fault injection."}));
  } finally { await closeSession(cdp, session); }
}

// Context metadata has no public worker operation. These finite audit oracles
// inspect the already authenticated interpreter in the page's owned worker;
// the separate UI cases below exercise the unchanged public transport.
async function testPythonStructureContracts(cdp, baseUrl, downloads, fixtureState, engineDigest, parserFixtures) {
  const deadline = Date.now() + 300000;
  const observations = [];
  async function withinCase(name, findings, boundary, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "Python browser group exceeded its 300-second budget");
    const started = Date.now();
    let timer;
    try {
      const observed = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Python browser case timed out: ${name}`)), remaining);
      })]);
      const row = {case:name, findings, boundary, result:"PASS", elapsed_ms:Date.now() - started, observed};
      observations.push(row);
      console.log("[PASS] browser-python-i07-case: " + JSON.stringify(row));
    } finally { clearTimeout(timer); }
  }
  const invalidCode = "if True:\n    value = 1\n  value = 2\n";
  const directCases = [
    {name:"python-lexical-diagnostics", finding:"A02-F001", script:`
code = ${JSON.stringify(invalidCode)}
context = module.build_analysis_context(code, 'broken.py', 'python')
assert context.ast_tree is None and 'IndentationError at line 3' in context.tokenizer_error
assert any(item.startswith('Tokenizer warning:') for item in context.notes)
assert any(item.startswith('AST warning:') for item in context.notes)
unfinished = module.build_analysis_context('value = (1\\n', 'unfinished.py', 'python')
assert unfinished.ast_tree is None and 'TokenError' in unfinished.tokenizer_error
observed = dict(tokenizer_error=context.tokenizer_error, ast_error=context.ast_error,
                unfinished_tokenizer_error=unfinished.tokenizer_error, notes=context.notes)
`},
    {name:"python-contextual-soft-keywords", finding:"A02-F002", script:`
ordinary = module.build_analysis_context('match = 1\\ncase = match + 1\\n', 'ordinary.py', 'python')
assert ordinary.identifiers == ['match', 'case', 'match'] and not ordinary.ast_error
roles = module.build_analysis_context('match match:\\n    case case:\\n        value = case\\n', 'roles.py', 'python')
assert roles.identifiers.count('match') == 1 and roles.identifiers.count('case') == 2
assert roles.tokens_operators.count('match') == 1 and roles.tokens_operators.count('case') == 1
literal = module.build_analysis_context("value = 'match case'\\n# match case\\n", 'literal.py', 'python')
assert literal.identifiers == ['value']
modern = module.build_analysis_context('type Alias = int\\n', 'modern.py', 'python')
assert modern.ast_tree is None and modern.ast_error and 'type' in modern.identifiers
observed = dict(ordinary=ordinary.identifiers, mixed_identifiers=roles.identifiers,
                mixed_operators=roles.tokens_operators, literal_identifiers=literal.identifiers,
                unsupported_type_ast_error=modern.ast_error)
`},
    {name:"python-import-binding-reads", finding:"A02-F008", script:`
cases = [
    ('direct-read', 'import os\\nos.getcwd()\\n', 1),
    ('rebound', 'import os\\nos = 3\\n', 0),
    ('deleted', 'import os\\ndel os\\n', 0),
    ('parameter-shadow', 'import os\\ndef f(os):\\n    return os\\n', 0),
    ('alias-read', 'import os as system\\nsystem.getcwd()\\n', 1),
    ('closure-read', 'import os\\ndef f():\\n    return os.getcwd()\\n', 1),
]
observed = []
for name, code, used in cases:
    context = module.build_analysis_context(code, 'imports.py', 'python')
    usage = context.python_import_usage
    metric = module.UsedImportRatioMetric({}).compute(code, 'python', context)
    assert usage['status'] == 'bounded-static' and usage['imported'] == 1 and usage['used'] == used
    assert metric.applicable and metric.value == float(used)
    observed.append(dict(case=name, usage=usage, metric_value=metric.value, detail=metric.detail))
code = 'import os\\ndef f():\\n    global os\\n    return os.getcwd()\\n'
context = module.build_analysis_context(code, 'ambiguous.py', 'python')
metric = module.UsedImportRatioMetric({}).compute(code, 'python', context)
assert context.python_import_usage['status'] == 'unavailable' and context.python_import_usage['limitations']
assert not metric.applicable and metric.value is None
observed.append(dict(case='global-ambiguity', usage=context.python_import_usage, metric_value=metric.value,
                     applicable=metric.applicable, explanation=metric.explanation, detail=metric.detail))
`},
    {name:"python-parameter-source-order", finding:"A02-F009", script:`
code = 'def order(a, /, b, *args, c, **kwargs):\\n    return a\\n\\nasync def simple(value):\\n    return value\\n'
context = module.build_analysis_context(code, 'parameters.py', 'python')
actual = [[f.name, f.parameters, f.lineno, f.end_lineno] for f in context.functions]
assert actual == [['order', ['a', 'b', 'args', 'c', 'kwargs'], 1, 2], ['simple', ['value'], 4, 5]]
observed = actual
`},
    {name:"python-comment-mask-coordinates", finding:"A02-F010", script:`
code = '# α\\r\\nλ=1 # z\\r\\n\\r\\n# fin'
scan = module.scan_python(code)
actual = dict(cleaned_code=scan.cleaned_code, comments=scan.comment_texts,
              comment_lines=sorted(scan.comment_line_numbers), code_lines=sorted(scan.code_line_numbers))
assert actual == dict(cleaned_code='   \\r\\nλ=1    \\r\\n\\r\\n     ', comments=['# α', '# z', '# fin'],
                      comment_lines=[1, 2, 4], code_lines=[2]) and not scan.tokenizer_error
observed = actual
`},
    {name:"python-per-callable-complexity", finding:"A02-F011", script:`
cases = [
    ('inner-only', 'def outer(x):\\n    def inner(y):\\n        if y:\\n            return 1\\n        return 0\\n    return inner(x)\\n',
     [['outer', 1, 6, 1], ['inner', 2, 5, 2]]),
    ('outer-only', 'def outer(x):\\n    def inner(y):\\n        return y\\n    if x:\\n        return inner(x)\\n    return 0\\n',
     [['outer', 1, 6, 2], ['inner', 2, 3, 1]]),
    ('nested-default', 'def outer(flag):\\n    def inner(value=1 if flag else 0):\\n        return value\\n    return inner()\\n',
     [['outer', 1, 4, 2], ['inner', 2, 3, 1]]),
]
observed = []
for name, code, expected in cases:
    context = module.build_analysis_context(code, 'callables.py', 'python')
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert actual == expected
    tree = ast.parse(code)
    source_functions = sorted((node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))), key=lambda node: node.lineno)
    assert [f.ast_signature for f in context.functions] == [Counter(type(child).__name__ for child in ast.walk(node)) for node in source_functions]
    observed.append(dict(case=name, functions=actual, whole_ast_signatures_preserved=True))
`},
  ];
  fixtureState.reset();
  const pageUrl = `${baseUrl}/app/index.html?python-i07=1`;
  let session = null, workerSession = null, ownership = null, actualRuntime = null;
  try {
    await withinCase("python-owned-worker", [], "authenticated-worker-ownership", async () => {
      await cdp.send("Target.setDiscoverTargets", {discover:true});
      const previous = new Set((await cdp.send("Target.getTargets")).targetInfos.map(item => item.targetId));
      session = await createSession(cdp, pageUrl);
      await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()", 60000);
      assertSingleVerifiedRequests(fixtureState);
      await cdp.send("Target.setAutoAttach", {autoAttach:true, waitForDebuggerOnStart:false, flatten:true,
        filter:[{type:"worker"}, {exclude:true}]}, session.sessionId);
      const discoveryDeadline = Date.now() + 5000;
      let workers = [], attachments = [];
      do {
        workers = (await cdp.send("Target.getTargets")).targetInfos.filter(item => item.type === "worker" && !previous.has(item.targetId) && item.parentId === session.targetId);
        attachments = [...cdp.attachedTargets.entries()].filter(([, item]) => item.parentSessionId === session.sessionId && workers.some(worker => worker.targetId === item.targetInfo.targetId));
        if (workers.length && attachments.length) break;
        await delay(100);
      } while (Date.now() < discoveryDeadline);
      assert(workers.length === 1 && attachments.length === 1, "Python oracle did not locate exactly one owned worker channel");
      const worker = workers[0];
      if (worker.openerId) assert(worker.openerId === session.targetId, "Python oracle worker opener differs from its owned page");
      assert(attachments[0][1].targetInfo.type === "worker" && attachments[0][1].targetInfo.parentId === session.targetId, "Python oracle attachment differs from its owned worker");
      [workerSession] = attachments[0];
      await cdp.send("Runtime.enable", {}, workerSession);
      const workerBase = await evaluate(cdp, workerSession, "self.CODEPROBE_BASE_URL");
      assert(workerBase === pageUrl, "Python oracle worker bootstrap URL differs from its owned page");
      ownership = {page_target_id:session.targetId, worker_target_id:worker.targetId, worker_parent_id:worker.parentId, bootstrap_url:workerBase};
      return ownership;
    });
    for (const item of directCases) {
      await withinCase(item.name, [item.finding], "context-in-authenticated-worker", async () => {
        const script = "def _codeprobe_python_i07_fixture():\n    import ast, json, sys\n    from collections import Counter\n    module = sys.modules['codeprobe_runtime']\n" +
          item.script.trim().split("\n").map(line => "    " + line).join("\n") +
          "\n    metadata = json.loads(module.codeprobe_engine_metadata('{}'))\n    return json.dumps(dict(observed=observed, runtime=metadata['python_runtime'], measured_sha256=metadata['engine_fingerprint']['value']), allow_nan=False)\n_codeprobe_python_i07_fixture()\n";
        const result = await evaluate(cdp, workerSession, `(async () => {
          const runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
          try { return JSON.parse(runtime.runPython(${JSON.stringify(script)})); }
          finally { runtime.globals.delete('_codeprobe_python_i07_fixture'); }
        })()`);
        assert(result.runtime.platform === "emscripten" && result.runtime.version === "3.11.3", "Python context oracle used an unexpected interpreter");
        assert(result.measured_sha256 === engineDigest, "Python context oracle used different engine bytes");
        actualRuntime = result.runtime;
        assertSingleVerifiedRequests(fixtureState);
        return {...result, oracle_sha256:crypto.createHash("sha256").update(script).digest("hex")};
      });
    }
  } finally {
    if (workerSession) await cdp.send("Target.detachFromTarget", {sessionId:workerSession}, session.sessionId);
    if (session) await closeSession(cdp, session);
    await cdp.send("Target.setDiscoverTargets", {discover:false});
  }
  for (const mode of ["main-file", "main-project", "compact-project"]) {
    const compact = mode.startsWith("compact"), kind = mode.endsWith("file") ? "file" : "project";
    const fitted = parserFixtures.cases.find(item => item.syntax === "common" && item.kind === kind);
    assert(fitted, `missing current-engine common-syntax ${kind} profile control`);
    fixtureState.reset();
    let page = null, id = null;
    const active = compact ? "state" : "appState";
    const button = compact ? "analyseBtn" : "analyzeBtn", status = compact ? "status" : "statusText";
    const exportName = kind === "file" ? "broken" : compact ? "parser" : "selected-files";
    try {
      await withinCase(`${mode}-diagnostic-json-text-downloads`, ["A02-F001"], "public-ui-worker-report-exports", async () => {
        page = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?python-i07-${mode}=1`);
        id = page.sessionId;
        if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
        await evaluate(cdp, id, `(() => {
          const transfer = new DataTransfer();
          const file = new File([${JSON.stringify(invalidCode)}], 'broken.py', {type:'text/x-python'});
          if (${kind === "project"}) Object.defineProperty(file, '_codeprobeRelativePath', {value:'parser/broken.py'});
          transfer.items.add(file);
          const input = document.getElementById('${kind === "file" ? "fileInput" : "folderInput"}');
          input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, `${active}.loadingInput === false && !document.getElementById('${button}').disabled`, 60000);
        await evaluate(cdp, id, `document.getElementById('${button}').click()`);
        await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === '${kind === "file" ? "Analysis completed." : "Project analysis completed."}'`, 60000);
        const result = await evaluate(cdp, id, `({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value,
          warnings:document.getElementById('${compact ? "reviewPanel" : "warningsList"}').textContent})`);
        assert(result.report.report_kind === kind && result.report.engine_fingerprint.value === engineDigest, "diagnostic UI report identity differs");
        assert(result.report.warnings.some(value => value.includes("Tokenizer warning: IndentationError at line 3")) && result.report.warnings.some(value => value.includes("AST warning:")), "diagnostic report lost tokenizer or AST warning");
        assert(result.text.includes("Tokenizer warning: IndentationError at line 3") && result.warnings.includes("Tokenizer warning: IndentationError at line 3"), "diagnostic text or rendered warning is absent");
        if (kind === "project") {
          assert(result.report.included_file_count === 1 && result.report.included_files[0].warnings.some(value => value.includes("AST warning:")), "diagnostic project lost its member or child warning");
          assert(result.report.warnings.some(value => value.includes("broken.py") && value.includes("AST warning:")), "project warning lacks its member path");
        }
        fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
        await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
        await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
        const jsonPath = path.join(downloads, `${exportName}.json`), textPath = path.join(downloads, `${exportName}.txt`);
        await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
        assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(result.report), "diagnostic JSON download differs from accepted report");
        assert(fs.readFileSync(textPath, "utf8") === result.text, "diagnostic text download differs from accepted report");
        assertSingleVerifiedRequests(fixtureState);
        return {warnings:result.report.warnings, source_sha256:crypto.createHash("sha256").update(invalidCode).digest("hex"), engine_sha256:engineDigest, export_name:exportName};
      });
      await withinCase(`${mode}-bound-invalid-refused`, ["A02-F001"], "public-ui-profile-worker-refusal", async () => {
        const positive = await evaluate(cdp, id, `${active}.workerSession.analyse(${JSON.stringify(kind)}, ${JSON.stringify(fitted.payload)})`);
        assert(positive.report.engine_fingerprint.value === engineDigest && positive.report.calibration_profile_id === fitted.payload.calibration_profile.profile_id, "valid same-kind profile control was not accepted");
        await evaluate(cdp, id, `(() => {
          const profile = document.getElementById('calibrationProfile'); profile.value = ${JSON.stringify(JSON.stringify(fitted.payload.calibration_profile))};
          profile.dispatchEvent(new Event('input', {bubbles:true}));
          document.getElementById('${button}').click();
        })()`);
        await waitForExpression(cdp, id, `${active}.busy === false && document.getElementById('${status}').textContent.includes('failed; no report was accepted')`, 60000);
        assert(await evaluate(cdp, id, `!${active}.workerSession.isReady() && document.getElementById('exportJsonBtn').disabled && document.getElementById('exportTextBtn').disabled && ${compact ? "state.json === ''" : "appState.currentReport === null"}`), "invalid bound source retained a reusable worker or accepted report");
        return {valid_same_kind_control:"PASS", invalid_source:"REFUSED", exports_disabled:true, worker_disposed:true, profile_id:fitted.payload.calibration_profile.profile_id};
      });
    } finally { if (page) await closeSession(cdp, page); }
  }
  console.log("[PASS] browser-python-i07: " + JSON.stringify({engine_sha256:engineDigest, runtime:actualRuntime, ownership, observations,
    qualification:"Six internal context oracles ran in the owned authenticated worker interpreter; main file/main project/compact project used actual File/DOM, public worker transport and JSON/text downloads. Bound invalid cases followed valid same-kind profile controls. Comment-mask equivalence is not a browser complexity benchmark; type-alias syntax remains unsupported on pinned Python 3.11.3."}));
}

// C-family context metadata has no public worker operation. Fixed lexical
// oracles inspect the owned authenticated interpreter; warning/export cases
// separately exercise the existing public UI and worker transport.
async function testCLikeStructureContracts(cdp, baseUrl, downloads, fixtureState, engineDigest) {
  const deadline = Date.now() + 300000;
  const observations = [];
  async function withinCase(name, findings, boundary, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "C-family browser group exceeded its 300-second budget");
    const started = Date.now();
    let timer;
    try {
      const observed = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`C-family browser case timed out: ${name}`)), remaining);
      })]);
      const row = {case:name, findings, boundary, result:"PASS", elapsed_ms:Date.now() - started, observed};
      observations.push(row);
      console.log("[PASS] browser-cfamily-i08-case: " + JSON.stringify(row));
    } finally { clearTimeout(timer); }
  }
  const directCases = [
    {name:"c-cpp-spliced-comment-and-raw-control", finding:"A02-F003", script:`
code = '// continued comment \\\\\\nint phantom(void) { return 1; }\\nint real(void) { return 2; }\\n'
observed = []
for language, filename in [('c', 'spliced.c'), ('cpp', 'spliced.cpp')]:
    context = module.build_analysis_context(code, filename, language)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert actual == [['real', 3, 3, 1]] and 'phantom' not in context.identifiers
    assert len(context.cleaned_code) == len(code)
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n']
    observed.append(dict(language=language, functions=actual, physical_coordinates_preserved=True))
raw = 'const char *text = R"tag(// literal \\\\\\nint phantom(void) { return 1; }\\n)tag";\\nint real(void) { return 2; }\\n'
context = module.build_analysis_context(raw, 'raw.cpp', 'cpp')
assert [[f.name, f.lineno, f.end_lineno] for f in context.functions] == [['real', 4, 4]]
assert not context.comment_texts and 'phantom' not in context.identifiers
observed.append(dict(language='cpp', case='raw-splice-control', functions=[[f.name, f.lineno, f.end_lineno] for f in context.functions], comments=context.comment_texts))
`},
    {name:"csharp-raw-interpolation-and-unsafe-diagnostic", finding:"A02-F004", script:`
observed = []
for quote_count in (3, 4):
    quotes = '"' * quote_count
    code = 'class Demo {\\n string text = ' + quotes + '\\n int Phantom() { if (true) return 1; }\\n ' + quotes + ';\\n int Real() { return 0; }\\n}\\n'
    context = module.build_analysis_context(code, 'raw.cs', 'csharp')
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert actual == [['Real', 5, 5, 1]] and 'Phantom' not in context.identifiers and not context.comment_texts
    assert context.c_family_lexically_safe
    observed.append(dict(case='raw-' + str(quote_count), functions=actual, lexical_safe=True))
for label, literal in [('interpolation', '$"{format(\\"//\\")}"'), ('verbatim', '@"quoted ""//"" text"')]:
    code = 'class Demo { string text = ' + literal + '; int Real() { return 0; } }\\n'
    context = module.build_analysis_context(code, label + '.cs', 'csharp')
    assert [f.name for f in context.functions] == ['Real'] and not context.comment_texts and context.c_family_lexically_safe
    observed.append(dict(case=label, functions=[f.name for f in context.functions], comments=context.comment_texts))
code = 'class Demo {\\n string text = """unterminated\\n int Phantom() { return 1; }\\n}\\n'
context = module.build_analysis_context(code, 'unsafe.cs', 'csharp')
assert not context.c_family_lexically_safe and not context.functions
assert any(note.startswith('Tokenizer warning: C-family ') for note in context.notes)
observed.append(dict(case='unterminated-raw', lexical_safe=context.c_family_lexically_safe, functions=[], notes=context.notes))
`},
    {name:"c-family-unicode-and-csharp-verbatim-spelling", finding:"A02-F005", script:`
observed = []
for language, filename in [('c', 'names.c'), ('cpp', 'names.cpp'), ('csharp', 'names.cs')]:
    code = 'int café(int λ) { return λ; }\\nint cafe\\u0301(int λ) { return λ; }\\n'
    if language == 'csharp':
        code = 'class Demo {\\n' + code + '}\\n'
    context = module.build_analysis_context(code, filename, language)
    assert [f.name for f in context.functions] == ['café', 'cafe\\u0301']
    assert all(f.parameters == ['int λ'] for f in context.functions)
    assert context.identifiers.count('café') == 1 and context.identifiers.count('cafe\\u0301') == 1 and context.identifiers.count('λ') == 4
    observed.append(dict(language=language, names=[f.name for f in context.functions], parameters=[f.parameters for f in context.functions], identifiers=context.identifiers))
code = 'class Demo { int @class(int @return) { return @return; } }\\n'
context = module.build_analysis_context(code, 'verbatim.cs', 'csharp')
assert [f.name for f in context.functions] == ['@class'] and context.functions[0].parameters == ['int @return']
assert context.identifiers.count('@class') == 1 and context.identifiers.count('@return') == 2
assert '@class' not in context.tokens_operators and '@return' not in context.tokens_operators
observed.append(dict(language='csharp', case='verbatim', names=[f.name for f in context.functions], identifiers=context.identifiers))
`},
    {name:"c-family-explicit-extraction-subset-and-header-bound", finding:"A02-F006", script:`
observed = []
cases = [
    ('operator', 'cpp', 'operator.cpp', 'struct Number { Number operator+(const Number& other) const { return other; }\\n int Real() { return 0; }\\n};\\n'),
    ('expression-body', 'csharp', 'expression.cs', 'class Demo { int Hidden() => 1;\\n int Real() { return 0; }\\n}\\n'),
]
for name, language, filename, code in cases:
    context = module.build_analysis_context(code, filename, language)
    assert [f.name for f in context.functions] == ['Real']
    assert context.c_family_function_issues and any(note.startswith('C-family extraction warning:') for note in context.notes)
    observed.append(dict(case=name, functions=[f.name for f in context.functions], issues=context.c_family_function_issues, notes=context.notes))
for length in (799, 800, 801):
    prefix, suffix = 'int long_header(', 'int value)'
    header = prefix + ' ' * (length - len(prefix) - len(suffix)) + suffix
    assert len(header) == length
    code = header + '{ return value; }\\n'
    context = module.build_analysis_context(code, 'header.c', 'c')
    if length <= 800:
        assert [[f.name, f.lineno, f.end_lineno] for f in context.functions] == [['long_header', 1, 1]]
    else:
        assert not context.functions and context.c_family_function_issues
        assert any(note.startswith('C-family extraction warning:') for note in context.notes)
    observed.append(dict(case='header-' + str(length), functions=[[f.name, f.lineno, f.end_lineno] for f in context.functions], issues=context.c_family_function_issues))
`},
    {name:"c-family-declarator-initialiser-separation-and-proxies", finding:"A02-F007", script:`
observed = []
for expression in ('x < y', 'x > y', 'x <= y', '(x, y)'):
    code = 'int f(int x,int y) {\\n int a=' + expression + ',b=2;\\n return a+b;\\n}\\n'
    context = module.build_analysis_context(code, 'declarations.c', 'c')
    assert len(context.functions) == 1 and context.functions[0].name == 'f'
    function = context.functions[0]
    declarations = module.extract_local_declarations(function, 'c')
    assert [[d['name'], d['size'], d['absolute_line']] for d in declarations] == [['a', 4, 2], ['b', 4, 2]]
    pressure = module.register_pressure_profile(function, 'c')
    frame = module.stack_frame_profile(function, 'c')
    assert pressure['locals'] == 2 and frame['locals'] == 2 and frame['frame_bytes'] == 8
    observed.append(dict(case=expression, declarations=declarations, pressure=pressure, frame=frame))
code = 'int f(void) {\\n typedef int count_t;\\n count_t a = 1,\\n b = 2;\\n return a+b;\\n}\\n'
context = module.build_analysis_context(code, 'multiline.c', 'c')
declarations = module.extract_local_declarations(context.functions[0], 'c')
assert [d['name'] for d in declarations] == ['a', 'b'] and [d['size'] for d in declarations] == [4, 4]
observed.append(dict(case='multiline-local-typedef', declarations=declarations, qualification='Fixed type-size and lexical lifetime proxies; no actual register or stack measurement.'))
`}
  ];
  fixtureState.reset();
  const pageUrl = `${baseUrl}/app/index.html?cfamily-i08=1`;
  let session = null, workerSession = null, ownership = null, actualRuntime = null;
  try {
    await withinCase("cfamily-owned-worker", [], "authenticated-worker-ownership", async () => {
      await cdp.send("Target.setDiscoverTargets", {discover:true});
      const previous = new Set((await cdp.send("Target.getTargets")).targetInfos.map(item => item.targetId));
      session = await createSession(cdp, pageUrl);
      await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()", 60000);
      assertSingleVerifiedRequests(fixtureState);
      await cdp.send("Target.setAutoAttach", {autoAttach:true, waitForDebuggerOnStart:false, flatten:true,
        filter:[{type:"worker"}, {exclude:true}]}, session.sessionId);
      const discoveryDeadline = Date.now() + 5000;
      let workers = [], attachments = [];
      do {
        workers = (await cdp.send("Target.getTargets")).targetInfos.filter(item => item.type === "worker" && !previous.has(item.targetId) && item.parentId === session.targetId);
        attachments = [...cdp.attachedTargets.entries()].filter(([, item]) => item.parentSessionId === session.sessionId && workers.some(worker => worker.targetId === item.targetInfo.targetId));
        if (workers.length && attachments.length) break;
        await delay(100);
      } while (Date.now() < discoveryDeadline);
      assert(workers.length === 1 && attachments.length === 1, "C-family oracle did not locate exactly one owned worker channel");
      const worker = workers[0];
      if (worker.openerId) assert(worker.openerId === session.targetId, "C-family oracle worker opener differs from its owned page");
      assert(attachments[0][1].targetInfo.type === "worker" && attachments[0][1].targetInfo.parentId === session.targetId, "C-family oracle attachment differs from its owned worker");
      [workerSession] = attachments[0];
      await cdp.send("Runtime.enable", {}, workerSession);
      const workerBase = await evaluate(cdp, workerSession, "self.CODEPROBE_BASE_URL");
      assert(workerBase === pageUrl, "C-family oracle worker bootstrap URL differs from its owned page");
      ownership = {page_target_id:session.targetId, worker_target_id:worker.targetId, worker_parent_id:worker.parentId, bootstrap_url:workerBase};
      return ownership;
    });
    for (const item of directCases) {
      await withinCase(item.name, [item.finding], "context-in-authenticated-worker", async () => {
        const script = "def _codeprobe_cfamily_i08_fixture():\n    import json, sys\n    module = sys.modules['codeprobe_runtime']\n" +
          item.script.trim().split("\n").map(line => "    " + line).join("\n") +
          "\n    metadata = json.loads(module.codeprobe_engine_metadata('{}'))\n    return json.dumps(dict(observed=observed, runtime=metadata['python_runtime'], measured_sha256=metadata['engine_fingerprint']['value']), allow_nan=False)\n_codeprobe_cfamily_i08_fixture()\n";
        const result = await evaluate(cdp, workerSession, `(async () => {
          const runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
          try { return JSON.parse(runtime.runPython(${JSON.stringify(script)})); }
          finally { runtime.globals.delete('_codeprobe_cfamily_i08_fixture'); }
        })()`);
        assert(result.runtime.platform === "emscripten" && result.runtime.version === "3.11.3", "C-family context oracle used an unexpected interpreter");
        assert(result.measured_sha256 === engineDigest, "C-family context oracle used different engine bytes");
        actualRuntime = result.runtime;
        assertSingleVerifiedRequests(fixtureState);
        return {...result, oracle_sha256:crypto.createHash("sha256").update(script).digest("hex")};
      });
    }
  } finally {
    if (workerSession) await cdp.send("Target.detachFromTarget", {sessionId:workerSession}, session.sessionId);
    if (session) await closeSession(cdp, session);
    await cdp.send("Target.setDiscoverTargets", {discover:false});
  }

  const warningCases = [
    {name:"unsafe-raw", finding:"A02-F004", prefix:"Tokenizer warning: C-family ", code:'class Demo {\n string text = """unterminated\n int Phantom() { return 1; }\n}\n'},
    {name:"expression-body", finding:"A02-F006", prefix:"C-family extraction warning:", code:'class Demo { int Hidden() => 1;\n int Real() { return 0; }\n}\n'},
  ];
  for (const mode of ["main-file", "main-project", "compact-project"]) {
    const compact = mode.startsWith("compact"), kind = mode.endsWith("file") ? "file" : "project";
    fixtureState.reset();
    let page = null, id = null;
    const active = compact ? "state" : "appState";
    const button = compact ? "analyseBtn" : "analyzeBtn", status = compact ? "status" : "statusText";
    const exportName = kind === "file" ? "bounded" : compact ? "cfamily" : "selected-files";
    try {
      for (const item of warningCases) {
        await withinCase(`${mode}-${item.name}-json-text-downloads`, [item.finding], "public-ui-worker-report-exports", async () => {
          if (!page) {
            page = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?cfamily-i08-${mode}=1`);
            id = page.sessionId;
            if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
          }
          await evaluate(cdp, id, `(() => {
            const transfer = new DataTransfer();
            const file = new File([${JSON.stringify(item.code)}], 'bounded.cs', {type:'text/plain'});
            if (${kind === "project"}) Object.defineProperty(file, '_codeprobeRelativePath', {value:'cfamily/bounded.cs'});
            transfer.items.add(file);
            const input = document.getElementById('${kind === "file" ? "fileInput" : "folderInput"}');
            input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles:true}));
          })()`);
          await waitForExpression(cdp, id, `${active}.loadingInput === false && !document.getElementById('${button}').disabled`, 60000);
          await evaluate(cdp, id, `document.getElementById('${button}').click()`);
          await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === '${kind === "file" ? "Analysis completed." : "Project analysis completed."}'`, 60000);
          const result = await evaluate(cdp, id, `({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value,
            warnings:document.getElementById('${compact ? "reviewPanel" : "warningsList"}').textContent})`);
          assert(result.report.report_kind === kind && result.report.engine_fingerprint.value === engineDigest, "C-family UI report identity differs");
          assert(result.report.engine_fingerprint.source === "packaged-verified", "C-family UI report lost authenticated engine provenance");
          assert(result.report.warnings.some(value => value.includes(item.prefix)), "C-family diagnostic report lost its warning");
          assert(result.text.includes(item.prefix) && result.warnings.includes(item.prefix), "C-family diagnostic text or rendered warning is absent");
          if (kind === "project") {
            assert(result.report.included_file_count === 1 && result.report.included_files[0].warnings.some(value => value.includes(item.prefix)), "C-family project lost its member or child warning");
            assert(result.report.warnings.some(value => value.includes("bounded.cs") && value.includes(item.prefix)), "C-family project warning lacks its member path");
          }
          fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
          await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
          await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
          const jsonPath = path.join(downloads, `${exportName}.json`), textPath = path.join(downloads, `${exportName}.txt`);
          await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
          assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(result.report), "C-family JSON download differs from accepted report");
          assert(fs.readFileSync(textPath, "utf8") === result.text, "C-family text download differs from accepted report");
          assertSingleVerifiedRequests(fixtureState);
          return {warnings:result.report.warnings, source_sha256:crypto.createHash("sha256").update(item.code).digest("hex"), engine_sha256:engineDigest, export_name:exportName};
        });
      }
    } finally { if (page) await closeSession(cdp, page); }
  }
  console.log("[PASS] browser-cfamily-i08: " + JSON.stringify({engine_sha256:engineDigest, runtime:actualRuntime, ownership, observations,
    qualification:"Five finite C-family context groups ran in the owned authenticated worker interpreter; main file/main project/compact project used actual File/DOM, public worker transport and JSON/text downloads for lexical and extraction warnings. The supported subset is bounded; these fixtures do not establish full compiler semantics or real register/stack measurements."}));
}

// JavaScript/Bash context metadata has no public worker operation. Fixed lexical
// oracles inspect the owned authenticated interpreter; warning/export cases
// separately exercise the existing public UI and worker transport.
async function testScriptStructureContracts(cdp, baseUrl, downloads, fixtureState, engineDigest) {
  const deadline = Date.now() + 300000;
  const observations = [];
  async function withinCase(name, findings, boundary, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "JavaScript/Bash browser group exceeded its 300-second budget");
    const started = Date.now();
    let timer;
    try {
      const observed = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`JavaScript/Bash browser case timed out: ${name}`)), remaining);
      })]);
      const row = {case:name, findings, boundary, result:"PASS", elapsed_ms:Date.now() - started, observed};
      observations.push(row);
      console.log("[PASS] browser-scripts-i09-case: " + JSON.stringify(row));
    } finally { clearTimeout(timer); }
  }
  const directCases = [
    {name:"bash-hash-and-heredoc-data", finding:"A02-F012", script:`
cases = [
    {'id': 'SH-01-comment-control', 'finding': 'F012', 'source': 'echo ok # actual comment\\n', 'language': 'bash', 'filename': 'SH-01-comment-control.sh', 'expected': {'comments': [1], 'lexical_error': False}},
    {'id': 'SH-03-word-hash', 'finding': 'F012', 'source': 'echo alpha#beta\\n', 'language': 'bash', 'filename': 'SH-03-word-hash.sh', 'expected': {'comments': [], 'lexical_error': False, 'cleaned_contains': ['alpha#beta']}},
    {'id': 'SH-04-length-expansion', 'finding': 'F012', 'source': 'echo \\u0024{#name}\\n', 'language': 'bash', 'filename': 'SH-04-length-expansion.sh', 'expected': {'comments': [], 'lexical_error': False}},
    {'id': 'SH-05-prefix-expansion', 'finding': 'F012', 'source': 'echo \\u0024{name#prefix}\\n', 'language': 'bash', 'filename': 'SH-05-prefix-expansion.sh', 'expected': {'comments': [], 'lexical_error': False}},
    {'id': 'SH-08-heredoc-phantom', 'finding': 'F012', 'source': "cat <<'EOF'\\nphantom() {\\n echo text\\n}\\nEOF\\nreal() {\\n echo ok\\n}\\n", 'language': 'bash', 'filename': 'SH-08-heredoc-phantom.sh', 'expected': {'functions': [['real', 6, 8, 1]], 'lexical_error': False, 'identifiers_absent': ['phantom']}},
    {'id': 'sh-queued-quoted-heredocs', 'finding': 'A02-F012', 'language': 'bash', 'source': 'cat <<\\'ONE\\' <<-"TWO"\\nPhantom1() { if true; then :; fi; }\\nONE\\n\\tPhantom2() { for x in a; do :; done; }\\n\\tTWO\\nreal() {\\n :\\n}\\n', 'filename': 'sh-queued-quoted-heredocs.sh', 'expected': {'functions': [['real', 6, 8, 1]], 'comments': [], 'lexical_error': False, 'identifiers_absent': ['Phantom1', 'Phantom2']}, 'rationale': 'Two heredocs are consumed in declaration order; the second uses tab-stripped delimiter matching.'}
]

observed = []
for case in cases:
    code, language, expected = case['source'], case['language'], case['expected']
    context = module.build_analysis_context(code, case['filename'], language)
    scan = {'javascript': module.scan_javascript, 'bash': module.scan_bash}[language](code)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert len(context.cleaned_code) == len(code), case['id']
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n'], case['id']
    for key, value in [('functions', actual), ('identifiers', context.identifiers), ('comments', sorted(scan.comment_line_numbers)), ('lexical_error', bool(context.tokenizer_error))]:
        if key in expected:
            assert value == expected[key], (case['id'], key, value, expected[key])
    for text in expected.get('cleaned_contains', []):
        assert text in context.cleaned_code, (case['id'], text)
    for text in expected.get('cleaned_absent', []):
        assert text not in context.cleaned_code, (case['id'], text)
    for name in expected.get('identifiers_absent', []):
        assert name not in context.identifiers, (case['id'], name)
    for function in context.functions:
        physical = '\\n'.join(code.split('\\n')[function.lineno - 1:function.end_lineno])
        assert function.body == physical and function.length == function.end_lineno - function.lineno + 1, case['id']
        if case.get('verify_signature'):
            assert function.signature == physical.split('\\n')[0].strip(), (case['id'], function.signature)
    metrics = {}
    if expected.get('lexical_error'):
        assert not context.script_lexically_safe, case['id']
        assert expected['diagnostic_code'] in context.tokenizer_error, case['id']
        result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=code, filename=case['filename'], language_hint=language))))
        report = result['report']
        assert any(expected['diagnostic_code'] in warning for warning in report['warnings']), case['id']
        assert expected['diagnostic_code'] in result['text'], case['id']
        by_name = {item['name']: item for item in report['metrics']}
        for name in expected['unavailable']:
            metric = by_name[name]
            assert metric['applicable'] is False and metric['value'] is None, (case['id'], name)
            metrics[name] = dict(applicable=metric['applicable'], value=metric['value'])
    observed.append(dict(case=case['id'], functions=actual, identifiers=context.identifiers,
                         comments=sorted(scan.comment_line_numbers), tokenizer_error=context.tokenizer_error,
                         notes=context.notes, unavailable_metrics=metrics, original_body_and_coordinates_preserved=True))
`},
    {name:"javascript-regex-export-arrow-and-template", finding:"A02-F013", script:`
cases = [
    {'id': 'JS-03-regex-after-control', 'finding': 'F013', 'source': 'function f(ok, x) {\\n if (ok) /[}]/.test(x);\\n return x;\\n}\\n', 'language': 'javascript', 'filename': 'JS-03-regex-after-control.js', 'expected': {'functions': [['f', 1, 4, 2]], 'lexical_error': False, 'cleaned_absent': ['[}]']}},
    {'id': 'JS-04-export-function', 'finding': 'F013', 'source': 'export function add(a, b) {\\n return a + b;\\n}\\n', 'language': 'javascript', 'filename': 'a.mjs', 'expected': {'functions': [['add', 1, 3, 1]], 'lexical_error': False}},
    {'id': 'JS-06-arrow-destructuring', 'finding': 'F013', 'source': 'const pick = ({value}) => {\\n return value;\\n};\\n', 'language': 'javascript', 'filename': 'JS-06-arrow-destructuring.js', 'expected': {'functions': [['pick', 1, 3, 1]], 'lexical_error': False}},
    {'id': 'JS-08-template-interpolation', 'finding': 'F013', 'source': 'const text = \`value: \\u0024{lookup(value)}\`;\\n', 'language': 'javascript', 'filename': 'JS-08-template-interpolation.js', 'expected': {'identifiers': ['text', 'lookup', 'value'], 'lexical_error': False, 'cleaned_contains': ['lookup(value)']}},
    {'id': 'JS-19-division-after-call', 'finding': 'F013', 'source': 'function ratio(a, b) {\\n return get(a) / b;\\n}\\n', 'language': 'javascript', 'filename': 'JS-19-division-after-call.js', 'expected': {'functions': [['ratio', 1, 3, 1]], 'lexical_error': False, 'cleaned_contains': ['get(a) / b']}}
]

observed = []
for case in cases:
    code, language, expected = case['source'], case['language'], case['expected']
    context = module.build_analysis_context(code, case['filename'], language)
    scan = {'javascript': module.scan_javascript, 'bash': module.scan_bash}[language](code)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert len(context.cleaned_code) == len(code), case['id']
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n'], case['id']
    for key, value in [('functions', actual), ('identifiers', context.identifiers), ('comments', sorted(scan.comment_line_numbers)), ('lexical_error', bool(context.tokenizer_error))]:
        if key in expected:
            assert value == expected[key], (case['id'], key, value, expected[key])
    for text in expected.get('cleaned_contains', []):
        assert text in context.cleaned_code, (case['id'], text)
    for text in expected.get('cleaned_absent', []):
        assert text not in context.cleaned_code, (case['id'], text)
    for name in expected.get('identifiers_absent', []):
        assert name not in context.identifiers, (case['id'], name)
    for function in context.functions:
        physical = '\\n'.join(code.split('\\n')[function.lineno - 1:function.end_lineno])
        assert function.body == physical and function.length == function.end_lineno - function.lineno + 1, case['id']
        if case.get('verify_signature'):
            assert function.signature == physical.split('\\n')[0].strip(), (case['id'], function.signature)
    metrics = {}
    if expected.get('lexical_error'):
        assert not context.script_lexically_safe, case['id']
        assert expected['diagnostic_code'] in context.tokenizer_error, case['id']
        result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=code, filename=case['filename'], language_hint=language))))
        report = result['report']
        assert any(expected['diagnostic_code'] in warning for warning in report['warnings']), case['id']
        assert expected['diagnostic_code'] in result['text'], case['id']
        by_name = {item['name']: item for item in report['metrics']}
        for name in expected['unavailable']:
            metric = by_name[name]
            assert metric['applicable'] is False and metric['value'] is None, (case['id'], name)
            metrics[name] = dict(applicable=metric['applicable'], value=metric['value'])
    observed.append(dict(case=case['id'], functions=actual, identifiers=context.identifiers,
                         comments=sorted(scan.comment_line_numbers), tokenizer_error=context.tokenizer_error,
                         notes=context.notes, unavailable_metrics=metrics, original_body_and_coordinates_preserved=True))
`},
    {name:"script-cleaned-complexity-and-original-evidence", finding:"A02-F014", script:`
cases = [
    {'id': 'JS-14-complexity-comment', 'finding': 'F014', 'source': 'function f() {\\n // if for while catch && ||\\n return 1;\\n}\\n', 'language': 'javascript', 'filename': 'JS-14-complexity-comment.js', 'expected': {'functions': [['f', 1, 4, 1]], 'lexical_error': False}},
    {'id': 'JS-15-complexity-string', 'finding': 'F014', 'source': 'function f() {\\n return "if for while catch && ||";\\n}\\n', 'language': 'javascript', 'filename': 'JS-15-complexity-string.js', 'expected': {'functions': [['f', 1, 3, 1]], 'lexical_error': False}},
    {'id': 'JS-16-complexity-regex', 'finding': 'F014', 'source': 'function f() {\\n return /if|for|while|catch|&&|\\\\|\\\\|/;\\n}\\n', 'language': 'javascript', 'filename': 'JS-16-complexity-regex.js', 'expected': {'functions': [['f', 1, 3, 1]], 'lexical_error': False}},
    {'id': 'JS-17-complexity-template', 'finding': 'F014', 'source': 'function f() {\\n return \`if for while catch && ||\`;\\n}\\n', 'language': 'javascript', 'filename': 'JS-17-complexity-template.js', 'expected': {'functions': [['f', 1, 3, 1]], 'lexical_error': False}},
    {'id': 'JS-18-real-branch-control', 'finding': 'F014', 'source': 'function f(ok) {\\n if (ok) return 1;\\n return 0;\\n}\\n', 'language': 'javascript', 'filename': 'JS-18-real-branch-control.js', 'expected': {'functions': [['f', 1, 4, 2]], 'lexical_error': False}},
    {'id': 'SH-11-complexity-comment', 'finding': 'F014', 'source': 'f() {\\n # if for while until && ||\\n echo ok\\n}\\n', 'language': 'bash', 'filename': 'SH-11-complexity-comment.sh', 'expected': {'functions': [['f', 1, 4, 1]], 'lexical_error': False}},
    {'id': 'SH-12-complexity-string', 'finding': 'F014', 'source': 'f() {\\n echo "if for while until && ||"\\n}\\n', 'language': 'bash', 'filename': 'SH-12-complexity-string.sh', 'expected': {'functions': [['f', 1, 3, 1]], 'lexical_error': False}},
    {'id': 'SH-13-complexity-heredoc', 'finding': 'F014', 'source': "f() {\\n cat <<'EOF'\\nif for while until && ||\\nEOF\\n}\\n", 'language': 'bash', 'filename': 'SH-13-complexity-heredoc.sh', 'expected': {'functions': [['f', 1, 5, 1]], 'lexical_error': False}},
    {'id': 'SH-14-real-branch-control', 'finding': 'F014', 'source': 'f() {\\n if test -n "\\u0024value"; then\\n  echo ok\\n fi\\n}\\n', 'language': 'bash', 'filename': 'SH-14-real-branch-control.sh', 'expected': {'functions': [['f', 1, 5, 2]], 'lexical_error': False}},
    {'id': 'js-template-executable-contrast', 'finding': 'A02-F014', 'language': 'javascript', 'filename': 'js-template-executable-contrast.js', 'source': 'function f(flag) {\\n return \`if for \\u0024{flag && call()}\`;\\n}\\n', 'expected': {'functions': [['f', 1, 3, 2]], 'cleaned_contains': ['flag && call()'], 'identifiers_absent': ['if', 'for'], 'lexical_error': False}, 'rationale': 'Supported template substitution retains executable conjunction while template text containing branch words remains inert.'}
]

observed = []
for case in cases:
    code, language, expected = case['source'], case['language'], case['expected']
    context = module.build_analysis_context(code, case['filename'], language)
    scan = {'javascript': module.scan_javascript, 'bash': module.scan_bash}[language](code)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert len(context.cleaned_code) == len(code), case['id']
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n'], case['id']
    for key, value in [('functions', actual), ('identifiers', context.identifiers), ('comments', sorted(scan.comment_line_numbers)), ('lexical_error', bool(context.tokenizer_error))]:
        if key in expected:
            assert value == expected[key], (case['id'], key, value, expected[key])
    for text in expected.get('cleaned_contains', []):
        assert text in context.cleaned_code, (case['id'], text)
    for text in expected.get('cleaned_absent', []):
        assert text not in context.cleaned_code, (case['id'], text)
    for name in expected.get('identifiers_absent', []):
        assert name not in context.identifiers, (case['id'], name)
    for function in context.functions:
        physical = '\\n'.join(code.split('\\n')[function.lineno - 1:function.end_lineno])
        assert function.body == physical and function.length == function.end_lineno - function.lineno + 1, case['id']
        if case.get('verify_signature'):
            assert function.signature == physical.split('\\n')[0].strip(), (case['id'], function.signature)
    metrics = {}
    if expected.get('lexical_error'):
        assert not context.script_lexically_safe, case['id']
        assert expected['diagnostic_code'] in context.tokenizer_error, case['id']
        result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=code, filename=case['filename'], language_hint=language))))
        report = result['report']
        assert any(expected['diagnostic_code'] in warning for warning in report['warnings']), case['id']
        assert expected['diagnostic_code'] in result['text'], case['id']
        by_name = {item['name']: item for item in report['metrics']}
        for name in expected['unavailable']:
            metric = by_name[name]
            assert metric['applicable'] is False and metric['value'] is None, (case['id'], name)
            metrics[name] = dict(applicable=metric['applicable'], value=metric['value'])
    observed.append(dict(case=case['id'], functions=actual, identifiers=context.identifiers,
                         comments=sorted(scan.comment_line_numbers), tokenizer_error=context.tokenizer_error,
                         notes=context.notes, unavailable_metrics=metrics, original_body_and_coordinates_preserved=True))
`},
    {name:"script-eof-diagnostics-and-availability", finding:"A02-F016", script:`
cases = [
    {'id': 'JS-09-unclosed-comment', 'finding': 'F016', 'source': 'function f() {}\\n/* unfinished', 'language': 'javascript', 'filename': 'JS-09-unclosed-comment.js', 'expected': {'lexical_error': True, 'unavailable': ['cyclomatic_complexity', 'halstead_difficulty'], 'diagnostic_code': 'JS_UNTERMINATED_COMMENT'}},
    {'id': 'JS-10-unclosed-string', 'finding': 'F016', 'source': 'const message = "unfinished', 'language': 'javascript', 'filename': 'JS-10-unclosed-string.js', 'expected': {'lexical_error': True, 'unavailable': ['cyclomatic_complexity', 'halstead_difficulty'], 'diagnostic_code': 'JS_UNTERMINATED_STRING'}},
    {'id': 'JS-11-unclosed-template', 'finding': 'F016', 'source': 'const message = \`unfinished', 'language': 'javascript', 'filename': 'JS-11-unclosed-template.js', 'expected': {'lexical_error': True, 'unavailable': ['cyclomatic_complexity', 'halstead_difficulty'], 'diagnostic_code': 'JS_UNTERMINATED_TEMPLATE'}},
    {'id': 'JS-21-eof-line-comment-control', 'finding': 'F016', 'source': 'function f() { return 1; } // EOF', 'language': 'javascript', 'filename': 'JS-21-eof-line-comment-control.js', 'expected': {'functions': [['f', 1, 1, 1]], 'comments': [1], 'lexical_error': False}},
    {'id': 'SH-10-unclosed-quote', 'finding': 'F016', 'source': "echo 'unfinished", 'language': 'bash', 'filename': 'SH-10-unclosed-quote.sh', 'expected': {'lexical_error': True, 'unavailable': ['cyclomatic_complexity', 'halstead_difficulty'], 'diagnostic_code': 'BASH_UNTERMINATED_STRING'}},
    {'id': 'SH-16-unclosed-double-quote', 'finding': 'F016', 'source': 'echo "unfinished', 'language': 'bash', 'filename': 'SH-16-unclosed-double-quote.sh', 'expected': {'lexical_error': True, 'unavailable': ['cyclomatic_complexity', 'halstead_difficulty'], 'diagnostic_code': 'BASH_UNTERMINATED_STRING'}},
    {'id': 'SH-17-eof-comment-control', 'finding': 'F016', 'source': 'f() { echo ok; } # EOF', 'language': 'bash', 'filename': 'SH-17-eof-comment-control.sh', 'expected': {'functions': [['f', 1, 1, 1]], 'comments': [1], 'lexical_error': False}}
]

observed = []
for case in cases:
    code, language, expected = case['source'], case['language'], case['expected']
    context = module.build_analysis_context(code, case['filename'], language)
    scan = {'javascript': module.scan_javascript, 'bash': module.scan_bash}[language](code)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert len(context.cleaned_code) == len(code), case['id']
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n'], case['id']
    for key, value in [('functions', actual), ('identifiers', context.identifiers), ('comments', sorted(scan.comment_line_numbers)), ('lexical_error', bool(context.tokenizer_error))]:
        if key in expected:
            assert value == expected[key], (case['id'], key, value, expected[key])
    for text in expected.get('cleaned_contains', []):
        assert text in context.cleaned_code, (case['id'], text)
    for text in expected.get('cleaned_absent', []):
        assert text not in context.cleaned_code, (case['id'], text)
    for name in expected.get('identifiers_absent', []):
        assert name not in context.identifiers, (case['id'], name)
    for function in context.functions:
        physical = '\\n'.join(code.split('\\n')[function.lineno - 1:function.end_lineno])
        assert function.body == physical and function.length == function.end_lineno - function.lineno + 1, case['id']
        if case.get('verify_signature'):
            assert function.signature == physical.split('\\n')[0].strip(), (case['id'], function.signature)
    metrics = {}
    if expected.get('lexical_error'):
        assert not context.script_lexically_safe, case['id']
        assert expected['diagnostic_code'] in context.tokenizer_error, case['id']
        result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=code, filename=case['filename'], language_hint=language))))
        report = result['report']
        assert any(expected['diagnostic_code'] in warning for warning in report['warnings']), case['id']
        assert expected['diagnostic_code'] in result['text'], case['id']
        by_name = {item['name']: item for item in report['metrics']}
        for name in expected['unavailable']:
            metric = by_name[name]
            assert metric['applicable'] is False and metric['value'] is None, (case['id'], name)
            metrics[name] = dict(applicable=metric['applicable'], value=metric['value'])
    observed.append(dict(case=case['id'], functions=actual, identifiers=context.identifiers,
                         comments=sorted(scan.comment_line_numbers), tokenizer_error=context.tokenizer_error,
                         notes=context.notes, unavailable_metrics=metrics, original_body_and_coordinates_preserved=True))
`},
    {name:"javascript-dollar-and-unicode-spelling", finding:"A02-F017", script:`
cases = [
    {'id': 'JS-05-unicode-function', 'finding': 'F017', 'source': 'function λ(value) {\\n return value;\\n}\\n', 'language': 'javascript', 'filename': 'JS-05-unicode-function.js', 'expected': {'functions': [['λ', 1, 3, 1]], 'identifiers': ['λ', 'value', 'value'], 'lexical_error': False}},
    {'id': 'JS-12-dollar-identifier', 'finding': 'F017', 'source': 'const \\u0024count = 1;\\n\\u0024count;\\n', 'language': 'javascript', 'filename': 'JS-12-dollar-identifier.js', 'expected': {'identifiers': ['\\u0024count', '\\u0024count'], 'lexical_error': False}},
    {'id': 'JS-13-unicode-identifier', 'finding': 'F017', 'source': 'const π = 1;\\nπ;\\n', 'language': 'javascript', 'filename': 'JS-13-unicode-identifier.js', 'expected': {'identifiers': ['π', 'π'], 'lexical_error': False}},
    {'id': 'JS-20-distinct-identifier-spellings', 'finding': 'F017', 'source': 'const \\u0024count = 1, count = 2, café = 3, café = 4;\\n\\u0024count + count + café + café;\\n', 'language': 'javascript', 'filename': 'JS-20-distinct-identifier-spellings.js', 'expected': {'identifiers': ['\\u0024count', 'count', 'café', 'café', '\\u0024count', 'count', 'café', 'café'], 'lexical_error': False}}
]

observed = []
for case in cases:
    code, language, expected = case['source'], case['language'], case['expected']
    context = module.build_analysis_context(code, case['filename'], language)
    scan = {'javascript': module.scan_javascript, 'bash': module.scan_bash}[language](code)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert len(context.cleaned_code) == len(code), case['id']
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n'], case['id']
    for key, value in [('functions', actual), ('identifiers', context.identifiers), ('comments', sorted(scan.comment_line_numbers)), ('lexical_error', bool(context.tokenizer_error))]:
        if key in expected:
            assert value == expected[key], (case['id'], key, value, expected[key])
    for text in expected.get('cleaned_contains', []):
        assert text in context.cleaned_code, (case['id'], text)
    for text in expected.get('cleaned_absent', []):
        assert text not in context.cleaned_code, (case['id'], text)
    for name in expected.get('identifiers_absent', []):
        assert name not in context.identifiers, (case['id'], name)
    for function in context.functions:
        physical = '\\n'.join(code.split('\\n')[function.lineno - 1:function.end_lineno])
        assert function.body == physical and function.length == function.end_lineno - function.lineno + 1, case['id']
        if case.get('verify_signature'):
            assert function.signature == physical.split('\\n')[0].strip(), (case['id'], function.signature)
    metrics = {}
    if expected.get('lexical_error'):
        assert not context.script_lexically_safe, case['id']
        assert expected['diagnostic_code'] in context.tokenizer_error, case['id']
        result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=code, filename=case['filename'], language_hint=language))))
        report = result['report']
        assert any(expected['diagnostic_code'] in warning for warning in report['warnings']), case['id']
        assert expected['diagnostic_code'] in result['text'], case['id']
        by_name = {item['name']: item for item in report['metrics']}
        for name in expected['unavailable']:
            metric = by_name[name]
            assert metric['applicable'] is False and metric['value'] is None, (case['id'], name)
            metrics[name] = dict(applicable=metric['applicable'], value=metric['value'])
    observed.append(dict(case=case['id'], functions=actual, identifiers=context.identifiers,
                         comments=sorted(scan.comment_line_numbers), tokenizer_error=context.tokenizer_error,
                         notes=context.notes, unavailable_metrics=metrics, original_body_and_coordinates_preserved=True))
`},
    {name:"bash-physical-function-ranges", finding:"A02-F019", script:`
cases = [
    {'id': 'SH-09-leading-trivia', 'finding': 'F019', 'source': 'echo start\\n\\nreal() {\\n echo ok\\n}\\n', 'language': 'bash', 'filename': 'SH-09-leading-trivia.sh', 'expected': {'functions': [['real', 3, 5, 1]], 'lexical_error': False}, 'verify_signature': True},
    {'id': 'SH-15-comment-trivia', 'finding': 'F019', 'source': '# heading\\n\\n  function real {\\n echo ok\\n}\\n', 'language': 'bash', 'filename': 'SH-15-comment-trivia.sh', 'expected': {'functions': [['real', 3, 5, 1]], 'lexical_error': False}, 'verify_signature': True},
    {'id': 'SH-08-heredoc-phantom', 'finding': 'F012', 'source': "cat <<'EOF'\\nphantom() {\\n echo text\\n}\\nEOF\\nreal() {\\n echo ok\\n}\\n", 'language': 'bash', 'filename': 'SH-08-heredoc-phantom.sh', 'expected': {'functions': [['real', 6, 8, 1]], 'lexical_error': False, 'identifiers_absent': ['phantom']}, 'verify_signature': True}
]

observed = []
for case in cases:
    code, language, expected = case['source'], case['language'], case['expected']
    context = module.build_analysis_context(code, case['filename'], language)
    scan = {'javascript': module.scan_javascript, 'bash': module.scan_bash}[language](code)
    actual = [[f.name, f.lineno, f.end_lineno, f.cyclomatic] for f in context.functions]
    assert len(context.cleaned_code) == len(code), case['id']
    assert [i for i, ch in enumerate(context.cleaned_code) if ch == '\\n'] == [i for i, ch in enumerate(code) if ch == '\\n'], case['id']
    for key, value in [('functions', actual), ('identifiers', context.identifiers), ('comments', sorted(scan.comment_line_numbers)), ('lexical_error', bool(context.tokenizer_error))]:
        if key in expected:
            assert value == expected[key], (case['id'], key, value, expected[key])
    for text in expected.get('cleaned_contains', []):
        assert text in context.cleaned_code, (case['id'], text)
    for text in expected.get('cleaned_absent', []):
        assert text not in context.cleaned_code, (case['id'], text)
    for name in expected.get('identifiers_absent', []):
        assert name not in context.identifiers, (case['id'], name)
    for function in context.functions:
        physical = '\\n'.join(code.split('\\n')[function.lineno - 1:function.end_lineno])
        assert function.body == physical and function.length == function.end_lineno - function.lineno + 1, case['id']
        if case.get('verify_signature'):
            assert function.signature == physical.split('\\n')[0].strip(), (case['id'], function.signature)
    metrics = {}
    if expected.get('lexical_error'):
        assert not context.script_lexically_safe, case['id']
        assert expected['diagnostic_code'] in context.tokenizer_error, case['id']
        result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=code, filename=case['filename'], language_hint=language))))
        report = result['report']
        assert any(expected['diagnostic_code'] in warning for warning in report['warnings']), case['id']
        assert expected['diagnostic_code'] in result['text'], case['id']
        by_name = {item['name']: item for item in report['metrics']}
        for name in expected['unavailable']:
            metric = by_name[name]
            assert metric['applicable'] is False and metric['value'] is None, (case['id'], name)
            metrics[name] = dict(applicable=metric['applicable'], value=metric['value'])
    observed.append(dict(case=case['id'], functions=actual, identifiers=context.identifiers,
                         comments=sorted(scan.comment_line_numbers), tokenizer_error=context.tokenizer_error,
                         notes=context.notes, unavailable_metrics=metrics, original_body_and_coordinates_preserved=True))
`}
  ];
  fixtureState.reset();
  const pageUrl = `${baseUrl}/app/index.html?scripts-i09=1`;
  let session = null, workerSession = null, ownership = null, actualRuntime = null;
  try {
    await withinCase("scripts-owned-worker", [], "authenticated-worker-ownership", async () => {
      await cdp.send("Target.setDiscoverTargets", {discover:true});
      const previous = new Set((await cdp.send("Target.getTargets")).targetInfos.map(item => item.targetId));
      session = await createSession(cdp, pageUrl);
      await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()", 60000);
      assertSingleVerifiedRequests(fixtureState);
      await cdp.send("Target.setAutoAttach", {autoAttach:true, waitForDebuggerOnStart:false, flatten:true,
        filter:[{type:"worker"}, {exclude:true}]}, session.sessionId);
      const discoveryDeadline = Date.now() + 5000;
      let workers = [], attachments = [];
      do {
        workers = (await cdp.send("Target.getTargets")).targetInfos.filter(item => item.type === "worker" && !previous.has(item.targetId) && item.parentId === session.targetId);
        attachments = [...cdp.attachedTargets.entries()].filter(([, item]) => item.parentSessionId === session.sessionId && workers.some(worker => worker.targetId === item.targetInfo.targetId));
        if (workers.length && attachments.length) break;
        await delay(100);
      } while (Date.now() < discoveryDeadline);
      assert(workers.length === 1 && attachments.length === 1, "JavaScript/Bash oracle did not locate exactly one owned worker channel");
      const worker = workers[0];
      if (worker.openerId) assert(worker.openerId === session.targetId, "JavaScript/Bash oracle worker opener differs from its owned page");
      assert(attachments[0][1].targetInfo.type === "worker" && attachments[0][1].targetInfo.parentId === session.targetId, "JavaScript/Bash oracle attachment differs from its owned worker");
      [workerSession] = attachments[0];
      await cdp.send("Runtime.enable", {}, workerSession);
      const workerBase = await evaluate(cdp, workerSession, "self.CODEPROBE_BASE_URL");
      assert(workerBase === pageUrl, "JavaScript/Bash oracle worker bootstrap URL differs from its owned page");
      ownership = {page_target_id:session.targetId, worker_target_id:worker.targetId, worker_parent_id:worker.parentId, bootstrap_url:workerBase};
      return ownership;
    });
    for (const item of directCases) {
      await withinCase(item.name, [item.finding], "context-in-authenticated-worker", async () => {
        const script = "def _codeprobe_scripts_i09_fixture():\n    import json, sys\n    module = sys.modules['codeprobe_runtime']\n" +
          item.script.trim().split("\n").map(line => "    " + line).join("\n") +
          "\n    metadata = json.loads(module.codeprobe_engine_metadata('{}'))\n    return json.dumps(dict(observed=observed, runtime=metadata['python_runtime'], measured_sha256=metadata['engine_fingerprint']['value']), allow_nan=False)\n_codeprobe_scripts_i09_fixture()\n";
        const result = await evaluate(cdp, workerSession, `(async () => {
          const runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
          try { return JSON.parse(runtime.runPython(${JSON.stringify(script)})); }
          finally { runtime.globals.delete('_codeprobe_scripts_i09_fixture'); }
        })()`);
        assert(result.runtime.platform === "emscripten" && result.runtime.version === "3.11.3", "JavaScript/Bash context oracle used an unexpected interpreter");
        assert(result.measured_sha256 === engineDigest, "JavaScript/Bash context oracle used different engine bytes");
        actualRuntime = result.runtime;
        assertSingleVerifiedRequests(fixtureState);
        return {...result, oracle_sha256:crypto.createHash("sha256").update(script).digest("hex")};
      });
    }
  } finally {
    if (workerSession) await cdp.send("Target.detachFromTarget", {sessionId:workerSession}, session.sessionId);
    if (session) await closeSession(cdp, session);
    await cdp.send("Target.setDiscoverTargets", {discover:false});
  }

  const warningCases = [
  {
    "name": "javascript-unclosed-string",
    "finding": "A02-F016",
    "filename": "bounded.js",
    "code": "const text = \"unfinished",
    "prefix": "JS_UNTERMINATED_STRING",
    "language": "javascript"
  },
  {
    "name": "bash-unclosed-string",
    "finding": "A02-F016",
    "filename": "bounded.sh",
    "code": "echo 'unfinished",
    "prefix": "BASH_UNTERMINATED_STRING",
    "language": "bash"
  }
];
  for (const mode of ["main-file", "main-project", "compact-project"]) {
    const compact = mode.startsWith("compact"), kind = mode.endsWith("file") ? "file" : "project";
    fixtureState.reset();
    let page = null, id = null;
    const active = compact ? "state" : "appState";
    const button = compact ? "analyseBtn" : "analyzeBtn", status = compact ? "status" : "statusText";
    const exportName = kind === "file" ? "bounded" : compact ? "scripts" : "selected-files";
    try {
      for (const item of warningCases) {
        await withinCase(`${mode}-${item.name}-json-text-downloads`, [item.finding], "public-ui-worker-report-exports", async () => {
          if (!page) {
            page = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?scripts-i09-${mode}=1`);
            id = page.sessionId;
            if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
          }
          await evaluate(cdp, id, `(() => {
            const transfer = new DataTransfer();
            const file = new File([${JSON.stringify(item.code)}], ${JSON.stringify(item.filename)}, {type:'text/plain'});
            if (${kind === "project"}) Object.defineProperty(file, '_codeprobeRelativePath', {value:${JSON.stringify('scripts/' + item.filename)}});
            transfer.items.add(file);
            const input = document.getElementById('${kind === "file" ? "fileInput" : "folderInput"}');
            input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles:true}));
          })()`);
          await waitForExpression(cdp, id, `${active}.loadingInput === false && !document.getElementById('${button}').disabled`, 60000);
          await evaluate(cdp, id, `document.getElementById('${button}').click()`);
          await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === '${kind === "file" ? "Analysis completed." : "Project analysis completed."}'`, 60000);
          const result = await evaluate(cdp, id, `({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value,
            warnings:document.getElementById('${compact ? "reviewPanel" : "warningsList"}').textContent})`);
          assert(result.report.report_kind === kind && result.report.engine_fingerprint.value === engineDigest, "JavaScript/Bash UI report identity differs");
          assert(result.report.engine_fingerprint.source === "packaged-verified", "JavaScript/Bash UI report lost authenticated engine provenance");
          assert(result.report.warnings.some(value => value.includes(item.prefix)), "JavaScript/Bash diagnostic report lost its warning");
          assert(result.text.includes(item.prefix) && result.warnings.includes(item.prefix), "JavaScript/Bash diagnostic text or rendered warning is absent");
          if (kind === "project") {
            assert(result.report.included_file_count === 1 && result.report.included_files[0].warnings.some(value => value.includes(item.prefix)), "JavaScript/Bash project lost its member or child warning");
            assert(result.report.warnings.some(value => value.includes(item.filename) && value.includes(item.prefix)), "JavaScript/Bash project warning lacks its member path");
          }
          const member = kind === "file" ? result.report : result.report.included_files[0];
          assert(member.language === item.language, "JavaScript/Bash UI report language differs");
          const unavailable = {};
          for (const name of ["cyclomatic_complexity", "halstead_difficulty"]) {
            const metric = member.metrics.find(value => value.name === name);
            assert(metric && metric.applicable === false && metric.value === null, `unsafe source retained metric ${name}`);
            unavailable[name] = {applicable:metric.applicable, value:metric.value};
          }
          fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
          await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
          await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
          const jsonPath = path.join(downloads, `${exportName}.json`), textPath = path.join(downloads, `${exportName}.txt`);
          await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
          assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(result.report), "JavaScript/Bash JSON download differs from accepted report");
          assert(fs.readFileSync(textPath, "utf8") === result.text, "JavaScript/Bash text download differs from accepted report");
          assertSingleVerifiedRequests(fixtureState);
          return {warnings:result.report.warnings, source_sha256:crypto.createHash("sha256").update(item.code).digest("hex"), engine_sha256:engineDigest, export_name:exportName, filename:item.filename, language:member.language, unavailable_metrics:unavailable};
        });
      }
    } finally { if (page) await closeSession(cdp, page); }
  }
  console.log("[PASS] browser-scripts-i09: " + JSON.stringify({engine_sha256:engineDigest, runtime:actualRuntime, ownership, observations,
    qualification:"Six finite JavaScript/Bash context groups ran in the owned authenticated worker interpreter; main file/main project/compact project used actual File/DOM, public worker transport and JSON/text downloads for EOF diagnostics and unavailable code metrics. Submitted source was analysed as data. These bounded lexical observations do not establish full language validation, compiler semantics or empirical authorship accuracy."}));
}

// Markdown/detection context metadata has no public worker operation. Fixed lexical
// oracles inspect the owned authenticated interpreter; warning/export cases
// separately exercise the existing public UI and worker transport.
async function testDocumentLanguageContracts(cdp, baseUrl, downloads, fixtureState, engineDigest) {
  const deadline = Date.now() + 300000;
  const observations = [];
  async function withinCase(name, findings, boundary, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "Markdown/detection browser group exceeded its 300-second budget");
    const started = Date.now();
    let timer;
    try {
      const observed = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Markdown/detection browser case timed out: ${name}`)), remaining);
      })]);
      const row = {case:name, findings, boundary, result:"PASS", elapsed_ms:Date.now() - started, observed};
      observations.push(row);
      console.log("[PASS] browser-documents-i10-case: " + JSON.stringify(row));
    } finally { clearTimeout(timer); }
  }
  const directCases = [
  {
    "name": "markdown-finite-structure-and-documentation",
    "finding": "A02-F015",
    "script": "cases = [{'id': 'MD-01-basic-fence', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '# Visible\\n```js\\n# Hidden\\n```\\n', 'expected': {'fences': 1, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '32ff67a8a293ddd5eff13f44ae75a4ac5c77b491b2b89754fb996f4125a4108d'}, {'id': 'MD-02-shorter-closer', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '````\\n```\\n# Hidden\\n````\\n# Visible\\n', 'expected': {'fences': 1, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '63180415d47988a306c2c6639262541f2c26272924120b10f771563c90085d90'}, {'id': 'MD-03-trailing-close-text', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '```\\n``` not-a-close\\n# Hidden\\n```\\n# Visible\\n', 'expected': {'fences': 1, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '61688e2f71eee2a24c8a4099bdaff3c78e5aebe156eff0eff7c93e6c6ef3b8e3'}, {'id': 'MD-04-indented-code', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '    ```\\n    # Hidden\\n    ```\\n# Visible\\n', 'expected': {'fences': 0, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': 'bd4caf111262177082717bbbaec0be6d1a83321e96d22f27555d4b207e1e5385'}, {'id': 'MD-05-setext-heading', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': 'Visible\\n=======\\n', 'expected': {'fences': 0, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '6848e9ed3dfd1f40bf9f3577d108ead215e77c788731ed594d6a0c3fdc47ca13'}, {'id': 'MD-06-inline-code-link', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '`[not a link](https://example.invalid)`\\n', 'expected': {'fences': 0, 'headings': [], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': 'f422635604ebb492f2f4477ff3eeeb2b2cfa196ddc3b518a44bc06f0a7248613'}, {'id': 'MD-07-inline-link-control', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '[a link](https://example.invalid)\\n', 'expected': {'fences': 0, 'headings': [], 'links': 1}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '0b731e7f984fa45c1864a209222d9c7a78bc1532f8c968dac346b574b568cd82'}, {'id': 'MD-08-reference-link', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '[a link][ref]\\n\\n[ref]: https://example.invalid\\n', 'expected': {'fences': 0, 'headings': [], 'links': 1}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': 'ee028118388064a5c15a33980e5ced8e27a544b0c51e4ecc9ba8cadac01ed2ff'}, {'id': 'MD-09-other-character', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '```\\n~~~\\n# Hidden\\n```\\n# Visible\\n', 'expected': {'fences': 1, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '33207807ed1b374319cd956d01bf75bb176a0e29e74efa5d1bc97d730092cd2a'}, {'id': 'MD-11-whitespace-close-suffix', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '```\\n# Hidden\\n``` \\t\\n# Visible\\n', 'expected': {'fences': 1, 'headings': ['Visible'], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '8c49349999269a77bfef1d146fd624932fe86bf5c36416be62916a4b6c810b43'}, {'id': 'MD-18-multiline-code-span', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': '`first\\n[hidden](https://example.invalid)\\nlast`\\n', 'expected': {'fences': 0, 'headings': [], 'links': 0}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '0fed34da9ec4d9e6e3c98ea5fe3bd3984681d4dc45dbc54b510bb90fd162d07d'}, {'id': 'MD-29-documentation-programme', 'family': 'markdown', 'filename': 'fixture.md', 'hint': None, 'source': \"# Notes\\n\\n```python\\ndef phantom():\\n    raise RuntimeError('never execute')\\nphantom()\\n```\\n\\nRead [guide](https://example.invalid).\\n\", 'expected': {'fences': 1, 'headings': ['Notes'], 'links': 1}, 'oracle_basis': 'CommonMark 0.31.2 selected block/inline rules', 'source_sha256': '4dac2c1fc8fd8d3f4671eaef4dd48c9673ed84898911eaad08ccf5e982e8c726'}]\nobserved = []\nfor case in cases:\n    context = module.build_analysis_context(case['source'], case['filename'], case['hint'])\n    info = context.markdown\n    actual = dict(fences=info.code_fence_count, headings=[item[2] for item in info.headings], links=info.link_count)\n    assert actual == case['expected'], (case['id'], actual, case['expected'])\n    assert context.language == 'markdown' and not context.functions, case['id']\n    result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=case['source'], filename=case['filename']))))\n    report = result['report']\n    assert report['verdict_class'] == 'documentation' and report['overall_applicable'] is False, case['id']\n    assert all(not item['contributes_to_overall'] for item in report['metrics'] if item['name'].startswith('markdown_')), case['id']\n    observed.append(dict(case=case['id'], source_sha256=case['source_sha256'], features=actual,\n                         functions=[], verdict_class=report['verdict_class'], overall_applicable=report['overall_applicable']))\n"
  },
  {
    "name": "language-shebang-precedence-and-uncertainty",
    "finding": "A02-F018",
    "script": "cases = [{'id': 'DETECT-05-cue-substring', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'The python tutorial explains syntax.', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'b7a799bdc860e872a3718c042203622952238a5fb4ed7ab156ed0d41c145173f'}, {'id': 'DETECT-06-shebang', 'family': 'detection', 'filename': 'script', 'hint': None, 'source': '#!/usr/bin/env node\\nconsole.log(1);', 'expected': {'language': 'javascript'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'c4deb859a7bf7c089e108c44280a1ebd084f030ba7f3ae4abdf4e4390d239397'}, {'id': 'DETECT-07-direct-python3.12', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': '#!/usr/bin/python3.12\\n', 'expected': {'language': 'python'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'e0e69989eeec1a8663962a326029727c25814b2a6c6aac1c67c59042ef496728'}, {'id': 'DETECT-09-env-split', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': '#!/usr/bin/env -S node --trace-warnings\\n', 'expected': {'language': 'javascript'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '6af9d57870fdbe8ee99b74aa62940a8e1ad73da4814c3d0e7229ea6eb5b94674'}, {'id': 'DETECT-11-extension-before-shebang', 'family': 'detection', 'filename': 'sample.JS', 'hint': None, 'source': '#!/usr/bin/python3\\n', 'expected': {'language': 'javascript'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'aee50b3d023b039c7116109895cdbe61a93b7869da6ea0984da85862fc5b3ed7'}, {'id': 'DETECT-12-hint-before-extension', 'family': 'detection', 'filename': 'sample.JS', 'hint': 'bash', 'source': '#!/usr/bin/python3\\n', 'expected': {'language': 'bash'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'aee50b3d023b039c7116109895cdbe61a93b7869da6ea0984da85862fc5b3ed7'}, {'id': 'DETECT-13-h-header-c', 'family': 'detection', 'filename': 'sample.H', 'hint': None, 'source': 'int add(int value);\\n', 'expected': {'language': 'c'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'eed85c2b4dbaa14b84fbbb7e979753723517d7a0b05400556bb0967bf58d014c'}, {'id': 'DETECT-14-h-header-cpp', 'family': 'detection', 'filename': 'sample.h', 'hint': None, 'source': 'namespace one {}\\nnamespace two {}\\n', 'expected': {'language': 'cpp'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '4b99cda8df534a7aaaec1f4b8e48c3e2cf52726c931d574c53c2390f58e2e5fe'}, {'id': 'DETECT-17-prose-node', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'The node tutorial explains syntax.', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '63b35e89121d5d64e0a06ac9d4a10f88f845f608b98a34fc091b2377504421ae'}, {'id': 'DETECT-17-prose-deno', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'The deno tutorial explains syntax.', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'c097fbc4762104b6b7be269eb9b864b721e7411971cfb576f066c7e7d1af8db0'}, {'id': 'DETECT-17-prose-shell', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'The /shell tutorial explains syntax.', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '3cece6ff10d75640aff08a3db6732e2b9de2d1e2ff3572bc67a2e96dd71a2d99'}, {'id': 'DETECT-18-lookalike-python-tools', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': '#!/usr/bin/python-tools\\n', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'e3d7e7fffa1931282b9e6dd1ab848b039882e38a3ddd5ba41547bc6927e7b01b'}, {'id': 'DETECT-19-leading-space', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': ' #!/usr/bin/python3\\n', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '5bc3328e83a88c4d4c466334914a78e996a0beec8777e4659b33e964a802d2f1'}, {'id': 'DETECT-20-later-python', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'Plain prose\\n#!/usr/bin/python3\\n', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '381b31c2f43a5c637f13d518e14badc6cff63e71adf9b889406da1efd1165086'}, {'id': 'DETECT-21-later-shell', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'Plain prose\\n#!/bin/sh\\n', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '9baf5f4782aff5af369661e6aac1bf2eac8cebba8ea9ceb98e202808869d4e39'}, {'id': 'DETECT-23-env-assignment', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': '#!/usr/bin/env OPTION=x python3\\n', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '9c13b974ac22805affcc3306e71c527877c5abc594d890eb53d8020f3271d7c2'}, {'id': 'DETECT-25-env-quoted-split', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': '#!/usr/bin/env -S \"python3 -I\"\\n', 'expected': {'language': 'unknown'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': '0a3495bccfd3191e5a159ecdc29c4586dd21684152389575abc51b14a27cf212'}, {'id': 'DETECT-29-fallback-content', 'family': 'detection', 'filename': 'sample.txt', 'hint': None, 'source': 'The python tutorial explains syntax.\\nfunction add(value) { return value; }\\n', 'expected': {'language': 'javascript'}, 'oracle_basis': 'Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax', 'source_sha256': 'bcd32bd8cbcf76dabc74f88375ae7dee74985866e45c5f6a9098a68e6d84bed8'}]\nobserved = []\nwarning = 'The language could not be detected with strong confidence.'\nfor case in cases:\n    actual = module.detect_language(case['filename'], case['source'], case['hint'])\n    assert actual == case['expected']['language'], (case['id'], actual, case['expected'])\n    result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=case['source'], filename=case['filename'], language_hint=case['hint']))))\n    report = result['report']\n    assert report['language'] == actual, case['id']\n    assert (warning in report['warnings']) == (actual == 'unknown'), case['id']\n    if actual == 'unknown':\n        assert warning in result['text'], case['id']\n    observed.append(dict(case=case['id'], source_sha256=case['source_sha256'], language=actual, warnings=report['warnings']))\n"
  }
];
  fixtureState.reset();
  const pageUrl = `${baseUrl}/app/index.html?documents-i10=1`;
  let session = null, workerSession = null, ownership = null, actualRuntime = null;
  try {
    await withinCase("documents-owned-worker", [], "authenticated-worker-ownership", async () => {
      await cdp.send("Target.setDiscoverTargets", {discover:true});
      const previous = new Set((await cdp.send("Target.getTargets")).targetInfos.map(item => item.targetId));
      session = await createSession(cdp, pageUrl);
      await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()", 60000);
      assertSingleVerifiedRequests(fixtureState);
      await cdp.send("Target.setAutoAttach", {autoAttach:true, waitForDebuggerOnStart:false, flatten:true,
        filter:[{type:"worker"}, {exclude:true}]}, session.sessionId);
      const discoveryDeadline = Date.now() + 5000;
      let workers = [], attachments = [];
      do {
        workers = (await cdp.send("Target.getTargets")).targetInfos.filter(item => item.type === "worker" && !previous.has(item.targetId) && item.parentId === session.targetId);
        attachments = [...cdp.attachedTargets.entries()].filter(([, item]) => item.parentSessionId === session.sessionId && workers.some(worker => worker.targetId === item.targetInfo.targetId));
        if (workers.length && attachments.length) break;
        await delay(100);
      } while (Date.now() < discoveryDeadline);
      assert(workers.length === 1 && attachments.length === 1, "Markdown/detection oracle did not locate exactly one owned worker channel");
      const worker = workers[0];
      if (worker.openerId) assert(worker.openerId === session.targetId, "Markdown/detection oracle worker opener differs from its owned page");
      assert(attachments[0][1].targetInfo.type === "worker" && attachments[0][1].targetInfo.parentId === session.targetId, "Markdown/detection oracle attachment differs from its owned worker");
      [workerSession] = attachments[0];
      await cdp.send("Runtime.enable", {}, workerSession);
      const workerBase = await evaluate(cdp, workerSession, "self.CODEPROBE_BASE_URL");
      assert(workerBase === pageUrl, "Markdown/detection oracle worker bootstrap URL differs from its owned page");
      ownership = {page_target_id:session.targetId, worker_target_id:worker.targetId, worker_parent_id:worker.parentId, bootstrap_url:workerBase};
      return ownership;
    });
    for (const item of directCases) {
      await withinCase(item.name, [item.finding], "context-in-authenticated-worker", async () => {
        const script = "def _codeprobe_documents_i10_fixture():\n    import json, sys\n    module = sys.modules['codeprobe_runtime']\n" +
          item.script.trim().split("\n").map(line => "    " + line).join("\n") +
          "\n    metadata = json.loads(module.codeprobe_engine_metadata('{}'))\n    return json.dumps(dict(observed=observed, runtime=metadata['python_runtime'], measured_sha256=metadata['engine_fingerprint']['value']), allow_nan=False)\n_codeprobe_documents_i10_fixture()\n";
        const result = await evaluate(cdp, workerSession, `(async () => {
          const runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
          try { return JSON.parse(runtime.runPython(${JSON.stringify(script)})); }
          finally { runtime.globals.delete('_codeprobe_documents_i10_fixture'); }
        })()`);
        assert(result.runtime.platform === "emscripten" && result.runtime.version === "3.11.3", "Markdown/detection context oracle used an unexpected interpreter");
        assert(result.measured_sha256 === engineDigest, "Markdown/detection context oracle used different engine bytes");
        actualRuntime = result.runtime;
        assertSingleVerifiedRequests(fixtureState);
        return {...result, oracle_sha256:crypto.createHash("sha256").update(script).digest("hex")};
      });
    }
  } finally {
    if (workerSession) await cdp.send("Target.detachFromTarget", {sessionId:workerSession}, session.sessionId);
    if (session) await closeSession(cdp, session);
    await cdp.send("Target.setDiscoverTargets", {discover:false});
  }

  const fileCases = [
  {
    "id": "MD-02-shorter-closer",
    "family": "markdown",
    "filename": "fixture.md",
    "hint": null,
    "source": "````\n```\n# Hidden\n````\n# Visible\n",
    "expected": {
      "fences": 1,
      "headings": [
        "Visible"
      ],
      "links": 0
    },
    "oracle_basis": "CommonMark 0.31.2 selected block/inline rules",
    "source_sha256": "63180415d47988a306c2c6639262541f2c26272924120b10f771563c90085d90"
  },
  {
    "id": "MD-06-inline-code-link",
    "family": "markdown",
    "filename": "fixture.md",
    "hint": null,
    "source": "`[not a link](https://example.invalid)`\n",
    "expected": {
      "fences": 0,
      "headings": [],
      "links": 0,
      "prose_words": 0
    },
    "oracle_basis": "CommonMark 0.31.2 selected block/inline rules",
    "source_sha256": "f422635604ebb492f2f4477ff3eeeb2b2cfa196ddc3b518a44bc06f0a7248613"
  },
  {
    "id": "MD-29-documentation-programme",
    "family": "markdown",
    "filename": "fixture.md",
    "hint": null,
    "source": "# Notes\n\n```python\ndef phantom():\n    raise RuntimeError('never execute')\nphantom()\n```\n\nRead [guide](https://example.invalid).\n",
    "expected": {
      "fences": 1,
      "headings": [
        "Notes"
      ],
      "links": 1
    },
    "oracle_basis": "CommonMark 0.31.2 selected block/inline rules",
    "source_sha256": "4dac2c1fc8fd8d3f4671eaef4dd48c9673ed84898911eaad08ccf5e982e8c726"
  },
  {
    "id": "DETECT-05-cue-substring",
    "family": "detection",
    "filename": "sample.txt",
    "hint": null,
    "source": "The python tutorial explains syntax.",
    "expected": {
      "language": "unknown"
    },
    "oracle_basis": "Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax",
    "source_sha256": "b7a799bdc860e872a3718c042203622952238a5fb4ed7ab156ed0d41c145173f"
  },
  {
    "id": "DETECT-09-env-split",
    "family": "detection",
    "filename": "sample.txt",
    "hint": null,
    "source": "#!/usr/bin/env -S node --trace-warnings\n",
    "expected": {
      "language": "javascript"
    },
    "oracle_basis": "Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax",
    "source_sha256": "6af9d57870fdbe8ee99b74aa62940a8e1ad73da4814c3d0e7229ea6eb5b94674"
  }
];
  const projectCases = [
  {
    "id": "MD-29-documentation-programme",
    "family": "markdown",
    "filename": "fixture.md",
    "hint": null,
    "source": "# Notes\n\n```python\ndef phantom():\n    raise RuntimeError('never execute')\nphantom()\n```\n\nRead [guide](https://example.invalid).\n",
    "expected": {
      "fences": 1,
      "headings": [
        "Notes"
      ],
      "links": 1
    },
    "oracle_basis": "CommonMark 0.31.2 selected block/inline rules",
    "source_sha256": "4dac2c1fc8fd8d3f4671eaef4dd48c9673ed84898911eaad08ccf5e982e8c726",
    "selected_filename": "fixture.md"
  },
  {
    "id": "DETECT-05-cue-substring",
    "family": "detection",
    "filename": "sample.txt",
    "hint": null,
    "source": "The python tutorial explains syntax.",
    "expected": {
      "language": "unknown"
    },
    "oracle_basis": "Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax",
    "source_sha256": "b7a799bdc860e872a3718c042203622952238a5fb4ed7ab156ed0d41c145173f",
    "selected_filename": "sample.txt"
  },
  {
    "id": "DETECT-16-content-javascript",
    "family": "detection",
    "filename": "sample.txt",
    "hint": null,
    "source": "function add(value) { return value; }\n",
    "expected": {
      "language": "javascript"
    },
    "oracle_basis": "Frozen public hint/extension/shebang/content precedence; exact interpreter names and selected literal env syntax",
    "source_sha256": "c549c7cbdf94395322c3c4601f93ce67cb802176249cabeaddb691918d5d8a65",
    "selected_filename": "control.js"
  }
];

  const uncertainty = "The language could not be detected with strong confidence.";
  function checkFile(report, item) {
    const language = item.family === "markdown" ? "markdown" : item.expected.language;
    assert(report.language === language, "I10 file report selected an unexpected language");
    assert(report.engine_fingerprint.value === engineDigest && report.engine_fingerprint.source === "packaged-verified", "I10 file report lost verified provenance");
    if (language === "markdown") {
      assert(report.verdict_class === "documentation" && report.overall_applicable === false, "Markdown acquired a code authorship aggregate");
      assert(report.warnings.some(warning => warning.startsWith("Markdown scope:")), "Markdown report lost its finite extraction qualification");
      const fence = report.metrics.find(metric => metric.name === "markdown_code_fence_density");
      const link = report.metrics.find(metric => metric.name === "markdown_link_density");
      assert(fence.detail.includes(`code_fence_blocks=${item.expected.fences},`), "Markdown report lost exact fence count");
      if (item.expected.prose_words === 0) {
        // I12: the exact raw link count is checked by the retained context oracle.
        // A code-only span has no prose denominator; zero density is not measured.
        assert(link.applicable === false && link.value === null && link.value_display === "N/A", "Markdown without prose fabricated a link density");
        assert(link.explanation === "No recognised prose-token denominator is available for link density.", "Markdown lost its missing-denominator explanation");
      } else {
        assert(link.applicable === true, "Markdown with prose lost an applicable link density");
        assert(link.detail.startsWith(`links=${item.expected.links},`), "Markdown report lost exact link count");
      }
      assert(report.metrics.filter(metric => metric.name.startsWith("markdown_")).every(metric => metric.contributes_to_overall === false), "Markdown feature entered code aggregate");
    }
    assert(report.warnings.includes(uncertainty) === (language === "unknown"), "Language uncertainty was lost or fabricated");
    return language;
  }
  async function download(id, name, result) {
    fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
    await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
    await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
    const jsonPath = path.join(downloads, `${name}.json`), textPath = path.join(downloads, `${name}.txt`);
    await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
    assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(result.report), "I10 JSON download differs from accepted report");
    assert(fs.readFileSync(textPath, "utf8") === result.text, "I10 text download differs from accepted report");
  }
  fixtureState.reset();
  let page = null;
  try {
    for (const item of fileCases) {
      await withinCase(`main-file-${item.id}-json-text-downloads`, [item.family === "markdown" ? "A02-F015" : "A02-F018"], "public-file-ui-worker-report-exports", async () => {
        if (!page) {
          page = await createSession(cdp, `${baseUrl}/app/index.html?documents-i10-file=1`);
          await waitForExpression(cdp, page.sessionId, "appState.workerSession?.isReady()", 60000);
        }
        const id = page.sessionId;
        await evaluate(cdp, id, `(() => {
          const transfer = new DataTransfer();
          transfer.items.add(new File([${JSON.stringify(item.source)}], ${JSON.stringify(item.filename)}, {type:'text/plain'}));
          const input = document.getElementById('fileInput'); input.files = transfer.files;
          input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, "appState.loadingInput === false && !document.getElementById('analyzeBtn').disabled", 60000);
        const before = await evaluate(cdp, id, "({detected:appState.detectedLanguage, label:document.getElementById('langMeta').textContent, source:document.getElementById('editor').value})");
        const expectedLanguage = item.family === "markdown" ? "markdown" : item.expected.language;
        assert(before.source === item.source && before.detected === expectedLanguage, "I10 real File source or preview language differs");
        const labels = {markdown:"Markdown", unknown:"Unknown", javascript:"JavaScript"};
        assert(before.label === `Detected language: ${labels[expectedLanguage]}`, "I10 displayed language is inconsistent with the fixed oracle");
        await evaluate(cdp, id, "document.getElementById('analyzeBtn').click()");
        await waitForExpression(cdp, id, "document.getElementById('statusText').textContent === 'Analysis completed.'", 60000);
        const result = await evaluate(cdp, id, "({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, warnings:document.getElementById('warningsList').textContent, score:document.getElementById('scoreValue').textContent})");
        const language = checkFile(result.report, item);
        if (language === "markdown") {
          assert(result.score === "N/A", "Markdown UI displays an applicable code score");
          assert(result.text.includes("Markdown scope:") && result.warnings.includes("Markdown scope:"), "Markdown scope is missing from visible warnings or text report");
        }
        if (language === "unknown") assert(result.text.includes(uncertainty) && result.warnings.includes(uncertainty), "Ambiguity missing from visible warning or text report");
        const name = item.filename.replace(/\.[^.]+$/, "");
        await download(id, name, result);
        assertSingleVerifiedRequests(fixtureState);
        return {source_sha256:item.source_sha256, filename:item.filename, language, preview:before.label, warnings:result.report.warnings,
          verdict_class:result.report.verdict_class, overall_applicable:result.report.overall_applicable, engine_sha256:engineDigest};
      });
    }
  } finally { if (page) await closeSession(cdp, page); }
  for (const compact of [false, true]) {
    fixtureState.reset();
    let projectPage = null;
    const mode = compact ? "compact-project" : "main-project";
    const active = compact ? "state" : "appState", button = compact ? "analyseBtn" : "analyzeBtn", status = compact ? "status" : "statusText";
    try {
      await withinCase(`${mode}-default-documentation-exclusions-downloads`, ["A02-F015", "A02-F018"], "public-project-ui-default-exclusions-exports", async () => {
        projectPage = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?documents-i10-project=1`);
        const id = projectPage.sessionId;
        if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
        await evaluate(cdp, id, `(() => {
          const transfer = new DataTransfer();
          for (const item of ${JSON.stringify(projectCases)}) {
            const file = new File([item.source], item.selected_filename, {type:'text/plain'});
            Object.defineProperty(file, '_codeprobeRelativePath', {value:'documents/' + item.selected_filename});
            transfer.items.add(file);
          }
          const input = document.getElementById('folderInput'); input.files = transfer.files;
          input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, `${active}.loadingInput === false && !document.getElementById('${button}').disabled`, 60000);
        await evaluate(cdp, id, `document.getElementById('${button}').click()`);
        await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === 'Project analysis completed.'`, 60000);
        const result = await evaluate(cdp, id, "({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, dom:document.body.textContent})");
        assert(result.report.engine_fingerprint.value === engineDigest && result.report.included_file_count === 1 && result.report.excluded_file_count === 2, "Default project UI admission changed");
        assert(result.report.included_files[0].language === "javascript", "Default project lost extension-based code control");
        for (const name of ["fixture.md", "sample.txt"]) {
          assert(result.report.excluded_files.some(item => item.path.endsWith(name) && item.reason === "documentation_excluded_by_default"), "Default documentation exclusion missing");
          assert(result.text.includes(name), "Project text lost excluded documentation path");
        }
        assert(result.dom.includes("Excluded files: 2."), "Project UI hides its exclusion warning");
        await download(id, compact ? "documents" : "selected-files", result);
        assertSingleVerifiedRequests(fixtureState);
        return {included:1, excluded:result.report.excluded_files, source_cases:projectCases.map(item => ({case:item.id, source_sha256:item.source_sha256, selected_filename:item.selected_filename})), engine_sha256:engineDigest};
      });
      await withinCase(`${mode}-worker-explicit-documentation-opt-in`, ["A02-F015", "A02-F018"], "public-worker-project-api-explicit-opt-in", async () => {
        const id = projectPage.sessionId;
        const payload = await evaluate(cdp, id, compact ? "state.payload" : "appState.projectPayload");
        payload.include_documentation = true;
        const result = await evaluate(cdp, id, `${active}.workerSession.analyse('project', ${JSON.stringify(payload)})`);
        const report = result.report;
        assert(report.engine_fingerprint.value === engineDigest && report.included_file_count === 3 && report.excluded_file_count === 0, "Explicit worker documentation opt-in did not admit exact files");
        const document = report.included_files.find(item => item.path.endsWith("fixture.md"));
        const ambiguous = report.included_files.find(item => item.path.endsWith("sample.txt"));
        assert(document && ambiguous, "Explicit opt-in member inventory differs");
        checkFile(document, projectCases[0]); checkFile(ambiguous, projectCases[1]);
        assert(report.warnings.some(item => item.includes("sample.txt") && item.includes(uncertainty)), "Explicit project warning lacks uncertain member path");
        assert(report.warnings.some(item => item.includes("fixture.md") && item.includes("Markdown scope:")), "Explicit project warning lacks Markdown member qualification");
        assert(result.text.includes("fixture.md") && result.text.includes("Markdown scope:"), "Explicit project text lost Markdown scope");
        assert(result.text.includes("sample.txt") && result.text.includes(uncertainty), "Explicit project text lost language uncertainty");
        assert(JSON.stringify(report) === JSON.stringify(result.project_report), "Explicit worker project report aliases differ");
        assertSingleVerifiedRequests(fixtureState);
        return {included:3, excluded:0, languages:report.included_files.map(item => ({path:item.path, language:item.language, verdict_class:item.verdict_class, overall_applicable:item.overall_applicable})), warnings:report.warnings,
          engine_sha256:engineDigest, qualification:"Public worker API with explicit include_documentation=true, using actual File-decoded payload. This is not an available UI opt-in control or a UI download observation."};
      });
    } finally { if (projectPage) await closeSession(cdp, projectPage); }
  }
  console.log("[PASS] browser-documents-i10: " + JSON.stringify({engine_sha256:engineDigest, runtime:actualRuntime, ownership, observations,
    qualification:"Two fixed context groups ran in the owned authenticated worker interpreter. Five main-file cases used real File/DOM labels, public worker transport and JSON/text downloads. Both project UIs retained default documentation exclusions and downloaded exact reports; separate public worker calls explicitly opted in documentation. Source remained data; no fenced programme or shebang interpreter was executed. Finite extraction rules do not establish complete CommonMark conformance or authorship accuracy."}));
}

// Fixed I11 metric contracts: submitted source is data at every boundary.
async function testMetricContracts(cdp, baseUrl, downloads, fixtureState, engineDigest) {
  const deadline = Date.now() + 300000;
  const observations = [];
  async function withinCase(name, findings, boundary, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "Metric contracts browser group exceeded its 300-second budget");
    const started = Date.now();
    let timer;
    try {
      const observed = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Metric contracts browser case timed out: ${name}`)), remaining);
      })]);
      const row = {case:name, findings, boundary, result:"PASS", elapsed_ms:Date.now() - started, observed};
      observations.push(row);
      console.log("[PASS] browser-metrics-i11-case: " + JSON.stringify(row));
    } finally { clearTimeout(timer); }
  }
  const directCases = [
  {
    "name": "numeric-and-python-structural",
    "findings": [
      "A02-F020",
      "A02-F021",
      "A02-F022",
      "A02-F030"
    ],
    "script": "cases = [{'id': 'F020-numeric-suffix', 'finding_id': 'A02-F020', 'metric': 'magic_numbers', 'filename': 'fixture.py', 'source': 'value123 = 0\\n', 'expected': {'value': 0.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {'numbers': 1, 'magic_candidates': 0}, 'public_only': False, 'original_a02': 'magic_numbers:numeric_suffix', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '4c0ed73d0ff1bdadc924a89e9c99fc14486cbb7d3a0ab8d5b62d30b25f096428'}, {'id': 'F020-one-real-per-twenty', 'finding_id': 'A02-F020', 'metric': 'magic_numbers', 'filename': 'fixture.py', 'source': 'value = 42\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\npass\\n', 'expected': {'value': 1.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.36363636363636365}, 'detail_fields': {'numbers': 1, 'magic_candidates': 1}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'b64919a76bbc15550c18e17de9c93a4b0a29e3f7a0be804dd2d348bbd178fbaa'}, {'id': 'F020-inert-literal-text', 'finding_id': 'A02-F020', 'metric': 'magic_numbers', 'filename': 'fixture.py', 'source': \"# 123 456\\nlabel = '789 42'\\nvalue = 0\\n\", 'expected': {'value': 0.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {'numbers': 1, 'magic_candidates': 0}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '1dc2d2a2e2ea9fab0156c94689ab4413d9ae5882af68aaff5f5a36d20da3f4a7'}, {'id': 'F021-quoted-main-guard', 'finding_id': 'A02-F021', 'metric': 'boilerplate_presence', 'filename': 'fixture.py', 'source': 'label = \\'if __name__ == \"__main__\"\\'\\n', 'expected': {'value': 0.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'indicators': '0/5'}, 'public_only': False, 'original_a02': 'boilerplate:ignore_string_contents', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '69b17c01f3e3ece9108532e2e3d3f6d5c872a002869d42c0f96ae299b6f8b927'}, {'id': 'F021-real-main-guard', 'finding_id': 'A02-F021', 'metric': 'boilerplate_presence', 'filename': 'fixture.py', 'source': 'if __name__ == \"__main__\":\\n    pass\\n', 'expected': {'value': 0.2, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'indicators': '1/5'}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'f86aa87ed34409906d0bc17cd8a589add483d3905c281aeb2f41251c41141f29'}, {'id': 'F021-invalid-ast', 'finding_id': 'A02-F021', 'metric': 'boilerplate_presence', 'filename': 'fixture.py', 'source': 'if __name__ == \"__main__\"\\n    pass\\n', 'expected': {'value': None, 'applicable': False, 'group': 'context', 'contributes_to_overall': False}, 'detail_fields': {}, 'public_only': True, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '26c292f608558a71f9df12a8637ca834ad19d05394ac218c77e1909105be5944'}, {'id': 'F022-inert-string', 'finding_id': 'A02-F022', 'metric': 'defensive_programming', 'filename': 'fixture.py', 'source': 'label = \"if not ready\"\\nvalue = 1\\n', 'expected': {'value': 0.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'guards': 0}, 'public_only': False, 'original_a02': 'defensive:ignore_string', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '93b56fb55c5aabe14240b69027aad3de4c82f2990b033972913879ec815af717'}, {'id': 'F022-real-if-not', 'finding_id': 'A02-F022', 'metric': 'defensive_programming', 'filename': 'fixture.py', 'source': 'if not ready:\\n    pass\\n', 'expected': {'value': 10.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'guards': 1}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'cf0747dd51f6d6e4214a170e773a8abf3c573552424dbddab3737d02686bcee1'}, {'id': 'F022-quoted-none-comparison', 'finding_id': 'A02-F022', 'metric': 'defensive_programming', 'filename': 'fixture.py', 'source': 'if value == \"None\":\\n    pass\\n', 'expected': {'value': 0.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'guards': 0}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '3ea29ea8a11ad6648d38eb42d3a1bd27ed70bc39e672d3692cd91afc65698a84'}, {'id': 'F030-top-import-block', 'finding_id': 'A02-F030', 'metric': 'import_organization', 'filename': 'fixture.py', 'source': 'import os\\n\\nimport sys\\nvalue = 1', 'expected': {'value': 1.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {'top_aligned': True, 'sorted': True, 'grouped': True, 'imports': 2}, 'public_only': False, 'original_a02': 'E10-top-import-block-oracle lines', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'e37a93f8e730e4f43fbe52702edfdd3df3f84567490d2e0d3a476a35443a27f4'}, {'id': 'F030-late-unsorted', 'finding_id': 'A02-F030', 'metric': 'import_organization', 'filename': 'fixture.py', 'source': 'value = 1\\nimport sys\\nimport os', 'expected': {'value': 0.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'top_aligned': False, 'sorted': False, 'grouped': False, 'imports': 2}, 'public_only': False, 'original_a02': 'E10-valid-unorganised lines', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'aa9e4295a63ee1625886d09fda004d47aaa5ef30f9f4c48725a8efa30609af34'}, {'id': 'F030-local-imports', 'finding_id': 'A02-F030', 'metric': 'import_organization', 'filename': 'fixture.py', 'source': 'def work():\\n    import os\\n    import sys\\n    return os, sys\\n', 'expected': {'value': None, 'applicable': False, 'group': 'quality', 'contributes_to_overall': False}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '3c609aeb3eb15c3f94a42687c1333e9a56988fe4084b3cd496bedf4789ee071d'}]\n\nimport dataclasses, hashlib, math, re\nclasses = {item.name:item for item in module.MetricRegistry.metric_classes()}\nconfig = module.merged_metric_config('default')\nobserved = []\ndef same(actual, expected):\n    if isinstance(expected, float):\n        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)\n    return actual == expected\nfor case in cases:\n    assert hashlib.sha256(case['source'].encode()).hexdigest() == case['source_sha256'], case['id']\n    context = module.build_analysis_context(case['source'], case['filename'])\n    checks = []\n    def record(boundary, actual, expected):\n        checks.append(dict(boundary=boundary, actual=actual, expected=expected, matches=same(actual, expected)))\n    if 'identifiers_expected' in case:\n        record('context-identifiers', context.identifiers, case['identifiers_expected'])\n    if 'function_complexities_expected' in case:\n        record('context-function-complexities', [item.cyclomatic for item in context.functions], case['function_complexities_expected'])\n    result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=case['source'], filename=case['filename']))))\n    report_metric = next(item for item in result['report']['metrics'] if item['name'] == case['metric'])\n    metrics = [('public-file-json', report_metric, True)]\n    if not case['public_only']:\n        direct = classes[case['metric']](config).compute(case['source'], context.language, context)\n        metrics.insert(0, ('direct-metric', dataclasses.asdict(direct), False))\n    for boundary, metric, rounded in metrics:\n        for key, value in case['expected'].items():\n            expected = round(value, 4) if key == 'score' and rounded else value\n            record(boundary + ':' + key, metric.get(key), expected)\n        for key, value in case['detail_fields'].items():\n            found = re.search(r'(?:^|[,;] )' + re.escape(key) + r'=([^,; ]+)', metric.get('detail', ''))\n            actual = found.group(1) if found else None\n            record(boundary + ':detail:' + key, actual, str(value))\n        if not case['expected']['applicable']:\n            record(boundary + ':unavailable-reason', bool(metric.get('explanation')), True)\n            if case['metric'] == 'cyclomatic_complexity':\n                record(boundary + ':unavailable-method', all(not metric.get(key) for key in ('method','unit','domain')), True)\n    record('file-text-display-name', report_metric['display_name'] in result['text'], True)\n    if case['metric'] == 'cyclomatic_complexity' and case['expected']['applicable']:\n        unit_text = 'decisions/function' if case['expected']['unit'] == 'decisions_per_function' else 'branches/20 code lines'\n        record('file-unit-display', unit_text in report_metric['value_display'], True)\n        record('file-method-domain-detail', all(case['expected'][key] in report_metric['detail'] for key in ('method','domain')), True)\n        record('file-text-unit-and-method', unit_text in result['text'] and case['expected']['method'] in result['text'], True)\n    observed.append(dict(case=case['id'], source_sha256=case['source_sha256'], metric=case['metric'], checks=checks, matches=all(item['matches'] for item in checks)))\nassert all(item['matches'] for item in observed), [item['case'] for item in observed if not item['matches']]\n"
  },
  {
    "name": "script-and-c-inert-boundaries",
    "findings": [
      "A02-F023",
      "A02-F027",
      "A02-F028",
      "A02-F029",
      "A02-F032"
    ],
    "script": "cases = [{'id': 'F023-separate-then', 'finding_id': 'A02-F023', 'metric': 'nesting_depth', 'filename': 'fixture.sh', 'source': 'if true\\nthen\\n  :\\nfi\\n', 'expected': {'value': 1.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.15}, 'detail_fields': {}, 'public_only': False, 'original_a02': 'bash_nesting:separate_then', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '217af73b63757f074f5749ced43ce1d0405164d7cbf1f270f66f4e444aca63ef'}, {'id': 'F023-nested-two', 'finding_id': 'A02-F023', 'metric': 'nesting_depth', 'filename': 'fixture.sh', 'source': 'if true\\nthen\\n while true\\n do\\n  :\\n done\\nfi\\n', 'expected': {'value': 2.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'e376f8249dae1dbaf5ea826aaad10e05ecd5dd8ee2c5739b8ddbe1ba76675ea4'}, {'id': 'F023-inert-introducers', 'finding_id': 'A02-F023', 'metric': 'nesting_depth', 'filename': 'fixture.sh', 'source': \"# then do\\nprintf '%s' 'then do'\\ncat <<'EOF'\\nthen\\ndo\\nEOF\\n\", 'expected': {'value': 0.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.15}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'f360dd65dcd2d8e64074f0411a6e037ac59e4cbf8d2c306edad8392c5b9977eb'}, {'id': 'F023-mismatched-terminator', 'finding_id': 'A02-F023', 'metric': 'nesting_depth', 'filename': 'fixture.sh', 'source': 'if true; then\\n :\\ndone\\n', 'expected': {'value': None, 'applicable': False, 'group': 'context', 'contributes_to_overall': False}, 'detail_fields': {}, 'public_only': True, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '91f477cc22d102504cb2e7fe9152ce6f5eb73b76b06585468df2976855f1bea6'}, {'id': 'F027-comment-use', 'finding_id': 'A02-F027', 'metric': 'used_import_ratio', 'filename': 'fixture.js', 'source': \"import value from 'module';\\nconst result = 1;\\n// value\", 'expected': {'value': 0.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': 'E03-js-comment-use-oracle', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'fda7bb017a5aa94559541862e4db446738058c3d2f365674fa9aeab2c4a030bb'}, {'id': 'F027-real-read', 'finding_id': 'A02-F027', 'metric': 'used_import_ratio', 'filename': 'fixture.js', 'source': \"import value from 'module';\\nconst result = 1;\\nvalue();\", 'expected': {'value': 1.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'f36338c984b094da94b7305170e50e38d76d8c052f4e09cb62442ffae465b3c9'}, {'id': 'F027-named-alias', 'finding_id': 'A02-F027', 'metric': 'used_import_ratio', 'filename': 'fixture.js', 'source': \"import {left as used, right} from 'module';\\nused();\\n\", 'expected': {'value': 0.5, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '65caaae6b6b44b01ba8132343362fc3383e65c2592d833369afdadb56fcf1a9f'}, {'id': 'F028-comment-markers', 'finding_id': 'A02-F028', 'metric': 'javascript_modern_syntax', 'filename': 'fixture.js', 'source': 'var value = 1;\\n// const const => ?. ?? ...', 'expected': {'value': 0.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'modern': 0, 'legacy': 1}, 'public_only': False, 'original_a02': 'E08-comment-invariance-oracle', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '105ccaf36b558426e6e06c106afcc4a83bf52c2917bc0c711bcf2a97c109d72e'}, {'id': 'F028-const-arrow', 'finding_id': 'A02-F028', 'metric': 'javascript_modern_syntax', 'filename': 'fixture.js', 'source': 'const add = value => value;\\n', 'expected': {'value': 0.6666666666666666, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False}, 'detail_fields': {'modern': 2, 'legacy': 0}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '77abeed9047dd6db6e43d6d7255ca1ac183fd6c3a06a5225ce753d74ae49296d'}, {'id': 'F028-template-expression', 'finding_id': 'A02-F028', 'metric': 'javascript_modern_syntax', 'filename': 'fixture.js', 'source': 'const text = `value: ${value?.item}`;\\n', 'expected': {'value': 0.75, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False}, 'detail_fields': {'modern': 3, 'legacy': 0}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '2de4d49893506c032349302892c1b57f9ef41851dc1de06f1623675afd64b4e8'}, {'id': 'F028-template-inert-markers', 'finding_id': 'A02-F028', 'metric': 'javascript_modern_syntax', 'filename': 'fixture.js', 'source': 'var text = `const let => ?. ?? ...`;\\n', 'expected': {'value': 0.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'modern': 0, 'legacy': 1}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '076a4a83552a112e5eb62d6b4f960eff29d045b6fc9cca58e8e6afb622361d23'}, {'id': 'F029-grouped-five', 'finding_id': 'A02-F029', 'metric': 'bash_quoting_consistency', 'filename': 'fixture.sh', 'source': 'printf \"%s\" \"$a $b $c $d $e\"', 'expected': {'value': 1.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {'references': 5, 'double_quoted': 5}, 'public_only': False, 'original_a02': 'E09-grouped-quoting-oracle', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '623b60893ee75ad390f18fc379e838c6ccb4c5528afad0c80031871961bb1a4c'}, {'id': 'F029-mixed-four-of-six', 'finding_id': 'A02-F029', 'metric': 'bash_quoting_consistency', 'filename': 'fixture.sh', 'source': 'printf \"%s\" \"$a $b $c $d\" $e $f\\n', 'expected': {'value': 0.6666666666666666, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.2713178294573643}, 'detail_fields': {'references': 6, 'double_quoted': 4}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '4bdf0b36e73e7ce858eeaf3f59fa1d78251445fe0772cb5809c703a92898d428'}, {'id': 'F029-inert-dollars', 'finding_id': 'A02-F029', 'metric': 'bash_quoting_consistency', 'filename': 'fixture.sh', 'source': \"printf '%s' '$a $b $c $d $e'\\n# $a $b $c $d $e\\nprintf '%s' \\\\$a \\\\$b \\\\$c \\\\$d \\\\$e\\n\", 'expected': {'value': None, 'applicable': False, 'group': 'quality', 'contributes_to_overall': False}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '969d0900a57a2ebdba3f1072eff753c988cce608967f0b8c7a87519deaa947ff'}, {'id': 'F032-comment-guard', 'finding_id': 'A02-F032', 'metric': 'preprocessor_hygiene', 'filename': 'fixture.h', 'source': '/*\\n#ifndef FAKE\\n#define FAKE\\n*/\\nint value;\\n', 'expected': {'value': 0.75, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.75}, 'detail_fields': {'has_guard': False}, 'public_only': False, 'original_a02': 'E15-comment-guard-oracle', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'b926dd0b53835db31a22b91138c64a77d6b03560ecb6fa254aebc6ffa4816f46'}, {'id': 'F032-real-guard', 'finding_id': 'A02-F032', 'metric': 'preprocessor_hygiene', 'filename': 'fixture.h', 'source': '#ifndef HEADER\\n#define HEADER\\nint value;\\n#endif\\n', 'expected': {'value': 1.0, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {'has_guard': True}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'd4a2783fb523df30de7140cb216faa58c85266f8e22557bc85f18ecf817acb0c'}, {'id': 'F032-missing-end', 'finding_id': 'A02-F032', 'metric': 'preprocessor_hygiene', 'filename': 'fixture.h', 'source': '#ifndef HEADER\\n#define HEADER\\nint value;\\n', 'expected': {'value': 0.75, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.75}, 'detail_fields': {'has_guard': False, 'conditional_depth': 1}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '30519158a7b558ad06352b4ae41a44ace58e833bdc5f8cfe6c722ee9f24b1b2f'}]\n\nimport dataclasses, hashlib, math, re\nclasses = {item.name:item for item in module.MetricRegistry.metric_classes()}\nconfig = module.merged_metric_config('default')\nobserved = []\ndef same(actual, expected):\n    if isinstance(expected, float):\n        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)\n    return actual == expected\nfor case in cases:\n    assert hashlib.sha256(case['source'].encode()).hexdigest() == case['source_sha256'], case['id']\n    context = module.build_analysis_context(case['source'], case['filename'])\n    checks = []\n    def record(boundary, actual, expected):\n        checks.append(dict(boundary=boundary, actual=actual, expected=expected, matches=same(actual, expected)))\n    if 'identifiers_expected' in case:\n        record('context-identifiers', context.identifiers, case['identifiers_expected'])\n    if 'function_complexities_expected' in case:\n        record('context-function-complexities', [item.cyclomatic for item in context.functions], case['function_complexities_expected'])\n    result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=case['source'], filename=case['filename']))))\n    report_metric = next(item for item in result['report']['metrics'] if item['name'] == case['metric'])\n    metrics = [('public-file-json', report_metric, True)]\n    if not case['public_only']:\n        direct = classes[case['metric']](config).compute(case['source'], context.language, context)\n        metrics.insert(0, ('direct-metric', dataclasses.asdict(direct), False))\n    for boundary, metric, rounded in metrics:\n        for key, value in case['expected'].items():\n            expected = round(value, 4) if key == 'score' and rounded else value\n            record(boundary + ':' + key, metric.get(key), expected)\n        for key, value in case['detail_fields'].items():\n            found = re.search(r'(?:^|[,;] )' + re.escape(key) + r'=([^,; ]+)', metric.get('detail', ''))\n            actual = found.group(1) if found else None\n            record(boundary + ':detail:' + key, actual, str(value))\n        if not case['expected']['applicable']:\n            record(boundary + ':unavailable-reason', bool(metric.get('explanation')), True)\n            if case['metric'] == 'cyclomatic_complexity':\n                record(boundary + ':unavailable-method', all(not metric.get(key) for key in ('method','unit','domain')), True)\n    record('file-text-display-name', report_metric['display_name'] in result['text'], True)\n    if case['metric'] == 'cyclomatic_complexity' and case['expected']['applicable']:\n        unit_text = 'decisions/function' if case['expected']['unit'] == 'decisions_per_function' else 'branches/20 code lines'\n        record('file-unit-display', unit_text in report_metric['value_display'], True)\n        record('file-method-domain-detail', all(case['expected'][key] in report_metric['detail'] for key in ('method','domain')), True)\n        record('file-text-unit-and-method', unit_text in result['text'] and case['expected']['method'] in result['text'], True)\n    observed.append(dict(case=case['id'], source_sha256=case['source_sha256'], metric=case['metric'], checks=checks, matches=all(item['matches'] for item in checks)))\nassert all(item['matches'] for item in observed), [item['case'] for item in observed if not item['matches']]\n"
  },
  {
    "name": "units-lttr-and-pressure",
    "findings": [
      "A02-F025",
      "A02-F026",
      "A02-F031"
    ],
    "script": "cases = [{'id': 'F025-function-mean', 'finding_id': 'A02-F025', 'metric': 'cyclomatic_complexity', 'filename': 'fixture.py', 'source': 'def first():\\n    return 0\\n\\ndef second(a, b):\\n    if a:\\n        return 1\\n    if b:\\n        return 2\\n    return 0\\n', 'expected': {'value': 2.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 1.0, 'method': 'python_ast_function_mean', 'unit': 'decisions_per_function', 'domain': 'recognised_functions'}, 'detail_fields': {'functions': 2}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'function_complexities_expected': [1, 3], 'source_sha256': '8a602b3ef1bccc18cef57a40f04288ca307077d025ce7f6e8bc5e85e03dbe983'}, {'id': 'F025-branch-density', 'finding_id': 'A02-F025', 'metric': 'cyclomatic_complexity', 'filename': 'fixture.js', 'source': 'if (a) ready();\\nif (b) ready();\\nready();\\nready();\\nready();\\nready();\\nready();\\nready();\\nready();\\nready();\\n', 'expected': {'value': 4.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 0.4214876033057851, 'method': 'lexical_branch_density', 'unit': 'branches_per_20_code_lines', 'domain': 'cleaned_file_code'}, 'detail_fields': {'approximate_branches': 2}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'cb57344e3704867885e8d75df66c836d5a038c032a2bb3f53e643e23310cafb1'}, {'id': 'F025-no-python-functions', 'finding_id': 'A02-F025', 'metric': 'cyclomatic_complexity', 'filename': 'fixture.py', 'source': 'value = 0\\n', 'expected': {'value': None, 'applicable': False, 'group': 'context', 'contributes_to_overall': False}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'a06106e01c0ed5a953720fe62093cdd5cc2cbcc2144ca6a260e43a2393c81c0f'}, {'id': 'F025-unclosed-javascript', 'finding_id': 'A02-F025', 'metric': 'cyclomatic_complexity', 'filename': 'fixture.js', 'source': 'const value = \"unfinished', 'expected': {'value': None, 'applicable': False, 'group': 'context', 'contributes_to_overall': False}, 'detail_fields': {}, 'public_only': True, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'b2593e2004d9e20a037d68033b9b587a58be0b4b62eae4aa510fa9563a3f34c4'}, {'id': 'F026-tokens-19-types-1', 'finding_id': 'A02-F026', 'metric': 'type_token_ratio', 'filename': 'fixture.py', 'source': 'a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a\\n', 'expected': {'value': None, 'applicable': False, 'group': 'stylometry', 'contributes_to_overall': True, 'score': 0.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'identifiers_expected': ['a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'], 'source_sha256': '806370577ab20e093a3fa3d295cb4ed4f33c618eff184d24a2e873459a11303a'}, {'id': 'F026-tokens-20-types-1', 'finding_id': 'A02-F026', 'metric': 'type_token_ratio', 'filename': 'fixture.py', 'source': 'a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a + a\\n', 'expected': {'value': 0.0, 'applicable': True, 'group': 'stylometry', 'contributes_to_overall': True, 'score': 0.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': 'E01-single-type-log-oracle identifiers', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'identifiers_expected': ['a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'], 'source_sha256': 'da764d005d87cf36714025bed247b2c14ecec68dea84419ffef3783b03a64654'}, {'id': 'F026-tokens-25-types-5', 'finding_id': 'A02-F026', 'metric': 'type_token_ratio', 'filename': 'fixture.py', 'source': 'a + b + c + d + e + a + b + c + d + e + a + b + c + d + e + a + b + c + d + e + a + b + c + d + e\\n', 'expected': {'value': 0.5, 'applicable': True, 'group': 'stylometry', 'contributes_to_overall': True, 'score': 0.0}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'identifiers_expected': ['a', 'b', 'c', 'd', 'e', 'a', 'b', 'c', 'd', 'e', 'a', 'b', 'c', 'd', 'e', 'a', 'b', 'c', 'd', 'e', 'a', 'b', 'c', 'd', 'e'], 'source_sha256': 'a1636ece09d9c3197aa3b5bdac23ae33ca7aa5c955eb08ab8579e2d1f0f1f5c9'}, {'id': 'F026-tokens-20-types-20', 'finding_id': 'A02-F026', 'metric': 'type_token_ratio', 'filename': 'fixture.py', 'source': 'name0 + name1 + name2 + name3 + name4 + name5 + name6 + name7 + name8 + name9 + name10 + name11 + name12 + name13 + name14 + name15 + name16 + name17 + name18 + name19\\n', 'expected': {'value': 1.0, 'applicable': True, 'group': 'stylometry', 'contributes_to_overall': True}, 'detail_fields': {}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'identifiers_expected': ['name0', 'name1', 'name2', 'name3', 'name4', 'name5', 'name6', 'name7', 'name8', 'name9', 'name10', 'name11', 'name12', 'name13', 'name14', 'name15', 'name16', 'name17', 'name18', 'name19'], 'source_sha256': 'a515a1f29c5fd0ade13206f68bde9f79f4fa0d6e7cbf1436cd9745d2f164cff4'}, {'id': 'F031-live-06', 'finding_id': 'A02-F031', 'metric': 'register_pressure', 'filename': 'fixture.c', 'source': 'int f(void) {\\nint item_0 = 0;\\nint item_1 = 0;\\nint item_2 = 0;\\nint item_3 = 0;\\nint item_4 = 0;\\nint item_5 = 0;\\nreturn item_0 + item_1 + item_2 + item_3 + item_4 + item_5;\\n}', 'expected': {'value': 0.46153846153846156, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 1.0}, 'detail_fields': {'peak_live': 6}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '050ecd684f0cc4c6cf11428a210df1ead37995355d56fdc123090b80fc5c9e28'}, {'id': 'F031-live-11', 'finding_id': 'A02-F031', 'metric': 'register_pressure', 'filename': 'fixture.c', 'source': 'int f(void) {\\nint item_0 = 0;\\nint item_1 = 0;\\nint item_2 = 0;\\nint item_3 = 0;\\nint item_4 = 0;\\nint item_5 = 0;\\nint item_6 = 0;\\nint item_7 = 0;\\nint item_8 = 0;\\nint item_9 = 0;\\nint item_10 = 0;\\nreturn item_0 + item_1 + item_2 + item_3 + item_4 + item_5 + item_6 + item_7 + item_8 + item_9 + item_10;\\n}', 'expected': {'value': 0.8461538461538461, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.5054945054945055}, 'detail_fields': {'peak_live': 11}, 'public_only': False, 'original_a02': 'E11-monotone-quality-oracle source11', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'cf0a48e11235232767b6052fd508d2f70dec4f2498bc59a7d217612392caf8ee'}, {'id': 'F031-live-12', 'finding_id': 'A02-F031', 'metric': 'register_pressure', 'filename': 'fixture.c', 'source': 'int f(void) {\\nint item_0 = 0;\\nint item_1 = 0;\\nint item_2 = 0;\\nint item_3 = 0;\\nint item_4 = 0;\\nint item_5 = 0;\\nint item_6 = 0;\\nint item_7 = 0;\\nint item_8 = 0;\\nint item_9 = 0;\\nint item_10 = 0;\\nint item_11 = 0;\\nreturn item_0 + item_1 + item_2 + item_3 + item_4 + item_5 + item_6 + item_7 + item_8 + item_9 + item_10 + item_11;\\n}', 'expected': {'value': 0.9230769230769231, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.40865384615384615}, 'detail_fields': {'peak_live': 12}, 'public_only': False, 'original_a02': 'E11-monotone-quality-oracle source12', 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': 'd119de0cd7b1d7262445a5a473602439c63182c921f784b20f1ad7009b7f7faf'}, {'id': 'F031-live-17', 'finding_id': 'A02-F031', 'metric': 'register_pressure', 'filename': 'fixture.c', 'source': 'int f(void) {\\nint item_0 = 0;\\nint item_1 = 0;\\nint item_2 = 0;\\nint item_3 = 0;\\nint item_4 = 0;\\nint item_5 = 0;\\nint item_6 = 0;\\nint item_7 = 0;\\nint item_8 = 0;\\nint item_9 = 0;\\nint item_10 = 0;\\nint item_11 = 0;\\nint item_12 = 0;\\nint item_13 = 0;\\nint item_14 = 0;\\nint item_15 = 0;\\nint item_16 = 0;\\nreturn item_0 + item_1 + item_2 + item_3 + item_4 + item_5 + item_6 + item_7 + item_8 + item_9 + item_10 + item_11 + item_12 + item_13 + item_14 + item_15 + item_16;\\n}', 'expected': {'value': 1.3076923076923077, 'applicable': True, 'group': 'quality', 'contributes_to_overall': False, 'score': 0.0}, 'detail_fields': {'peak_live': 17}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'source_sha256': '71d66889ed4312c2c4f7af3c1e2c544320da7d8fcf5e6694d905986cbb042211'}]\n\nimport dataclasses, hashlib, math, re\nclasses = {item.name:item for item in module.MetricRegistry.metric_classes()}\nconfig = module.merged_metric_config('default')\nobserved = []\ndef same(actual, expected):\n    if isinstance(expected, float):\n        return isinstance(actual, (int, float)) and not isinstance(actual, bool) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)\n    return actual == expected\nfor case in cases:\n    assert hashlib.sha256(case['source'].encode()).hexdigest() == case['source_sha256'], case['id']\n    context = module.build_analysis_context(case['source'], case['filename'])\n    checks = []\n    def record(boundary, actual, expected):\n        checks.append(dict(boundary=boundary, actual=actual, expected=expected, matches=same(actual, expected)))\n    if 'identifiers_expected' in case:\n        record('context-identifiers', context.identifiers, case['identifiers_expected'])\n    if 'function_complexities_expected' in case:\n        record('context-function-complexities', [item.cyclomatic for item in context.functions], case['function_complexities_expected'])\n    result = json.loads(module.codeprobe_analyze(json.dumps(dict(code=case['source'], filename=case['filename']))))\n    report_metric = next(item for item in result['report']['metrics'] if item['name'] == case['metric'])\n    metrics = [('public-file-json', report_metric, True)]\n    if not case['public_only']:\n        direct = classes[case['metric']](config).compute(case['source'], context.language, context)\n        metrics.insert(0, ('direct-metric', dataclasses.asdict(direct), False))\n    for boundary, metric, rounded in metrics:\n        for key, value in case['expected'].items():\n            expected = round(value, 4) if key == 'score' and rounded else value\n            record(boundary + ':' + key, metric.get(key), expected)\n        for key, value in case['detail_fields'].items():\n            found = re.search(r'(?:^|[,;] )' + re.escape(key) + r'=([^,; ]+)', metric.get('detail', ''))\n            actual = found.group(1) if found else None\n            record(boundary + ':detail:' + key, actual, str(value))\n        if not case['expected']['applicable']:\n            record(boundary + ':unavailable-reason', bool(metric.get('explanation')), True)\n            if case['metric'] == 'cyclomatic_complexity':\n                record(boundary + ':unavailable-method', all(not metric.get(key) for key in ('method','unit','domain')), True)\n    record('file-text-display-name', report_metric['display_name'] in result['text'], True)\n    if case['metric'] == 'cyclomatic_complexity' and case['expected']['applicable']:\n        unit_text = 'decisions/function' if case['expected']['unit'] == 'decisions_per_function' else 'branches/20 code lines'\n        record('file-unit-display', unit_text in report_metric['value_display'], True)\n        record('file-method-domain-detail', all(case['expected'][key] in report_metric['detail'] for key in ('method','domain')), True)\n        record('file-text-unit-and-method', unit_text in result['text'] and case['expected']['method'] in result['text'], True)\n    observed.append(dict(case=case['id'], source_sha256=case['source_sha256'], metric=case['metric'], checks=checks, matches=all(item['matches'] for item in checks)))\nassert all(item['matches'] for item in observed), [item['case'] for item in observed if not item['matches']]\n"
  },
  {
    "name": "inactive-config-identity-and-notes",
    "findings": [
      "A02-F024"
    ],
    "script": "case = {'id': 'F025-function-mean', 'finding_id': 'A02-F025', 'metric': 'cyclomatic_complexity', 'filename': 'fixture.py', 'source': 'def first():\\n    return 0\\n\\ndef second(a, b):\\n    if a:\\n        return 1\\n    if b:\\n        return 2\\n    return 0\\n', 'expected': {'value': 2.0, 'applicable': True, 'group': 'context', 'contributes_to_overall': False, 'score': 1.0, 'method': 'python_ast_function_mean', 'unit': 'decisions_per_function', 'domain': 'recognised_functions'}, 'detail_fields': {'functions': 2}, 'public_only': False, 'original_a02': None, 'oracle_basis': 'Manual lexical/structural counts or rational arithmetic from the declared finite metric contract', 'function_complexities_expected': [1, 3], 'source_sha256': '8a602b3ef1bccc18cef57a40f04288ca307077d025ce7f6e8bc5e85e03dbe983'}\ninactive = ['identifier_style.ai_low', 'identifier_style.ai_high', 'line_length_uniformity.ai_high', 'halstead_difficulty.mi_high']\noverrides = [None, {'identifier_style': {'thresholds': {'ai_low': -1000, 'ai_high': 1000}}, 'line_length_uniformity': {'thresholds': {'ai_high': -1000}}, 'halstead_difficulty': {'thresholds': {'mi_high': 1000}}}, {'identifier_style': {'thresholds': {'ai_low': 1000, 'ai_high': -1000}}, 'line_length_uniformity': {'thresholds': {'ai_high': 1000}}, 'halstead_difficulty': {'thresholds': {'mi_high': -1000}}}]\nobserved = []\nfor mode in ('file', 'project'):\n    signatures = []\n    digests = []\n    warnings = []\n    for index, override in enumerate(overrides):\n        payload = dict(code=case['source'], filename=case['filename']) if mode == 'file' else dict(files=[dict(path=case['filename'],content=case['source'])])\n        if override is not None:\n            payload['config_override'] = override\n        analyse = module.codeprobe_analyze if mode == 'file' else module.codeprobe_analyze_project\n        result = json.loads(analyse(json.dumps(payload)))\n        report = result['report']\n        child = report if mode == 'file' else report['files'][0]\n        signatures.append([(metric['name'],metric['value'],metric['score'],metric['applicable'],metric['contributes_to_overall']) for metric in child['metrics']])\n        digests.append(report['metric_config_digest'])\n        warnings.append(report['warnings'])\n        checks = dict(inactive_keys=sorted(report['tool_metadata'].get('inactive_thresholds',[])) == sorted(inactive),\n                      note=all(key in '\\n'.join(report['notes']) for key in inactive),\n                      text=all(key in result['text'] for key in inactive),\n                      metrics_unchanged=signatures[-1] == signatures[0],\n                      warnings_unchanged=warnings[-1] == warnings[0],\n                      distinct_config_digest=len(set(digests)) == len(digests))\n        observed.append(dict(case='inactive-thresholds-' + mode + '-' + str(index), source_sha256=case['source_sha256'], metric_config_digest=digests[-1], inactive_thresholds=report['tool_metadata'].get('inactive_thresholds'), notes=report['notes'], checks=checks, matches=all(checks.values())))\nassert all(item['matches'] for item in observed), [item['case'] for item in observed if not item['matches']]\n"
  }
];
  fixtureState.reset();
  const pageUrl = `${baseUrl}/app/index.html?metrics-i11=1`;
  let session = null, workerSession = null, ownership = null, actualRuntime = null;
  try {
    await withinCase("metrics-owned-worker", [], "authenticated-worker-ownership", async () => {
      await cdp.send("Target.setDiscoverTargets", {discover:true});
      const previous = new Set((await cdp.send("Target.getTargets")).targetInfos.map(item => item.targetId));
      session = await createSession(cdp, pageUrl);
      await waitForExpression(cdp, session.sessionId, "appState.workerSession?.isReady()", 60000);
      assertSingleVerifiedRequests(fixtureState);
      await cdp.send("Target.setAutoAttach", {autoAttach:true, waitForDebuggerOnStart:false, flatten:true,
        filter:[{type:"worker"}, {exclude:true}]}, session.sessionId);
      const discoveryDeadline = Date.now() + 5000;
      let workers = [], attachments = [];
      do {
        workers = (await cdp.send("Target.getTargets")).targetInfos.filter(item => item.type === "worker" && !previous.has(item.targetId) && item.parentId === session.targetId);
        attachments = [...cdp.attachedTargets.entries()].filter(([, item]) => item.parentSessionId === session.sessionId && workers.some(worker => worker.targetId === item.targetInfo.targetId));
        if (workers.length && attachments.length) break;
        await delay(100);
      } while (Date.now() < discoveryDeadline);
      assert(workers.length === 1 && attachments.length === 1, "Metric contracts oracle did not locate exactly one owned worker channel");
      const worker = workers[0];
      if (worker.openerId) assert(worker.openerId === session.targetId, "Metric contracts oracle worker opener differs from its owned page");
      assert(attachments[0][1].targetInfo.type === "worker" && attachments[0][1].targetInfo.parentId === session.targetId, "Metric contracts oracle attachment differs from its owned worker");
      [workerSession] = attachments[0];
      await cdp.send("Runtime.enable", {}, workerSession);
      const workerBase = await evaluate(cdp, workerSession, "self.CODEPROBE_BASE_URL");
      assert(workerBase === pageUrl, "Metric contracts oracle worker bootstrap URL differs from its owned page");
      ownership = {page_target_id:session.targetId, worker_target_id:worker.targetId, worker_parent_id:worker.parentId, bootstrap_url:workerBase};
      return ownership;
    });
    for (const item of directCases) {
      await withinCase(item.name, item.findings, "context-in-authenticated-worker", async () => {
        const script = "def _codeprobe_metrics_i11_fixture():\n    import json, sys\n    module = sys.modules['codeprobe_runtime']\n" +
          item.script.trim().split("\n").map(line => "    " + line).join("\n") +
          "\n    metadata = json.loads(module.codeprobe_engine_metadata('{}'))\n    return json.dumps(dict(observed=observed, runtime=metadata['python_runtime'], measured_sha256=metadata['engine_fingerprint']['value']), allow_nan=False)\n_codeprobe_metrics_i11_fixture()\n";
        const result = await evaluate(cdp, workerSession, `(async () => {
          const runtime = await self.CodeProbeRuntime.loadVerifiedPyodide();
          try { return JSON.parse(runtime.runPython(${JSON.stringify(script)})); }
          finally { runtime.globals.delete('_codeprobe_metrics_i11_fixture'); }
        })()`);
        assert(result.runtime.platform === "emscripten" && result.runtime.version === "3.11.3", "Metric contracts context oracle used an unexpected interpreter");
        assert(result.measured_sha256 === engineDigest, "Metric contracts context oracle used different engine bytes");
        actualRuntime = result.runtime;
        assertSingleVerifiedRequests(fixtureState);
        return {...result, oracle_sha256:crypto.createHash("sha256").update(script).digest("hex")};
      });
    }
  } finally {
    if (workerSession) await cdp.send("Target.detachFromTarget", {sessionId:workerSession}, session.sessionId);
    if (session) await closeSession(cdp, session);
    await cdp.send("Target.setDiscoverTargets", {discover:false});
  }

  const fileCases = [
  {
    "id": "F025-function-mean",
    "finding_id": "A02-F025",
    "metric": "cyclomatic_complexity",
    "filename": "fixture.py",
    "source": "def first():\n    return 0\n\ndef second(a, b):\n    if a:\n        return 1\n    if b:\n        return 2\n    return 0\n",
    "expected": {
      "value": 2.0,
      "applicable": true,
      "group": "context",
      "contributes_to_overall": false,
      "score": 1.0,
      "method": "python_ast_function_mean",
      "unit": "decisions_per_function",
      "domain": "recognised_functions"
    },
    "detail_fields": {
      "functions": 2
    },
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "function_complexities_expected": [
      1,
      3
    ],
    "source_sha256": "8a602b3ef1bccc18cef57a40f04288ca307077d025ce7f6e8bc5e85e03dbe983"
  },
  {
    "id": "F025-branch-density",
    "finding_id": "A02-F025",
    "metric": "cyclomatic_complexity",
    "filename": "fixture.js",
    "source": "if (a) ready();\nif (b) ready();\nready();\nready();\nready();\nready();\nready();\nready();\nready();\nready();\n",
    "expected": {
      "value": 4.0,
      "applicable": true,
      "group": "context",
      "contributes_to_overall": false,
      "score": 0.4214876033057851,
      "method": "lexical_branch_density",
      "unit": "branches_per_20_code_lines",
      "domain": "cleaned_file_code"
    },
    "detail_fields": {
      "approximate_branches": 2
    },
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "cb57344e3704867885e8d75df66c836d5a038c032a2bb3f53e643e23310cafb1"
  },
  {
    "id": "F025-no-python-functions",
    "finding_id": "A02-F025",
    "metric": "cyclomatic_complexity",
    "filename": "fixture.py",
    "source": "value = 0\n",
    "expected": {
      "value": null,
      "applicable": false,
      "group": "context",
      "contributes_to_overall": false
    },
    "detail_fields": {},
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "a06106e01c0ed5a953720fe62093cdd5cc2cbcc2144ca6a260e43a2393c81c0f"
  },
  {
    "id": "F026-tokens-25-types-5",
    "finding_id": "A02-F026",
    "metric": "type_token_ratio",
    "filename": "fixture.py",
    "source": "a + b + c + d + e + a + b + c + d + e + a + b + c + d + e + a + b + c + d + e + a + b + c + d + e\n",
    "expected": {
      "value": 0.5,
      "applicable": true,
      "group": "stylometry",
      "contributes_to_overall": true,
      "score": 0.0
    },
    "detail_fields": {},
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "identifiers_expected": [
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e"
    ],
    "source_sha256": "a1636ece09d9c3197aa3b5bdac23ae33ca7aa5c955eb08ab8579e2d1f0f1f5c9"
  },
  {
    "id": "F031-live-12",
    "finding_id": "A02-F031",
    "metric": "register_pressure",
    "filename": "fixture.c",
    "source": "int f(void) {\nint item_0 = 0;\nint item_1 = 0;\nint item_2 = 0;\nint item_3 = 0;\nint item_4 = 0;\nint item_5 = 0;\nint item_6 = 0;\nint item_7 = 0;\nint item_8 = 0;\nint item_9 = 0;\nint item_10 = 0;\nint item_11 = 0;\nreturn item_0 + item_1 + item_2 + item_3 + item_4 + item_5 + item_6 + item_7 + item_8 + item_9 + item_10 + item_11;\n}",
    "expected": {
      "value": 0.9230769230769231,
      "applicable": true,
      "group": "quality",
      "contributes_to_overall": false,
      "score": 0.40865384615384615
    },
    "detail_fields": {
      "peak_live": 12
    },
    "public_only": false,
    "original_a02": "E11-monotone-quality-oracle source12",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "d119de0cd7b1d7262445a5a473602439c63182c921f784b20f1ad7009b7f7faf"
  },
  {
    "id": "F021-quoted-main-guard",
    "finding_id": "A02-F021",
    "metric": "boilerplate_presence",
    "filename": "fixture.py",
    "source": "label = 'if __name__ == \"__main__\"'\n",
    "expected": {
      "value": 0.0,
      "applicable": true,
      "group": "context",
      "contributes_to_overall": false,
      "score": 0.0
    },
    "detail_fields": {
      "indicators": "0/5"
    },
    "public_only": false,
    "original_a02": "boilerplate:ignore_string_contents",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "69b17c01f3e3ece9108532e2e3d3f6d5c872a002869d42c0f96ae299b6f8b927"
  }
];
  const projectCases = [
  {
    "id": "F025-function-mean",
    "finding_id": "A02-F025",
    "metric": "cyclomatic_complexity",
    "filename": "fixture.py",
    "source": "def first():\n    return 0\n\ndef second(a, b):\n    if a:\n        return 1\n    if b:\n        return 2\n    return 0\n",
    "expected": {
      "value": 2.0,
      "applicable": true,
      "group": "context",
      "contributes_to_overall": false,
      "score": 1.0,
      "method": "python_ast_function_mean",
      "unit": "decisions_per_function",
      "domain": "recognised_functions"
    },
    "detail_fields": {
      "functions": 2
    },
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "function_complexities_expected": [
      1,
      3
    ],
    "source_sha256": "8a602b3ef1bccc18cef57a40f04288ca307077d025ce7f6e8bc5e85e03dbe983",
    "selected_filename": "F025-function-mean.py"
  },
  {
    "id": "F025-branch-density",
    "finding_id": "A02-F025",
    "metric": "cyclomatic_complexity",
    "filename": "fixture.js",
    "source": "if (a) ready();\nif (b) ready();\nready();\nready();\nready();\nready();\nready();\nready();\nready();\nready();\n",
    "expected": {
      "value": 4.0,
      "applicable": true,
      "group": "context",
      "contributes_to_overall": false,
      "score": 0.4214876033057851,
      "method": "lexical_branch_density",
      "unit": "branches_per_20_code_lines",
      "domain": "cleaned_file_code"
    },
    "detail_fields": {
      "approximate_branches": 2
    },
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "cb57344e3704867885e8d75df66c836d5a038c032a2bb3f53e643e23310cafb1",
    "selected_filename": "F025-branch-density.js"
  },
  {
    "id": "F025-no-python-functions",
    "finding_id": "A02-F025",
    "metric": "cyclomatic_complexity",
    "filename": "fixture.py",
    "source": "value = 0\n",
    "expected": {
      "value": null,
      "applicable": false,
      "group": "context",
      "contributes_to_overall": false
    },
    "detail_fields": {},
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "a06106e01c0ed5a953720fe62093cdd5cc2cbcc2144ca6a260e43a2393c81c0f",
    "selected_filename": "F025-no-python-functions.py"
  },
  {
    "id": "F026-tokens-25-types-5",
    "finding_id": "A02-F026",
    "metric": "type_token_ratio",
    "filename": "fixture.py",
    "source": "a + b + c + d + e + a + b + c + d + e + a + b + c + d + e + a + b + c + d + e + a + b + c + d + e\n",
    "expected": {
      "value": 0.5,
      "applicable": true,
      "group": "stylometry",
      "contributes_to_overall": true,
      "score": 0.0
    },
    "detail_fields": {},
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "identifiers_expected": [
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e",
      "a",
      "b",
      "c",
      "d",
      "e"
    ],
    "source_sha256": "a1636ece09d9c3197aa3b5bdac23ae33ca7aa5c955eb08ab8579e2d1f0f1f5c9",
    "selected_filename": "F026-tokens-25-types-5.py"
  },
  {
    "id": "F031-live-12",
    "finding_id": "A02-F031",
    "metric": "register_pressure",
    "filename": "fixture.c",
    "source": "int f(void) {\nint item_0 = 0;\nint item_1 = 0;\nint item_2 = 0;\nint item_3 = 0;\nint item_4 = 0;\nint item_5 = 0;\nint item_6 = 0;\nint item_7 = 0;\nint item_8 = 0;\nint item_9 = 0;\nint item_10 = 0;\nint item_11 = 0;\nreturn item_0 + item_1 + item_2 + item_3 + item_4 + item_5 + item_6 + item_7 + item_8 + item_9 + item_10 + item_11;\n}",
    "expected": {
      "value": 0.9230769230769231,
      "applicable": true,
      "group": "quality",
      "contributes_to_overall": false,
      "score": 0.40865384615384615
    },
    "detail_fields": {
      "peak_live": 12
    },
    "public_only": false,
    "original_a02": "E11-monotone-quality-oracle source12",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "d119de0cd7b1d7262445a5a473602439c63182c921f784b20f1ad7009b7f7faf",
    "selected_filename": "F031-live-12.c"
  },
  {
    "id": "F021-quoted-main-guard",
    "finding_id": "A02-F021",
    "metric": "boilerplate_presence",
    "filename": "fixture.py",
    "source": "label = 'if __name__ == \"__main__\"'\n",
    "expected": {
      "value": 0.0,
      "applicable": true,
      "group": "context",
      "contributes_to_overall": false,
      "score": 0.0
    },
    "detail_fields": {
      "indicators": "0/5"
    },
    "public_only": false,
    "original_a02": "boilerplate:ignore_string_contents",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "69b17c01f3e3ece9108532e2e3d3f6d5c872a002869d42c0f96ae299b6f8b927",
    "selected_filename": "F021-quoted-main-guard.py"
  },
  {
    "id": "F027-comment-use",
    "finding_id": "A02-F027",
    "metric": "used_import_ratio",
    "filename": "fixture.js",
    "source": "import value from 'module';\nconst result = 1;\n// value",
    "expected": {
      "value": 0.0,
      "applicable": true,
      "group": "quality",
      "contributes_to_overall": false,
      "score": 0.0
    },
    "detail_fields": {},
    "public_only": false,
    "original_a02": "E03-js-comment-use-oracle",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "fda7bb017a5aa94559541862e4db446738058c3d2f365674fa9aeab2c4a030bb",
    "selected_filename": "F027-comment-use.js"
  },
  {
    "id": "F028-template-inert-markers",
    "finding_id": "A02-F028",
    "metric": "javascript_modern_syntax",
    "filename": "fixture.js",
    "source": "var text = `const let => ?. ?? ...`;\n",
    "expected": {
      "value": 0.0,
      "applicable": true,
      "group": "quality",
      "contributes_to_overall": false,
      "score": 0.0
    },
    "detail_fields": {
      "modern": 0,
      "legacy": 1
    },
    "public_only": false,
    "original_a02": null,
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "076a4a83552a112e5eb62d6b4f960eff29d045b6fc9cca58e8e6afb622361d23",
    "selected_filename": "F028-template-inert-markers.js"
  },
  {
    "id": "F029-grouped-five",
    "finding_id": "A02-F029",
    "metric": "bash_quoting_consistency",
    "filename": "fixture.sh",
    "source": "printf \"%s\" \"$a $b $c $d $e\"",
    "expected": {
      "value": 1.0,
      "applicable": true,
      "group": "quality",
      "contributes_to_overall": false,
      "score": 1.0
    },
    "detail_fields": {
      "references": 5,
      "double_quoted": 5
    },
    "public_only": false,
    "original_a02": "E09-grouped-quoting-oracle",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "623b60893ee75ad390f18fc379e838c6ccb4c5528afad0c80031871961bb1a4c",
    "selected_filename": "F029-grouped-five.sh"
  },
  {
    "id": "F032-comment-guard",
    "finding_id": "A02-F032",
    "metric": "preprocessor_hygiene",
    "filename": "fixture.h",
    "source": "/*\n#ifndef FAKE\n#define FAKE\n*/\nint value;\n",
    "expected": {
      "value": 0.75,
      "applicable": true,
      "group": "quality",
      "contributes_to_overall": false,
      "score": 0.75
    },
    "detail_fields": {
      "has_guard": false
    },
    "public_only": false,
    "original_a02": "E15-comment-guard-oracle",
    "oracle_basis": "Manual lexical/structural counts or rational arithmetic from the declared finite metric contract",
    "source_sha256": "b926dd0b53835db31a22b91138c64a77d6b03560ecb6fa254aebc6ffa4816f46",
    "selected_filename": "F032-comment-guard.h"
  }
];
  const inactiveKeys = [
  "identifier_style.ai_low",
  "identifier_style.ai_high",
  "line_length_uniformity.ai_high",
  "halstead_difficulty.mi_high"
];
  const inactiveOverrides = [
  {
    "identifier_style": {
      "thresholds": {
        "ai_low": -1000,
        "ai_high": 1000
      }
    },
    "line_length_uniformity": {
      "thresholds": {
        "ai_high": -1000
      }
    },
    "halstead_difficulty": {
      "thresholds": {
        "mi_high": 1000
      }
    }
  },
  {
    "identifier_style": {
      "thresholds": {
        "ai_low": 1000,
        "ai_high": -1000
      }
    },
    "line_length_uniformity": {
      "thresholds": {
        "ai_high": 1000
      }
    },
    "halstead_difficulty": {
      "thresholds": {
        "mi_high": -1000
      }
    }
  }
];

  function same(actual, expected) {
    return typeof expected === "number" ? typeof actual === "number" && Math.abs(actual - expected) <= 1e-10 : actual === expected;
  }
  function checkMetric(report, item) {
    assert(report.engine_fingerprint.value === engineDigest && report.engine_fingerprint.source === "packaged-verified", "I11 metric report lost verified provenance");
    const metric = report.metrics.find(value => value.name === item.metric);
    assert(metric, `I11 metric missing: ${item.metric}`);
    for (const [key, expected] of Object.entries(item.expected)) {
      const value = key === "score" ? Math.round((expected + Number.EPSILON) * 10000) / 10000 : expected;
      assert(same(metric[key], value), `I11 ${item.id} ${key}: ${JSON.stringify(metric[key])} differs from ${JSON.stringify(value)}`);
    }
    for (const [key, expected] of Object.entries(item.detail_fields)) {
      const found = new RegExp(`(?:^|[,;] )${key}=([^,; ]+)`).exec(metric.detail || "");
      const value = typeof expected === "boolean" ? (expected ? "True" : "False") : String(expected);
      assert(found && found[1] === value, `I11 ${item.id} lost exact detail ${key}=${value}`);
    }
    if (!metric.applicable) {
      assert(metric.explanation && metric.value === null, "I11 unavailable metric lost its reason or null value");
      if (item.metric === "cyclomatic_complexity") assert(["method","unit","domain"].every(key => !(key in metric)), "Unavailable cyclomatic metric acquired method metadata");
    }
    return metric;
  }
  function checkNotes(report, text) {
    assert(JSON.stringify([...report.tool_metadata.inactive_thresholds].sort()) === JSON.stringify([...inactiveKeys].sort()), "I11 inactive-threshold inventory differs");
    assert(inactiveKeys.every(key => report.notes.join("\n").includes(key) && text.includes(key)), "I11 inactive-threshold explanation is absent from notes/text");
  }
  async function download(id, name, result) {
    fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
    await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
    await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
    const jsonPath = path.join(downloads, `${name}.json`), textPath = path.join(downloads, `${name}.txt`);
    await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
    assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(result.report), "I11 JSON download differs from accepted report");
    assert(fs.readFileSync(textPath, "utf8") === result.text, "I11 text download differs from accepted report");
  }
  fixtureState.reset();
  let page = null;
  try {
    for (const item of fileCases) {
      await withinCase(`main-file-${item.id}-metric-notes-exports`, [item.finding_id, "A02-F024"], "public-file-ui-worker-report-exports", async () => {
        if (!page) {
          page = await createSession(cdp, `${baseUrl}/app/index.html?metrics-i11-file=1`);
          await waitForExpression(cdp, page.sessionId, "appState.workerSession?.isReady()", 60000);
        }
        const id = page.sessionId;
        const override = item.id === "F025-function-mean" ? inactiveOverrides[0] : {};
        await evaluate(cdp, id, `(() => {
          const config = document.getElementById('configOverride'); config.value = ${JSON.stringify(JSON.stringify(override))};
          config.dispatchEvent(new Event('input', {bubbles:true})); config.closest('details').open = true;
          const transfer = new DataTransfer();
          transfer.items.add(new File([${JSON.stringify(item.source)}], ${JSON.stringify(item.filename)}, {type:'text/plain'}));
          const input = document.getElementById('fileInput'); input.files = transfer.files;
          input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, "appState.loadingInput === false && !document.getElementById('analyzeBtn').disabled", 60000);
        const imported = await evaluate(cdp, id, "document.getElementById('editor').value");
        assert(imported === item.source, "I11 File import changed source bytes");
        await evaluate(cdp, id, "document.getElementById('analyzeBtn').click()");
        await waitForExpression(cdp, id, "document.getElementById('statusText').textContent === 'Analysis completed.'", 60000);
        await evaluate(cdp, id, "document.getElementById('result-tab-summary').click()");
        const result = await evaluate(cdp, id, "({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, notes:document.getElementById('notesList').textContent, help:document.getElementById('configOverride').closest('details').textContent, notesVisible:document.getElementById('notesList').getClientRects().length > 0})");
        const metric = checkMetric(result.report, item);
        checkNotes(result.report, result.text);
        assert(result.notesVisible && inactiveKeys.every(key => result.notes.includes(key) && result.help.includes(key)), "I11 main UI hides inactive keys or omits configuration help");
        const metricIndex = result.report.metrics.findIndex(value => value.name === item.metric);
        await evaluate(cdp, id, `document.getElementById('result-tab-metrics').click(); document.querySelector('[data-metric-index="${metricIndex}"]').click()`);
        const visible = await evaluate(cdp, id, `({row:document.querySelector('[data-metric-index="${metricIndex}"]').textContent, detail:document.getElementById('metricDetail').textContent, shown:document.getElementById('metricDetail').getClientRects().length > 0})`);
        assert(visible.shown && visible.row.includes(metric.value_display) && visible.detail.includes(metric.value_display), "I11 metric value is absent from the visible row/detail");
        assert(result.text.includes(metric.display_name), "I11 text export omits the metric");
        if (item.metric === "cyclomatic_complexity" && metric.applicable) {
          const unit = metric.unit === "decisions_per_function" ? "decisions/function" : "branches/20 code lines";
          assert(visible.row.includes(unit) && visible.detail.includes(metric.method) && visible.detail.includes(metric.domain), "I11 visible Cyclomatic value lacks unit/method/domain");
          assert(result.text.includes(unit) && result.text.includes(metric.method), "I11 Cyclomatic text lacks unit/method");
        }
        await download(id, item.filename.replace(/\.[^.]+$/, ""), result);
        assertSingleVerifiedRequests(fixtureState);
        return {case:item.id, source_sha256:item.source_sha256, metric, visible, inactive_thresholds:result.report.tool_metadata.inactive_thresholds,
          config_override:override, metric_config_digest:result.report.metric_config_digest, engine_sha256:engineDigest};
      });
    }
  } finally { if (page) await closeSession(cdp, page); }
  for (const compact of [false, true]) {
    fixtureState.reset();
    let projectPage = null;
    const mode = compact ? "compact-project" : "main-project";
    const active = compact ? "state" : "appState", button = compact ? "analyseBtn" : "analyzeBtn", status = compact ? "status" : "statusText";
    try {
      await withinCase(`${mode}-metric-metadata-notes-exports`, ["A02-F021","A02-F024","A02-F025","A02-F026","A02-F027","A02-F028","A02-F029","A02-F031","A02-F032"], "public-project-ui-worker-report-exports", async () => {
        projectPage = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?metrics-i11-project=1`);
        const id = projectPage.sessionId;
        if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
        await evaluate(cdp, id, `(() => {
          const transfer = new DataTransfer();
          for (const item of ${JSON.stringify(projectCases)}) {
            const file = new File([item.source], item.selected_filename, {type:'text/plain'});
            Object.defineProperty(file, '_codeprobeRelativePath', {value:'metrics/' + item.selected_filename});
            transfer.items.add(file);
          }
          const input = document.getElementById('folderInput'); input.files = transfer.files;
          input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, `${active}.loadingInput === false && !document.getElementById('${button}').disabled`, 60000);
        await evaluate(cdp, id, `document.getElementById('${button}').click()`);
        await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === 'Project analysis completed.'`, 60000);
        if (!compact) await evaluate(cdp, id, "document.getElementById('result-tab-text').click()");
        const result = await evaluate(cdp, id, "({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, textVisible:document.getElementById('textReport').getClientRects().length > 0})");
        assert(result.report.engine_fingerprint.value === engineDigest && result.report.included_file_count === projectCases.length && result.report.excluded_file_count === 0, "I11 project admission differs from actual File inventory");
        checkNotes(result.report, result.text);
        assert(result.textVisible, "I11 project notes/text are not visible");
        const checked = [];
        for (const item of projectCases) {
          const child = result.report.files.find(value => value.path.endsWith(item.selected_filename));
          assert(child && result.text.includes(item.selected_filename), "I11 project member/path missing from JSON/text");
          const metric = checkMetric(child, item);
          if (item.metric === "cyclomatic_complexity" && metric.applicable) {
            assert([metric.method, metric.unit, metric.domain].every(value => result.text.includes(value)), "I11 project child Cyclomatic text lacks metadata");
          }
          checked.push({case:item.id, source_sha256:item.source_sha256, path:child.path, metric});
        }
        await download(id, compact ? "metrics" : "selected-files", result);
        assertSingleVerifiedRequests(fixtureState);
        return {included:projectCases.length, excluded:0, checked, inactive_thresholds:result.report.tool_metadata.inactive_thresholds,
          engine_sha256:engineDigest, qualification:compact ? "Actual compact project UI and visible text report; no config override control exists on this page." : "Actual main project UI and visible text report using default configuration."};
      });
    } finally { if (projectPage) await closeSession(cdp, projectPage); }
  }
  console.log("[PASS] browser-metrics-i11: " + JSON.stringify({engine_sha256:engineDigest, runtime:actualRuntime, ownership, observations,
    qualification:"Three fixed groups cover 41 source-bound metric rows; one group checks six file/project inactive-configuration observations. Six main File/DOM cases and both project UIs transport actual source through the public worker and download exact JSON/text. Native observations are separately qualified. The compact UI exposes notes through its visible text report and has no config override control. Finite structural/lexical proxies and arithmetic do not establish empirical authorship validity."}));
}

async function testReportingContracts(cdp, baseUrl, downloads, fixtureState, engineDigest) {
  const deadline = Date.now() + 300000;
  const observations = [];
  // Fixed source/count oracles, not expectations derived from candidate output.
  const pythonSource = Array.from({length:8}, (_, i) => `def scale_${i}(value):\n    """Return a scaled value."""\n    result = value * ${i + 2}\n    return result\n`).join("\n");
  const cSource = "int sum(int *items, int n) {\n  int total = 0;\n  int scratch[10];\n  for (int i=0; i<n; i++) { total += items[i] + items[i]; }\n  return total;\n}\n";
  const custom = {docstring_coverage:{weight:0.5, contributes_to_overall:true}};
  const cases = [
    {id:"python-default", filename:"reporting.py", source:pythonSource, nominal:0.31, count:7},
    {id:"python-custom", filename:"reporting.py", source:pythonSource, override:custom, nominal:0.81, count:8},
    {id:"python-disabled-custom", filename:"reporting.py", source:pythonSource, override:{docstring_coverage:{weight:0.5, contributes_to_overall:false}}, nominal:0.31, count:7},
    {id:"markdown-siblings", filename:"siblings.md", source:"# Top\n## One\n## Two\n## Three\n", nominal:0.31, count:7, metric:"markdown_heading_structure", value:1, applicable:true},
    {id:"markdown-jump", filename:"jump.md", source:"# Top\n### Detail\n", nominal:0.31, count:7, metric:"markdown_heading_structure", value:0.5, applicable:true},
    {id:"markdown-code-only", filename:"inline.md", source:"`[not a link](https://example.invalid)`\n", nominal:0.31, count:7, metric:"markdown_link_density", value:null, applicable:false},
    {id:"markdown-link-free-prose", filename:"prose.md", source:"This guide uses prose without links or code.\n", nominal:0.31, count:7, metric:"markdown_link_density", value:0, applicable:true},
    {id:"c-source-proxies", filename:"sample.c", source:cSource, nominal:0.31, count:7, proxies:true},
    {id:"c-unavailable-proxies", filename:"empty.c", source:"int value;\n", nominal:0.31, count:7, proxies:false}
  ];
  const proxyExpectations = {
    register_pressure:[2/13,"peak_scalar_names_per_13"],
    stack_frame_depth:[48,"estimated_bytes"],
    redundant_memory_access:[20/3,"cues_per_20_function_lines"]
  };
  function near(actual, expected, label, tolerance = 1e-10) {
    assert(typeof actual === "number" && Number.isFinite(actual) && Math.abs(actual - expected) <= tolerance, label);
  }
  function checkCoverage(report, text, project = false) {
    const basis = report.evidence_coverage_basis;
    assert(basis && report.evidence_coverage === report.confidence && basis.category === report.confidence, "I12 coverage aliases disagree");
    assert(basis.interpretation.includes("not a probability") && basis.warning_timing.includes("later"), "I12 coverage claims statistical confidence or loses warning timing");
    assert(text.includes(`Evidence coverage: ${report.confidence}`) && !text.includes("Confidence:"), "I12 text label differs from heuristic coverage");
    assert(basis.factors.sloc === report.sloc, "I12 coverage source quantity differs");
    if (project) {
      assert(basis.factors.included_files === report.included_file_count, "I12 project coverage loses its file denominator");
      near(report.aggregation.effective_weight_sloc, report.aggregation.contributors.reduce((sum, item) => sum + item.weight, 0), "I12 project weighting does not reconcile");
    } else {
      const contributors = report.metrics.filter(item => item.applicable && item.contributes_to_overall && item.weight > 0);
      assert(basis.factors.applicable_contributors === contributors.length, "I12 applicable contributor count differs");
      near(report.aggregation.effective_weight, contributors.reduce((sum, item) => sum + item.weight, 0), "I12 effective metric denominator differs");
      near(report.aggregation.aggregate_applied_weight, report.overall_applicable ? report.aggregation.effective_weight : 0, "I12 ineligible aggregate applies a weight");
      assert(JSON.stringify(report.aggregation.contributors) === JSON.stringify(contributors.map(item => item.name)), "I12 contributor identities differ");
    }
  }
  function checkReportingFile(report, text, item) {
    checkCoverage(report, text);
    const roles = report.metric_role_summary;
    assert(roles && roles.configured_contributor_count === item.count, "I12 nominal contributor count differs");
    near(roles.contributing_weight, item.nominal, "I12 nominal weight differs");
    near(report.aggregation.nominal_weight, item.nominal, "I12 aggregation mislabels nominal weight");
    assert(text.includes(`Nominal configured weight: ${item.nominal}`), "I12 text loses the nominal weight");
    if (item.id.startsWith("python-")) {
      assert(report.overall_applicable, "I12 positive Python control has no aggregate");
      const doc = report.metrics.find(metric => metric.name === "docstring_coverage");
      assert(doc && doc.applicable && doc.contributes_to_overall === (item.count === 8), "I12 Boolean contribution override differs from its native contract");
    }
    if (item.metric) {
      const metric = report.metrics.find(value => value.name === item.metric);
      assert(metric && metric.applicable === item.applicable && metric.value === item.value, "I12 Markdown result differs from fixed editorial/denominator oracle");
      assert(report.overall_applicable === false && report.evidence_coverage === "N/A" && metric.contributes_to_overall === false, "I12 Markdown acquired a code aggregate");
      if (!item.applicable) assert(metric.explanation.includes("prose-token denominator"), "I12 absent denominator lacks its explanation");
      if (item.id === "markdown-jump") assert(metric.explanation.includes("not a CommonMark error"), "I12 editorial preference became a syntax claim");
    }
    if (item.proxies !== undefined) {
      for (const [name, [value, unit]] of Object.entries(proxyExpectations)) {
        const metric = report.metrics.find(item => item.name === name);
        assert(metric && metric.applicable === item.proxies, "I12 proxy availability differs");
        if (item.proxies) {
          // Public metric values are rounded to four decimal places.
          near(metric.value, value, "I12 source proxy value changed", 0.000051);
          assert(metric.unit === unit && metric.domain === "recognised_functions" && metric.method, "I12 source proxy metadata differs");
          assert(metric.explanation.toLowerCase().includes("source") && metric.explanation.toLowerCase().includes("not"), "I12 proxy is presented as hardware evidence");
          assert(text.includes(metric.explanation), "I12 text loses source-proxy scope");
          assert(metric.reference_usage.length === metric.references.length && metric.reference_usage.length > 0, "I12 reference scopes are absent");
          metric.reference_usage.forEach((ref, index) => assert(ref.citation === metric.references[index] && ["definition","motivation","context"].includes(ref.role) && ref.scope, "I12 reference identity or role differs"));
          if (name === "register_pressure") assert(metric.references.some(ref => ref.includes("Chaitin, G. J. (1982)") && ref.includes("10.1145/872726.806984")), "I12 register-allocation reference metadata differs");
        } else assert(metric.value === null && !metric.method, "I12 unavailable proxy claims a measurement");
      }
    }
    return {case:item.id, source_sha256:crypto.createHash("sha256").update(item.source).digest("hex"), coverage:report.evidence_coverage, aggregation:report.aggregation, configured_count:roles.configured_contributor_count};
  }
  // Native-checkable contract helpers end; subsequent code uses genuine CDP/UI.
  async function record(name, operation) {
    const remaining = Math.min(60000, deadline - Date.now());
    assert(remaining > 0, "I12 reporting group exceeded its budget");
    let timer;
    try {
      const result = await Promise.race([operation(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`I12 reporting case timed out: ${name}`)), remaining);
      })]);
      observations.push({case:name, result:"PASS", observed:result});
      console.log("[PASS] browser-reporting-i12-case: " + JSON.stringify(observations.at(-1)));
    } finally { clearTimeout(timer); }
  }
  function checkProvenance(report) {
    assert(report.engine_fingerprint.value === engineDigest && report.engine_fingerprint.source === "packaged-verified", "I12 report lost verified source identity");
    assert(report.tool_metadata.python_runtime.platform === "emscripten" && report.tool_metadata.python_runtime.version === "3.11.3", "I12 browser fixture is not the pinned interpreter");
    assertSingleVerifiedRequests(fixtureState);
  }
  async function download(id, name, result) {
    fs.rmSync(downloads, {recursive:true, force:true}); fs.mkdirSync(downloads, {recursive:true});
    await cdp.send("Browser.setDownloadBehavior", {behavior:"allow", downloadPath:downloads});
    await evaluate(cdp, id, "document.getElementById('exportJsonBtn').click(); document.getElementById('exportTextBtn').click()");
    const jsonPath = path.join(downloads, `${name}.json`), textPath = path.join(downloads, `${name}.txt`);
    await Promise.all([waitForFile(jsonPath, 60000), waitForFile(textPath, 60000)]);
    assert(JSON.stringify(JSON.parse(fs.readFileSync(jsonPath, "utf8"))) === JSON.stringify(result.report), "I12 downloaded JSON differs");
    assert(fs.readFileSync(textPath, "utf8") === result.text, "I12 downloaded text differs");
  }
  fixtureState.reset();
  let page = null;
  try {
    await record("main-runtime-ready", async () => {
      page = await createSession(cdp, `${baseUrl}/app/index.html?reporting-i12=1`);
      await waitForExpression(cdp, page.sessionId, "appState.workerSession?.isReady()", 60000);
      assertSingleVerifiedRequests(fixtureState);
      return {page_target_id:page.targetId};
    });
    const id = page.sessionId;
    for (const item of cases) await record(`main-file-${item.id}`, async () => {
      await evaluate(cdp, id, `(() => {
        const config = document.getElementById('configOverride'); config.value = ${JSON.stringify(item.override ? JSON.stringify(item.override) : "")};
        config.dispatchEvent(new Event('change', {bubbles:true}));
        const transfer = new DataTransfer(); transfer.items.add(new File([${JSON.stringify(item.source)}], ${JSON.stringify(item.filename)}, {type:'text/plain'}));
        const input = document.getElementById('fileInput'); input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles:true}));
      })()`);
      await waitForExpression(cdp, id, "appState.loadingInput === false && !document.getElementById('analyzeBtn').disabled", 60000);
      assert(await evaluate(cdp, id, `document.getElementById('editor').value === ${JSON.stringify(item.source)}`), "I12 File source changed before analysis");
      await evaluate(cdp, id, "document.getElementById('analyzeBtn').click()");
      await waitForExpression(cdp, id, "document.getElementById('statusText').textContent === 'Analysis completed.'", 60000);
      await evaluate(cdp, id, "document.getElementById('result-tab-summary').click()");
      const result = await evaluate(cdp, id, "({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, label:document.getElementById('confidenceValue').textContent, basis:document.getElementById('evidenceCoverageBasis').textContent, basisVisible:document.getElementById('evidenceCoverageBasis').getClientRects().length > 0})");
      checkProvenance(result.report);
      const checked = checkReportingFile(result.report, result.text, item);
      assert(result.label === result.report.evidence_coverage && result.basisVisible && result.basis.includes(JSON.stringify(result.report.evidence_coverage_basis.factors)), "I12 visible coverage factors differ from the accepted report");
      if (item.proxies) {
        const index = result.report.metrics.findIndex(metric => metric.name === "register_pressure");
        await evaluate(cdp, id, `document.getElementById('result-tab-metrics').click(); document.querySelector('[data-metric-index="${index}"]').click()`);
        const detail = await evaluate(cdp, id, "({text:document.getElementById('metricDetail').textContent, visible:document.getElementById('metricDetail').getClientRects().length > 0})");
        const metric = result.report.metrics[index];
        assert(detail.visible && detail.text.includes(metric.explanation) && metric.reference_usage.every(ref => detail.text.includes(ref.scope)), "I12 visible metric detail loses reference or proxy scope");
      }
      await download(id, item.filename.replace(/\.[^.]+$/, ""), result);
      return checked;
    });
    await record("main-invalid-Boolean-override", async () => {
      await evaluate(cdp, id, `(() => {
        const config = document.getElementById('configOverride');
        config.value = '{"docstring_coverage":{"contributes_to_overall":"true"}}';
        config.dispatchEvent(new Event('change', {bubbles:true}));
        document.getElementById('analyzeBtn').click();
      })()`);
      await waitForExpression(cdp, id, "document.getElementById('statusText').textContent.startsWith('Invalid configuration override:')", 60000);
      assert(await evaluate(cdp, id, "document.getElementById('statusText').textContent.includes('contributes_to_overall for docstring_coverage must be true or false.') && document.getElementById('exportJsonBtn').disabled && appState.currentReport === null"), "I12 invalid Boolean override was accepted or left a stale report");
      return {invalid_type:"string", refused:true, exports_disabled:true};
    });
    await record("public-worker-empty-markdown", async () => {
      const result = await evaluate(cdp, id, "appState.workerSession.analyse('file', {code:'', filename:'empty.md'})");
      checkProvenance(result.report); checkCoverage(result.report, result.text);
      for (const name of ["markdown_code_fence_density", "markdown_link_density"]) {
        const metric = result.report.metrics.find(item => item.name === name);
        assert(metric && metric.applicable === false && metric.value === null, "I12 empty Markdown fabricated a denominator");
      }
      return {coverage:result.report.evidence_coverage, qualification:"Public worker transport, not an empty-editor UI analysis or download."};
    });
    await record("main-reset-coverage", async () => {
      await evaluate(cdp, id, "document.getElementById('clearBtn').click()");
      assert(await evaluate(cdp, id, "document.getElementById('confidenceValue').textContent === '—' && document.getElementById('evidenceCoverageBasis').textContent === 'Heuristic source and metric coverage; not statistical confidence.' && document.getElementById('exportJsonBtn').disabled"), "I12 reset retains a stale coverage result");
      return {stale_basis_removed:true};
    });
  } finally { if (page) await closeSession(cdp, page); }
  for (const mode of ["main-default", "main-custom", "compact-default"]) {
    fixtureState.reset();
    const compact = mode.startsWith("compact"), override = mode === "main-custom" ? custom : null;
    const active = compact ? "state" : "appState", button = compact ? "analyseBtn" : "analyzeBtn", status = compact ? "status" : "statusText";
    let projectPage = null;
    try {
      await record(`${mode}-project`, async () => {
        projectPage = await createSession(cdp, `${baseUrl}/app/${compact ? "project" : "index"}.html?reporting-i12-project=1`);
        const id = projectPage.sessionId;
        if (!compact) await waitForExpression(cdp, id, "appState.workerSession?.isReady()", 60000);
        const selected = [cases[0], {...cases[0], filename:"second.py"}, cases[7], {filename:"README.md", source:"# Notes\n"}];
        await evaluate(cdp, id, `(() => {
          const config = document.getElementById('configOverride');
          if (config) { config.value = ${JSON.stringify(override ? JSON.stringify(override) : "")}; config.dispatchEvent(new Event('change', {bubbles:true})); }
          const transfer = new DataTransfer();
          for (const item of ${JSON.stringify(selected)}) {
            const file = new File([item.source], item.filename, {type:'text/plain'});
            Object.defineProperty(file, '_codeprobeRelativePath', {value:'reporting/' + item.filename}); transfer.items.add(file);
          }
          const input = document.getElementById('folderInput'); input.files = transfer.files; input.dispatchEvent(new Event('change', {bubbles:true}));
        })()`);
        await waitForExpression(cdp, id, `${active}.loadingInput === false && !document.getElementById('${button}').disabled`, 60000);
        await evaluate(cdp, id, `document.getElementById('${button}').click()`);
        await waitForExpression(cdp, id, `document.getElementById('${status}').textContent === 'Project analysis completed.'`, 60000);
        if (!compact) await evaluate(cdp, id, "document.getElementById('result-tab-summary').click()");
        const result = await evaluate(cdp, id, `({report:JSON.parse(document.getElementById('jsonReport').value), text:document.getElementById('textReport').value, visible:document.getElementById('${compact ? "reviewPanel" : "evidenceCoverageBasis"}').getClientRects().length > 0, dom:document.getElementById('${compact ? "reviewPanel" : "evidenceCoverageBasis"}').textContent})`);
        checkProvenance(result.report); checkCoverage(result.report, result.text, true);
        assert(result.report.included_file_count === 3 && result.report.excluded_file_count === 1 && result.report.excluded_files.some(item => item.path.endsWith("README.md")), "I12 project inventory or default documentation exclusion differs");
        assert(result.visible && result.dom.includes(JSON.stringify(result.report.evidence_coverage_basis.factors)), "I12 project coverage factors are not visible");
        for (const item of selected.slice(0, 3)) {
          const child = result.report.files.find(value => value.path.endsWith(item.filename));
          assert(child, "I12 project child missing");
          checkReportingFile(child, result.text, {...item, nominal:override ? 0.81 : 0.31, count:override ? 8 : 7});
        }
        await download(id, compact ? "reporting" : "selected-files", result);
        return {included:3, excluded:1, coverage:result.report.evidence_coverage, nominal:result.report.metric_role_summary.contributing_weight};
      });
    } finally { if (projectPage) await closeSession(cdp, projectPage); }
  }
  console.log("[PASS] browser-reporting-i12: " + JSON.stringify({engine_sha256:engineDigest, observations,
    qualification:"Nine real File cases, three real project UI cases and exact JSON/text downloads qualify finite reporting contracts. Empty Markdown is checked through the public worker, not the empty-editor UI. Native calibration counts have separate evidence; no empirical authorship or hardware validity is implied."}));
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
    const parserFixtures = await testParserReplayBoundary(cdp, baseUrl, state);
    await testStrictJsonContracts(cdp, baseUrl, state, engineDigest);
    await testIntakeContracts(cdp, baseUrl, downloads, state, false, engineDigest);
    await testIntakeContracts(cdp, baseUrl, downloads, state, true, engineDigest);
    await testPythonStructureContracts(cdp, baseUrl, downloads, state, engineDigest, parserFixtures);
    await testCLikeStructureContracts(cdp, baseUrl, downloads, state, engineDigest);
    await testScriptStructureContracts(cdp, baseUrl, downloads, state, engineDigest);
    await testDocumentLanguageContracts(cdp, baseUrl, downloads, state, engineDigest);
    await testMetricContracts(cdp, baseUrl, downloads, state, engineDigest);
    await testReportingContracts(cdp, baseUrl, downloads, state, engineDigest);
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
