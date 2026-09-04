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
    reset({ tamperEngine = false, tamperCore = "" } = {}) {
      this.counts.clear();
      this.tamperEngine = tamperEngine;
      this.tamperCore = tamperCore;
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
