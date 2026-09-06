#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const TIMEOUT_MS = 20_000;
const processes = new Set();
const navigationModes = [];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
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

async function waitForHttp(url, timeout = TIMEOUT_MS) {
  const deadline = Date.now() + timeout;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const status = await new Promise((resolve, reject) => {
        const request = http.get(url, response => {
          response.resume();
          resolve(response.statusCode || 0);
        });
        request.setTimeout(1_000, () => request.destroy(new Error("HTTP probe timed out")));
        request.once("error", reject);
      });
      if (status === 200) return;
      lastError = new Error(`HTTP probe returned ${status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw new Error(`Local server did not become ready: ${lastError || "timeout"}`);
}

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
  throw new Error(`Chrome DevTools endpoint did not become ready: ${lastError || "timeout"}`);
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
      const timer = setTimeout(() => reject(new Error("CDP WebSocket connection timed out")), TIMEOUT_MS);
      this.socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
      this.socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("CDP WebSocket connection failed")); }, { once: true });
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
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  }, sessionId);
  if (result.exceptionDetails) {
    const exception = result.exceptionDetails.exception || {};
    const detail = exception.description || exception.value || result.exceptionDetails.text || "unknown error";
    throw new Error(`Browser evaluation failed: ${detail}`);
  }
  return result.result ? result.result.value : undefined;
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
    await delay(50);
  }
  const detail = lastError ? `; last browser error: ${lastError.message || lastError}` : "";
  throw new Error(`Browser condition timed out: ${expression}${detail}`);
}

async function injectLocalPage(cdp, sessionId, url) {
  const parsed = new URL(url);
  const relative = parsed.pathname.replace(/^\/+/, "");
  const htmlPath = path.join(ROOT, relative);
  const pageName = path.basename(relative);
  const project = pageName === "project.html";
  const cssPath = path.join(ROOT, "app", project ? "project.css" : "codeprobe.css");
  const scriptPath = path.join(ROOT, "app", project ? "project-ui.js" : "codeprobe-ui.js");
  let html = fs.readFileSync(htmlPath, "utf8");
  html = html
    .replace(/<meta\b[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>\s*/gi, "")
    .replace(/<link\b[^>]*rel=["']stylesheet["'][^>]*>\s*/gi, "")
    .replace(/<script\b[^>]*\bsrc=["'][^"']+["'][^>]*><\/script>\s*/gi, "");
  const frameTree = await cdp.send("Page.getFrameTree", {}, sessionId);
  const frameId = frameTree.frameTree.frame.id;
  await cdp.send("Page.setDocumentContent", { frameId, html }, sessionId);
  const css = fs.readFileSync(cssPath, "utf8");
  await evaluate(cdp, sessionId, `(() => {
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css)};
    document.head.appendChild(style);
    window.CodeProbeRuntime = Object.freeze({
      ensurePyodideLoader: async () => { throw new Error('external runtime intentionally unavailable in injected browser test'); },
      getPyodideIndexURL: () => 'https://cdn.jsdelivr.net/pyodide/v0.25.0/full/'
    });
  })()`);
  const source = fs.readFileSync(scriptPath, "utf8");
  const storageShim = project ? "" : `
    const storedValues = new Map();
    const localStorage = {
      getItem(key) { return storedValues.has(String(key)) ? storedValues.get(String(key)) : null; },
      setItem(key, value) { storedValues.set(String(key), String(value)); },
      removeItem(key) { storedValues.delete(String(key)); },
      clear() { storedValues.clear(); }
    };
  `;
  await evaluate(cdp, sessionId, `(function () {${storageShim}\n${source}\n})();\n//# sourceURL=${pageName}-browser-test.js`);
  await waitForExpression(cdp, sessionId, "document.readyState === 'complete'");
}

async function navigate(cdp, sessionId, url) {
  const result = await cdp.send("Page.navigate", { url }, sessionId);
  if (!result.errorText) {
    await waitForExpression(cdp, sessionId, "document.readyState === 'complete'");
    const href = await evaluate(cdp, sessionId, "location.href");
    if (href === url || href.startsWith(url + "#")) {
      navigationModes.push("http");
      return;
    }
  }
  if (process.env.CODEPROBE_REQUIRE_HTTP_NAVIGATION === "1") {
    throw new Error(`Browser HTTP navigation failed: ${result.errorText || "unexpected final location"}`);
  }
  await injectLocalPage(cdp, sessionId, url);
  navigationModes.push(`injected:${result.errorText || "unexpected final location"}`);
}

async function key(cdp, sessionId, name, code, keyCode) {
  const common = { key: name, code, windowsVirtualKeyCode: keyCode, nativeVirtualKeyCode: keyCode };
  await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", ...common }, sessionId);
  await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", ...common }, sessionId);
  await delay(50);
}

function axRole(node) {
  return node && node.role ? node.role.value : "";
}

function axName(node) {
  return node && node.name ? node.name.value : "";
}

async function accessibilityTree(cdp, sessionId) {
  const result = await cdp.send("Accessibility.getFullAXTree", {}, sessionId);
  return (result.nodes || []).filter(node => !node.ignored);
}

async function testMainInterface(cdp, sessionId, baseUrl) {
  await navigate(cdp, sessionId, `${baseUrl}/app/index.html`);
  await waitForExpression(cdp, sessionId, "document.querySelectorAll('[role=tab]').length === 6");

  const contract = await evaluate(cdp, sessionId, `(() => {
    const tabs = [...document.querySelectorAll('[role="tab"]')].map(tab => ({
      id: tab.id,
      controls: tab.getAttribute('aria-controls'),
      selected: tab.getAttribute('aria-selected'),
      tabIndex: tab.tabIndex,
    }));
    const panels = [...document.querySelectorAll('[role="tabpanel"]')].map(panel => ({
      id: panel.id,
      labelledBy: panel.getAttribute('aria-labelledby'),
      hidden: panel.hidden,
    }));
    const named = ['editor', 'languageSelect', 'profileSelect', 'configOverride', 'calibrationProfile', 'textReport', 'jsonReport']
      .map(id => {
        const element = document.getElementById(id);
        return { id, labels: [...element.labels].map(label => label.textContent.trim()), labelledBy: element.getAttribute('aria-labelledby'), ariaLabel: element.getAttribute('aria-label') };
      });
    const status = document.getElementById('statusText');
    const progress = ['scoreProgress', 'lowLevelQualityProgress'].map(id => {
      const element = document.getElementById(id);
      return { id, role: element.getAttribute('role'), min: element.getAttribute('aria-valuemin'), max: element.getAttribute('aria-valuemax'), text: element.getAttribute('aria-valuetext') };
    });
    return { tabs, panels, named, status: { role: status.getAttribute('role'), live: status.getAttribute('aria-live'), atomic: status.getAttribute('aria-atomic') }, progress };
  })()`);
  assert(contract.tabs.length === 6, "main interface did not expose six tabs");
  assert(contract.tabs.filter(tab => tab.selected === "true" && tab.tabIndex === 0).length === 1, "main tab roving state is invalid");
  assert(contract.panels.filter(panel => !panel.hidden).length === 1, "main interface did not expose exactly one tabpanel");
  assert(contract.named.every(item => item.labels.length > 0 || item.labelledBy || item.ariaLabel), "main interface contains an unnamed textarea or select");
  assert(contract.status.role === "status" && contract.status.live === "polite" && contract.status.atomic === "true", "main status live-region contract is incomplete");
  assert(contract.progress.every(item => item.role === "progressbar" && item.min === "0" && item.max === "100" && item.text), "main progress semantics are incomplete");

  await evaluate(cdp, sessionId, "document.getElementById('result-tab-summary').focus()");
  await key(cdp, sessionId, "ArrowRight", "ArrowRight", 39);
  let state = await evaluate(cdp, sessionId, `({
    active: document.activeElement.id,
    selected: document.querySelector('[role="tab"][aria-selected="true"]').id,
    panel: [...document.querySelectorAll('[role="tabpanel"]')].find(panel => !panel.hidden).id,
    focusVisible: document.activeElement.matches(':focus-visible'),
    outline: getComputedStyle(document.activeElement).outlineStyle,
    outlineWidth: getComputedStyle(document.activeElement).outlineWidth,
  })`);
  assert(state.active === "result-tab-review" && state.selected === "result-tab-review" && state.panel === "tab-review", "ArrowRight did not activate and focus the next tab");
  assert(state.focusVisible && state.outline !== "none" && state.outlineWidth !== "0px", "keyboard tab focus is not visibly rendered");

  await key(cdp, sessionId, "End", "End", 35);
  state = await evaluate(cdp, sessionId, `({ active: document.activeElement.id, panel: [...document.querySelectorAll('[role="tabpanel"]')].find(panel => !panel.hidden).id })`);
  assert(state.active === "result-tab-history" && state.panel === "tab-history", "End did not activate the final tab");
  await key(cdp, sessionId, "Home", "Home", 36);
  state = await evaluate(cdp, sessionId, `({ active: document.activeElement.id, panel: [...document.querySelectorAll('[role="tabpanel"]')].find(panel => !panel.hidden).id })`);
  assert(state.active === "result-tab-summary" && state.panel === "tab-summary", "Home did not activate the first tab");
  await key(cdp, sessionId, "ArrowLeft", "ArrowLeft", 37);
  state = await evaluate(cdp, sessionId, `({ active: document.activeElement.id, panel: [...document.querySelectorAll('[role="tabpanel"]')].find(panel => !panel.hidden).id })`);
  assert(state.active === "result-tab-history" && state.panel === "tab-history", "ArrowLeft did not wrap to the final tab");

  await evaluate(cdp, sessionId, "document.getElementById('clearBtn').click()");
  const statusAfterClear = await evaluate(cdp, sessionId, "document.getElementById('statusText').textContent");
  assert(statusAfterClear === "Editor cleared.", "main status region did not receive the clear action announcement");

  await evaluate(cdp, sessionId, `(() => {
    document.getElementById('result-tab-summary').click();
    document.querySelectorAll('#tab-summary details').forEach(details => { details.open = true; });
  })()`);
  let axNodes = await accessibilityTree(cdp, sessionId);
  const tabNames = axNodes.filter(node => axRole(node) === "tab").map(axName);
  for (const name of ["Summary", "Manual review", "Metrics", "Text report", "JSON", "History"]) {
    assert(tabNames.includes(name), `accessibility tree is missing tab ${name}`);
  }
  let textNames = axNodes.filter(node => axRole(node) === "textbox").map(axName);
  for (const name of ["Source code editor", "Metric configuration JSON override", "Calibration profile JSON"]) {
    assert(textNames.includes(name), `accessibility tree is missing textbox name ${name}`);
  }
  const progressNames = axNodes.filter(node => axRole(node) === "progressbar").map(axName);
  assert(progressNames.includes("AI-style concern score"), "accessibility tree is missing the main score progressbar");
  assert(axNodes.some(node => axRole(node) === "status"), "accessibility tree is missing the main status region");

  await evaluate(cdp, sessionId, "document.getElementById('result-tab-text').click()");
  axNodes = await accessibilityTree(cdp, sessionId);
  textNames = axNodes.filter(node => axRole(node) === "textbox").map(axName);
  assert(textNames.includes("Text report output"), "accessibility tree is missing the text-report output name");

  await evaluate(cdp, sessionId, "document.getElementById('result-tab-json').click()");
  axNodes = await accessibilityTree(cdp, sessionId);
  textNames = axNodes.filter(node => axRole(node) === "textbox").map(axName);
  assert(textNames.includes("JSON report output"), "accessibility tree is missing the JSON-report output name");

  await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, sessionId);
  await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, sessionId);
}

async function testProjectInterface(cdp, sessionId, baseUrl) {
  await navigate(cdp, sessionId, `${baseUrl}/app/project.html`);
  await waitForExpression(cdp, sessionId, "document.getElementById('profileSelect') !== null");
  const contract = await evaluate(cdp, sessionId, `(() => {
    const ids = ['profileSelect', 'calibrationProfile', 'textReport', 'jsonReport'];
    const named = ids.map(id => ({ id, labels: [...document.getElementById(id).labels].map(label => label.textContent.trim()) }));
    const status = document.getElementById('status');
    const progress = document.getElementById('projectScoreProgress');
    return {
      named,
      status: { role: status.getAttribute('role'), live: status.getAttribute('aria-live'), atomic: status.getAttribute('aria-atomic') },
      progress: { role: progress.getAttribute('role'), min: progress.getAttribute('aria-valuemin'), max: progress.getAttribute('aria-valuemax'), text: progress.getAttribute('aria-valuetext') },
    };
  })()`);
  assert(contract.named.every(item => item.labels.length > 0), "project interface contains an unnamed textarea or select");
  assert(contract.status.role === "status" && contract.status.live === "polite" && contract.status.atomic === "true", "project status live-region contract is incomplete");
  assert(contract.progress.role === "progressbar" && contract.progress.min === "0" && contract.progress.max === "100" && contract.progress.text, "project score progress semantics are incomplete");

  const statusAfterSyntheticZip = await evaluate(cdp, sessionId, `(async () => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([new Uint8Array([80, 75, 3, 4])], 'sample.zip', { type: 'application/zip' }));
    const input = document.getElementById('zipInput');
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
    await new Promise(resolve => setTimeout(resolve, 100));
    return document.getElementById('status').textContent;
  })()`);
  assert(statusAfterSyntheticZip === "Loaded ZIP: sample.zip.", "project status region did not announce a loaded ZIP");

  await evaluate(cdp, sessionId, "document.querySelector('details').open = true");
  const axNodes = await accessibilityTree(cdp, sessionId);
  const comboboxNames = axNodes.filter(node => axRole(node) === "combobox").map(axName);
  assert(comboboxNames.includes("Scoring profile"), "accessibility tree is missing the project scoring-profile name");
  const textNames = axNodes.filter(node => axRole(node) === "textbox").map(axName);
  for (const name of ["Calibration profile JSON", "Project text report output", "Project JSON report output"]) {
    assert(textNames.includes(name), `accessibility tree is missing project textbox name ${name}`);
  }
  const progressNames = axNodes.filter(node => axRole(node) === "progressbar").map(axName);
  assert(progressNames.includes("Score"), "accessibility tree is missing the project score progressbar");
  assert(axNodes.some(node => axRole(node) === "status"), "accessibility tree is missing the project status region");
}

async function main() {
  const serverPort = await freePort();
  const debugPort = await freePort();
  const browser = findBrowser();
  const python = process.env.CODEPROBE_PYTHON || "python";
  const userDataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "codeprobe-browser-"));
  const serverLog = [];
  const browserLog = [];

  const server = childProcess.spawn(python, [
    "-u", "-I", "-S", "-B", "tools/run_local_server.py",
    "--host", "127.0.0.1", "--port", String(serverPort), "--no-browser",
  ], {
    cwd: ROOT,
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  processes.add(server);
  server.stdout.on("data", chunk => serverLog.push(String(chunk)));
  server.stderr.on("data", chunk => serverLog.push(String(chunk)));
  server.once("exit", code => {
    if (code !== null && code !== 0) serverLog.push(`server exited with ${code}`);
  });

  const baseUrl = `http://127.0.0.1:${serverPort}`;
  await waitForHttp(`${baseUrl}/app/index.html`);

  const browserArguments = [
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
    `--user-data-dir=${userDataDirectory}`,
    "about:blank",
  ];
  const chrome = childProcess.spawn(browser, browserArguments, { stdio: ["ignore", "pipe", "pipe"] });
  processes.add(chrome);
  chrome.stdout.on("data", chunk => browserLog.push(String(chunk)));
  chrome.stderr.on("data", chunk => browserLog.push(String(chunk)));

  let cdp = null;
  try {
    const version = await waitForJson(`http://127.0.0.1:${debugPort}/json/version`);
    assert(version.webSocketDebuggerUrl, "Chrome did not expose a DevTools WebSocket URL.");
    cdp = new CdpConnection(version.webSocketDebuggerUrl);
    await cdp.connect();
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Page.enable", {}, sessionId);
    await cdp.send("Runtime.enable", {}, sessionId);
    await cdp.send("Network.enable", {}, sessionId);
    await cdp.send("Accessibility.enable", {}, sessionId);
    await cdp.send("Network.setBlockedURLs", { urls: ["https://cdn.jsdelivr.net/*"] }, sessionId);
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);

    await testMainInterface(cdp, sessionId, baseUrl);
    await testProjectInterface(cdp, sessionId, baseUrl);

    const browserVersion = childProcess.spawnSync(browser, ["--version"], { encoding: "utf8" });
    const renderedVersion = String(browserVersion.stdout || browserVersion.stderr || browser).trim();
    console.log(`[PASS] browser-accessibility: real Chrome DevTools Protocol checks passed (${renderedVersion})`);
    console.log(`[PASS] browser-accessibility: page modes ${navigationModes.join(", ")}`);
    console.log("[PASS] browser-accessibility: tabs, keyboard navigation, focus visibility, names, live regions and progress semantics verified");
  } catch (error) {
    const details = [
      `[FAIL] browser-accessibility: ${error && error.stack ? error.stack : error}`,
      serverLog.length ? `server log:\n${serverLog.join("").slice(-4_000)}` : "",
      browserLog.length ? `browser log:\n${browserLog.join("").slice(-4_000)}` : "",
    ].filter(Boolean).join("\n");
    console.error(details);
    process.exitCode = 1;
  } finally {
    if (cdp) cdp.close();
    stopProcess(chrome);
    stopProcess(server);
    processes.delete(chrome);
    processes.delete(server);
    try { fs.rmSync(userDataDirectory, { recursive: true, force: true }); } catch (_) { /* best effort */ }
  }
}

main().catch(error => {
  console.error(`[FAIL] browser-accessibility: ${error && error.stack ? error.stack : error}`);
  cleanup();
  process.exitCode = 1;
});
