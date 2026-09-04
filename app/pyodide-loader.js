(function () {
  "use strict";

  const DEFAULT_CONFIG = Object.freeze({
    schema: "codeprobe-runtime-config/v1",
    production: true,
    pyodide: {
      mode: "cdn",
      version: "0.25.0",
      loader_url: "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/pyodide.js",
      index_url: "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/",
      local_loader_url: "vendor/pyodide/v0.25.0/full/pyodide.js",
      local_index_url: "vendor/pyodide/v0.25.0/full/",
      provenance_url: "pyodide-provenance.json",
      expected_loader_sha256: "9c79c9999999b15de7587aa220c61d06aa14e76babb75dc50c2f873aa826ad4d",
      require_integrity: true,
      verify_core_startup_set: true
    },
    privacy: {
      history_enabled_default: false,
      store_source_in_history: false,
      clear_pyodide_payload_after_run: true
    }
  });

  // Updated by the release-evidence refresh after the Python runtime is final.
  const PACKAGED_ENGINE_RECORD = Object.freeze({
    name: "codeprobe_runtime.py",
    path: "../src/codeprobe_runtime.py",
    size_bytes: 264631,
    sha256_hex: "5575a1005894b1d4035787f8a964113b849ad6d8ec3bf5041c850e2ba8c6f378"
  });

  const PROVENANCE_SCHEMA = "codeprobe-pyodide-provenance/v1";
  const REQUIRED_STARTUP_ARTIFACTS = Object.freeze([
    "pyodide.js",
    "pyodide-lock.json",
    "python_stdlib.zip",
    "pyodide.asm.js",
    "pyodide.asm.wasm"
  ]);
  const BOOTSTRAP_FETCH_ARTIFACTS = Object.freeze([
    "pyodide-lock.json",
    "python_stdlib.zip",
    "pyodide.asm.wasm"
  ]);
  const MIME_TYPES = Object.freeze({
    "pyodide.js": "text/javascript; charset=utf-8",
    "pyodide-lock.json": "application/json; charset=utf-8",
    "python_stdlib.zip": "application/zip",
    "pyodide.asm.js": "text/javascript; charset=utf-8",
    "pyodide.asm.wasm": "application/wasm",
    "codeprobe_runtime.py": "text/x-python; charset=utf-8"
  });

  let configPromise = null;
  let provenancePromise = null;
  let startupArtifactsPromise = null;
  let pyodideScriptPromise = null;
  let pyodideRuntimePromise = null;
  let verifiedEnginePromise = null;
  let activeConfig = null;
  let activeProvenance = null;
  let activeIndexURL = DEFAULT_CONFIG.pyodide.index_url;
  let activeLoaderURL = DEFAULT_CONFIG.pyodide.loader_url;
  let verifiedLoaderInstalled = false;
  let verifiedAsmFactoryInstalled = false;
  let bootstrapConsumption = null;

  function cloneDefaultConfig() {
    return JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  }

  function mergeConfig(raw) {
    const config = cloneDefaultConfig();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return config;
    if (Object.prototype.hasOwnProperty.call(raw, "production")) {
      config.production = Boolean(raw.production);
    }
    if (raw.pyodide && typeof raw.pyodide === "object" && !Array.isArray(raw.pyodide)) {
      Object.assign(config.pyodide, raw.pyodide);
    }
    if (raw.privacy && typeof raw.privacy === "object" && !Array.isArray(raw.privacy)) {
      Object.assign(config.privacy, raw.privacy);
    }
    return config;
  }

  function normaliseSha256(value) {
    const rendered = String(value || "").trim().toLowerCase().replace(/^sha256[:=-]?/i, "");
    if (!/^[0-9a-f]{64}$/.test(rendered)) {
      throw new Error("Integrity metadata contains an invalid SHA-256 value.");
    }
    return rendered;
  }

  function positiveInteger(value, label) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`${label} must be a positive safe integer.`);
    }
    return value;
  }

  function absoluteURL(value, base = document.baseURI) {
    return new URL(String(value), base).href;
  }

  function validateRuntimeConfig(config) {
    if (config.schema !== DEFAULT_CONFIG.schema) {
      throw new Error(`Unsupported runtime configuration schema: ${String(config.schema)}`);
    }
    const pyodide = config.pyodide || {};
    const mode = String(pyodide.mode || "").toLowerCase();
    if (!new Set(["cdn", "local"]).has(mode)) {
      throw new Error("Pyodide mode must be cdn or local.");
    }
    if (!/^\d+\.\d+\.\d+$/.test(String(pyodide.version || ""))) {
      throw new Error("Pyodide version must be an exact semantic version.");
    }
    if (config.production) {
      if (!pyodide.require_integrity || !pyodide.verify_core_startup_set) {
        throw new Error("Production runtime configuration must verify the complete core startup set.");
      }
      normaliseSha256(pyodide.expected_loader_sha256);
      if (!String(pyodide.provenance_url || "").trim()) {
        throw new Error("Production runtime configuration requires a provenance manifest.");
      }
    }
    return config;
  }

  async function loadRuntimeConfig() {
    if (configPromise) return configPromise;
    configPromise = (async () => {
      let raw = null;
      try {
        const response = await fetch("runtime-config.json", {
          cache: "no-store",
          credentials: "same-origin"
        });
        if (!response.ok) throw new Error(`runtime-config.json returned ${response.status}`);
        raw = await response.json();
      } catch (error) {
        raw = cloneDefaultConfig();
        raw.runtime_config_warning = String(error && error.message ? error.message : error);
      }
      activeConfig = validateRuntimeConfig(mergeConfig(raw));
      const pyodide = activeConfig.pyodide;
      const mode = String(pyodide.mode).toLowerCase();
      activeLoaderURL = mode === "local"
        ? absoluteURL(pyodide.local_loader_url)
        : absoluteURL(pyodide.loader_url);
      activeIndexURL = mode === "local"
        ? absoluteURL(pyodide.local_index_url)
        : absoluteURL(pyodide.index_url);
      if (!activeIndexURL.endsWith("/")) activeIndexURL += "/";
      return activeConfig;
    })().catch(error => {
      configPromise = null;
      throw error;
    });
    return configPromise;
  }

  async function sha256Hex(value) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Browser WebCrypto SHA-256 is unavailable.");
    }
    const bytes = value instanceof Uint8Array
      ? value
      : new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer);
    const digest = await window.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  function validateProvenance(raw, config) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("Pyodide provenance manifest must be an object.");
    }
    if (raw.schema !== PROVENANCE_SCHEMA) {
      throw new Error(`Unsupported Pyodide provenance schema: ${String(raw.schema)}`);
    }
    if (raw.version !== config.pyodide.version) {
      throw new Error("Pyodide provenance version does not match runtime configuration.");
    }
    const upstream = raw.upstream || {};
    if (!/^[0-9a-f]{40}$/.test(String(upstream.commit || ""))) {
      throw new Error("Pyodide provenance requires an exact upstream commit.");
    }
    if (upstream.tag !== raw.version) {
      throw new Error("Pyodide provenance tag does not match the declared version.");
    }
    const records = Array.isArray(raw.startup_artifacts) ? raw.startup_artifacts : [];
    const byName = new Map();
    for (const record of records) {
      if (!record || typeof record !== "object" || Array.isArray(record)) {
        throw new Error("Pyodide startup artefact records must be objects.");
      }
      const name = String(record.name || "");
      if (!REQUIRED_STARTUP_ARTIFACTS.includes(name) || byName.has(name)) {
        throw new Error(`Unexpected or duplicate Pyodide startup artefact: ${name}`);
      }
      const digest = normaliseSha256(record.sha256_hex);
      positiveInteger(record.size_bytes, `${name} size_bytes`);
      if (!String(record.sri_sha256 || "").startsWith("sha256-")) {
        throw new Error(`${name} requires an SRI SHA-256 value.`);
      }
      byName.set(name, Object.freeze({ ...record, sha256_hex: digest }));
    }
    for (const name of REQUIRED_STARTUP_ARTIFACTS) {
      if (!byName.has(name)) throw new Error(`Pyodide provenance is missing ${name}.`);
    }
    if (byName.get("pyodide.js").sha256_hex !== normaliseSha256(config.pyodide.expected_loader_sha256)) {
      throw new Error("Configured Pyodide loader digest does not match provenance.");
    }
    const lock = raw.lock_info || {};
    if (lock.version !== raw.version || !String(lock.python || "").match(/^\d+\.\d+\.\d+$/)) {
      throw new Error("Pyodide lock metadata is incomplete or inconsistent.");
    }
    positiveInteger(lock.package_count, "lock package_count");
    return Object.freeze({ ...raw, startup_by_name: byName });
  }

  async function loadProvenance() {
    if (provenancePromise) return provenancePromise;
    provenancePromise = (async () => {
      const config = await loadRuntimeConfig();
      const url = absoluteURL(config.pyodide.provenance_url);
      const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
      if (!response.ok) throw new Error(`Pyodide provenance manifest returned ${response.status}.`);
      activeProvenance = validateProvenance(await response.json(), config);
      return activeProvenance;
    })().catch(error => {
      provenancePromise = null;
      throw error;
    });
    return provenancePromise;
  }

  function copyBytes(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
    return bytes.slice();
  }

  async function fetchVerifiedArtifact(record, url) {
    const target = absoluteURL(url);
    const sameOrigin = new URL(target).origin === window.location.origin;
    const response = await fetch(target, {
      cache: "reload",
      credentials: sameOrigin ? "same-origin" : "omit"
    });
    if (!response.ok) throw new Error(`Could not fetch ${record.name} (${response.status}).`);
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength !== record.size_bytes) {
      throw new Error(`${record.name} size mismatch: expected ${record.size_bytes}, got ${buffer.byteLength}.`);
    }
    const actual = await sha256Hex(buffer);
    if (actual !== normaliseSha256(record.sha256_hex)) {
      throw new Error(`${record.name} integrity mismatch: expected ${record.sha256_hex}, got ${actual}.`);
    }
    return new Uint8Array(buffer);
  }

  async function loadVerifiedStartupSet(provenance) {
    if (startupArtifactsPromise) return startupArtifactsPromise;
    startupArtifactsPromise = (async () => {
      const pairs = await Promise.all(REQUIRED_STARTUP_ARTIFACTS.map(async name => {
        const record = provenance.startup_by_name.get(name);
        const url = name === "pyodide.js" ? activeLoaderURL : new URL(name, activeIndexURL).href;
        return [name, await fetchVerifiedArtifact(record, url)];
      }));
      return new Map(pairs);
    })().catch(error => {
      startupArtifactsPromise = null;
      throw error;
    });
    return startupArtifactsPromise;
  }

  async function appendVerifiedScript(name, bytes) {
    const source = new Blob([copyBytes(bytes)], { type: MIME_TYPES[name] || "text/javascript" });
    const blobURL = URL.createObjectURL(source);
    let script = null;
    try {
      await new Promise((resolve, reject) => {
        script = document.createElement("script");
        script.src = blobURL;
        script.async = false;
        script.dataset.codeprobeVerifiedResource = name;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`Verified ${name} could not be executed.`));
        document.head.appendChild(script);
      });
    } finally {
      if (script) script.remove();
      URL.revokeObjectURL(blobURL);
    }
  }

  function responseForVerifiedArtifact(name, bytes) {
    return new Response(copyBytes(bytes), {
      status: 200,
      statusText: "OK",
      headers: {
        "Cache-Control": "no-store",
        "Content-Length": String(bytes.byteLength),
        "Content-Type": MIME_TYPES[name] || "application/octet-stream"
      }
    });
  }

  function requestURL(input) {
    if (typeof Request !== "undefined" && input instanceof Request) return absoluteURL(input.url);
    return absoluteURL(input);
  }

  async function withVerifiedBootstrapFetch(artifacts, operation) {
    const verifiedByURL = new Map();
    for (const name of BOOTSTRAP_FETCH_ARTIFACTS) {
      verifiedByURL.set(new URL(name, activeIndexURL).href, { name, bytes: artifacts.get(name) });
    }
    const served = new Map(BOOTSTRAP_FETCH_ARTIFACTS.map(name => [name, 0]));
    const previousDescriptor = Object.getOwnPropertyDescriptor(window, "fetch");
    const previousFetch = window.fetch;
    if (typeof previousFetch !== "function") throw new Error("Browser fetch is unavailable.");

    const verifiedFetch = async function (input, init = undefined) {
      const url = requestURL(input);
      const requestMethod = typeof Request !== "undefined" && input instanceof Request ? input.method : "GET";
      const method = String(init && init.method ? init.method : requestMethod || "GET").toUpperCase();
      const verified = verifiedByURL.get(url);
      if (!verified) return previousFetch.call(window, input, init);
      if (method !== "GET") throw new Error(`Verified bootstrap artefact ${verified.name} permits only GET.`);
      served.set(verified.name, served.get(verified.name) + 1);
      return responseForVerifiedArtifact(verified.name, verified.bytes);
    };

    Object.defineProperty(window, "fetch", {
      configurable: true,
      enumerable: previousDescriptor ? previousDescriptor.enumerable : true,
      writable: true,
      value: verifiedFetch
    });
    try {
      const result = await operation();
      for (const name of BOOTSTRAP_FETCH_ARTIFACTS) {
        if (!served.get(name)) {
          throw new Error(`Pyodide bootstrap did not consume the verified ${name} bytes.`);
        }
      }
      bootstrapConsumption = Object.freeze(Object.fromEntries(served));
      return result;
    } finally {
      if (previousDescriptor) Object.defineProperty(window, "fetch", previousDescriptor);
      else {
        delete window.fetch;
        window.fetch = previousFetch;
      }
    }
  }

  async function ensurePyodideLoader() {
    if (verifiedLoaderInstalled && verifiedAsmFactoryInstalled) return;
    if (pyodideScriptPromise) return pyodideScriptPromise;
    pyodideScriptPromise = (async () => {
      if (typeof window.loadPyodide === "function" && !verifiedLoaderInstalled) {
        throw new Error("An unverified loadPyodide() function was present before verified startup.");
      }
      if (typeof window._createPyodideModule === "function" && !verifiedAsmFactoryInstalled) {
        throw new Error("An unverified Pyodide ASM factory was present before verified startup.");
      }
      const config = await loadRuntimeConfig();
      const provenance = await loadProvenance();
      if (!config.pyodide.verify_core_startup_set) {
        throw new Error("Core startup verification is disabled.");
      }
      const artifacts = await loadVerifiedStartupSet(provenance);
      await appendVerifiedScript("pyodide.js", artifacts.get("pyodide.js"));
      if (typeof window.loadPyodide !== "function") {
        throw new Error("Verified Pyodide loader did not expose loadPyodide().");
      }
      verifiedLoaderInstalled = true;
      await appendVerifiedScript("pyodide.asm.js", artifacts.get("pyodide.asm.js"));
      if (typeof window._createPyodideModule !== "function") {
        throw new Error("Verified Pyodide ASM JavaScript did not expose its module factory.");
      }
      verifiedAsmFactoryInstalled = true;
    })().catch(error => {
      pyodideScriptPromise = null;
      throw error;
    });
    return pyodideScriptPromise;
  }

  function validatePyodideOptions(options, config) {
    if (!options || typeof options !== "object" || Array.isArray(options)) {
      throw new Error("Pyodide options must be an object.");
    }
    for (const key of ["indexURL", "lockFileURL", "stdLibURL"]) {
      if (Object.prototype.hasOwnProperty.call(options, key)) {
        throw new Error(`${key} is controlled by the verified runtime boundary.`);
      }
    }
    if (config.production) {
      if (options.fullStdLib === true) {
        throw new Error("Production startup does not load the unverified optional standard-library package set.");
      }
      if (Array.isArray(options.packages) && options.packages.length) {
        throw new Error("Production startup does not accept unverified optional packages.");
      }
    }
    return { ...options };
  }

  async function verifyLoadedRuntime(runtime, provenance) {
    let runtimeVersion = String(runtime && runtime.version ? runtime.version : "");
    if (!runtimeVersion && runtime && typeof runtime.runPython === "function") {
      runtimeVersion = String(runtime.runPython("import pyodide; pyodide.__version__"));
    }
    if (runtimeVersion !== provenance.version) {
      throw new Error(`Loaded Pyodide version mismatch: expected ${provenance.version}, got ${runtimeVersion || "unknown"}.`);
    }
    if (runtime && typeof runtime.runPython === "function") {
      const pythonVersion = String(runtime.runPython("import platform; platform.python_version()"));
      if (pythonVersion !== provenance.lock_info.python) {
        throw new Error(`Loaded Python version mismatch: expected ${provenance.lock_info.python}, got ${pythonVersion}.`);
      }
    }
    return runtime;
  }

  async function loadVerifiedPyodide(options = {}) {
    if (pyodideRuntimePromise) return pyodideRuntimePromise;
    pyodideRuntimePromise = (async () => {
      const config = await loadRuntimeConfig();
      const safeOptions = validatePyodideOptions(options, config);
      await ensurePyodideLoader();
      const provenance = await loadProvenance();
      const artifacts = await loadVerifiedStartupSet(provenance);
      const runtime = await withVerifiedBootstrapFetch(artifacts, () => window.loadPyodide({
        ...safeOptions,
        indexURL: activeIndexURL,
        lockFileURL: new URL("pyodide-lock.json", activeIndexURL).href,
        stdLibURL: new URL("python_stdlib.zip", activeIndexURL).href,
        fullStdLib: false,
        packages: []
      }));
      return verifyLoadedRuntime(runtime, provenance);
    })().catch(error => {
      pyodideRuntimePromise = null;
      throw error;
    });
    return pyodideRuntimePromise;
  }

  function decodeLatin1(bytes) {
    const parts = [];
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      parts.push(String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)));
    }
    return parts.join("");
  }

  function sourceBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    throw new TypeError("Source bytes must be an ArrayBuffer or typed array.");
  }

  function normaliseLineEndings(text) {
    return String(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  }

  function decodeSourceBytes(value) {
    const bytes = sourceBytes(value);
    if (bytes.slice(0, 4096).includes(0)) {
      throw new Error("The file appears to be binary because it contains NUL bytes.");
    }
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      return Object.freeze({ text: normaliseLineEndings(text), encoding: "utf-8", warning: "" });
    } catch (_) {
      return Object.freeze({
        text: normaliseLineEndings(decodeLatin1(bytes)),
        encoding: "latin-1",
        warning: "Decoded as latin-1; review the file encoding."
      });
    }
  }

  function normaliseProjectPath(value) {
    const original = String(value || "").replace(/\\/g, "/").trim();
    if (!original || original.includes("\0")) throw new Error("Project path is empty or contains NUL.");
    if (original.startsWith("/") || /^[A-Za-z]:\//.test(original)) {
      throw new Error("Absolute project paths are not accepted.");
    }
    const parts = [];
    for (const rawPart of original.split("/")) {
      if (!rawPart || rawPart === ".") continue;
      if (rawPart === "..") throw new Error("Parent-directory traversal is not accepted.");
      const part = rawPart.normalize("NFC");
      if (!part || part === "." || part === "..") throw new Error("Project path is not canonical.");
      parts.push(part);
    }
    if (!parts.length) throw new Error("Project path is empty after normalisation.");
    return parts.join("/");
  }

  async function loadVerifiedEngine() {
    if (verifiedEnginePromise) return verifiedEnginePromise;
    verifiedEnginePromise = (async () => {
      positiveInteger(PACKAGED_ENGINE_RECORD.size_bytes, "Packaged engine size_bytes");
      const expected = normaliseSha256(PACKAGED_ENGINE_RECORD.sha256_hex);
      const url = absoluteURL(PACKAGED_ENGINE_RECORD.path);
      if (new URL(url).origin !== window.location.origin) {
        throw new Error("The packaged Python engine must be loaded from the application origin.");
      }
      const bytes = await fetchVerifiedArtifact(PACKAGED_ENGINE_RECORD, url);
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      return Object.freeze({
        text: normaliseLineEndings(decoded),
        bytes: copyBytes(bytes),
        copyBytes() { return copyBytes(bytes); },
        fingerprint: Object.freeze({
          algorithm: "sha256",
          value: expected,
          available: true,
          scope: "src/codeprobe_runtime.py",
          source: "packaged-verified"
        }),
        trusted: true,
        source: "packaged-verified"
      });
    })().catch(error => {
      verifiedEnginePromise = null;
      throw error;
    });
    return verifiedEnginePromise;
  }

  window.CodeProbeRuntime = Object.freeze({
    loadRuntimeConfig,
    loadProvenance,
    ensurePyodideLoader,
    loadVerifiedPyodide,
    loadVerifiedEngine,
    decodeSourceBytes,
    normaliseProjectPath,
    getConfig() { return activeConfig || DEFAULT_CONFIG; },
    getProvenance() { return activeProvenance; },
    getPyodideIndexURL() { return activeIndexURL; },
    getPyodideLoaderURL() { return activeLoaderURL; },
    getBootstrapConsumption() { return bootstrapConsumption; },
    getPackagedEngineRecord() { return PACKAGED_ENGINE_RECORD; }
  });
})();
