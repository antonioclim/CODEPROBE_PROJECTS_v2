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

  const PROVENANCE_SCHEMA = "codeprobe-pyodide-provenance/v1";
  const REQUIRED_STARTUP_ARTIFACTS = Object.freeze([
    "pyodide.js",
    "pyodide-lock.json",
    "python_stdlib.zip",
    "pyodide.asm.js",
    "pyodide.asm.wasm"
  ]);

  let configPromise = null;
  let provenancePromise = null;
  let pyodideScriptPromise = null;
  let pyodideRuntimePromise = null;
  let activeConfig = null;
  let activeProvenance = null;
  let activeIndexURL = DEFAULT_CONFIG.pyodide.index_url;
  let activeLoaderURL = DEFAULT_CONFIG.pyodide.loader_url;

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
      throw new Error("Pyodide integrity metadata contains an invalid SHA-256 value.");
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
        const response = await fetch("runtime-config.json", { cache: "no-store" });
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
    })();
    return configPromise;
  }

  async function sha256Hex(buffer) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("Browser WebCrypto SHA-256 is unavailable.");
    }
    const digest = await window.crypto.subtle.digest("SHA-256", buffer);
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
      byName.set(name, { ...record, sha256_hex: digest });
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
      const response = await fetch(url, { cache: "no-store" });
      if (!response.ok) throw new Error(`Pyodide provenance manifest returned ${response.status}.`);
      activeProvenance = validateProvenance(await response.json(), config);
      return activeProvenance;
    })();
    return provenancePromise;
  }

  async function fetchVerifiedArtifact(record, url) {
    const response = await fetch(url, { cache: "reload", credentials: "omit" });
    if (!response.ok) throw new Error(`Could not fetch ${record.name} (${response.status}).`);
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength !== record.size_bytes) {
      throw new Error(`${record.name} size mismatch: expected ${record.size_bytes}, got ${bytes.byteLength}.`);
    }
    const actual = await sha256Hex(bytes);
    if (actual !== record.sha256_hex) {
      throw new Error(`${record.name} integrity mismatch: expected ${record.sha256_hex}, got ${actual}.`);
    }
    return bytes;
  }

  async function appendVerifiedLoader(record) {
    const bytes = await fetchVerifiedArtifact(record, activeLoaderURL);
    const source = new Blob([bytes], { type: "text/javascript" });
    const blobURL = URL.createObjectURL(source);
    try {
      await new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = blobURL;
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error("Verified Pyodide loader could not be executed."));
        document.head.appendChild(script);
      });
    } finally {
      URL.revokeObjectURL(blobURL);
    }
  }

  async function verifyCoreStartupSet(provenance) {
    for (const name of REQUIRED_STARTUP_ARTIFACTS) {
      if (name === "pyodide.js") continue;
      const record = provenance.startup_by_name.get(name);
      await fetchVerifiedArtifact(record, new URL(name, activeIndexURL).href);
    }
  }

  async function ensurePyodideLoader() {
    if (typeof window.loadPyodide === "function") return;
    if (pyodideScriptPromise) return pyodideScriptPromise;
    pyodideScriptPromise = (async () => {
      const config = await loadRuntimeConfig();
      const provenance = await loadProvenance();
      if (config.pyodide.verify_core_startup_set) {
        await verifyCoreStartupSet(provenance);
      }
      await appendVerifiedLoader(provenance.startup_by_name.get("pyodide.js"));
      if (typeof window.loadPyodide !== "function") {
        throw new Error("Verified Pyodide loader did not expose loadPyodide().");
      }
    })();
    return pyodideScriptPromise;
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
      await ensurePyodideLoader();
      const provenance = await loadProvenance();
      const runtime = await window.loadPyodide({ ...options, indexURL: activeIndexURL });
      return verifyLoadedRuntime(runtime, provenance);
    })();
    return pyodideRuntimePromise;
  }

  window.CodeProbeRuntime = Object.freeze({
    loadRuntimeConfig,
    loadProvenance,
    ensurePyodideLoader,
    loadVerifiedPyodide,
    getConfig() { return activeConfig || DEFAULT_CONFIG; },
    getProvenance() { return activeProvenance; },
    getPyodideIndexURL() { return activeIndexURL; },
    getPyodideLoaderURL() { return activeLoaderURL; }
  });
})();
