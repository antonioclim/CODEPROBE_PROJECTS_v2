(function () {
  "use strict";

  const DEFAULT_CONFIG = Object.freeze({
    schema: "codeprobe-runtime-config/v1",
    pyodide: {
      mode: "cdn",
      version: "0.25.0",
      loader_url: "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/pyodide.js",
      index_url: "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/",
      local_loader_url: "vendor/pyodide/v0.25.0/full/pyodide.js",
      local_index_url: "vendor/pyodide/v0.25.0/full/",
      expected_loader_sha256: "",
      require_integrity: false
    },
    privacy: {
      history_enabled_default: false,
      store_source_in_history: false,
      clear_pyodide_payload_after_run: true
    }
  });

  let configPromise = null;
  let pyodideScriptPromise = null;
  let activeConfig = null;
  let activeIndexURL = DEFAULT_CONFIG.pyodide.index_url;
  let activeLoaderURL = DEFAULT_CONFIG.pyodide.loader_url;

  function mergeConfig(raw) {
    const config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return config;
    }
    if (raw.pyodide && typeof raw.pyodide === "object" && !Array.isArray(raw.pyodide)) {
      Object.assign(config.pyodide, raw.pyodide);
    }
    if (raw.privacy && typeof raw.privacy === "object" && !Array.isArray(raw.privacy)) {
      Object.assign(config.privacy, raw.privacy);
    }
    return config;
  }

  async function loadRuntimeConfig() {
    if (configPromise) return configPromise;
    configPromise = (async () => {
      try {
        const response = await fetch("runtime-config.json", { cache: "no-store" });
        if (!response.ok) throw new Error(`runtime-config.json returned ${response.status}`);
        activeConfig = mergeConfig(await response.json());
      } catch (error) {
        activeConfig = mergeConfig(null);
        activeConfig.runtime_config_warning = String(error && error.message ? error.message : error);
      }
      const pyodide = activeConfig.pyodide || {};
      const mode = String(pyodide.mode || "cdn").toLowerCase();
      if (mode === "local") {
        activeLoaderURL = pyodide.local_loader_url || DEFAULT_CONFIG.pyodide.local_loader_url;
        activeIndexURL = pyodide.local_index_url || DEFAULT_CONFIG.pyodide.local_index_url;
      } else {
        activeLoaderURL = pyodide.loader_url || DEFAULT_CONFIG.pyodide.loader_url;
        activeIndexURL = pyodide.index_url || DEFAULT_CONFIG.pyodide.index_url;
      }
      return activeConfig;
    })();
    return configPromise;
  }

  async function sha256Hex(text) {
    if (!window.crypto || !window.crypto.subtle || typeof TextEncoder === "undefined") {
      return "";
    }
    const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
    return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, "0")).join("");
  }

  function appendScript(url) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = url;
      script.async = true;
      script.crossOrigin = "anonymous";
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`Could not load Pyodide runtime from ${url}`));
      document.head.appendChild(script);
    });
  }

  async function appendVerifiedScript(url, expectedSha256) {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Could not fetch Pyodide runtime for integrity verification (${response.status}).`);
    }
    const source = await response.text();
    const actual = await sha256Hex(source);
    if (!actual) {
      throw new Error("Browser WebCrypto SHA-256 is unavailable, but runtime-config requires integrity verification.");
    }
    const expected = String(expectedSha256 || "").toLowerCase().replace(/^sha256[:=-]?/i, "");
    if (actual.toLowerCase() !== expected) {
      throw new Error(`Pyodide runtime integrity mismatch: expected ${expected}, got ${actual}.`);
    }
    const blob = new Blob([source], { type: "text/javascript" });
    const blobURL = URL.createObjectURL(blob);
    try {
      await appendScript(blobURL);
    } finally {
      URL.revokeObjectURL(blobURL);
    }
  }

  async function ensurePyodideLoader() {
    if (typeof window.loadPyodide === "function") {
      return;
    }
    if (pyodideScriptPromise) return pyodideScriptPromise;
    pyodideScriptPromise = (async () => {
      const config = await loadRuntimeConfig();
      const pyodide = config.pyodide || {};
      const expected = String(pyodide.expected_loader_sha256 || "").trim();
      const requireIntegrity = Boolean(pyodide.require_integrity);
      if (expected) {
        await appendVerifiedScript(activeLoaderURL, expected);
      } else {
        if (requireIntegrity) {
          throw new Error("runtime-config requires Pyodide integrity verification, but expected_loader_sha256 is empty.");
        }
        await appendScript(activeLoaderURL);
      }
      if (typeof window.loadPyodide !== "function") {
        throw new Error("Pyodide loaded but did not expose loadPyodide().");
      }
    })();
    return pyodideScriptPromise;
  }

  window.CodeProbeRuntime = Object.freeze({
    loadRuntimeConfig,
    ensurePyodideLoader,
    getConfig() { return activeConfig || DEFAULT_CONFIG; },
    getPyodideIndexURL() { return activeIndexURL; },
    getPyodideLoaderURL() { return activeLoaderURL; }
  });
})();
