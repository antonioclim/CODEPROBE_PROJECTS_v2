    function pyodideIndexURL() {
      return window.CodeProbeRuntime?.getPyodideIndexURL?.() || "https://cdn.jsdelivr.net/pyodide/v0.25.0/full/";
    }
    const MAX_BROWSER_DROP_FILES = 2000;
    const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;
    const MAX_BROWSER_PROJECT_ZIP_BYTES = 8000000;
    const MAX_BROWSER_PROJECT_TOTAL_BYTES = 20000000;
    const MAX_BROWSER_PROJECT_ENTRIES = 2000;
    const els = {
      zipBtn: document.getElementById("zipBtn"), zipInput: document.getElementById("zipInput"),
      folderBtn: document.getElementById("folderBtn"), folderInput: document.getElementById("folderInput"),
      profileSelect: document.getElementById("profileSelect"), analyseBtn: document.getElementById("analyseBtn"),
      calibrationProfile: document.getElementById("calibrationProfile"),
      exportJsonBtn: document.getElementById("exportJsonBtn"), exportTextBtn: document.getElementById("exportTextBtn"),
      status: document.getElementById("status"), score: document.getElementById("score"), reading: document.getElementById("reading"),
      analysed: document.getElementById("analysed"), excluded: document.getElementById("excluded"),
      reviewPanel: document.getElementById("reviewPanel"), dropOverlay: document.getElementById("dropOverlay"),
      textReport: document.getElementById("textReport"), jsonReport: document.getElementById("jsonReport")
    };
    const state = { pyodide: null, ready: false, payload: null, projectName: "project", text: "", json: "", engineSource: null, engineFingerprint: null };
    function bytesToBase64(bytes) {
      const chunk = 0x8000; let binary = "";
      for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
      return btoa(binary);
    }
    function escapeHtml(text) {
      return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
    function renderList(items) {
      if (!Array.isArray(items) || !items.length) return `<p class="muted">None recorded.</p>`;
      return `<ul class="review-list">${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
    }
    function renderReview(report) {
      const guidance = report?.manual_review_guidance;
      if (!els.reviewPanel || !guidance) return;
      const zones = Array.isArray(guidance.risk_zones) ? guidance.risk_zones : [];
      const packaging = report?.input_packaging || report?.project?.input_packaging || {};
      const packagingText = packaging.source
        ? `${packaging.source}${packaging.common_root_stripped ? `; stripped common root: ${packaging.common_root_detected || "unknown"}` : "; no common root stripped"}`
        : "not recorded";
      const zoneHtml = zones.length ? zones.map((zone, index) => {
        const level = String(zone.risk_level || "moderate").toLowerCase();
        const title = zone.display_name || zone.path || zone.title || zone.metric || zone.scope || "Risk zone";
        const score = typeof zone.score_percent === "number" ? ` (${zone.score_percent.toFixed(1)}%)` : "";
        return `<article class="risk-card risk-${escapeHtml(level)}"><h3>${index + 1}. ${escapeHtml(title)}${score}</h3><p>${escapeHtml(zone.evidence_summary || zone.reading || "Review this area manually.")}</p>${renderList(zone.manual_review_actions || [])}</article>`;
      }).join("") : `<p class="muted">No risk zone reached the reporting threshold.</p>`;
      els.reviewPanel.innerHTML = `
        <article class="review-card"><h3>Status</h3><p><strong>${escapeHtml(guidance.status_label || guidance.status || "not specified")}</strong></p><p>${escapeHtml(guidance.defensibility_note || "The score is a triage signal, not a misconduct finding.")}</p></article>
        <article class="review-card"><h3>Input packaging</h3><p>${escapeHtml(packagingText)}</p><p>${escapeHtml(packaging.common_root_reason || "Packaging normalisation was not needed or not available for this report.")}</p></article>
        <article class="review-card"><h3>Recommended manual steps</h3>${renderList(guidance.recommended_manual_steps || [])}</article>
        <article class="review-card"><h3>Priority questions</h3>${renderList(guidance.priority_questions || [])}</article>
        <article class="review-card"><h3>Evidence to request</h3>${renderList(guidance.evidence_to_request || [])}</article>
        ${zoneHtml}
      `;
    }
    function annotateDroppedFile(file, relativePath) {
      if (relativePath) {
        try { Object.defineProperty(file, "_codeprobeRelativePath", { value: relativePath.replace(/\\/g, "/"), configurable: true }); }
        catch (error) { file._codeprobeRelativePath = relativePath.replace(/\\/g, "/"); }
      }
      return file;
    }
    function readAllDirectoryEntries(reader) {
      return new Promise((resolve, reject) => {
        const entries = [];
        function readBatch() { reader.readEntries(batch => { if (!batch.length) { resolve(entries); return; } entries.push(...batch); readBatch(); }, reject); }
        readBatch();
      });
    }
    async function filesFromEntry(entry, prefix = "") {
      if (!entry) return [];
      if (entry.isFile) return new Promise(resolve => entry.file(file => resolve([annotateDroppedFile(file, `${prefix}${file.name}`)]), () => resolve([])));
      if (entry.isDirectory) {
        const entries = await readAllDirectoryEntries(entry.createReader());
        const files = [];
        for (const child of entries) { files.push(...await filesFromEntry(child, `${prefix}${entry.name}/`)); if (files.length > MAX_BROWSER_DROP_FILES) break; }
        return files;
      }
      return [];
    }
    async function collectDroppedFiles(dataTransfer) {
      const items = Array.from(dataTransfer?.items || []);
      const entries = items.map(item => (item.kind === "file" && typeof item.webkitGetAsEntry === "function") ? item.webkitGetAsEntry() : null).filter(Boolean);
      if (entries.length) {
        const files = [];
        for (const entry of entries) { files.push(...await filesFromEntry(entry)); if (files.length > MAX_BROWSER_DROP_FILES) break; }
        return files;
      }
      return Array.from(dataTransfer?.files || []);
    }
    function hasFileDrag(event) { return Array.from(event.dataTransfer?.types || []).includes("Files"); }
    function showDropOverlay(show) { if (els.dropOverlay) { els.dropOverlay.classList.toggle("hidden", !show); els.dropOverlay.setAttribute("aria-hidden", show ? "false" : "true"); } }
    async function handleDroppedProject(dataTransfer) {
      const files = await collectDroppedFiles(dataTransfer);
      if (!files.length) { els.status.textContent = "No readable files were dropped."; return; }
      if (files.length > MAX_BROWSER_DROP_FILES) { els.status.textContent = `Too many files were dropped (${files.length}). Use tools/analyze_project.py for very large projects.`; return; }
      if (files.length === 1 && /\.zip$/i.test(files[0].name || "")) await loadZip(files[0]);
      else await loadFolder(files);
    }
    async function sha256Hex(text) {
      if (!window.crypto || !window.crypto.subtle || typeof TextEncoder === "undefined") return "";
      const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(text)));
      return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, "0")).join("");
    }
    async function engineFingerprint() {
      if (state.engineFingerprint) return state.engineFingerprint;
      if (!state.engineSource) {
        const response = await fetch("../src/codeprobe_runtime.py", { cache: "no-store" });
        state.engineSource = await response.text();
      }
      const value = await sha256Hex(state.engineSource);
      state.engineFingerprint = { algorithm: "sha256", value, available: Boolean(value), scope: "src/codeprobe_runtime.py", source: "browser-fetch" };
      return state.engineFingerprint;
    }
    function looksBinary(bytes) {
      if (!bytes.length) return false;
      if (bytes.slice(0, 4096).includes(0)) return true;
      let suspicious = 0;
      for (const value of bytes.slice(0, 4096)) if (value < 7 || (value > 14 && value < 32)) suspicious += 1;
      return suspicious > Math.max(8, bytes.length * 0.2);
    }
    async function decodeTextFile(file) {
      const buffer = await file.arrayBuffer(); const bytes = new Uint8Array(buffer);
      if (looksBinary(bytes)) throw new Error("binary file");
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      return { path: file._codeprobeRelativePath || file.webkitRelativePath || file.name, content: text, size_bytes: file.size };
    }
    async function initEngine() {
      if (state.ready) return;
      els.status.textContent = "Loading Pyodide and src/codeprobe_runtime.py…";
      if (window.CodeProbeRuntime?.ensurePyodideLoader) {
        await window.CodeProbeRuntime.ensurePyodideLoader();
      }
      state.pyodide = await loadPyodide({ indexURL: pyodideIndexURL() });
      const engineSource = await (await fetch("../src/codeprobe_runtime.py", { cache: "no-store" })).text();
      state.engineSource = engineSource;
      state.pyodide.FS.writeFile("codeprobe_runtime.py", engineSource);
      state.pyodide.runPython("import codeprobe_runtime");
      state.ready = true;
      els.status.textContent = "Engine ready.";
    }
    async function loadZip(file) {
      if ((file.size || 0) > MAX_BROWSER_PROJECT_ZIP_BYTES) { els.status.textContent = `ZIP exceeds the ${MAX_BROWSER_PROJECT_ZIP_BYTES} byte browser limit.`; return; }
      const buffer = await file.arrayBuffer();
      state.projectName = (file.name || "project.zip").replace(/\.zip$/i, "");
      state.payload = { project_name: state.projectName, zip_base64: bytesToBase64(new Uint8Array(buffer)), max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES };
      els.analyseBtn.disabled = false;
      els.status.textContent = `Loaded ZIP: ${file.name}.`;
    }
    async function loadFolder(fileList) {
      const selected = Array.from(fileList || []);
      if (selected.length > MAX_BROWSER_PROJECT_ENTRIES) {
        els.status.textContent = "Folder selection contains too many files for the browser UI; use tools/analyze_project.py for this project.";
        return;
      }
      const files = []; const warnings = []; let acceptedBytes = 0;
      for (const file of selected) {
        const path = file._codeprobeRelativePath || file.webkitRelativePath || file.name;
        if ((file.size || 0) > MAX_BROWSER_PROJECT_TEXT_BYTES) { warnings.push(`${path}: skipped in browser because it exceeds 1 MB`); continue; }
        if (acceptedBytes + (file.size || 0) > MAX_BROWSER_PROJECT_TOTAL_BYTES) { warnings.push(`${path}: skipped because the browser project budget is ${MAX_BROWSER_PROJECT_TOTAL_BYTES} bytes`); continue; }
        try { files.push(await decodeTextFile(file)); acceptedBytes += file.size || 0; } catch (error) { warnings.push(`${path}: ${error.message}`); }
      }
      const first = files[0]?.path || "project";
      state.projectName = first.split("/").filter(Boolean)[0] || "project";
      state.payload = { project_name: state.projectName, files, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES, max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES };
      els.analyseBtn.disabled = false;
      els.status.textContent = `Loaded folder: ${files.length} text file(s)${warnings.length ? `; ${warnings.length} skipped by browser` : ""}.`;
    }
    function calibrationProfileObject() {
      const raw = els.calibrationProfile.value.trim();
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Calibration profile must be a JSON object.");
      return parsed;
    }
    async function analyse() {
      if (!state.payload) return;
      await initEngine();
      let calibration_profile = null;
      try { calibration_profile = calibrationProfileObject(); }
      catch (error) { els.status.textContent = error.message; return; }
      const payload = { ...state.payload, profile: els.profileSelect.value, calibration_profile, engine_fingerprint: await engineFingerprint() };
      state.pyodide.globals.set("payload_json", JSON.stringify(payload));
      let resultText = "";
      try { resultText = state.pyodide.runPython("import codeprobe_runtime\ncodeprobe_runtime.codeprobe_analyze_project(payload_json)"); }
      finally { state.pyodide.globals.delete("payload_json"); }
      const result = JSON.parse(resultText);
      const report = result.project_report;
      state.text = result.text;
      state.json = JSON.stringify(report, null, 2);
      els.textReport.value = state.text;
      els.jsonReport.value = state.json;
      els.score.textContent = report.overall_applicable === false ? "N/A" : `${Number(report.overall_percent || 0).toFixed(1)}%`;
      els.reading.textContent = report.reading || report.verdict || "—";
      els.analysed.textContent = String(report.included_file_count ?? report.analysed_file_count ?? 0);
      els.excluded.textContent = String(report.excluded_file_count ?? 0);
      renderReview(report);
      els.exportJsonBtn.disabled = false; els.exportTextBtn.disabled = false;
      els.status.textContent = "Project analysis completed.";
    }
    function download(name, content, type) { const blob = new Blob([content], { type }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); }
    els.zipBtn.addEventListener("click", () => els.zipInput.click());
    els.folderBtn.addEventListener("click", () => els.folderInput.click());
    els.zipInput.addEventListener("change", async event => { const [file] = Array.from(event.target.files || []); if (file) await loadZip(file); els.zipInput.value = ""; });
    els.folderInput.addEventListener("change", async event => { await loadFolder(event.target.files); els.folderInput.value = ""; });
    els.analyseBtn.addEventListener("click", analyse);
    let dragDepth = 0;
    document.addEventListener("dragenter", event => { if (!hasFileDrag(event)) return; event.preventDefault(); dragDepth += 1; showDropOverlay(true); });
    document.addEventListener("dragover", event => { if (!hasFileDrag(event)) return; event.preventDefault(); if (event.dataTransfer) event.dataTransfer.dropEffect = "copy"; showDropOverlay(true); });
    document.addEventListener("dragleave", event => { if (!hasFileDrag(event)) return; dragDepth = Math.max(0, dragDepth - 1); if (dragDepth === 0) showDropOverlay(false); });
    document.addEventListener("drop", async event => { if (!hasFileDrag(event)) return; event.preventDefault(); dragDepth = 0; showDropOverlay(false); await handleDroppedProject(event.dataTransfer); });
    els.exportJsonBtn.addEventListener("click", () => download(`${state.projectName || "project"}.json`, state.json, "application/json;charset=utf-8"));
    els.exportTextBtn.addEventListener("click", () => download(`${state.projectName || "project"}.txt`, state.text, "text/plain;charset=utf-8"));
