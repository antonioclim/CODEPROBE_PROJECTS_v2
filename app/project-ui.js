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
      cancelBtn: document.getElementById("cancelBtn"),
      exportJsonBtn: document.getElementById("exportJsonBtn"), exportTextBtn: document.getElementById("exportTextBtn"),
      status: document.getElementById("status"), score: document.getElementById("score"),
      scoreProgress: document.getElementById("projectScoreProgress"), scoreBar: document.getElementById("projectScoreBar"), reading: document.getElementById("reading"),
      analysed: document.getElementById("analysed"), excluded: document.getElementById("excluded"),
      reviewPanel: document.getElementById("reviewPanel"), dropOverlay: document.getElementById("dropOverlay"),
      textReport: document.getElementById("textReport"), jsonReport: document.getElementById("jsonReport")
    };
    const state = { workerSession: null, busy: false, generation: 0, ready: false, payload: null, projectName: "project", text: "", json: "", engineBundle: null, engineFingerprint: null };
    function setStatus(text, { busy = false } = {}) {
      els.status.textContent = String(text);
      els.status.setAttribute("aria-busy", busy ? "true" : "false");
    }
    function setProgressBar(value, unavailableText = "Not available") {
      const numeric = Number(value);
      if (value === null || value === undefined || !Number.isFinite(numeric)) {
        els.scoreBar.style.width = "0%";
        els.scoreProgress.removeAttribute("aria-valuenow");
        els.scoreProgress.setAttribute("aria-valuetext", unavailableText);
        return;
      }
      const bounded = Math.max(0, Math.min(100, numeric));
      const rendered = bounded.toFixed(1);
      els.scoreBar.style.width = `${bounded}%`;
      els.scoreProgress.setAttribute("aria-valuenow", rendered);
      els.scoreProgress.setAttribute("aria-valuetext", `${rendered} per cent`);
    }
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
    async function collectDroppedFiles(dataTransfer) {
      return window.CodeProbeRuntime.collectDroppedFiles(dataTransfer);
    }
    function hasFileDrag(event) { return Array.from(event.dataTransfer?.types || []).includes("Files"); }
    function showDropOverlay(show) { if (els.dropOverlay) { els.dropOverlay.classList.toggle("hidden", !show); els.dropOverlay.setAttribute("aria-hidden", show ? "false" : "true"); } }
    async function handleDroppedProject(dataTransfer) {
      if (state.busy) { setStatus("Cancel the current operation before loading another input."); return; }
      let files;
      try { files = await collectDroppedFiles(dataTransfer); }
      catch (error) { setStatus(error.message); return; }
      if (!files.length) { setStatus("No readable files were dropped."); return; }
      if (files.length > MAX_BROWSER_DROP_FILES) { setStatus(`Too many files were dropped (${files.length}). Use tools/analyze_project.py for very large projects.`); return; }
      if (files.length === 1 && /\.zip$/i.test(files[0].name || "")) await loadZip(files[0]);
      else await loadFolder(files);
    }
    function looksBinary(bytes) {
      if (!bytes.length) return false;
      if (bytes.slice(0, 4096).includes(0)) return true;
      let suspicious = 0;
      for (const value of bytes.slice(0, 4096)) if (value < 7 || (value > 14 && value < 32)) suspicious += 1;
      return suspicious > Math.max(8, bytes.length * 0.2);
    }
    async function decodeTextFile(file, path) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (looksBinary(bytes)) throw new Error("binary file");
      if (!window.CodeProbeRuntime?.decodeSourceBytes) {
        throw new Error("the shared source-decoding boundary is unavailable");
      }
      const decoded = window.CodeProbeRuntime.decodeSourceBytes(bytes);
      return {
        path,
        content: decoded.text,
        size_bytes: file.size,
        decoding_warning: decoded.warning
      };
    }
    function setBusy(busy) {
      state.busy = busy;
      els.analyseBtn.disabled = busy || !state.payload;
      els.cancelBtn.disabled = !busy;
      for (const key of ["zipBtn", "folderBtn", "profileSelect", "calibrationProfile"]) els[key].disabled = busy;
    }
    function clearResults() {
      state.text = ""; state.json = "";
      els.textReport.value = ""; els.jsonReport.value = "";
      els.exportJsonBtn.disabled = true; els.exportTextBtn.disabled = true;
      els.score.textContent = "—"; setProgressBar(null);
      els.reading.textContent = "—"; els.analysed.textContent = "0"; els.excluded.textContent = "0";
      els.reviewPanel.replaceChildren();
    }
    function cancelAnalysis() {
      state.generation += 1;
      state.workerSession?.cancel();
      state.ready = false;
      clearResults();
      setBusy(false);
      setStatus("Analysis cancelled; the worker was terminated.");
    }
    async function initEngine() {
      if (state.workerSession?.isReady()) return;
      setStatus("Loading Pyodide and src/codeprobe_runtime.py…", { busy: true });
      if (!state.workerSession) state.workerSession = window.CodeProbeRuntime.createAnalysisSession();
      const metadata = await state.workerSession.initialise();
      state.engineFingerprint = metadata.fingerprint;
      state.ready = true;
    }
    async function loadZip(file) {
      if ((file.size || 0) > MAX_BROWSER_PROJECT_ZIP_BYTES) { setStatus(`ZIP exceeds the ${MAX_BROWSER_PROJECT_ZIP_BYTES} byte browser limit.`); return; }
      const buffer = await file.arrayBuffer();
      state.projectName = (file.name || "project.zip").replace(/\.zip$/i, "");
      state.payload = { project_name: state.projectName, zip_base64: bytesToBase64(new Uint8Array(buffer)), max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES };
      els.analyseBtn.disabled = false;
      setStatus(`Loaded ZIP: ${file.name}.`);
    }
    async function loadFolder(fileList) {
      const selected = Array.from(fileList || []);
      if (selected.length > MAX_BROWSER_PROJECT_ENTRIES) {
        setStatus("Folder selection contains too many files for the browser UI; use tools/analyze_project.py for this project.");
        return;
      }
      const files = []; const warnings = []; let acceptedBytes = 0;
      for (const file of selected) {
        const rawPath = file._codeprobeRelativePath || file.webkitRelativePath || file.name;
        let path = rawPath;
        try {
          path = window.CodeProbeRuntime.normaliseProjectPath(rawPath);
        } catch (error) {
          files.push({ path: rawPath, content: "", size_bytes: file.size || 0 });
          warnings.push(`${rawPath}: ${error.message}`);
          continue;
        }
        if ((file.size || 0) > MAX_BROWSER_PROJECT_TEXT_BYTES) { warnings.push(`${path}: skipped in browser because it exceeds 1 MB`); continue; }
        if (acceptedBytes + (file.size || 0) > MAX_BROWSER_PROJECT_TOTAL_BYTES) { warnings.push(`${path}: skipped because the browser project budget is ${MAX_BROWSER_PROJECT_TOTAL_BYTES} bytes`); continue; }
        try {
          const decoded = await decodeTextFile(file, path);
          files.push({ path: decoded.path, content: decoded.content, size_bytes: decoded.size_bytes });
          acceptedBytes += file.size || 0;
          if (decoded.decoding_warning) warnings.push(`${path}: ${decoded.decoding_warning}`);
        } catch (error) {
          warnings.push(`${path}: ${error.message}`);
        }
      }
      const first = files[0]?.path || "project";
      state.projectName = first.split("/").filter(Boolean)[0] || "project";
      state.payload = { project_name: state.projectName, files, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES, max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES };
      els.analyseBtn.disabled = false;
      setStatus(`Loaded folder: ${files.length} text file(s)${warnings.length ? `; ${warnings.length} skipped by browser` : ""}.`);
    }
    function calibrationProfileObject() {
      const raw = els.calibrationProfile.value.trim();
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Calibration profile must be a JSON object.");
      return parsed;
    }
    async function analyse() {
      if (!state.payload || state.busy) return;
      const generation = state.generation;
      setBusy(true); clearResults();
      try {
        const calibration_profile = calibrationProfileObject();
        await initEngine();
        if (generation !== state.generation) return;
        const payload = { ...state.payload, profile: els.profileSelect.value, calibration_profile };
        setStatus("Project analysis running…", { busy: true });
        const result = await state.workerSession.analyse("project", payload);
        if (generation !== state.generation) return;
      const report = result.project_report;
      state.text = result.text;
      state.json = JSON.stringify(report, null, 2);
      els.textReport.value = state.text;
      els.jsonReport.value = state.json;
      const overallPercent = Number(report.overall_percent || 0);
      els.score.textContent = report.overall_applicable === false ? "N/A" : `${overallPercent.toFixed(1)}%`;
      setProgressBar(report.overall_applicable === false ? null : overallPercent, "Not applicable");
      els.reading.textContent = report.reading || report.verdict || "—";
      els.analysed.textContent = String(report.included_file_count ?? report.analysed_file_count ?? 0);
      els.excluded.textContent = String(report.excluded_file_count ?? 0);
      renderReview(report);
      els.exportJsonBtn.disabled = false; els.exportTextBtn.disabled = false;
      setStatus("Project analysis completed.");
      } catch (error) {
        if (generation !== state.generation) return;
        state.ready = state.workerSession?.isReady() || false;
        setStatus(error.name === "TimeoutError" || error.name === "AbortError" ? error.message : "Project analysis failed; no report was accepted.");
      } finally {
        if (generation === state.generation) setBusy(false);
      }
    }
    function download(name, content, type) { const blob = new Blob([content], { type }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); }
    els.zipBtn.addEventListener("click", () => els.zipInput.click());
    els.folderBtn.addEventListener("click", () => els.folderInput.click());
    els.zipInput.addEventListener("change", async event => { const [file] = Array.from(event.target.files || []); if (file) await loadZip(file); els.zipInput.value = ""; });
    els.folderInput.addEventListener("change", async event => { await loadFolder(event.target.files); els.folderInput.value = ""; });
    els.cancelBtn.addEventListener("click", () => cancelAnalysis());
    window.addEventListener("pagehide", () => cancelAnalysis());
    els.analyseBtn.addEventListener("click", analyse);
    let dragDepth = 0;
    document.addEventListener("dragenter", event => { if (!hasFileDrag(event)) return; event.preventDefault(); dragDepth += 1; showDropOverlay(true); });
    document.addEventListener("dragover", event => { if (!hasFileDrag(event)) return; event.preventDefault(); if (event.dataTransfer) event.dataTransfer.dropEffect = "copy"; showDropOverlay(true); });
    document.addEventListener("dragleave", event => { if (!hasFileDrag(event)) return; dragDepth = Math.max(0, dragDepth - 1); if (dragDepth === 0) showDropOverlay(false); });
    document.addEventListener("drop", async event => { if (!hasFileDrag(event)) return; event.preventDefault(); dragDepth = 0; showDropOverlay(false); await handleDroppedProject(event.dataTransfer); });
    els.exportJsonBtn.addEventListener("click", () => download(`${state.projectName || "project"}.json`, state.json, "application/json;charset=utf-8"));
    els.exportTextBtn.addEventListener("click", () => download(`${state.projectName || "project"}.txt`, state.text, "text/plain;charset=utf-8"));
