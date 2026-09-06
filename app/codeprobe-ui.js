    const HISTORY_KEY = "codeprobe_html_history_v2";
    const HISTORY_ENABLED_KEY = "codeprobe_html_history_enabled_v1";
    const MAX_BROWSER_DROP_FILES = 2000;
    const MAX_BROWSER_PROJECT_TEXT_BYTES = 1000000;
    const MAX_BROWSER_PROJECT_ZIP_BYTES = 8000000;
    const MAX_BROWSER_PROJECT_TOTAL_BYTES = 20000000;
    const MAX_BROWSER_PROJECT_ENTRIES = 2000;
    const ALLOWED_CONFIG_KEYS = new Set(["enabled", "weight", "thresholds", "notes", "group", "contributes_to_overall"]);
    const ALLOWED_METRIC_GROUPS = new Set(["stylometry", "context", "quality", "documentation"]);
    const NON_AUTHORSHIP_METRICS = new Set([
      "magic_numbers", "dead_code_residue", "indentation_consistency", "used_import_ratio",
      "docstring_coverage", "type_hint_coverage", "javascript_modern_syntax",
      "bash_quoting_consistency", "import_organization", "register_pressure",
      "stack_frame_depth", "redundant_memory_access", "code_elegance",
      "preprocessor_hygiene", "error_handling_density", "boilerplate_presence",
      "cyclomatic_complexity", "halstead_difficulty", "nesting_depth",
      "defensive_programming", "declarative_ratio", "control_ratio",
      "markdown_heading_structure", "markdown_code_fence_density",
      "markdown_link_density", "markdown_prose_entropy"
    ]);
    const LANGUAGE_LABELS = {
      auto: "Auto",
      python: "Python",
      javascript: "JavaScript",
      bash: "Bash",
      c: "C",
      cpp: "C++",
      csharp: "C#",
      markdown: "Markdown",
      project: "Project",
      unknown: "Unknown"
    };
    const KEYWORDS = {
      python: [
        "False","None","True","and","as","assert","async","await","break","class","continue",
        "def","del","elif","else","except","finally","for","from","global","if","import","in",
        "is","lambda","match","case","nonlocal","not","or","pass","raise","return","try","while",
        "with","yield"
      ],
      javascript: [
        "async","await","break","case","catch","class","const","continue","default","delete","do",
        "else","export","extends","finally","for","function","if","import","in","instanceof","let",
        "new","return","switch","throw","try","typeof","var","while","yield","null","undefined",
        "true","false"
      ],
      bash: [
        "if","then","elif","else","fi","for","while","until","case","esac","select","do","done",
        "function","local","declare","readonly","export","source","in","return","exit"
      ],
      c: [
        "auto","break","case","const","continue","default","do","else","enum","extern","for","goto",
        "if","inline","register","restrict","return","sizeof","static","struct","switch","typedef",
        "union","volatile","while","_Bool","_Generic","_Noreturn","_Static_assert","_Thread_local",
        "char","double","float","int","long","short","signed","unsigned","void"
      ],
      cpp: [
        "alignas","alignof","auto","bool","break","case","catch","class","const","constexpr","consteval",
        "constinit","continue","default","delete","do","else","enum","explicit","export","false","final",
        "for","friend","goto","if","inline","mutable","namespace","new","noexcept","nullptr","operator",
        "override","private","protected","public","register","requires","return","sizeof","static",
        "struct","switch","template","this","throw","true","try","typename","using","virtual","volatile",
        "while","char","double","float","int","long","short","signed","unsigned","void"
      ],
      csharp: [
        "abstract","as","async","await","base","bool","break","case","catch","class","const","continue",
        "default","delegate","do","else","enum","event","explicit","extern","false","finally","for",
        "foreach","if","implicit","in","interface","internal","is","lock","namespace","new","null",
        "operator","out","override","params","private","protected","public","readonly","record","ref",
        "return","sealed","static","struct","switch","this","throw","true","try","typeof","using","var",
        "virtual","void","while","yield","int","long","short","float","double","decimal","string","char"
      ],
      markdown: [],
      project: []
    };

    const appState = {
      workerSession: null,
      busy: false,
      generation: 0,
      loadingInput: false,
      engineReady: false,
      engineFailed: false,
      enginePromise: null,
      engineBundle: null,
      engineSourceMode: null,
      engineFingerprint: null,
      localEngineFile: null,
      currentFileName: "fragment.py",
      analysisMode: "single",
      projectPayload: null,
      currentReport: null,
      currentProjectReport: null,
      currentTextReport: "",
      currentJsonReport: "",
      detectedLanguage: "python",
      reportStale: false,
      fileWarnings: []
    };

    const els = {
      engineBadge: document.getElementById("engineBadge"),
      openBtn: document.getElementById("openBtn"),
      fileInput: document.getElementById("fileInput"),
      openProjectZipBtn: document.getElementById("openProjectZipBtn"),
      projectZipInput: document.getElementById("projectZipInput"),
      openFolderBtn: document.getElementById("openFolderBtn"),
      folderInput: document.getElementById("folderInput"),
      loadEngineBtn: document.getElementById("loadEngineBtn"),
      engineFileInput: document.getElementById("engineFileInput"),
      analyzeBtn: document.getElementById("analyzeBtn"),
      cancelBtn: document.getElementById("cancelBtn"),
      clearBtn: document.getElementById("clearBtn"),
      exportJsonBtn: document.getElementById("exportJsonBtn"),
      exportTextBtn: document.getElementById("exportTextBtn"),
      clearHistoryBtn: document.getElementById("clearHistoryBtn"),
      privacyWipeBtn: document.getElementById("privacyWipeBtn"),
      historyEnabled: document.getElementById("historyEnabled"),
      languageSelect: document.getElementById("languageSelect"),
      profileSelect: document.getElementById("profileSelect"),
      editor: document.getElementById("editor"),
      highlightLayer: document.getElementById("highlightLayer"),
      dropZone: document.getElementById("dropZone"),
      editorModeBadge: document.getElementById("editorModeBadge"),
      fileMeta: document.getElementById("fileMeta"),
      lineMeta: document.getElementById("lineMeta"),
      langMeta: document.getElementById("langMeta"),
      staleMeta: document.getElementById("staleMeta"),
      scoreValue: document.getElementById("scoreValue"),
      scoreProgress: document.getElementById("scoreProgress"),
      scoreBar: document.getElementById("scoreBar"),
      verdictValue: document.getElementById("verdictValue"),
      confidenceValue: document.getElementById("confidenceValue"),
      summaryLanguage: document.getElementById("summaryLanguage"),
      summaryProfile: document.getElementById("summaryProfile"),
      lowLevelQualityCard: document.getElementById("lowLevelQualityCard"),
      lowLevelQualityValue: document.getElementById("lowLevelQualityValue"),
      lowLevelQualityProgress: document.getElementById("lowLevelQualityProgress"),
      lowLevelQualityBar: document.getElementById("lowLevelQualityBar"),
      notesList: document.getElementById("notesList"),
      warningsList: document.getElementById("warningsList"),
      configOverride: document.getElementById("configOverride"),
      calibrationProfile: document.getElementById("calibrationProfile"),
      metricsBody: document.getElementById("metricsBody"),
      metricDetail: document.getElementById("metricDetail"),
      textReport: document.getElementById("textReport"),
      jsonReport: document.getElementById("jsonReport"),
      historyList: document.getElementById("historyList"),
      manualReviewPanel: document.getElementById("manualReviewPanel"),
      globalDropOverlay: document.getElementById("globalDropOverlay"),
      spinner: document.getElementById("spinner"),
      statusBar: document.getElementById("applicationStatus"),
      statusText: document.getElementById("statusText"),
      contextText: document.getElementById("contextText"),
      tabButtons: Array.from(document.querySelectorAll(".tab-btn")),
      tabPanels: Array.from(document.querySelectorAll(".tab-panel"))
    };

    function clamp(value, low = 0, high = 1) {
      return Math.max(low, Math.min(high, value));
    }

    function escapeHtml(text) {
      return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function escapeRegex(text) {
      return String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }

    async function sha256Bytes(bytes) {
      if (!window.crypto || !window.crypto.subtle) {
        throw new Error("Browser WebCrypto SHA-256 is unavailable.");
      }
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
    }

    async function loadManualEngineBundle(file) {
      if (!file) throw new Error("No local engine file was selected.");
      if (file.size > 1000000) throw new Error("The unverified engine override exceeds 1 MB.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      let text = "";
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch (_) {
        throw new Error("The selected engine file is not valid UTF-8.");
      }
      const value = await sha256Bytes(bytes);
      return Object.freeze({
        text,
        size_bytes: bytes.byteLength,
        trusted: false,
        source: "manual-unverified",
        fingerprint: Object.freeze({
          algorithm: "sha256",
          value,
          available: true,
          scope: "src/codeprobe_runtime.py",
          source: "manual-unverified"
        }),
        copyBytes() { return bytes.slice(); }
      });
    }

    async function getEngineBundle() {
      if (appState.engineBundle) return appState.engineBundle;
      const generation = appState.generation;
      const file = appState.localEngineFile;
      const bundle = file ? await loadManualEngineBundle(file) : await window.CodeProbeRuntime.loadVerifiedEngine();
      if (generation !== appState.generation || file !== appState.localEngineFile) {
        throw new DOMException("Engine loading was cancelled.", "AbortError");
      }
      appState.engineBundle = bundle;
      appState.engineSourceMode = file ? "manual-unverified" : "packaged-verified";
      appState.engineFingerprint = bundle.fingerprint;
      return bundle;
    }

    async function getEngineFingerprint() {
      if (appState.engineFingerprint) return appState.engineFingerprint;
      return (await getEngineBundle()).fingerprint;
    }

    function showEngineLoader(show) {
      els.loadEngineBtn.classList.toggle("hidden", !show);
    }

    function setStatus(text) {
      els.statusText.textContent = String(text);
    }

    function setBusy(isBusy, text) {
      const busy = Boolean(isBusy);
      els.spinner.classList.toggle("active", busy);
      els.statusBar.setAttribute("aria-busy", busy ? "true" : "false");
      setStatus(text);
      appState.busy = busy;
      els.analyzeBtn.disabled = busy || appState.loadingInput || appState.engineFailed;
      els.cancelBtn.disabled = !(busy || appState.loadingInput);
      els.editor.readOnly = busy || appState.analysisMode === "project";
      for (const key of ["openBtn", "openProjectZipBtn", "openFolderBtn", "loadEngineBtn", "languageSelect", "profileSelect", "configOverride", "calibrationProfile"]) {
        els[key].disabled = busy;
      }
    }

    function setProgressBar(container, fill, value, unavailableText = "Not available") {
      const numeric = Number(value);
      if (value === null || value === undefined || !Number.isFinite(numeric)) {
        fill.style.width = "0%";
        container.removeAttribute("aria-valuenow");
        container.setAttribute("aria-valuetext", unavailableText);
        return;
      }
      const bounded = clamp(numeric, 0, 100);
      const rendered = bounded.toFixed(1);
      fill.style.width = `${bounded}%`;
      container.setAttribute("aria-valuenow", rendered);
      container.setAttribute("aria-valuetext", `${rendered} per cent`);
    }

    function setEngineBadge(state, text) {
      els.engineBadge.className = `badge ${state}`;
      els.engineBadge.textContent = text;
    }

    function formatDateTime(isoText) {
      try {
        const date = new Date(isoText);
        return new Intl.DateTimeFormat("en-GB", {
          dateStyle: "short",
          timeStyle: "medium"
        }).format(date);
      } catch (error) {
        return isoText;
      }
    }

    function defaultFileNameForLanguage(lang) {
      const extensionMap = {
        python: ".py",
        javascript: ".js",
        bash: ".sh",
        c: ".c",
        cpp: ".cpp",
        csharp: ".cs",
        markdown: ".md"
      };
      return "fragment" + (extensionMap[lang] || ".txt");
    }

    function detectLanguage(filename, code, hint = null) {
      const supported = ["python", "javascript", "bash", "c", "cpp", "csharp", "markdown"];
      if (hint && supported.includes(hint)) {
        return hint;
      }

      const lowerName = String(filename || "").toLowerCase();
      const extension = lowerName.includes(".") ? lowerName.split(".").pop() : "";
      if (["py", "pyw"].includes(extension)) return "python";
      if (["js", "mjs", "cjs", "jsx", "ts", "tsx"].includes(extension)) return "javascript";
      if (["sh", "bash", "zsh", "ksh"].includes(extension)) return "bash";
      if (["cpp", "cxx", "cc", "hpp", "hxx", "hh"].includes(extension)) return "cpp";
      if (extension === "cs") return "csharp";
      if (["md", "markdown"].includes(extension)) return "markdown";
      if (extension === "c") return "c";
      if (extension === "h") {
        const cppHeaderHits = (code.match(/\b(?:namespace|template\s*<|std::|class\s+[A-Za-z_]|using\s+namespace|constexpr)\b/g) || []).length;
        return cppHeaderHits >= 2 ? "cpp" : "c";
      }

      const firstLine = code ? String(code).split("\n", 1)[0] : "";
      if (firstLine.includes("python")) return "python";
      if (firstLine.includes("node") || firstLine.includes("deno")) return "javascript";
      if (firstLine.includes("bash") || firstLine.startsWith("#!/bin/sh") || firstLine.includes("/sh")) return "bash";

      const markdownHits =
        (code.match(/(^|\n)#{1,6}\s+\S/g) || []).length +
        (code.match(/```/g) || []).length +
        (code.match(/\[[^\]]+\]\([^)]+\)/g) || []).length;
      const pyHits = (code.match(/(^|\n)\s*(?:def |class |import |from |if __name__ == )/g) || []).length;
      const jsHits = (code.match(/(^|\n)\s*(?:function |const |let |var |import |export |class )/g) || []).length;
      const shHits = (code.match(/(^|\n)\s*(?:#!\/bin\/(?:ba)?sh|if \[|for \w+ in|echo |export )/g) || []).length;
      const csharpHits =
        (code.match(/\busing\s+[A-Z][A-Za-z0-9_.]*\s*;/g) || []).length +
        (code.match(/\bnamespace\s+[A-Z][A-Za-z0-9_.]*/g) || []).length +
        (code.match(/\b(?:public|private|protected|internal)\s+(?:static\s+)?(?:class|interface|struct|record)\b/g) || []).length +
        (code.match(/\[[A-Za-z_][A-Za-z0-9_.]*(?:\([^\]]*\))?\]/g) || []).length;
      const cppHits =
        (code.match(/\bnamespace\s+[A-Za-z_][A-Za-z0-9_]*\b/g) || []).length +
        (code.match(/\btemplate\s*</g) || []).length +
        (code.match(/\bstd::/g) || []).length +
        (code.match(/\b(?:class|typename|constexpr|nullptr)\b/g) || []).length;
      const cHits =
        (code.match(/#include\s+<[^>]+>/g) || []).length +
        (code.match(/\b(?:printf|scanf|malloc|calloc|free|typedef\s+struct)\b/g) || []).length +
        (code.match(/\b(?:restrict|volatile|enum|union)\b/g) || []).length;

      const ranked = [
        [markdownHits, "markdown"],
        [pyHits, "python"],
        [jsHits, "javascript"],
        [shHits, "bash"],
        [csharpHits, "csharp"],
        [cppHits, "cpp"],
        [cHits, "c"]
      ].sort((left, right) => right[0] - left[0]);

      if (ranked[0][0] > 0) {
        return ranked[0][1];
      }
      return "unknown";
    }

    function getHighlightLanguage() {
      if (appState.analysisMode === "project") {
        return "markdown";
      }
      const selected = els.languageSelect.value;
      const code = els.editor.value;
      if (selected && selected !== "auto") return selected;
      const detected = appState.currentReport?.language || detectLanguage(appState.currentFileName, code, null);
      return detected === "unknown" ? "python" : detected;
    }

    function syntaxHighlight(code, language) {
      // Large legal inputs use plain escaped text rather than synchronous regex highlighting.
      if (code.length > 50000) return escapeHtml(code);
      let text = String(code || "");
      const placeholders = [];
      const stash = (value, cls) => {
        const token = `@@CODEPROBE_${placeholders.length}@@`;
        placeholders.push({ token, html: `<span class="${cls}">${escapeHtml(value)}</span>` });
        return token;
      };

      if (language === "python") {
        text = text.replace(/("{3}[\s\S]*?"{3}|'{3}[\s\S]*?'{3}|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/g, match => stash(match, "tok-string"));
        text = text.replace(/#.*$/gm, match => stash(match, "tok-comment"));
      } else if (language === "javascript") {
        text = text.replace(/(`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/g, match => stash(match, "tok-string"));
        text = text.replace(/\/\*[\s\S]*?\*\//g, match => stash(match, "tok-comment"));
        text = text.replace(/\/\/.*$/gm, match => stash(match, "tok-comment"));
      } else if (language === "bash") {
        text = text.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, match => stash(match, "tok-string"));
        text = text.replace(/#.*$/gm, match => stash(match, "tok-comment"));
      } else if (language === "c" || language === "cpp" || language === "csharp") {
        text = text.replace(/@"(?:""|[^"])*"/g, match => stash(match, "tok-string"));
        text = text.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, match => stash(match, "tok-string"));
        text = text.replace(/^\s*#.*$/gm, match => stash(match, "tok-preprocessor"));
        text = text.replace(/\/\*[\s\S]*?\*\//g, match => stash(match, "tok-comment"));
        text = text.replace(/\/\/\/.*$/gm, match => stash(match, "tok-comment"));
        text = text.replace(/\/\/.*$/gm, match => stash(match, "tok-comment"));
      } else if (language === "markdown") {
        text = text.replace(/```[\s\S]*?```/g, match => stash(match, "tok-fence"));
        text = text.replace(/~~~[\s\S]*?~~~/g, match => stash(match, "tok-fence"));
        text = text.replace(/`[^`\n]+`/g, match => stash(match, "tok-string"));
      }

      text = escapeHtml(text);

      if (language === "markdown") {
        text = text.replace(/^#{1,6}\s.*$/gm, '<span class="tok-heading">$&</span>');
        text = text.replace(/\[[^\]]+\]\([^)]+\)/g, '<span class="tok-link">$&</span>');
        text = text.replace(/(?:\*\*[^*\n]+\*\*|__[^_\n]+__|\*[^*\n]+\*|_[^_\n]+_)/g, '<span class="tok-emphasis">$&</span>');
      } else {
        const keywordList = KEYWORDS[language] || [];
        if (keywordList.length) {
          const keywordPattern = new RegExp(`\\b(?:${keywordList.sort((left, right) => right.length - left.length).map(escapeRegex).join("|")})\\b`, "g");
          text = text.replace(keywordPattern, '<span class="tok-keyword">$&</span>');
        }
        text = text.replace(/\b(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b/g, '<span class="tok-number">$&</span>');
        if (language === "csharp") {
          text = text.replace(/(\[[A-Za-z_][A-Za-z0-9_.]*(?:\([^\]\n]*\))?\])/g, '<span class="tok-attribute">$1</span>');
        }
      }

      for (const item of placeholders) {
        text = text.replaceAll(item.token, item.html);
      }

      if (text.endsWith("\n")) {
        text += " ";
      }
      return text;
    }

    let highlightScheduled = false;
    function scheduleHighlight() {
      if (highlightScheduled) return;
      highlightScheduled = true;
      requestAnimationFrame(() => {
        highlightScheduled = false;
        const lang = getHighlightLanguage();
        els.highlightLayer.innerHTML = syntaxHighlight(els.editor.value, lang);
        els.editorModeBadge.textContent = `Highlight: ${LANGUAGE_LABELS[lang] || lang}`;
      });
    }

    function syncEditorScroll() {
      els.highlightLayer.scrollTop = els.editor.scrollTop;
      els.highlightLayer.scrollLeft = els.editor.scrollLeft;
    }

    function renderList(container, items, emptyText, cssClass = "") {
      if (!Array.isArray(items) || items.length === 0) {
        container.innerHTML = `<li class="empty-state">${escapeHtml(emptyText)}</li>`;
        return;
      }
      container.innerHTML = items.map(item => `<li class="${cssClass}">${escapeHtml(item)}</li>`).join("");
    }

    function renderPlainList(items, cssClass = "review-list") {
      if (!Array.isArray(items) || !items.length) {
        return `<p class="empty-state">None recorded.</p>`;
      }
      return `<ul class="${cssClass}">${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
    }

    function zoneTitle(zone) {
      return zone.display_name || zone.path || zone.title || zone.metric || zone.scope || "Risk zone";
    }

    function renderRiskZone(zone, index) {
      const level = String(zone.risk_level || "moderate").toLowerCase();
      const score = typeof zone.score_percent === "number" ? `<span class="badge info">${zone.score_percent.toFixed(1)}%</span>` : "";
      const group = zone.group ? `<span class="badge info">${escapeHtml(zone.group)}</span>` : "";
      const path = zone.path ? `<span class="badge info">${escapeHtml(zone.path)}</span>` : "";
      const actions = zone.manual_review_actions || [];
      const metricHits = Array.isArray(zone.top_metric_hits) && zone.top_metric_hits.length
        ? `<div class="mt-md"><strong>Top metric hits</strong><ul class="risk-list">${zone.top_metric_hits.map(hit => `<li>${escapeHtml(hit.display_name || hit.metric || "metric")}: ${Number(hit.score_percent || 0).toFixed(1)}%${hit.value_display ? ` — ${escapeHtml(hit.value_display)}` : ""}</li>`).join("")}</ul></div>`
        : "";
      return `
        <article class="risk-card risk-${escapeHtml(level)}">
          <h3>${index + 1}. ${escapeHtml(zoneTitle(zone))}</h3>
          <div class="meta"><span class="badge warn">${escapeHtml(level)}</span>${score}${group}${path}</div>
          <p class="help-inline">${escapeHtml(zone.evidence_summary || zone.reading || zone.interpretation_limit || "Review this area manually.")}</p>
          ${metricHits}
          <div class="mt-md"><strong>Manual action</strong>${renderPlainList(actions, "risk-list")}</div>
        </article>`;
    }

    function renderManualReview(report) {
      if (!els.manualReviewPanel) return;
      const guidance = report?.manual_review_guidance;
      if (!guidance) {
        els.manualReviewPanel.innerHTML = `<div class="empty-state">No manual-review guidance is available for this report.</div>`;
        return;
      }
      const zones = Array.isArray(guidance.risk_zones) ? guidance.risk_zones : [];
      const recommendations = guidance.recommended_manual_steps || report.manual_review_recommendations || [];
      const packaging = report?.input_packaging || report?.project?.input_packaging || {};
      const packagingText = packaging.source
        ? `${packaging.source}${packaging.common_root_stripped ? `; stripped common root: ${packaging.common_root_detected || "unknown"}` : "; no common root stripped"}`
        : "not recorded";
      els.manualReviewPanel.innerHTML = `
        <div class="review-grid">
          <section class="review-card">
            <h3>Review status</h3>
            <p><strong>${escapeHtml(guidance.status_label || guidance.status || "not specified")}</strong></p>
            <p class="help-inline">${escapeHtml(guidance.defensibility_note || "The score is a triage signal, not a misconduct finding.")}</p>
            <p class="help-inline">Review trigger: ${Number(guidance.review_trigger_percent ?? report.review_trigger_percent ?? 60).toFixed(1)}%; reached: ${guidance.review_triggered ? "yes" : "no"}.</p>
          </section>
          <section class="review-card">
            <h3>Input packaging</h3>
            <p>${escapeHtml(packagingText)}</p>
            <p class="help-inline">${escapeHtml(packaging.common_root_reason || "Packaging normalisation was not needed or not available for this report.")}</p>
          </section>
          <section class="review-card">
            <h3>Evidence to request</h3>
            ${renderPlainList(guidance.evidence_to_request || [])}
          </section>
          <section class="review-card">
            <h3>Recommended manual steps</h3>
            ${renderPlainList(recommendations)}
          </section>
          <section class="review-card">
            <h3>Priority questions</h3>
            ${renderPlainList(guidance.priority_questions || [])}
          </section>
        </div>
        <div class="mt-xl">
          <h3>Risk zones for manual inspection</h3>
          ${zones.length ? zones.map(renderRiskZone).join("") : `<div class="empty-state">No reported risk zone reached the configured reporting threshold.</div>`}
        </div>
      `;
    }

    function verdictClassName(report) {
      const raw = report?.reading_class || report?.verdict_class || "insufficient";
      return `verdict-${raw}`;
    }

    function aggregateLowLevelQuality(report) {
      if (!report || !Array.isArray(report.metrics)) return null;
      if (!["c", "cpp", "csharp"].includes(report.language)) return null;
      const names = new Set(["register_pressure", "stack_frame_depth", "redundant_memory_access"]);
      const items = report.metrics.filter(item => names.has(item.name) && item.applicable);
      if (!items.length) {
        return { percent: null, text: "N/A" };
      }
      const percent = items.reduce((sum, item) => sum + Number(item.score_percent ?? 0), 0) / items.length;
      return { percent, text: `${percent.toFixed(1)}%` };
    }

    function renderSummary(report) {
      const isProject = report?.mode === "project" || report?.report_kind === "project";
      const project = isProject ? (report.project || {}) : {};
      const overallApplicable = report && report.overall_applicable !== false;
      const percent = Number(report?.overall_percent ?? 0);
      els.scoreValue.textContent = overallApplicable ? `${percent.toFixed(1)}%` : "N/A";
      setProgressBar(els.scoreProgress, els.scoreBar, overallApplicable ? percent : null, "Not applicable");
      els.verdictValue.textContent = report.reading || report.verdict || "—";
      els.verdictValue.className = `value ${verdictClassName(report)}`;
      els.confidenceValue.textContent = report.confidence || "—";
      els.summaryLanguage.textContent = isProject
        ? `Project (${Number(project.included_file_count || 0)} files)`
        : (LANGUAGE_LABELS[report.language] || report.language || "—");
      const calibrationLabel = report.calibration_profile_id || report.calibration_profile_name || report.calibration_profile_label || "default calibration";
      els.summaryProfile.textContent = `${report.profile || els.profileSelect.value} · ${calibrationLabel}`;
      renderList(els.notesList, report.notes, "The report contains no notes.");
      renderList(els.warningsList, report.warnings, "No warnings.");
      if (isProject) {
        els.contextText.textContent =
          `Project: ${report.filename || "project"} · candidates ${Number(project.candidate_file_count || 0)} · included ${Number(project.included_file_count || 0)} · contributing ${Number(project.contributing_file_count || 0)} · excluded ${Number(project.excluded_file_count || 0)} · SLOC ${Number(project.total_sloc ?? report.sloc ?? 0)}`;
      } else {
        els.contextText.textContent =
          `File: ${report.filename} · LOC ${report.loc} · SLOC ${report.sloc} · metrics ${report.metrics.filter(item => item.applicable).length}/${report.metrics.length}`;
      }

      const lowLevel = isProject ? null : aggregateLowLevelQuality(report);
      if (lowLevel) {
        els.lowLevelQualityCard.classList.remove("hidden");
        els.lowLevelQualityValue.textContent = lowLevel.text;
        setProgressBar(els.lowLevelQualityProgress, els.lowLevelQualityBar, lowLevel.percent, "Not applicable");
      } else {
        els.lowLevelQualityCard.classList.add("hidden");
        els.lowLevelQualityValue.textContent = "—";
        setProgressBar(els.lowLevelQualityProgress, els.lowLevelQualityBar, null);
      }
    }

    function populateProjectFiles(files, excludedFiles = []) {
      if ((!Array.isArray(files) || files.length === 0) && (!Array.isArray(excludedFiles) || excludedFiles.length === 0)) {
        els.metricsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No project files were analysed.</td></tr>`;
        els.metricDetail.innerHTML = "Project mode found no analysable authored source files.";
        return;
      }
      const analysedRows = (files || []).map((item, index) => `
          <tr data-project-index="${index}">
            <td>${escapeHtml(item.filename || item.path || "file")}</td>
            <td>${escapeHtml(LANGUAGE_LABELS[item.language] || item.language || "unknown")} · SLOC ${Number(item.sloc || 0)}</td>
            <td>${item.overall_applicable === false ? "N/A" : `${Number(item.overall_percent ?? 0).toFixed(1)}%`}</td>
            <td>${Number(item.weight_sloc || Math.min(Number(item.sloc || 0), 500)).toFixed(0)}</td>
            <td class="${item.overall_applicable === false ? "state-na" : "state-ok"}">${escapeHtml(item.verdict_class || "included")}</td>
          </tr>
        `);
      const excludedRows = (excludedFiles || []).slice(0, 120).map((item, index) => `
          <tr data-excluded-index="${index}">
            <td>${escapeHtml(item.path || "file")}</td>
            <td>${escapeHtml(item.reason || "excluded")}</td>
            <td>N/A</td>
            <td>0</td>
            <td class="state-na">excluded</td>
          </tr>
        `);
      els.metricsBody.innerHTML = analysedRows.concat(excludedRows).join("");
      if (files && files.length) {
        selectProjectFileByIndex(0);
      } else {
        els.metricDetail.innerHTML = "Only excluded project files are available in this report. Check the text or JSON report for the full exclusion list.";
      }
    }

    function selectProjectFileByIndex(index) {
      const report = appState.currentProjectReport || appState.currentReport;
      if (!report || !(report.mode === "project" || report.report_kind === "project")) return;
      const files = report.project?.included_files || [];
      const item = files[index];
      if (!item) return;
      Array.from(els.metricsBody.querySelectorAll("tr")).forEach((row) => {
        row.classList.toggle("selected", row.dataset.projectIndex === String(index));
      });
      const warningList = item.warnings && item.warnings.length
        ? `<h3 class="mt-xl">Warnings</h3><ul class="warning-list">${item.warnings.map(value => `<li>${escapeHtml(value)}</li>`).join("")}</ul>`
        : "";
      els.metricDetail.innerHTML = `
        <div><strong>${escapeHtml(item.filename || item.path || "file")}</strong></div>
        <div class="mt-sm">Language: ${escapeHtml(LANGUAGE_LABELS[item.language] || item.language || "unknown")}</div>
        <div>LOC: ${Number(item.loc || 0)} · SLOC: ${Number(item.sloc || 0)} · weighting SLOC: ${Number(item.weight_sloc || Math.min(Number(item.sloc || 0), 500))}</div>
        <div>Score: ${item.overall_applicable === false ? "N/A" : `${Number(item.overall_percent ?? 0).toFixed(1)}%`}</div>
        <div>Reading: ${escapeHtml(item.reading || item.verdict || "—")}</div>
        <div class="mt-xl">This file is included in the project aggregate unless its score is not applicable.</div>
        ${warningList}
      `;
    }

    function selectExcludedFileByIndex(index) {
      const report = appState.currentProjectReport || appState.currentReport;
      if (!report || !(report.mode === "project" || report.report_kind === "project")) return;
      const item = (report.project?.excluded_files || [])[index];
      if (!item) return;
      Array.from(els.metricsBody.querySelectorAll("tr")).forEach((row) => {
        row.classList.toggle("selected", row.dataset.excludedIndex === String(index));
      });
      els.metricDetail.innerHTML = `
        <div><strong>${escapeHtml(item.path || "file")}</strong></div>
        <div class="mt-sm">Excluded from project aggregate.</div>
        <div>Reason: ${escapeHtml(item.reason || "not specified")}</div>
        ${item.detail ? `<div class="mt-md">${escapeHtml(item.detail)}</div>` : ""}
      `;
    }

    function metricStateLabel(metric) {
      return metric.applicable ? "Applicable" : "N/A";
    }

    function populateMetrics(metrics) {
      if (!Array.isArray(metrics) || metrics.length === 0) {
        els.metricsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No metrics are available.</td></tr>`;
        els.metricDetail.innerHTML = "Select a metric for an explanation, details and references.";
        return;
      }
      els.metricsBody.innerHTML = metrics.map((metric, index) => {
        const stateClass = metric.applicable ? "state-ok" : "state-na";
        const suffixMap = { quality: " · quality", context: " · context", documentation: " · documentation" };
        const suffix = suffixMap[metric.group] || "";
        return `
          <tr data-metric-index="${index}">
            <td>${escapeHtml(metric.display_name)}${suffix ? `<span class="help-inline">${escapeHtml(suffix)}</span>` : ""}</td>
            <td>${escapeHtml(metric.value_display ?? "N/A")}</td>
            <td>${Number(metric.score_percent ?? 0).toFixed(1)}%</td>
            <td>${Number(metric.weight ?? 0).toFixed(2)}</td>
            <td class="${stateClass}">${metricStateLabel(metric)}</td>
          </tr>
        `;
      }).join("");
      selectMetricByIndex(0);
    }

    function selectMetricByIndex(index) {
      if (!appState.currentReport || !Array.isArray(appState.currentReport.metrics)) return;
      const metrics = appState.currentReport.metrics;
      if (!metrics[index]) return;
      Array.from(els.metricsBody.querySelectorAll("tr")).forEach((row, rowIndex) => {
        row.classList.toggle("selected", rowIndex === index);
      });
      const metric = metrics[index];
      const refs = metric.references && metric.references.length
        ? `<h3 class="mt-xl">References</h3><ul class="ref-list">${metric.references.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
        : "";
      const group = metric.group ? `<div>Group: ${escapeHtml(metric.group)}</div>` : "";
      els.metricDetail.innerHTML = `
        <div><strong>${escapeHtml(metric.display_name)}</strong></div>
        <div class="mt-sm">Value: ${escapeHtml(metric.value_display ?? "N/A")}</div>
        <div>Score: ${Number(metric.score_percent ?? 0).toFixed(1)}%</div>
        <div>Weight: ${Number(metric.weight ?? 0).toFixed(2)}</div>
        <div>Applicable: ${metric.applicable ? "yes" : "no"}</div>
        ${group}
        <div class="mt-xl">${escapeHtml(metric.explanation || "")}</div>
        ${metric.detail ? `<div class="mt-lg">${escapeHtml(metric.detail)}</div>` : ""}
        ${refs}
      `;
    }

    function activateTab(tabId, { focusTab = false } = {}) {
      const requested = els.tabButtons.find(button => button.dataset.tab === tabId);
      if (!requested) return;
      els.tabButtons.forEach(button => {
        const selected = button === requested;
        button.classList.toggle("active", selected);
        button.setAttribute("aria-selected", selected ? "true" : "false");
        button.tabIndex = selected ? 0 : -1;
      });
      els.tabPanels.forEach(panel => {
        const selected = panel.id === tabId;
        panel.classList.toggle("active", selected);
        panel.hidden = !selected;
      });
      if (focusTab) requested.focus();
    }

    function handleTabKeydown(event) {
      const currentIndex = els.tabButtons.indexOf(event.currentTarget);
      if (currentIndex < 0) return;
      let nextIndex = null;
      if (event.key === "ArrowRight") nextIndex = (currentIndex + 1) % els.tabButtons.length;
      else if (event.key === "ArrowLeft") nextIndex = (currentIndex - 1 + els.tabButtons.length) % els.tabButtons.length;
      else if (event.key === "Home") nextIndex = 0;
      else if (event.key === "End") nextIndex = els.tabButtons.length - 1;
      if (nextIndex === null) return;
      event.preventDefault();
      activateTab(els.tabButtons[nextIndex].dataset.tab, { focusTab: true });
    }

    function downloadBlob(filename, content, contentType) {
      const blob = new Blob([content], { type: contentType });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    }

    function markReportStale(isStale) {
      appState.reportStale = Boolean(isStale);
      els.staleMeta.textContent = isStale
        ? "The editor or project input has changed since the last analysis."
        : (appState.currentReport ? "The report matches the current input." : "No report has been generated yet.");
    }

    function updateEditorMeta() {
      if (appState.analysisMode === "project" && appState.projectPayload) {
        const project = appState.projectPayload;
        const itemCount = project.zip_base64 ? 1 : (project.files || []).length;
        els.fileMeta.textContent = `Project: ${project.project_name || "project"}`;
        els.lineMeta.textContent = project.zip_base64 ? "Input: ZIP archive" : `Input files: ${itemCount}`;
        els.langMeta.textContent = "Detected language: Project mode";
        appState.detectedLanguage = "project";
        return;
      }
      const code = els.editor.value;
      const lineCount = code.length === 0 ? 0 : code.split("\n").length;
      const lang = detectLanguage(appState.currentFileName, code, els.languageSelect.value === "auto" ? null : els.languageSelect.value);
      appState.detectedLanguage = lang;
      els.fileMeta.textContent = `File: ${appState.currentFileName}`;
      els.lineMeta.textContent = `Lines: ${lineCount}`;
      els.langMeta.textContent = `Detected language: ${LANGUAGE_LABELS[lang] || lang}`;
    }

    function looksBinary(bytes) {
      if (!bytes || bytes.length === 0) return false;
      let suspicious = 0;
      let printable = 0;
      for (let index = 0; index < bytes.length; index += 1) {
        const value = bytes[index];
        if (value === 0) return true;
        if (value === 9 || value === 10 || value === 13 || (value >= 32 && value <= 126)) {
          printable += 1;
        } else if (value < 7 || (value > 14 && value < 32)) {
          suspicious += 1;
        }
      }
      return suspicious > bytes.length * 0.2 && printable < bytes.length * 0.8;
    }

    async function decodeFile(file) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (looksBinary(bytes)) {
        throw new Error("The file appears to be binary rather than source text.");
      }
      if (!window.CodeProbeRuntime?.decodeSourceBytes) {
        throw new Error("The shared source-decoding boundary is unavailable.");
      }
      const decoded = window.CodeProbeRuntime.decodeSourceBytes(bytes);
      return { text: decoded.text, warnings: decoded.warning ? [decoded.warning] : [] };
    }

    function assertPlainObject(value, label) {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`${label} must be a JSON object.`);
      }
    }

    function validateConfigOverrideObject(parsed) {
      assertPlainObject(parsed, "The override");
      for (const [metricName, metricConfig] of Object.entries(parsed)) {
        assertPlainObject(metricConfig, `Override for ${metricName}`);
        for (const [key, value] of Object.entries(metricConfig)) {
          if (!ALLOWED_CONFIG_KEYS.has(key)) {
            throw new Error(`Unsupported override key for ${metricName}: ${key}`);
          }
          if (key === "enabled" || key === "contributes_to_overall") {
            if (typeof value !== "boolean") {
              throw new Error(`${key} for ${metricName} must be true or false.`);
            }
            if (key === "contributes_to_overall" && value && NON_AUTHORSHIP_METRICS.has(metricName)) {
              throw new Error(`${metricName} is quality/context/documentation-only and cannot be re-enabled in the AI-style aggregate from the browser.`);
            }
          } else if (key === "weight") {
            if (typeof value !== "number" || !Number.isFinite(value)) {
              throw new Error(`weight for ${metricName} must be a finite number.`);
            }
            if (value < 0 || value > 1) {
              throw new Error(`weight for ${metricName} must be between 0 and 1.`);
            }
          } else if (key === "group") {
            if (typeof value !== "string" || !ALLOWED_METRIC_GROUPS.has(value)) {
              throw new Error(`group for ${metricName} must be one of: stylometry, context, quality, documentation.`);
            }
          } else if (key === "thresholds") {
            assertPlainObject(value, `thresholds for ${metricName}`);
            for (const [thresholdName, thresholdValue] of Object.entries(value)) {
              if (typeof thresholdValue !== "number" || !Number.isFinite(thresholdValue)) {
                throw new Error(`threshold ${thresholdName} for ${metricName} must be a finite number.`);
              }
            }
          } else if (key === "notes" && typeof value !== "string") {
            throw new Error(`notes for ${metricName} must be a string.`);
          }
        }
      }
      return parsed;
    }

    function getCalibrationProfileObject() {
      const raw = els.calibrationProfile.value.trim();
      if (!raw) return null;
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch (error) {
        throw new Error(`Calibration profile JSON is invalid: ${error.message}`);
      }
      assertPlainObject(parsed, "The calibration profile");
      return parsed;
    }

    function arrayBufferToBase64(buffer) {
      const bytes = new Uint8Array(buffer);
      const chunkSize = 0x8000;
      let binary = "";
      for (let index = 0; index < bytes.length; index += chunkSize) {
        const chunk = bytes.subarray(index, index + chunkSize);
        binary += String.fromCharCode.apply(null, chunk);
      }
      return btoa(binary);
    }

    function projectNameFromFiles(files) {
      const first = files[0];
      if (!first) return "project";
      const relative = first.webkitRelativePath || first.name || "project";
      const parts = String(relative).split("/").filter(Boolean);
      return parts.length > 1 ? parts[0] : "selected-files";
    }

    function setProjectEditorPreview(projectPayload) {
      const lines = [
        "# CodeProbe project mode loaded",
        `# Project: ${projectPayload.project_name || "project"}`,
        projectPayload.zip_base64
          ? `# ZIP archive: ${projectPayload.zip_filename || "archive.zip"}`
          : `# Browser-selected files: ${(projectPayload.files || []).length}`,
        "# Run Analyse to process authored source files, apply .codeprobeignore and aggregate the result.",
        "# Documentation, generated files, dependency folders and minified/binary assets are excluded by default.",
        "# This preview is not the analysed source; it is only a local project-mode summary."
      ];
      if (projectPayload.files && projectPayload.files.length) {
        lines.push("# Preview of selected paths:");
        projectPayload.files.slice(0, 60).forEach(item => lines.push(`# - ${item.path}`));
        if (projectPayload.files.length > 60) {
          lines.push(`# - ... ${projectPayload.files.length - 60} further files`);
        }
      }
      els.editor.value = lines.join("\n") + "\n";
    }

    function invalidateInputState() {
      if (appState.busy) cancelAnalysis();
      else { appState.generation += 1; clearReport(); }
      appState.loadingInput = false;
      els.analyzeBtn.disabled = appState.engineFailed;
      els.cancelBtn.disabled = true;
    }

    function beginInputRead() {
      invalidateInputState();
      appState.loadingInput = true;
      appState.projectPayload = null;
      appState.currentFileName = "";
      appState.fileWarnings = [];
      appState.analysisMode = "single";
      els.editor.value = "";
      els.editor.readOnly = false;
      els.analyzeBtn.disabled = true;
      els.cancelBtn.disabled = false;
      updateEditorMeta(); scheduleHighlight();
      return appState.generation;
    }

    function finishInputRead(generation) {
      if (generation !== appState.generation) return;
      appState.loadingInput = false;
      els.analyzeBtn.disabled = appState.busy || appState.engineFailed;
      els.cancelBtn.disabled = !appState.busy;
    }

    function rejectedInput(file, path, reason) {
      const size = Number.isSafeInteger(file.size) && file.size >= 0 ? file.size : 0;
      return { path: String(path).slice(0, 4096), size_bytes: size, intake_rejection: { reason } };
    }

    async function handleProjectZip(file) {
      if (!file) return;
      const generation = beginInputRead();
      try {
        if ((file.size || 0) > MAX_BROWSER_PROJECT_ZIP_BYTES) throw new Error(`Project ZIP exceeds the ${MAX_BROWSER_PROJECT_ZIP_BYTES} byte browser limit.`);
        const buffer = await file.arrayBuffer();
        if (generation !== appState.generation) return;
        if (buffer.byteLength > MAX_BROWSER_PROJECT_ZIP_BYTES) throw new Error("Project ZIP exceeds the browser byte limit.");
        appState.analysisMode = "project";
        appState.projectPayload = {
          project_name: String(file.name || "zip-project").replace(/\.zip$/i, "") || "zip-project",
          zip_filename: file.name || "archive.zip", zip_base64: arrayBufferToBase64(buffer),
          max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES, max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES,
          max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES, max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES
        };
        appState.currentFileName = appState.projectPayload.project_name;
        setProjectEditorPreview(appState.projectPayload);
        updateEditorMeta(); scheduleHighlight(); syncEditorScroll();
        setStatus(`Project ZIP loaded: ${file.name}.`);
      } catch (error) {
        if (generation === appState.generation) setStatus(error.message);
      } finally { finishInputRead(generation); }
    }

    function projectTextCandidate(path) {
      const lower = String(path || "").toLowerCase();
      if (lower.endsWith(".codeprobeignore")) return true;
      return /\.(py|pyw|js|mjs|cjs|jsx|ts|tsx|sh|bash|zsh|ksh|c|h|cpp|cxx|cc|hpp|hxx|hh|cs|md|markdown|txt|json|toml|yaml|yml|xml|html|css)$/i.test(lower);
    }

    async function handleProjectFiles(fileList) {
      const files = Array.from(fileList || []);
      if (!files.length) return;
      if (files.length === 1 && /\.zip$/i.test(files[0].name || "")) return handleProjectZip(files[0]);
      const generation = beginInputRead();
      try {
        if (files.length > MAX_BROWSER_PROJECT_ENTRIES) throw new Error(`Project selection exceeds the ${MAX_BROWSER_PROJECT_ENTRIES} entry browser limit.`);
        const payloadFiles = [], warnings = [];
        let acceptedBytes = 0;
        for (const file of files) {
          if (generation !== appState.generation) return;
          const rawPath = file._codeprobeRelativePath || file.webkitRelativePath || file.name || "file";
          let path;
          try { path = window.CodeProbeRuntime.normaliseProjectPath(rawPath); }
          catch (_) { payloadFiles.push(rejectedInput(file, rawPath, "unsafe_path")); continue; }
          let reason = !projectTextCandidate(path) ? "unsupported_file_type" : "";
          if ((file.size || 0) > MAX_BROWSER_PROJECT_TEXT_BYTES) reason = "file_too_large";
          if (!reason && acceptedBytes + (file.size || 0) > MAX_BROWSER_PROJECT_TOTAL_BYTES) reason = "project_total_byte_limit";
          if (reason) { payloadFiles.push(rejectedInput(file, path, reason)); continue; }
          try {
            const decoded = await decodeFile(file);
            if (generation !== appState.generation) return;
            const bytes = new TextEncoder().encode(decoded.text).length;
            if (bytes > MAX_BROWSER_PROJECT_TEXT_BYTES) { payloadFiles.push(rejectedInput(file, path, "file_too_large")); continue; }
            if (acceptedBytes + bytes > MAX_BROWSER_PROJECT_TOTAL_BYTES) { payloadFiles.push(rejectedInput(file, path, "project_total_byte_limit")); continue; }
            acceptedBytes += bytes;
            payloadFiles.push({ path, content: decoded.text, size_bytes: bytes });
            if (decoded.warnings?.length) warnings.push(`${path}: ${decoded.warnings.join("; ")}`);
          } catch (_) {
            if (generation !== appState.generation) return;
            payloadFiles.push(rejectedInput(file, path, "unreadable_file"));
          }
        }
        if (generation !== appState.generation) return;
        const projectName = projectNameFromFiles(files);
        appState.analysisMode = "project";
        appState.projectPayload = { project_name: projectName, files: payloadFiles,
          max_zip_entries: MAX_BROWSER_PROJECT_ENTRIES, max_file_bytes: MAX_BROWSER_PROJECT_TEXT_BYTES,
          max_total_bytes: MAX_BROWSER_PROJECT_TOTAL_BYTES, max_zip_bytes: MAX_BROWSER_PROJECT_ZIP_BYTES };
        appState.currentFileName = projectName;
        appState.fileWarnings = warnings;
        setProjectEditorPreview(appState.projectPayload);
        updateEditorMeta(); scheduleHighlight(); syncEditorScroll();
        const rejected = payloadFiles.filter(item => item.intake_rejection).length;
        setStatus(`Project files loaded: ${payloadFiles.length - rejected}; ${rejected} intake exclusions retained.`);
      } catch (error) {
        if (generation === appState.generation) setStatus(error.message);
      } finally { finishInputRead(generation); }
    }

    function getConfigOverrideObject() {
      const raw = els.configOverride.value.trim();
      if (!raw) return null;
      try {
        const parsed = JSON.parse(raw);
        return validateConfigOverrideObject(parsed);
      } catch (error) {
        throw new Error(`Invalid configuration override: ${error.message}`);
      }
    }

    function isHistoryEnabled() {
      return els.historyEnabled && els.historyEnabled.checked;
    }

    function saveHistory(report, textReport, jsonReport) {
      if (!isHistoryEnabled()) {
        renderHistory();
        return;
      }
      const isProject = report?.mode === "project" || report?.report_kind === "project";
      const entry = {
        timestamp: new Date().toISOString(),
        filename: report.filename || (isProject ? "project" : "report"),
        language: isProject ? "project" : report.language,
        overall_percent: report.overall_percent,
        verdict: report.verdict,
        verdict_class: report.verdict_class,
        reading: report.reading || report.verdict,
        reading_class: report.reading_class || report.verdict_class,
        confidence: report.confidence,
        profile: report.profile,
        overall_applicable: report.overall_applicable,
        is_project: isProject,
        textReport,
        jsonReport
      };
      let items = [];
      try {
        items = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      } catch (error) {
        items = [];
      }
      items.unshift(entry);
      items = items.slice(0, 12);
      while (items.length) {
        try {
          localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
          break;
        } catch (error) {
          items.pop();
        }
      }
      renderHistory();
    }

    function loadHistory() {
      try {
        const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
        return Array.isArray(parsed) ? parsed : [];
      } catch (error) {
        return [];
      }
    }

    function renderHistory() {
      if (!isHistoryEnabled()) {
        els.historyList.innerHTML = `<div class="empty-state">Local history is disabled.</div>`;
        return;
      }
      const items = loadHistory();
      if (!items.length) {
        els.historyList.innerHTML = `<div class="empty-state">History is empty.</div>`;
        return;
      }
      els.historyList.innerHTML = items.map((item, index) => `
        <article class="history-item">
          <div class="top">
            <strong>${escapeHtml(item.filename || "untitled")}</strong>
            <span class="badge info">${escapeHtml(item.profile || "default")}</span>
          </div>
          <div class="meta">
            ${escapeHtml(formatDateTime(item.timestamp))} · ${escapeHtml(LANGUAGE_LABELS[item.language] || item.language || "Unknown")}
            · score ${item.overall_applicable === false ? "N/A" : `${Number(item.overall_percent ?? 0).toFixed(1)}%`}
          </div>
          <div>${escapeHtml(item.reading || item.verdict || "—")}</div>
          <div class="history-actions">
            <button type="button" class="ghost" data-history-index="${index}" data-history-action="load">Load in panel</button>
            <button type="button" class="ghost" data-history-index="${index}" data-history-action="json">Download JSON</button>
            <button type="button" class="ghost" data-history-index="${index}" data-history-action="text">Download text</button>
          </div>
        </article>
      `).join("");
    }

    function loadHistoryEntry(index) {
      const items = loadHistory();
      const item = items[index];
      if (!item) return;
      invalidateInputState();
      try {
        const parsed = JSON.parse(item.jsonReport);
        renderReport({ report: parsed, text: item.textReport }, false);
        activateTab("tab-summary");
        setStatus("A report was loaded from local history.");
      } catch (error) {
        setStatus("Local history is corrupted.");
      }
    }

    function cancelAnalysis() {
      appState.loadingInput = false;
      appState.generation += 1;
      appState.workerSession?.cancel();
      appState.engineReady = false;
      appState.engineFailed = false;
      appState.enginePromise = null;
      appState.engineFingerprint = null;
      clearReport();
      setEngineBadge("warn", "Worker stopped");
      setBusy(false, "Analysis cancelled; the worker was terminated.");
    }

    async function initEngine() {
      if (appState.workerSession?.isReady()) return;
      if (appState.enginePromise) return appState.enginePromise;
      const generation = appState.generation;
      appState.enginePromise = (async () => {
        setBusy(true, "Loading the in-browser Python engine…");
        setEngineBadge("warn", "Engine initialising");
        showEngineLoader(false);
        if (!window.CodeProbeRuntime?.createAnalysisSession) throw new Error("The isolated analysis worker is unavailable.");
        if (!appState.workerSession) appState.workerSession = window.CodeProbeRuntime.createAnalysisSession();
        const manual = appState.localEngineFile ? { bytes: (await getEngineBundle()).copyBytes() } : null;
        if (generation !== appState.generation) return;
        const metadata = await appState.workerSession.initialise(manual);
        if (generation !== appState.generation) return;
        appState.engineFingerprint = metadata.fingerprint;
        appState.engineSourceMode = metadata.fingerprint.source;
        appState.engineReady = true;
        appState.engineFailed = false;
        setEngineBadge("ready", "Engine ready");
        setBusy(false, "The analysis engine is ready.");
        els.contextText.textContent = appState.engineSourceMode === "manual-unverified"
          ? "Unverified local engine override is active. Do not treat its reports as packaged CodeProbe evidence."
          : "The packaged Python engine passed its SHA-256 check before import in an isolated worker.";
        showEngineLoader(false);
      })().catch(error => {
        if (generation !== appState.generation) return;
        appState.engineReady = false;
        appState.engineFailed = error.name !== "AbortError" && error.name !== "TimeoutError";
        setEngineBadge("error", "Initialisation failed");
        showEngineLoader(true);
        setBusy(false, error.name === "TimeoutError" ? error.message : "The in-browser Python engine could not be loaded.");
        els.contextText.textContent = "Check the runtime configuration, verified Pyodide source and packaged engine integrity record.";
        appState.enginePromise = null;
        throw error;
      });
      return appState.enginePromise;
    }

    async function analyzeNow() {
      if (appState.busy || appState.loadingInput) return;
      const generation = appState.generation;
      const isProject = appState.analysisMode === "project";
      const code = els.editor.value;
      if (!isProject && (code.length > MAX_BROWSER_PROJECT_TEXT_BYTES || new TextEncoder().encode(code).length > MAX_BROWSER_PROJECT_TEXT_BYTES)) {
        setStatus("Single-file analysis is limited to 1 MB of UTF-8 text in the browser.");
        return;
      }
      if (!isProject && !code.trim()) {
        setStatus("The editor is empty.");
        return;
      }
      if (isProject && !appState.projectPayload) {
        setStatus("No project payload is loaded.");
        return;
      }
      try {
        await initEngine();
      } catch (error) {
        return;
      }

      if (generation !== appState.generation || !appState.workerSession?.isReady()) return;
      let override = null;
      let calibrationProfile = null;
      try {
        override = getConfigOverrideObject();
        calibrationProfile = getCalibrationProfileObject();
      } catch (error) {
        setStatus(error.message);
        activateTab("tab-summary");
        return;
      }

      clearReport();
      setBusy(true, isProject ? "Project analysis running…" : "Analysis running…");
      await new Promise(resolve => requestAnimationFrame(resolve));

      try {
        const selectedLanguage = els.languageSelect.value;
        const engineFingerprint = await getEngineFingerprint();
        let payload;

        if (isProject) {
          payload = {
            ...appState.projectPayload,
            profile: els.profileSelect.value,
            config_override: override,
            calibration_profile: calibrationProfile,
            include_documentation: false,
            engine_fingerprint: engineFingerprint
          };

        } else {
          const fallbackLanguage = selectedLanguage === "auto" ? appState.detectedLanguage : selectedLanguage;
          const filename = appState.currentFileName || defaultFileNameForLanguage(fallbackLanguage);
          payload = {
            code,
            filename,
            language_hint: selectedLanguage === "auto" ? null : selectedLanguage,
            profile: els.profileSelect.value,
            config_override: override,
            calibration_profile: calibrationProfile,
            engine_fingerprint: engineFingerprint
          };

        }
        if (generation !== appState.generation) return;
        const parsed = await appState.workerSession.analyse(isProject ? "project" : "file", payload);
        if (generation !== appState.generation) return;
        renderReport(parsed, true);
        setBusy(false, isProject ? "Project analysis completed." : "Analysis completed.");
      } catch (error) {
        if (generation !== appState.generation) return;
        appState.engineReady = appState.workerSession.isReady();
        appState.enginePromise = null;
        setBusy(false, error.name === "TimeoutError" || error.name === "AbortError" ? error.message : "Analysis failed; no report was accepted.");
        els.contextText.textContent = "Retry starts a fresh worker after cancellation, timeout or worker failure.";
      }
    }

    function renderReport(bundle, persistHistory = true) {
      const report = bundle.report;
      const isProject = report?.mode === "project" || report?.report_kind === "project";
      appState.currentReport = report;
      appState.currentProjectReport = isProject ? report : null;
      appState.currentFileName = report.filename || appState.currentFileName;
      appState.currentTextReport = bundle.text;
      appState.currentJsonReport = JSON.stringify(report, null, 2);
      els.textReport.value = bundle.text;
      els.jsonReport.value = appState.currentJsonReport;
      renderSummary(report);
      renderManualReview(report);
      if (isProject) {
        const project = report.project || {};
        populateProjectFiles(project.included_files || [], project.excluded_files || []);
      } else {
        populateMetrics(report.metrics || []);
      }
      els.exportJsonBtn.disabled = false;
      els.exportTextBtn.disabled = false;
      markReportStale(false);
      if (persistHistory) {
        saveHistory(report, bundle.text, appState.currentJsonReport);
      }
      activateTab("tab-summary");
      updateEditorMeta();
    }

    function clearReport() {
      appState.currentReport = null;
      appState.currentProjectReport = null;
      appState.currentTextReport = "";
      appState.currentJsonReport = "";
      els.exportJsonBtn.disabled = true;
      els.exportTextBtn.disabled = true;
      els.scoreValue.textContent = "—";
      setProgressBar(els.scoreProgress, els.scoreBar, null);
      els.verdictValue.textContent = "Insufficient data";
      els.verdictValue.className = "value verdict-insufficient";
      els.confidenceValue.textContent = "—";
      els.summaryLanguage.textContent = "—";
      els.summaryProfile.textContent = els.profileSelect.value;
      els.lowLevelQualityCard.classList.add("hidden");
      els.lowLevelQualityValue.textContent = "—";
      setProgressBar(els.lowLevelQualityProgress, els.lowLevelQualityBar, null);
      renderList(els.notesList, [], "The report will appear here after the first analysis.");
      renderList(els.warningsList, [], "No warnings.");
      els.textReport.value = "The text report will appear here.";
      els.jsonReport.value = "{}";
      els.metricsBody.innerHTML = `<tr><td colspan="5" class="empty-state">No metrics yet.</td></tr>`;
      els.metricDetail.innerHTML = "Select a metric for an explanation, details and references.";
      if (els.manualReviewPanel) {
        els.manualReviewPanel.innerHTML = `<div class="empty-state">Manual-review guidance will appear after analysis. The guidance is a defensible triage plan, not a misconduct finding.</div>`;
      }
      els.contextText.textContent = "No current report.";
      markReportStale(false);
    }

    async function handleFile(file) {
      if (!file) return;
      const generation = beginInputRead();
      try {
        if (file.size > MAX_BROWSER_PROJECT_TEXT_BYTES) throw new Error("Single-file loading is limited to 1 MB in the browser.");
        const decoded = await decodeFile(file);
        if (generation !== appState.generation) return;
        if (new TextEncoder().encode(decoded.text).length > MAX_BROWSER_PROJECT_TEXT_BYTES) throw new Error("Decoded source exceeds the 1 MB browser limit.");
        appState.analysisMode = "single";
        appState.projectPayload = null;
        appState.currentFileName = file.name || "fragment.txt";
        appState.fileWarnings = decoded.warnings || [];
        els.editor.value = decoded.text;
        updateEditorMeta(); scheduleHighlight(); syncEditorScroll();
        const warningText = appState.fileWarnings.length ? ` (${appState.fileWarnings.join("; ")})` : "";
        setStatus(`File loaded: ${appState.currentFileName}${warningText}`);
      } catch (error) {
        if (generation === appState.generation) setStatus(error.message);
      } finally { finishInputRead(generation); }
    }

    function reportBaseName(report) {
      const raw = report?.project_name || report?.filename || "report";
      return String(raw).replace(/\.zip$/i, "").replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9._-]+/g, "_") || "report";
    }

    function clearPyodidePayloadReference() {
      cancelAnalysis();
      appState.localEngineFile = null;
      appState.engineBundle = null;
      appState.engineSourceMode = null;
    }

    function clearPrivacyData() {
      localStorage.removeItem(HISTORY_KEY);
      localStorage.removeItem(HISTORY_ENABLED_KEY);
      if (els.historyEnabled) {
        els.historyEnabled.checked = false;
      }
      clearPyodidePayloadReference();
      appState.analysisMode = "single";
      appState.projectPayload = null;
      appState.currentProjectReport = null;
      appState.fileWarnings = [];
      appState.currentFileName = defaultFileNameForLanguage(els.languageSelect.value === "auto" ? "python" : els.languageSelect.value);
      els.editor.value = "";
      els.configOverride.value = "";
      els.calibrationProfile.value = "";
      clearReport();
      renderHistory();
      updateEditorMeta();
      scheduleHighlight();
      syncEditorScroll();
      setStatus("Privacy data cleared from this browser session and local storage.");
    }

    function handleHistoryClick(event) {
      const button = event.target.closest("button[data-history-index]");
      if (!button) return;
      const index = Number(button.dataset.historyIndex);
      const action = button.dataset.historyAction;
      const items = loadHistory();
      const item = items[index];
      if (!item) return;
      if (action === "load") {
        loadHistoryEntry(index);
        return;
      }
      if (action === "json") {
        downloadBlob((item.filename || "report") + ".json", item.jsonReport || "{}", "application/json;charset=utf-8");
        return;
      }
      if (action === "text") {
        downloadBlob((item.filename || "report") + ".txt", item.textReport || "", "text/plain;charset=utf-8");
      }
    }

    function isZipLikeFile(file) {
      return Boolean(file && /\.zip$/i.test(file.name || ""));
    }

    function annotateDroppedFile(file, relativePath) {
      if (relativePath) {
        try {
          Object.defineProperty(file, "_codeprobeRelativePath", { value: relativePath.replace(/\\/g, "/"), configurable: true });
        } catch (error) {
          file._codeprobeRelativePath = relativePath.replace(/\\/g, "/");
        }
      }
      return file;
    }

    async function collectDroppedFiles(dataTransfer) {
      return window.CodeProbeRuntime.collectDroppedFiles(dataTransfer);
    }
    function hasFileDrag(event) {
      return Array.from(event.dataTransfer?.types || []).includes("Files");
    }

    function showDropOverlay(show) {
      if (!els.globalDropOverlay) return;
      els.globalDropOverlay.classList.toggle("hidden", !show);
      els.globalDropOverlay.setAttribute("aria-hidden", show ? "false" : "true");
    }

    async function handleDropDataTransfer(dataTransfer) {
      if (appState.busy) { setStatus("Cancel the current operation before loading another input."); return; }
      const generation = beginInputRead();
      let droppedFiles;
      try { droppedFiles = await collectDroppedFiles(dataTransfer); }
      catch (error) { if (generation === appState.generation) setStatus(error.message); return; }
      finally { finishInputRead(generation); }
      if (generation !== appState.generation) return;
      if (!droppedFiles.length) {
        setStatus("No readable files were dropped.");
        return;
      }
      if (droppedFiles.length > MAX_BROWSER_DROP_FILES) {
        setStatus(`Too many files were dropped (${droppedFiles.length}). Use tools/analyze_project.py for very large projects.`);
        return;
      }
      if (droppedFiles.length === 1 && isZipLikeFile(droppedFiles[0])) {
        await handleProjectZip(droppedFiles[0]);
      } else if (droppedFiles.length > 1 || droppedFiles.some(file => file._codeprobeRelativePath || file.webkitRelativePath)) {
        await handleProjectFiles(droppedFiles);
      } else {
        await handleFile(droppedFiles[0]);
      }
    }

    els.openBtn.addEventListener("click", () => {
      els.fileInput.click();
    });

    els.openProjectZipBtn.addEventListener("click", () => {
      els.projectZipInput.click();
    });

    els.openFolderBtn.addEventListener("click", () => {
      els.folderInput.click();
    });

    els.loadEngineBtn.addEventListener("click", () => {
      els.engineFileInput.click();
    });

    els.fileInput.addEventListener("change", async event => {
      const [file] = Array.from(event.target.files || []);
      els.fileInput.value = "";
      await handleFile(file);
    });

    els.projectZipInput.addEventListener("change", async event => {
      const [file] = Array.from(event.target.files || []);
      els.projectZipInput.value = "";
      await handleProjectZip(file);
    });

    els.folderInput.addEventListener("change", async event => {
      const files = Array.from(event.target.files || []);
      els.folderInput.value = "";
      await handleProjectFiles(files);
    });

    els.engineFileInput.addEventListener("change", async event => {
      const [file] = Array.from(event.target.files || []);
      els.engineFileInput.value = "";
      if (!file) {
        return;
      }
      const approved = window.confirm(
        "This bypasses the packaged Python-engine integrity check. Continue with an explicitly unverified local engine?"
      );
      if (!approved) {
        setStatus("The unverified local engine override was cancelled.");
        return;
      }
      cancelAnalysis();
      appState.localEngineFile = file;
      appState.engineBundle = null;
      appState.engineSourceMode = null;
      appState.engineFingerprint = null;
      appState.engineReady = false;
      appState.enginePromise = null;
      setStatus(`Unverified local engine selected: ${file.name}.`);
      try {
        await initEngine();
      } catch (error) {
        /* the status bar already shows the failure */
      }
    });

    els.cancelBtn.addEventListener("click", () => cancelAnalysis());
    window.addEventListener("pagehide", () => cancelAnalysis());
    els.analyzeBtn.addEventListener("click", () => {
      analyzeNow();
    });

    els.clearBtn.addEventListener("click", () => {
      cancelAnalysis();
      els.editor.value = "";
      appState.analysisMode = "single";
      appState.projectPayload = null;
      appState.currentProjectReport = null;
      appState.currentFileName = defaultFileNameForLanguage(els.languageSelect.value === "auto" ? "python" : els.languageSelect.value);
      updateEditorMeta();
      scheduleHighlight();
      syncEditorScroll();
      clearReport();
      setStatus("Editor cleared.");
    });

    els.exportJsonBtn.addEventListener("click", () => {
      if (!appState.currentReport) return;
      downloadBlob(`${reportBaseName(appState.currentReport)}.json`, appState.currentJsonReport, "application/json;charset=utf-8");
    });

    els.exportTextBtn.addEventListener("click", () => {
      if (!appState.currentReport) return;
      downloadBlob(`${reportBaseName(appState.currentReport)}.txt`, appState.currentTextReport, "text/plain;charset=utf-8");
    });

    els.clearHistoryBtn.addEventListener("click", () => {
      localStorage.removeItem(HISTORY_KEY);
      renderHistory();
      setStatus("Local history cleared.");
    });

    els.privacyWipeBtn.addEventListener("click", clearPrivacyData);

    if (els.historyEnabled) {
      const storedHistoryPreference = localStorage.getItem(HISTORY_ENABLED_KEY);
      els.historyEnabled.checked = storedHistoryPreference === null ? false : storedHistoryPreference === "true";
      els.historyEnabled.addEventListener("change", () => {
        localStorage.setItem(HISTORY_ENABLED_KEY, String(els.historyEnabled.checked));
        if (!els.historyEnabled.checked) {
          localStorage.removeItem(HISTORY_KEY);
          setStatus("Local history disabled and cleared.");
        } else {
          setStatus("Local history enabled.");
        }
        renderHistory();
      });
    }

    els.languageSelect.addEventListener("change", () => {
      invalidateInputState();
      if (appState.currentReport || appState.currentProjectReport) {
        markReportStale(true);
      }
      updateEditorMeta();
      scheduleHighlight();
    });

    els.profileSelect.addEventListener("change", () => {
      invalidateInputState();
      els.summaryProfile.textContent = els.profileSelect.value;
      if (appState.currentReport || appState.currentProjectReport) {
        markReportStale(true);
      }
    });

    for (const key of ["configOverride", "calibrationProfile"]) {
      els[key].addEventListener("input", invalidateInputState);
      els[key].addEventListener("change", invalidateInputState);
    }
    els.editor.addEventListener("input", () => {
      invalidateInputState();
      if (appState.analysisMode === "project") {
        appState.analysisMode = "single";
        appState.projectPayload = null;
        appState.currentFileName = defaultFileNameForLanguage(els.languageSelect.value === "auto" ? "python" : els.languageSelect.value);
      }
      updateEditorMeta();
      scheduleHighlight();
      if (appState.currentReport || appState.currentProjectReport) {
        markReportStale(true);
      }
    });

    els.editor.addEventListener("scroll", syncEditorScroll);

    els.tabButtons.forEach(button => {
      button.addEventListener("click", () => activateTab(button.dataset.tab));
      button.addEventListener("keydown", handleTabKeydown);
    });

    els.metricsBody.addEventListener("click", event => {
      const projectRow = event.target.closest("tr[data-project-index]");
      if (projectRow) {
        selectProjectFileByIndex(Number(projectRow.dataset.projectIndex));
        return;
      }
      const excludedRow = event.target.closest("tr[data-excluded-index]");
      if (excludedRow) {
        selectExcludedFileByIndex(Number(excludedRow.dataset.excludedIndex));
        return;
      }
      const row = event.target.closest("tr[data-metric-index]");
      if (!row) return;
      selectMetricByIndex(Number(row.dataset.metricIndex));
    });

    els.historyList.addEventListener("click", handleHistoryClick);

    let dragDepth = 0;
    document.addEventListener("dragenter", event => {
      if (!hasFileDrag(event)) return;
      event.preventDefault();
      dragDepth += 1;
      els.dropZone.classList.add("dragover");
      showDropOverlay(true);
    });
    document.addEventListener("dragover", event => {
      if (!hasFileDrag(event)) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
      els.dropZone.classList.add("dragover");
      showDropOverlay(true);
    });
    document.addEventListener("dragleave", event => {
      if (!hasFileDrag(event)) return;
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) {
        els.dropZone.classList.remove("dragover");
        showDropOverlay(false);
      }
    });
    document.addEventListener("drop", async event => {
      if (!hasFileDrag(event)) return;
      event.preventDefault();
      dragDepth = 0;
      els.dropZone.classList.remove("dragover");
      showDropOverlay(false);
      await handleDropDataTransfer(event.dataTransfer);
    });

    window.addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "o") {
        if (appState.busy) { event.preventDefault(); return; }
        event.preventDefault();
        els.fileInput.click();
      } else if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        analyzeNow();
      } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        if (appState.currentReport) {
          downloadBlob(`${reportBaseName(appState.currentReport)}.json`, appState.currentJsonReport, "application/json;charset=utf-8");
        }
      }
    });

    renderHistory();
    updateEditorMeta();
    scheduleHighlight();
    syncEditorScroll();
    clearReport();
    activateTab("tab-summary");

    initEngine().catch(() => {
      /* the status bar already shows the failure */
    });
