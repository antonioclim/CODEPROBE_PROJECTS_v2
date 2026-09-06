# CodeProbe v2.2.0 — local source-code and documentation review

**Author and maintainer: Antonio Clim** ([`@antonioclim`](https://github.com/antonioclim)). See [Cite this repository](#cite-this-repository), [Contributing](CONTRIBUTING.md) and the [legacy lineage and retirement assessment](docs/history/14-legacy-lineage.md).

CodeProbe is an inspectable static-analysis kit for formative code review. It analyses **Python, JavaScript-family code, Bash-family shell scripts, C, C++ and C#**, with a separate **Markdown documentation profile**. Run it in a browser through Pyodide or use the native Python project-analysis and calibration tools. Submitted source is inspected as text; CodeProbe does not run the submitted programme, build its dependencies or connect to its databases.

![CodeProbe interface preview](docs/assets/interface-preview.png)

*The screenshot shows one example, not a C-only application. The main page's Language selector offers Auto, Python, JavaScript, Bash, C, C++ and C#, plus Markdown. The input and parser boundaries for each are listed below.*

The reported **AI-style concern score** is a **review signal**, **not proof of misconduct**, a probability of AI authorship or a certificate of independent work. Software tests and local calibration do not establish detector accuracy, authorship attribution or suitability for sanctions.

**Start here:** [supported languages](#supported-languages-and-source-extensions) · [documents and data](#documents-databases-and-other-file-types) · [folders and Git exports](#input-routes-folders-and-git-archives) · [quick start](#quick-start) · [CLI examples](#command-line-use) · [reports](#reports-and-exports) · [calibration](#course-local-calibration) · [input limits](#input-limits-and-exclusions) · [complete kit index](00-kit-index.md) · [citation](#cite-this-repository) · [legacy retirement](#relationship-to-the-legacy-repository).

## At a glance

| Question | Current behaviour |
|---|---|
| Which programming languages? | Six analysis families: Python, JavaScript, Bash, C, C++ and C#. TypeScript/JSX/TSX use the JavaScript family; zsh/ksh files use the Bash family, with the qualifications below. |
| Single snippet or file? | Paste text or open a source file in `app/index.html`. Automatic detection can be overridden with a supported language. |
| Whole project? | Select a folder, multiple files or a local ZIP. Projects may contain several supported languages. The CLI accepts a folder or ZIP. |
| GitHub export? | A downloaded source ZIP is accepted within the limits. A detected single wrapper directory is normalised. CodeProbe itself does not clone a URL or inspect Git history. |
| Markdown? | Yes, as documentation-quality context. It does not contribute an AI-style code score. |
| Word, PDF or spreadsheets? | **Not direct analysis inputs.** Bundled educator DOCX material does not imply DOCX ingestion. No PDF/OCR, Office extraction or spreadsheet analysis is implemented. |
| SQL or database files? | **Not supported as database or query-analysis inputs.** No database connection, schema introspection, query execution or record inspection is implemented. |
| JSON and CSV? | Used for specific configuration, calibration or report roles; accepting those roles is not generic dataset-analysis support. |
| Outputs? | Analysis reports in JSON and plain text. Calibration additionally produces a Markdown summary and CSV diagnostics. |
| Where does analysis run? | In a terminable browser worker or a local native Python process. The shipped browser configuration downloads a pinned Pyodide runtime; it is not a fully bundled offline application. |

## Supported languages and source extensions

This table follows the extension sets and language detector in [the runtime](src/codeprobe_runtime.py), not just the screenshot or file-picker filter.

| Analysis family / Language option | Recognised source extensions | Scope and qualifications |
|---|---|---|
| **Python** / `python` | `.py`, `.pyw` | Token and structure analysis, with AST-based metrics where parsing succeeds. Calibration and bound calibrated application require a successful Python AST parse on the executing runtime. Unbound analysis can return warning-bearing fallback diagnostics. |
| **JavaScript** / `javascript` | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` | JavaScript-family lexical and structural heuristics. **TypeScript, JSX and TSX are admitted through this family**, not through separate full TypeScript/React parsers. No type-checking, transpilation, module resolution or framework validation is performed. |
| **Bash** / `bash` | `.sh`, `.bash`, `.zsh`, `.ksh` | Shell-text heuristics. zsh and ksh extensions are admitted, but this is not a complete dialect-specific parser or a shell-execution validator. |
| **C** / `c` | `.c`, `.h` | Lexical and structural heuristics; no compiler, preprocessor execution, linking or binary analysis. A `.h` header may be classified as C++ from its contents. |
| **C++** / `cpp` | `.cpp`, `.cxx`, `.cc`, `.hpp`, `.hxx`, `.hh`; content-sensitive `.h` | C++ structural and quality heuristics, not standards-complete semantic analysis, template instantiation or build validation. |
| **C#** / `csharp` | `.cs` | C# lexical and structural heuristics. No Roslyn/.NET compilation, dependency resolution or runtime execution. |
| **Markdown** / `markdown` | `.md`, `.markdown` | Documentation metrics only. The overall AI-style code aggregate is not applicable. Fenced code is not recursively analysed as separate programmes. |

Extension matching is case-insensitive. Auto detection also examines first-line/shebang and content cues for a pasted snippet or a single text file. **Project admission is extension-based first:** an extensionless script, `.txt` file or unsupported-language file does not become an ordinary project source merely because the single-file detector could guess its contents.

For an ambiguous snippet, choose its actual supported language. For a mixed-language project, leave **Language = Auto** in the main interface; a forced language hint can be applied across its files. The compact project page uses per-file detection. In particular, `.h` classification is a heuristic, so inspect `language` in the report rather than assuming every header is C.

There are no dedicated analysers for Java, Go, Rust, R, PHP, Ruby, Swift, Kotlin, SQL, PowerShell, HTML, CSS or notebook JSON in this version. A text box accepting pasted text, an unknown-language fallback or the application itself using HTML/CSS does **not** establish support for those languages. Not every metric applies to every supported language; inspect metric applicability and warnings.

## Documents, databases and other file types

**Three roles must be kept separate:** a document shipped with the kit, a file admitted as analysis input and a configuration/report format. A format's presence in the repository does not mean the engine can read its contents as a document or dataset.

| File type | Analysis/import status | Practical handling |
|---|---|---|
| Markdown: `.md`, `.markdown` | Supported as single-file documentation context; excluded from browser project analysis by default. | Open individually and use Markdown. In the native CLI, `--include-documentation` admits supported documentation extensions subject to ignore rules. Markdown still does not contribute to the code aggregate. |
| Plain documentation: `.txt`, `.rst`, `.adoc` | Documentation extensions admitted by the native project's `--include-documentation` option; excluded by default. No dedicated reStructuredText or AsciiDoc parser. | Admission uses ordinary language detection, not conversion of the document format. Code-looking text can be detected as code; this option is **not** a universal guarantee of documentation-only scoring for every plain-text file. |
| A source snippet saved as `.txt` | Can be loaded or pasted in single-file mode and assigned a supported language. | For project analysis, preserve a suitable source extension instead of relying on content detection to bypass the extension filter. |
| Word/OpenDocument/RTF: `.doc`, `.docx`, `.odt`, `.rtf` | **No document-content extraction.** Not supported project source. | Export the relevant authored code to its real source language before analysis. The kit's educator `.docx` is a reading/editing resource, not an engine input. |
| PDF, including scanned PDF | **No PDF parser, OCR, layout, equation or embedded-code extraction.** Excluded from project source. | Code transcribed or exported into a supported source file can be analysed as that new input; the original PDF is not thereby analysed. |
| Spreadsheets: `.xls`, `.xlsx`, `.ods` | **No workbook, formula, cell or sheet analysis.** | A CSV calibration manifest is a different, prescribed input role; arbitrary tabular data are not scored. |
| Presentations, images, audio, video and fonts | Not analysed as source or documentation content. | These can be present in a repository but do not contribute to the source-code aggregate. |
| Databases: `.db`, `.sqlite`, `.sqlite3`, `.mdb`, `.accdb`, `.dbf` and database backups/dumps | **No database ingestion or database engine support.** Not supported project source extensions. | SQLite, PostgreSQL, MySQL/MariaDB, SQL Server and other database systems are not queried. Application code using a database can be inspected if its own language is supported; database behaviour is not tested. |
| SQL scripts: `.sql` | **No SQL parser or query-quality analyser.** Excluded as an unsupported project source extension. | SQL strings inside Python/JavaScript/C# are not separately validated. A migration written in a supported language is still subject to the default `migrations/` exclusion. |
| General `.json`, `.csv`, `.tsv`, `.xml`, `.yaml`, `.yml`, `.toml`, `.ini` | Not generic code, document or dataset analysis inputs. | JSON metric overrides, JSON calibration profiles and CSV/JSON corpus manifests are accepted only through their specific controls/tools and expected structures. Repository configuration files do not automatically enter the project score. |
| Jupyter `.ipynb`, Parquet, HDF5, Avro, Protobuf and serialised objects | No notebook-cell, data-container, schema or object ingestion. | Export authored source into a supported file when appropriate. Do not rename a container to `.py` or `.txt` and treat that as extraction. |
| Executables, bytecode, libraries and object files | No decompilation or binary-code analysis. | `.exe`, `.dll`, `.so`, `.class`, `.pyc`, `.o` and similar files are excluded. |

The folder selectors may let you select files outside the supported set. That is not a promise to analyse them: project reports record admitted files and exclusions. Unsupported files may appear as `unsupported_extension`, `binary_or_non_source_extension`, an ignore match or a browser intake rejection. The first applicable check determines the recorded reason; it need not equal the label in this table.

## Input routes, folders and Git archives

| Route | What to provide | Important boundary |
|---|---|---|
| **Main browser page**: `app/index.html` | Pasted source, one source file, multiple selected/dropped files, a folder or a local `.zip`. | A single source file uses single-file mode. Folders, multiple files and a ZIP use project mode. Language, metric override and calibration controls are available. |
| **Compact project page**: `app/project.html` | A folder, dropped file collection or local `.zip`. | Project workflow, scoring mode, calibration and JSON/text export; no single-file editor or general document reader. |
| **Native project CLI**: `tools/analyze_project.py` | Exactly one of `--folder` or `--zip`. | Adds configurable bounded limits, `--include-documentation` and explicit configuration/ignore/profile files. It has no `--file` or remote-repository URL input. |
| **Python API**: `src/codeprobe_engine/api.py` | A structured file or project payload. | `analyse_file` and `analyse_project` wrap the runtime's JSON entry points. They are local functions, not a hosted REST service. See [architecture](docs/02-architecture.md) and [report fields](docs/03-report-schema.md). |

### GitHub and other Git source exports

Download a repository's **source ZIP** to your computer, then open/drop it in CodeProbe or pass it to `--zip`. An ordinary `git archive --format=zip` source snapshot is also a ZIP input. Exports from GitLab, Bitbucket or another host are handled as ordinary archives **when they meet the same ZIP, path and resource constraints**; no host-specific API integration is implied.

For a recognised single export wrapper such as `repository-main/`, CodeProbe removes that wrapper before applying project-root `.codeprobeignore` rules. `input_packaging` records the detected root, whether it was stripped and the reason. Common-root stripping is conservative: not every first-level directory is automatically removed.

A cloned working directory can be analysed with `--folder`; `.git/` is excluded. The tool does **not** fetch repository URLs, use the chat's GitHub connector, compare branches, inspect commits or establish who wrote a file. Supply Git history separately for human review. Git LFS objects and submodule content are not fetched: inspect the actual downloaded files rather than assuming the export contains those objects.

### Accepted and rejected archive forms

The project reader supports ordinary **single-volume ZIP archives with stored or deflated members**. It checks compressed size, entry count, member size, expansion ratio, aggregate limits and paths. Encrypted members, links/special members and unsupported compression methods are excluded; malformed archives, ZIP64 and multi-disk ZIP containers are refused. Review the report's inventory when only part of an archive was admitted.

`.tar`, `.tar.gz`, `.tgz`, `.gz`, `.bz2`, `.xz`, `.7z` and `.rar` are **not alternative project archive inputs**. Extract trusted source locally and analyse the resulting folder, or create a compliant source ZIP. A `.bundle` is a Git history transport, not a CodeProbe project ZIP. `.jar`, `.war`, Office containers and nested archives are not recursively unpacked for source analysis. Selecting an outer ZIP does not add support for unsupported files inside it.

## Quick start

Obtain the complete kit from [the published releases](https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/releases), or use a complete checkout of the desired ref. Run commands from the directory containing this README and `tools/`; retain the `app/`, `src/` and configuration layout. A tagged release is a fixed snapshot. Documentation on `main` can subsequently improve without replacing the already published release assets.

### Requirements

| Component | Requirement and verification scope |
|---|---|
| Browser | A modern browser with Web Workers, WebAssembly, Web Crypto and file APIs. Automated functional/accessibility checks use Chromium. Equivalent comprehensive Firefox/Safari coverage is not claimed; folder selection varies by browser. |
| Pyodide/network | The shipped production configuration fetches the pinned **Pyodide 0.25.0** core from its configured CDN and verifies its bytes. Internet access is required for that configuration. |
| Native Python | **3.10–3.14** for the command-line tools, calibration and local helper server. Browser analysis itself runs in Pyodide, not your locally installed Python. |
| Node.js | Needed for maintainer JavaScript checks and browser test harnesses, not ordinary analysis. Canonical CI pins **24.20.0**. |
| Build/install | No application build step, `npm install`, database server or third-party Python package installation is required for the ordinary kit. |

**Offline qualification:** native analysis can operate without the CDN. The source kit does not bundle the complete browser runtime. Merely changing the runtime mode or copying vendor files is not a validated offline distribution: the committed dependency-boundary gate refuses unapproved local/vendored runtime additions. Maintainer procedures in [offline deployment](docs/05-offline-deployment.md) require the corresponding inventory, server and integrity controls to be reconciled and tested before an offline browser package is claimed.

### Launch the browser application

On Windows:

```powershell
py -3 -I -S -B tools/run_local_server.py
```

If `py` is unavailable but Python is installed, use `python -I -S -B tools/run_local_server.py`. On Linux or macOS:

```bash
python3 -I -S -B tools/run_local_server.py
```

Open the address printed by the server, normally `http://127.0.0.1:8123/app/index.html`. The compact page is at `http://127.0.0.1:8123/app/project.html`. Use the local HTTP server rather than double-clicking an HTML file. The helper publishes declared application resources, including the packaged engine needed for analysis; it does not expose the whole repository or directory listings. Non-loopback binding requires explicit `--allow-network` and is not a production multi-user security configuration.

Paste/open your source, confirm **Language**, choose a scoring mode and select **Analyse**. For a mixed-language project, keep Auto. Inspect included/excluded files, applicability, warnings and the review plan before saving JSON/text. **Cancel analysis** terminates the worker; retry starts a fresh interpreter. Loading new input or changing scoring settings invalidates the old report and export state.

## Command-line use

These examples assume that `work/submission/` and `work/submission.zip` are your actual inputs, while `work/reports/` is an **existing directory outside the analysed project**. Replace the paths accordingly; `work/` is illustrative, not a bundled sample dataset. On Windows, replace `python3` with `py -3` or `python` and use PowerShell's line-continuation syntax or a single line.

### Analyse a folder or a source ZIP

```bash
python3 -I -S -B tools/analyze_project.py \
  --folder work/submission \
  --json-out work/reports/submission.json \
  --text-out work/reports/submission.txt
```

```bash
python3 -I -S -B tools/analyze_project.py \
  --zip work/submission.zip \
  --json-out work/reports/archive.json \
  --text-out work/reports/archive.txt
```

With no `--text-out`, the text report is also printed to standard output. JSON output is opt-in through `--json-out`.

### Add documentation context or a bound calibration profile

```bash
python3 -I -S -B tools/analyze_project.py \
  --folder work/submission \
  --include-documentation \
  --json-out work/reports/with-context.json
```

`--include-documentation` permits `.md`, `.markdown`, `.txt`, `.rst` and `.adoc`; it does not permit DOCX, PDF, databases or spreadsheets and does not disable ignore rules. Refer to the plain-text detection caveat above.

```bash
python3 -I -S -B tools/analyze_project.py \
  --folder work/submission \
  --calibration-profile work/course/calibration_profile.json \
  --json-out work/reports/calibrated.json
```

Omitting `--profile` allows a bound calibration profile to select its calibrated scoring mode. An explicit incompatible mode/configuration is refused. Without a bound profile, the ordinary default applies; the available modes are `default`, `strict` and `permissive`. An additional `.codeprobeignore`-style file can be passed through `--ignore-file`; a metric-override object through `--config`. These files have prescribed roles, not arbitrary JSON/text semantics.

**Output safety:** JSON and text destinations must be distinct and must not alias the project, archive or auxiliary input files. Reports inside the analysed folder are refused, including new output names. Existing link/reparse-point or hard-linked destinations are refused, and parent directories must already exist. Each replacement is atomic, but the pair is not a filesystem transaction. The project command returns exit 2 on controlled input/output failure; exit 0 does not mean the score proves authorship.

For the exact flags and bounded native limits:

```bash
python3 -I -S -B tools/analyze_project.py --help
```

## Reports and exports

| Operation | Files or result | What is included |
|---|---|---|
| Browser file/project analysis | Downloadable **JSON** and **plain text (`.txt`)** | Identity, detected language(s), scores, metric details, warnings and manual-review guidance; projects add included/excluded inventories and packaging metadata. |
| Native project analysis | `--json-out`, `--text-out`; text on standard output when not written | The project report object and its readable text rendering. It does not require a database. |
| Calibration | `calibration_profile.json`, `validation_summary.md`, `calibration_observations.csv`, `threshold_sensitivity.csv` by default | The fitted policy, holdout diagnostics, sample observations and the fit-threshold sensitivity table; output paths can be selected explicitly. |
| Release packaging | Kit `.zip`, `.sha256.txt` and `.package_audit.json` | Distribution integrity and member accounting, not an analysis of a student's project. |

There is **no built-in DOCX, PDF, XLSX or HTML report export**. The educator Word document and the browser's HTML interface are separate resources. JSON analysis reports are outputs, not calibration profiles to paste into the calibration input.

The file report schema is `2.2.0`; the project schema is `2.2.0-project`. Useful fields include `filename`/`project_name`, `language`, `metrics`, `overall_applicable`, `overall_score`, `decision_score`, `review_triggered`, `manual_review_guidance`, `engine_fingerprint`, `metric_config_digest` and `tool_metadata`. Project `input_packaging` records common-root handling and effective limits. `decision_score` retains the unrounded comparison value; displayed values may be rounded. See [report schema notes](docs/03-report-schema.md).

### Reading the result

Metrics are separated into stylometry, quality, context and documentation roles. Good formatting, generic structure or a documentation-quality result should not be treated as evidence of AI authorship. Projects combine applicable file scores using source-line weighting with a per-file cap of **500 SLOC**. This is not a cross-file compiler, dependency graph or semantic clone detector.

The current generic bands use the following thresholds for an applicable score:

| Unrounded score displayed as a percentage | Built-in reading |
|---|---|
| Below 28% | Low AI-style concern |
| 28% to below 48% | Moderate AI-style concern |
| 48% to below 68% | Elevated AI-style concern |
| 68% or higher | High AI-style concern |
| Not applicable | Documentation-only or insufficient applicable evidence; not a zero-risk certificate |

The **60% provisional review trigger is separate from these display bands**. A local profile can change both; read the policy serialised with the actual report rather than applying a hard-coded band externally. The `confidence` label is an internal evidence-coverage heuristic, not a statistical confidence interval or a calibrated probability. Use independent code inspection, tests, development history and an explanation of the work; do not turn these bands into pass/fail marks or penalties.

## Course-local calibration

Calibration requires a real, appropriately authorised and labelled source corpus; the distributed templates do **not** contain an empirical validation dataset. CSV/JSON manifests point to source files, folders or ZIP samples and specify labels, groups and fit/evaluation partitions or a supported group-exclusive split. Generic spreadsheet or database contents cannot be substituted for source samples.

After curating a manifest and the referenced files, an example command is:

```bash
python3 -I -S -B tools/calibrate_profile.py \
  --manifest work/course/corpus-manifest.csv \
  --profile-id intro-python-course-v1 \
  --label "Intro Python course" \
  --target-fpr 0.10 \
  --out-dir work/calibration-output
```

The paths above are illustrative. Start from [the manifest templates](calibration/README.md), replace their sample paths and labels with justified corpus records and keep outputs separate from the manifest and samples. `--target-fpr 0.10` requests a fit-partition target; it is not a claim that the software achieves a 10% real-world error rate.

Scoring mode, effective metric configuration and engine identity are bound before fitting/evaluation and checked on application. Selection uses the fit partition; the holdout is not used to tune the threshold. An unmet fit target produces a **non-operational diagnostic profile**, refused on application. Successful writing of diagnostics can return exit 0; inspect `operational` and `operational_reason` instead of inferring feasibility from the exit code.

Python calibration requires successful AST parsing, including relevant project members. A native interpreter accepting newer syntax does not make that syntax parsable by Pyodide's interpreter. Runtime metadata do not certify universal cross-version replay. Old unbound profiles remain provisional and must not be relabelled as verified replay contracts.

Fresh opaque sample/group identifiers are assigned for export after partitioning and fitting. They do not anonymise scores, labels, row ordering or group sizes. See [calibration guide](docs/06-calibration-guide.md) and [contract reconciliation](docs/22-contract-reconciliation.md).

## Input limits and exclusions

Default byte counts below are decimal, not MiB/GiB. The applicable limits and exclusion inventory should be retained with the report.

| Boundary | Default |
|---|---:|
| Single browser source / individual project source | **1,000,000 bytes**; decoded/re-encoded text checks can also reject an input |
| Project source budget | **20,000,000 bytes** |
| Compressed outer ZIP | **8,000,000 bytes** |
| Project files admitted for analysis | **300** |
| ZIP entries / browser selection-entry bound | **2,000** |
| Maximum admitted ZIP-member expansion ratio | **100:1** |
| Project ignore text | **131,072 bytes**, at most **1,000 active rules** |
| Browser dropped-directory traversal | **2,000 entries including directories**, depth bound **32**, enumeration budget **10 seconds** |
| Browser worker startup / analysis watchdog | **60 seconds / 30 seconds** |

The native CLI exposes bounded overrides such as `--max-files`, `--max-file-bytes`, `--max-total-bytes`, `--max-entries`, `--max-archive-bytes` and `--max-compression-ratio`. This is not unlimited intake. The browser worker also bounds serialised requests/results; source size is not their only cost. Timer suspension, memory pressure, decoding, serialisation and rendering remain separate constraints, not hard real-time guarantees.

**Route matters near a budget:** browser folder intake can consume its raw read budget before documentation is excluded by the engine. Selection order may therefore affect which source files remain under that ceiling. ZIP prefiltering and native intake take different paths; do not assume identical admission for an oversized mixed-content selection. Inspect `overall_applicable` and excluded files, not just the score.

Built-in exclusions cover version-control/editor metadata, dependencies, build output, generated directories, migrations, common binaries and minified/bundled assets. Examples include `.git/`, `node_modules/`, `vendor/`, `dist/`, `build/`, `generated/`, `migrations/`, `*.min.js` and `*.bundle.js`. Some long-line JavaScript assets are also excluded heuristically as minified; inspect the reason rather than assuming authorship.

Copy [`.codeprobeignore.example`](.codeprobeignore.example) to the **root of the project being analysed**, naming it `.codeprobeignore`, and customise it for starter code, third-party material and files outside the assessed task. The reader supports comments, directory/glob patterns and negated re-inclusions, subject to safety/type limits. Nested `.codeprobeignore` files do not establish independent policies; `.gitignore` is not automatically imported. Re-inclusion does not add a parser for an unsupported format or bypass a size/path boundary.

Native folder readers reject unsafe links and special entries. Paths are normalised, including Unicode NFC, and unsafe/duplicate paths are refused or excluded as appropriate to the route. Browser pre-read rejection records preserve bounded selection metadata, not authenticated missing file contents. Archive-level failure may prevent a report entirely.

## Browser security, privacy and access

Both pages execute Python through an authenticated, terminable worker. The HTML uses Content Security Policy without `unsafe-inline`; scripts and styles are external. Local integrity metadata and SRI protect packaged resources. The loader verifies the five required Pyodide core artefacts and the engine bytes actually consumed, rather than trusting an unchecked second network response. This does not authenticate optional packages, upstream builds or the complete current vulnerability state.

Analysis is local to the executing browser/native process; the kit has no remote submission-analysis API. Browser startup still contacts the configured runtime host. The **manual engine-file override is explicitly unverified**; never use it to bypass an unexplained integrity failure or treat a worker as a security sandbox for a malicious replacement engine.

Report history in the main page is disabled by default and uses browser `localStorage` when enabled; there is no application SQL/NoSQL database. It stores reports rather than source text, but report metadata, filenames and scores can still be sensitive. **Clear privacy data** clears the current session and invalidates pending work even if persistent storage fails. When stored-report deletion cannot be verified, the interface warns that stored data may remain. This is not forensic erasure of browser memory or disk.

Both interfaces include labelled inputs, live status, visible keyboard focus and semantic score progress. The main result tabs support Left/Right and Home/End navigation. The real Chromium accessibility harness exercises the documented contract; it is not a universal accessibility certification.

See [browser security](docs/04-browser-security.md), [runtime integrity](docs/18-runtime-integrity.md), [worker resilience](docs/20-worker-resilience.md), [runtime lifecycle](docs/21-runtime-lifecycle.md) and [security policy](SECURITY.md).

## Repository layout and companion material

The **naming-stable release** layout keeps application code, resources and evidence separate. The [file catalogue](docs/00-file-catalogue.md), [naming policy](docs/01-naming-policy.md) and [migration map](release/file-rename-map.csv) describe the paths.

```text
.
├── 00-kit-index.md                         complete package navigator
├── README.md, CHANGELOG.md                 overview and change history
├── LICENSE, CONTRIBUTING.md                rights and contribution guidance
├── SECURITY.md, CITATION.cff, CITATION.bib  security and citation metadata
├── .codeprobeignore.example                project exclusion template
├── .github/                               canonical CI and CODEOWNERS
├── app/                                   two browser pages, JS/CSS and runtime configuration
├── src/                                   analysis runtime and native support modules
├── tools/                                 CLI, calibration, server, checks and packaging
├── docs/                                  technical Markdown, history and preview image
├── educator/                              teaching/review material in Markdown and DOCX
├── calibration/                           JSON/CSV templates and output placeholders
├── release/                               manifests, catalogue map and audit evidence
└── tests/                                 maintained regression suite
```

| Material | Role; not a new ingestion capability |
|---|---|
| [Complete kit index](00-kit-index.md) | Reading order and navigation across the package. |
| [Student quick start](educator/01-student-quick-start.md) | Student-facing procedure and limitations. |
| [Student announcement: DOCX](educator/02-student-announcement.docx) / [Markdown](educator/02-student-announcement.md) | Editable/reading resources supplied with the kit. Their presence does not add a Word parser. |
| [Disclosure template](educator/03-student-disclosure-template.md), [instructor checklist](educator/04-instructor-checklist.md) | Human evidence and review support. |
| [Review protocol](educator/05-review-protocol.md), [evidence rubric](educator/06-evidence-rubric.md), [course integration](educator/07-course-integration.md) | Guidance, not approval to base grading or sanctions on the score. |
| [Calibration resources](calibration/README.md) | Corpus manifests, profile templates and validation-summary templates; no completed empirical benchmark is implied. |
| [Architecture](docs/02-architecture.md), [UI extension guide](docs/07-ui-extension-guide.md), [tools index](tools/README.md) | Maintainer reference. |
| [Development provenance](docs/10-provenance.md), [design decisions](docs/11-design-decisions.md) | Attribution, assisted-development disclosure and methodological boundaries. |
| [Release process](docs/08-release-process.md), [integrity](docs/09-release-integrity.md), [recovery](docs/19-release-recovery.md) | Packaging, verification and process-interruption handling. |

The preview PNG is an interface illustration, not a scientific result. `CITATION.cff` does not imply a DOI or published paper. No PDF report pack, editable scientific figure series, production database or empirical authorship corpus is supplied by these resources.

## Maintainer verification and packaging

Run the canonical read-only gate from the kit root; Node is required for the complete JavaScript checks:

```bash
python3 -I -S -B tools/check_release.py --require-node
```

The maintained suite has a **487-case baseline**, with documented platform conditions. CI validates native Python 3.10–3.14, Windows/macOS, actual Chromium/Pyodide functionality, accessibility, supported-code coverage and release reproducibility. A successful gate does not prove bug absence or detector validity. Source inspection, integration tests and empirical claims have separate scopes.

Coverage enforcement requires the pinned **Python 3.14.7**, not an arbitrary interpreter:

```bash
python3 -I -S -B tools/check_coverage.py \
  --json-out /path/outside/the/repository/codeprobe-supported-coverage.json
```

It measures executable-line coverage with overall, root and high-risk file floors, not branch/condition or mutation coverage. After an intentional source or documentation change, regenerate evidence only through the full guarded gate:

```bash
python3 -I -S -B tools/check_release.py --require-node --write-release-evidence
python3 -I -S -B tools/check_release.py --require-node
```

Build the manifest-verified packet:

```bash
python3 -I -S -B tools/build_release.py --out dist/CodeProbe_Project_Kit_v2.2.0.zip
```

The builder captures immutable manifest-verified bytes under `CodeProbe_Project_Kit_v2.2.0/` and prepares the ZIP and both sidecars under a durable journal. The checksum is withdrawn before public mutation and installed last. A later build, or `--recover-only` with the same `--out`, retains a complete new packet, restores the recorded prior packet or stops on unknown concurrent state. Process-interruption tests do not prove universal power-loss durability or atomic replacement of all three names.

Building a local ZIP is **not** publishing a GitHub Release. Tags, published assets, the current main branch and subsequent README improvements are separate versioned objects. Preserve existing release assets rather than silently replacing them after a documentation edit. [Final package audit](docs/15-final-release-audit.md) describes the naming and integrity checks, not institutional authorisation.

## Relationship to the legacy repository

This repository is the maintained successor to
[CODEPROBE_PROJECTS_v1](https://github.com/antonioclim/CODEPROBE_PROJECTS_v1).
The repository suffixes distinguish distributions: the inspected legacy engine
already identified itself as CodeProbe 2.0.0, whereas this line uses 2.2.0.
The shared languages alone therefore do not describe the evolution.

**Legacy retirement notice.** Antonio Clim intends to withdraw the legacy
repository from public access to reduce the risk of its continued use for
unsupported evaluative decisions. He reports erroneous assessments exceeding
30% in some of his prior evaluations of research works or projects involving
the legacy version. This is an **author-reported operational observation**: not an independently reproduced benchmark, a measured false-positive rate or a
quantified accuracy comparison with this version. The corpus, denominator,
reference labels, unit of analysis, decision thresholds and error definition
are not available in the evidence supplied for this comparison.

Do not use the legacy output, or this successor's score, as a stand-alone basis
for grading, authorship accusations, research evaluation or sanctions. The
engineering improvements in this repository do not establish detector accuracy.
See the [legacy comparison](docs/history/14-legacy-lineage.md) for mechanisms, limits and migration requirements. The notice records an intention; it does not assert that public access has already been removed or that previously distributed copies cease to
exist.

## Cite this repository

For the published 2.2.0 release:

> Clim, A. (2026). *CodeProbe: Formative source-code and documentation review*
> (Version 2.2.0) [Computer software]. GitHub.
> https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/releases/tag/v2.2.0

Machine-readable citation metadata are provided in [CITATION.cff](CITATION.cff), with a downloadable [CITATION.bib](CITATION.bib). The CFF uses the JSON subset of YAML so the standard-library CI suite can check its structure and identity without an additional YAML dependency.
Use the author **Antonio Clim**, not the GitHub Actions bot that uploaded a
release. No DOI, ORCID, affiliation or publication is asserted by these metadata.

For a development checkout, record its exact commit alongside this citation.
A citation to release 2.2.0 must not imply that the preserved release package includes
later documentation changes on `main`. Attribution metadata are corrected
prospectively without rewriting published release files.

The citation identifies the published source commit `2d38fbd3772a9f415dfcc52ab2840aadd15575e3`. The scholarly author is distinct from automated committer labels and historic licence notices. Applicable notices and documented contributions remain unchanged.

## Licence and scientific limits

The existing [MIT licence](LICENSE) and contributor attribution apply unchanged. Keep the notices with redistributed copies and consult [CONTRIBUTING.md](CONTRIBUTING.md) for project practice.

This kit offers inspectable signals and a human review plan. Local calibration is limited by its labelled corpus, grouping and holdout design; it does not establish general sensitivity, specificity, causal authorship or robustness to all languages, generators and assignment styles. Small files, templates, copied/generated material and unsupported syntax can distort readings. A low score does not establish independent work; a high score does not establish misconduct. Institutional processing and any assessment policy require their own justified decisions.
