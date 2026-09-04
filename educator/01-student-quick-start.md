# Student quick start

Use this guide before submitting project code.

## 1. Choose the right files

Analyse only source files that you personally authored for the assessed task. Exclude starter code, third-party libraries, generated files, minified assets, build output and documentation.

Recommended project exclusions are provided in `.codeprobeignore.example`. Copy it to `.codeprobeignore` in your project and adjust it before analysis.

## 2. Open the kit

Run a local server from the package root:

```bash
python3 -I -S -B tools/run_local_server.py
```

Then open the address printed by the script. Alternatively, open `app/index.html` directly if your browser permits local Pyodide loading.

## 3. Analyse your work

For a single file, use **Open file**, paste the code, or drag the source file anywhere onto the browser page. For a full project, use **Open project ZIP**, **Open project folder**, or drag a folder / GitHub-generated ZIP export directly onto the page. Check the included and excluded file lists carefully before using the aggregate score.

## 4. Read the report correctly

The score is a review signal, not a judgement. A score above the active trigger means that you should revise, simplify or document the relevant parts and re-run the tool. It does not automatically mean misconduct.

Focus first on the explanations attached to individual metrics and on the **Manual review** tab. Quality and context metrics are improvement advice; they are not proof of AI use. The manual-review guidance tells you which evidence an instructor may reasonably ask for if a score needs discussion.

## 5. Export evidence

Export JSON and text reports if your instructor requests them. Keep your tests, commit history and design notes. You must still be able to explain the implementation decisions and the code paths in your own words.

## 6. When AI assistance was used

Complete `educator/03-student-disclosure-template.md`. State what the tool helped with, which outputs were rejected, what you rewrote, how you tested correctness and which parts remain entirely your own implementation.

## Interpretation boundary

The CodeProbe score is a review signal, not proof of misconduct and not a certificate of independent authorship.
