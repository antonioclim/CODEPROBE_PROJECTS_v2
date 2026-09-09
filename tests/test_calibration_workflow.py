"""Exercise the documented workflow on owned synthetic inputs, not an authorship corpus."""
from __future__ import annotations

import collections
import contextlib
import copy
import csv
import hashlib
import io
import json
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
import analyze_project
import calibrate_corpus
import calibrate_profile
import check_dependency_boundary
import codeprobe_runtime as engine

SOURCE = """def total(values):
    result = 0
    for value in values:
        result += value
    return result


def mean(values):
    if not values:
        raise ValueError("empty sequence")
    return total(values) / len(values)


def centred(values):
    average = mean(values)
    return [value - average for value in values]


def scale(values, factor):
    result = []
    for value in values:
        result.append(value * factor)
    return result
"""
TEMPLATES = {
    "file": "01-corpus-manifest-template",
    "project": "01-project-corpus-manifest-template",
}
OUTPUTS = ("calibration_profile.json", "validation_summary.md",
           "calibration_observations.csv", "threshold_sensitivity.csv")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
      "dc": "http://purl.org/dc/elements/1.1/",
      "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
      "dcterms": "http://purl.org/dc/terms/"}


def template(kind: str, suffix: str = "json") -> dict:
    path = ROOT / "calibration" / (TEMPLATES[kind] + "." + suffix)
    if suffix == "json":
        return json.loads(path.read_text(encoding="utf-8"))
    with path.open(encoding="utf-8", newline="") as handle:
        return {"samples": list(csv.DictReader(handle))}


def write_manifest(path: Path, value: dict) -> None:
    if path.suffix == ".json":
        path.write_text(json.dumps(value), encoding="utf-8")
    else:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(value["samples"][0]))
            writer.writeheader()
            writer.writerows(value["samples"])


def prepare_inputs(base: Path, kind: str, suffix: str = "json") -> Path:
    """Replace only the template paths; all declared labels/groups/splits stay intact."""
    value = template(kind, suffix)
    for index, row in enumerate(value["samples"]):
        relative = f"{kind}-fixtures/sample-{index}" + (".py" if kind == "file" else "")
        row["path"] = relative
        leaf = base / relative if kind == "file" else base / relative / "main.py"
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_text(SOURCE + f"\nfixture_number = {index}\n", encoding="utf-8")
    path = base / f"{kind}-manifest.{suffix}"
    write_manifest(path, value)
    return path


def calibrate(manifest: Path, output: Path) -> dict:
    with contextlib.redirect_stdout(io.StringIO()):
        result = calibrate_profile.main(["--manifest", str(manifest), "--out-dir", str(output)])
    if result != 0:
        raise AssertionError(f"calibration returned {result}")
    return json.loads((output / OUTPUTS[0]).read_text(encoding="utf-8"))


def input_snapshot(base: Path) -> dict:
    return {str(p.relative_to(base)): p.read_bytes() for p in base.rglob("*") if p.is_file()}


def analytics(profile: dict) -> dict:
    fields = ("label", "kind", "language", "score", "decision_score", "applicable", "sloc", "split")
    return {"scope": profile["scope"], "review_policy": profile["review_policy"],
            "rows": [{k: row[k] for k in fields} for row in profile["validation"]["sample_results"]]}


def commands() -> dict:
    found = {}
    for relative in ("calibration/README.md", "educator/09-project-kit-notice.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        for name, command in re.findall(r"<!-- workflow-command:([a-z-]+) -->\s*```console\s*([^`]+)```", text):
            if name in found:
                raise AssertionError(f"duplicate documented command: {name}")
            found[name] = shlex.split(command.strip())
    return found


def command_args(command: list[str], base: Path) -> list[str]:
    if command[:4] != ["python", "-I", "-S", "-B"]:
        raise AssertionError("documented commands must retain isolated, site-free Python")
    allowed = {"tools/calibrate_profile.py", "tools/calibrate_corpus.py", "tools/analyze_project.py",
               "tools/run_local_server.py", "codeprobe/tools/run_local_server.py"}
    result = []
    for arg in command[1:]:
        if arg in allowed:
            result.append(str(ROOT / arg.removeprefix("codeprobe/")))
        elif arg.startswith("../codeprobe-local/"):
            result.append(str(base / arg.removeprefix("../codeprobe-local/")))
        elif arg == "../codeprobe-local":
            result.append(str(base))
        else:
            result.append(arg)
    if not any(arg in allowed for arg in command):
        raise AssertionError("unexpected documented tool")
    return result


class CalibrationWorkflowTests(unittest.TestCase):
    def test_templates_have_one_domain_and_four_explicit_group_strata(self):
        expected = [("human", "fit"), ("ai_generated", "fit"),
                    ("human", "evaluation"), ("ai_generated", "evaluation")]
        for kind in TEMPLATES:
            with self.subTest(kind=kind):
                left, right = template(kind)["samples"], template(kind, "csv")["samples"]
                self.assertEqual(left, right)
                self.assertEqual([(r["label"], r["split"]) for r in left], expected)
                self.assertEqual({r["kind"] for r in left}, {kind})
                self.assertEqual(len({r["group_id"] for r in left}), 4)
                self.assertEqual(len({r["path"] for r in left}), 4)

    def test_all_four_path_substituted_templates_generate_scoped_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            for kind in TEMPLATES:
                profiles = []
                for suffix in ("json", "csv"):
                    with self.subTest(kind=kind, format=suffix):
                        manifest = prepare_inputs(base, kind, suffix)
                        before = input_snapshot(base / f"{kind}-fixtures")
                        manifest_bytes = manifest.read_bytes()
                        output = base / f"{kind}-{suffix}-out"
                        profile = calibrate(manifest, output)
                        profiles.append(profile)
                        self.assertEqual(input_snapshot(base / f"{kind}-fixtures"), before)
                        self.assertEqual(manifest.read_bytes(), manifest_bytes)
                        self.assertEqual({p.name for p in output.iterdir()}, set(OUTPUTS))
                        self.assertEqual(profile["scope"], {"report_kinds": [kind],
                            "languages": ["python" if kind == "file" else "project"], "mixed_domains_permitted": False})
                        self.assertTrue(profile["operational"])
                        self.assertEqual(profile["validation"]["evaluation_design"]["strategy"], "explicit_group_holdout")
                        for partition in ("fit", "evaluation"):
                            rates = profile["validation"]["descriptive_review_rates"][partition]
                            self.assertEqual((rates["sample_count"], rates["group_count"]), (2, 2))
                            self.assertEqual(rates["labels"]["human"]["eligible"], 1)
                            self.assertEqual(rates["labels"]["positive"]["eligible"], 1)
                self.assertEqual(analytics(profiles[0]), analytics(profiles[1]))

    def test_exports_keep_analytics_but_use_fresh_consistent_uuid4_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            manifest = prepare_inputs(base, "file")
            value = json.loads(manifest.read_text(encoding="utf-8"))
            for i, row in enumerate(value["samples"]):
                row["sample_id"] = f"private-person-{i}"
            write_manifest(manifest, value)
            profiles = [calibrate(manifest, base / f"out-{i}") for i in range(2)]
            self.assertEqual(analytics(profiles[0]), analytics(profiles[1]))
            for i, profile in enumerate(profiles):
                rows = profile["validation"]["sample_results"]
                with (base / f"out-{i}" / OUTPUTS[2]).open(encoding="utf-8", newline="") as handle:
                    exported = list(csv.DictReader(handle))
                for row, csv_row in zip(rows, exported):
                    for key, prefix in (("sample_id", "sample-"), ("group_id", "group-")):
                        self.assertTrue(row[key].startswith(prefix))
                        self.assertEqual(uuid.UUID(row[key][len(prefix):]).version, 4)
                        self.assertEqual(row[key], csv_row[key])
                    self.assertEqual(row["path"], row["sample_id"])
                    self.assertEqual(row["path"], csv_row["path"])
                exported_text = json.dumps(rows) + json.dumps(exported)
                for original in value["samples"]:
                    for key in ("sample_id", "path", "group_id"):
                        self.assertNotIn(original[key], exported_text)
                self.assertFalse(profile["validation"]["identifier_policy"]["mapping_exported"])
            first, second = [p["validation"]["sample_results"] for p in profiles]
            for key in ("sample_id", "group_id"):
                self.assertTrue({r[key] for r in first}.isdisjoint({r[key] for r in second}))

    def test_retired_option_is_refused_before_manifest_reads_or_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            victim = base / "profile.json"
            victim.write_bytes(b"unchanged")
            for value in ("0", "10", "99999"):
                with self.subTest(value=value), mock.patch.object(calibrate_profile, "load_manifest") as load:
                    diagnostic = io.StringIO()
                    with contextlib.redirect_stderr(diagnostic), self.assertRaises(SystemExit) as refused:
                        calibrate_profile.main(["--manifest", str(base / "absent.json"), "--profile-out", str(victim),
                                                "--min-per-class-for-language", value])
                    self.assertEqual(refused.exception.code, 2)
                    self.assertIn("unrecognized arguments", diagnostic.getvalue())
                    load.assert_not_called()
                    self.assertEqual(victim.read_bytes(), b"unchanged")
                    self.assertEqual([p.name for p in base.iterdir()], ["profile.json"])

    def test_help_explains_retirement_without_an_active_argument(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as help_exit:
            calibrate_profile.main(["--help"])
        self.assertEqual(help_exit.exception.code, 0)
        self.assertIn("removed", output.getvalue())
        self.assertNotIn("MIN_PER_CLASS_FOR_LANGUAGE", output.getvalue())

    def test_invalid_manifest_contracts_preserve_all_destinations(self):
        cases = ("mixed-kind", "mixed-language", "shared-partition", "mixed-label", "missing-split", "inapplicable")
        messages = ("cannot mix file and project", "cannot mix languages", "one partition", "cannot mix known-human",
                    "every calibration sample", "every sample must yield an applicable")
        for case, message in zip(cases, messages):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                manifest = prepare_inputs(base, "file")
                value = json.loads(manifest.read_text(encoding="utf-8"))
                rows = value["samples"]
                if case == "mixed-kind":
                    project = base / "project-fixture"
                    project.mkdir()
                    (project / "main.py").write_text(SOURCE, encoding="utf-8")
                    rows[0].update(path="project-fixture", kind="project")
                elif case == "mixed-language":
                    (base / "sample.js").write_text("\n".join(f"function scale{i}(value) {{\n  return value * {i+2};\n}}" for i in range(8)), encoding="utf-8")
                    rows[0].update(path="sample.js", language_hint="javascript")
                elif case == "shared-partition":
                    rows[2]["group_id"] = rows[0]["group_id"]
                elif case == "mixed-label":
                    rows[1]["group_id"] = rows[0]["group_id"]
                elif case == "missing-split":
                    del rows[0]["split"]
                else:
                    (base / rows[0]["path"]).write_text("value = 1\n", encoding="utf-8")
                write_manifest(manifest, value)
                output = base / "out"
                output.mkdir()
                for name in OUTPUTS:
                    (output / name).write_bytes(b"preserve prior output")
                before = input_snapshot(base)
                with self.assertRaisesRegex(ValueError, message):
                    calibrate(manifest, output)
                self.assertEqual(input_snapshot(base), before)

    def test_illustrative_profile_files_are_explicit_nonoperational_drafts(self):
        for name in ("02-calibration-profile-template.json", "03-example-calibration-profile.json"):
            with self.subTest(name=name):
                profile = json.loads((ROOT / "calibration" / name).read_text(encoding="utf-8"))
                self.assertIs(profile.get("operational"), False)
                self.assertFalse(profile.get("scoring_contract"))
                with self.assertRaisesRegex(ValueError, "(?i)not operational|non.operational"):
                    engine.codeprobe_analyze(json.dumps({"code": SOURCE, "filename": "sample.py", "calibration_profile": profile}))

    def test_small_partition_warning_and_infeasible_fit_remain_explicit(self):
        contract = engine.scoring_contract("default", engine.merged_metric_config("default"))
        rows = [calibrate_profile.SampleResult(str(i), label, "file", "python", score, True, 30, "high",
                split=split, group_id=f"declared-{i}", scoring_contract=contract, decision_score=score)
                for i, (label, split, score) in enumerate((("human", "fit", 1.0), ("ai_generated", "fit", .9),
                                                        ("human", "evaluation", .1), ("ai_generated", "evaluation", .9)))]
        profile = calibrate_profile.build_profile({}, rows, 0.0)
        self.assertFalse(profile["operational"])
        self.assertFalse(profile["validation"]["target_met"])
        self.assertIn("small", " ".join(profile["notes"]))
        self.assertEqual(profile["validation"]["evaluation_design"]["selection_partition"], "fit")
        changed = [copy.copy(row) for row in rows]
        changed[2].score = changed[2].decision_score = .99
        again = calibrate_profile.build_profile({}, changed, 0.0)
        self.assertEqual(profile["review_policy"], again["review_policy"])
        self.assertEqual(profile["validation"]["sensitivity"], again["validation"]["sensitivity"])

    def test_documented_commands_generate_and_apply_actual_outputs(self):
        documented = commands()
        self.assertEqual(set(documented), {"file-json", "file-csv", "project-json", "project-csv", "apply-project", "folder-wrapper", "server"})
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            for kind in TEMPLATES:
                for suffix in ("json", "csv"):
                    prepare_inputs(base, kind, suffix)
            review = base / "project-to-review"
            review.mkdir()
            (base / "review").mkdir()
            (review / "main.py").write_text(SOURCE, encoding="utf-8")
            for label in ("human", "ai"):
                for i in range(2):
                    leaf = base / "independent-files" / label / f"sample-{i}.py"
                    leaf.parent.mkdir(parents=True, exist_ok=True)
                    leaf.write_text(SOURCE + f"\nfixture_number = {i}\n", encoding="utf-8")
            for name in ("file-json", "file-csv", "project-json", "project-csv", "apply-project", "folder-wrapper"):
                with self.subTest(command=name):
                    result = subprocess.run([sys.executable, *command_args(documented[name], base)], cwd=ROOT,
                                            capture_output=True, text=True, encoding="utf-8", timeout=60)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for folder in ("file-output", "file-csv-output", "project-output", "project-csv-output", "wrapper-output"):
                for name in OUTPUTS:
                    self.assertGreater((base / folder / name).stat().st_size, 0)
            profile = json.loads((base / "project-output" / OUTPUTS[0]).read_text(encoding="utf-8"))
            report = json.loads((base / "review/report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["calibration_profile_id"], profile["profile_id"])
            self.assertEqual(report["included_file_count"], 1)
            self.assertIn("main.py", (base / "review/report.txt").read_text(encoding="utf-8"))
            wrapper = json.loads((base / "wrapper-output/generated_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(wrapper["samples"]), 4)
            self.assertTrue(all("group_id" not in row for row in wrapper["samples"]))
            print("DOCUMENTED_WORKFLOW: six distinct commands, real outputs and project replay; synthetic labels only")

    def test_cli_startup_guards_still_refuse_missing_isolation_or_site_flag(self):
        for tool in ("calibrate_profile.py", "calibrate_corpus.py", "analyze_project.py", "run_local_server.py"):
            for flags in (("-I", "-B"), ("-S", "-B")):
                with self.subTest(tool=tool, flags=flags):
                    result = subprocess.run([sys.executable, *flags, str(ROOT / "tools" / tool), "--help"],
                                            capture_output=True, text=True, encoding="utf-8", timeout=10)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("requires isolated, site-free Python", result.stdout + result.stderr)

    def test_documented_server_urls_serve_both_pages_and_process_stops(self):
        command = commands()["server"]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            process = subprocess.Popen(
                [sys.executable, *command_args(command, base)],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            self.assertIsNotNone(process.stdout)
            line_buffer: collections.deque[str] = collections.deque()
            line_condition = threading.Condition()
            stream_finished = False

            def capture_output() -> None:
                nonlocal stream_finished
                try:
                    assert process.stdout is not None
                    for line in process.stdout:
                        with line_condition:
                            line_buffer.append(line)
                            line_condition.notify()
                finally:
                    with line_condition:
                        stream_finished = True
                        line_condition.notify_all()

            reader = threading.Thread(
                target=capture_output,
                name="codeprobe-server-output",
                daemon=True,
            )
            reader.start()
            try:
                deadline = time.monotonic() + 10
                urls = []
                lines = []
                text = ""
                while time.monotonic() < deadline:
                    with line_condition:
                        remaining = deadline - time.monotonic()
                        if not line_buffer and not stream_finished:
                            line_condition.wait(timeout=min(0.10, max(0.01, remaining)))
                        while line_buffer:
                            lines.append(line_buffer.popleft())
                        finished = stream_finished
                    text = "".join(lines).replace("\r\n", "\n").replace("\r", "\n")
                    urls = re.findall(
                        r"^(?:Open|Project): "
                        r"(http://127\.0\.0\.1:\d+/app/(?:index|project)\.html)$",
                        text,
                        re.M,
                    )
                    if len(urls) == 2 or finished:
                        break
                self.assertEqual(len(urls), 2, text)
                for url, page in zip(urls, ("index.html", "project.html")):
                    with urllib.request.urlopen(url, timeout=5) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.read(), (ROOT / "app" / page).read_bytes())
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                if process.stdout is not None:
                    process.stdout.close()
                reader.join(timeout=1)
            self.assertFalse(reader.is_alive(), "server output reader did not stop")
            self.assertIsNotNone(process.returncode)


class ReportConsumerDocumentationTests(unittest.TestCase):
    def test_documented_file_and_project_projections_match_actual_fields(self):
        text = (ROOT / "docs/03-report-schema.md").read_text(encoding="utf-8")
        examples = dict(re.findall(r"<!-- report-example:(file|project) -->\s*```json\s*([^`]+)```", text))
        self.assertEqual(set(examples), {"file", "project"})
        for kind in ("file", "project"):
            with self.subTest(kind=kind):
                payload = {"code": SOURCE, "filename": "example.py"} if kind == "file" else {
                    "project_name": "example-project", "files": [{"path": "main.py", "content": SOURCE}]}
                operation = engine.codeprobe_analyze if kind == "file" else engine.codeprobe_analyze_project
                report = json.loads(operation(json.dumps(payload)))["report"]
                example = json.loads(examples[kind])
                for key, expected in example.items():
                    self.assertIn(key, report)
                    self.assertIs(type(report[key]), type(expected), key)
                    self.assertEqual(report[key], expected, key)
                self.assertIs(type(report["manual_review_recommendations"]), list)
                self.assertTrue(all(isinstance(item, str) for item in report["manual_review_recommendations"]))
                self.assertIs(type(report["engine_fingerprint"]), dict)
                self.assertRegex(report["metric_config_digest"], r"^[0-9a-f]{64}$")
                self.assertFalse({"detected_language", "input_lines", "input_sloc", "recommendations"} & example.keys())
                if kind == "file":
                    self.assertIs(type(report["loc"]), int)
                    self.assertIs(type(report["sloc"]), int)
                    self.assertEqual(report["loc"], SOURCE.count("\n") + 1)
                    self.assertEqual(report["sloc"], sum(bool(line.strip()) for line in SOURCE.splitlines()))

    def test_line_counts_retain_lf_split_endpoints_and_nonblank_comments(self):
        for source, loc, sloc in (("", 0, 0), ("value = 1", 1, 1), ("value = 1\n", 2, 1),
                                  ("# comment\r\nvalue = 1\r\n", 3, 2), ("\n\n", 3, 0)):
            with self.subTest(source=repr(source)):
                report = json.loads(engine.codeprobe_analyze(json.dumps({"code": source, "filename": "sample.py"})))["report"]
                self.assertEqual((report["loc"], report["sloc"]), (loc, sloc))

    def test_config_digest_and_measured_provenance_have_independent_oracles(self):
        config = engine.merged_metric_config("default")
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        expected = hashlib.sha256(canonical).hexdigest()
        report = json.loads(engine.codeprobe_analyze(json.dumps({"code": SOURCE, "filename": "example.py"})))["report"]
        self.assertEqual(report["metric_config_digest"], expected)
        actual_source = hashlib.sha256((ROOT / "src/codeprobe_runtime.py").read_bytes()).hexdigest()
        self.assertEqual(report["engine_fingerprint"]["value"], actual_source)
        declared = json.loads(engine.codeprobe_analyze(json.dumps({"code": SOURCE, "filename": "example.py",
                  "engine_fingerprint": {"value": "0" * 64, "source": "claimed-measurement"}})))["report"]["engine_fingerprint"]
        self.assertEqual(declared["source"], "caller-unverified")
        self.assertIs(declared["matches_loaded_source"], False)
        self.assertEqual(declared["measured_sha256"], actual_source)
        with mock.patch.object(engine, "__file__", "nonexistent-source-for-owned-test"):
            missing = engine.effective_engine_fingerprint()
        self.assertFalse(missing["available"])
        self.assertEqual(missing["value"], "")

    def test_fitted_profiles_replay_without_exporting_individual_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            for kind in TEMPLATES:
                with self.subTest(kind=kind):
                    profile = calibrate(prepare_inputs(base, kind), base / (kind + "-out"))
                    payload = {"code": SOURCE, "filename": "sample.py"} if kind == "file" else {"files": [{"path": "main.py", "content": SOURCE}]}
                    payload["calibration_profile"] = profile
                    operation = engine.codeprobe_analyze if kind == "file" else engine.codeprobe_analyze_project
                    report = json.loads(operation(json.dumps(payload)))["report"]
                    compact = report["calibration_profile"]["validation"]
                    self.assertEqual(report["calibration_profile_id"], profile["profile_id"])
                    self.assertNotIn("sample_results", compact)
                    self.assertNotIn("sensitivity", compact)
                    self.assertEqual(compact["descriptive_review_rates"], profile["validation"]["descriptive_review_rates"])
                    for key, value in (("engine_sha256", "0" * 64), ("metric_config_digest", "0" * 64)):
                        altered = copy.deepcopy(payload)
                        altered["calibration_profile"]["scoring_contract"][key] = value
                        with self.assertRaisesRegex(ValueError, "(?i)identity|configuration"):
                            operation(json.dumps(altered))
                    wrong_kind = engine.codeprobe_analyze_project if kind == "file" else engine.codeprobe_analyze
                    wrong_payload = {"files": [{"path": "main.py", "content": SOURCE}]} if kind == "file" else {"code": SOURCE, "filename": "sample.py"}
                    with self.assertRaisesRegex(ValueError, "(?i)incompatible"):
                        wrong_kind(json.dumps({**wrong_payload, "calibration_profile": profile}))


class EducationalContractTests(unittest.TestCase):
    def score_report(self, score: float, kind: str, policy: dict | None = None, code: str = SOURCE) -> dict:
        class FixedMetric:
            enabled = True
            name = "owned-score-fixture"
            def __init__(self, config):
                pass
            def supports(self, language):
                return True
            def compute(self, source, language, context):
                return engine.MetricResult(self.name, "Owned test fixture", score, str(score), score, .25, True, "Synthetic metric double")
        payload = {"code": code, "filename": "sample.py"} if kind == "file" else {"files": [{"path": "main.py", "content": code}]}
        if policy:
            payload["calibration_profile"] = {"profile_id": "owned-policy-not-fitted", "review_policy": policy}
        operation = engine.codeprobe_analyze if kind == "file" else engine.codeprobe_analyze_project
        with mock.patch.object(engine.MetricRegistry, "metric_classes", return_value=[FixedMetric] * 4):
            return json.loads(operation(json.dumps(payload)))["report"]

    def test_default_boundary_examples_keep_class_and_inclusive_trigger_separate(self):
        expected = ((28, "moderate", False), (48, "elevated", False), (50, "elevated", False),
                    (60, "elevated", True), (68, "high", True), (75, "high", True))
        text = (ROOT / "educator/07-course-integration.md").read_text(encoding="utf-8")
        for percent, reading, triggered in expected:
            self.assertIn(f"| {percent}% | `{reading}` | {'Yes' if triggered else 'No'} |", text)
            for kind in ("file", "project"):
                with self.subTest(percent=percent, kind=kind):
                    report = self.score_report(percent / 100, kind)
                    self.assertAlmostEqual(report["decision_score"], percent / 100)
                    self.assertEqual(report["reading_class"], reading)
                    self.assertIs(report["review_triggered"], triggered)

    def test_a_local_policy_is_not_described_by_the_default_bands(self):
        policy = {kind: {"low_max": .1, "moderate_max": .2, "elevated_max": .3, "review_trigger": .5}
                  for kind in ("file", "project")}
        for kind in policy:
            with self.subTest(kind=kind):
                report = self.score_report(.5, kind, policy)
                self.assertEqual(report["reading_class"], "high")
                self.assertEqual(report["review_trigger"], .5)
                self.assertTrue(report["review_triggered"])

    def test_nonapplicable_input_never_triggers_a_numeric_review(self):
        for kind in ("file", "project"):
            with self.subTest(kind=kind):
                report = self.score_report(.9, kind, code="value = 1\n")
                self.assertFalse(report["overall_applicable"])
                self.assertFalse(report["review_triggered"])

    def test_xml_declaration_preserves_shadowing_and_third_party_refusals(self):
        self.assertIn("xml", check_dependency_boundary.APPROVED_STDLIB_IMPORTS)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "tests").mkdir()
            source = base / "tests/test_xml.py"
            source.write_text("import xml.etree.ElementTree as ET\n", encoding="utf-8")
            self.assertEqual(check_dependency_boundary.check_python_imports(base), [])
            source.write_text("import lxml.etree as ET\n", encoding="utf-8")
            self.assertTrue(any("third-party or unresolved import 'lxml'" in error
                                for error in check_dependency_boundary.check_python_imports(base)))
            source.write_text("import xml.etree.ElementTree as ET\n", encoding="utf-8")
            (base / "tests/xml.py").write_text("VALUE = 1\n", encoding="utf-8")
            self.assertTrue(any("standard-library shadow" in error
                                for error in check_dependency_boundary.check_standard_library_shadowing(base)))

    def test_announcement_docx_matches_markdown_and_has_factual_metadata(self):
        text = (ROOT / "educator/02-student-announcement.md").read_text(encoding="utf-8")
        expected = [re.sub(r"^#\s+", "", p).strip() for p in re.split(r"\n\s*\n", text.strip())]
        with zipfile.ZipFile(ROOT / "educator/02-student-announcement.docx") as package:
            document = ET.fromstring(package.read("word/document.xml"))
            paragraphs = ["".join(p.itertext()) for p in document.findall("./w:body/w:p", NS)]
            self.assertEqual(paragraphs, expected)
            core = ET.fromstring(package.read("docProps/core.xml"))
            self.assertEqual(core.findtext("dc:creator", namespaces=NS), "Antonio Clim")
            self.assertIsNone(core.find("dcterms:created", NS))
            self.assertIsNone(core.find("dcterms:modified", NS))
            self.assertIsNone(core.find("cp:lastModifiedBy", NS))
            self.assertNotIn("v2.1.4", core.findtext("dc:description", default="", namespaces=NS))
            app = ET.fromstring(package.read("docProps/app.xml"))
            app_ns = "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}"
            self.assertEqual(app.findtext(app_ns + "Application"), "python-docx")
            self.assertEqual([child.tag for child in app], [app_ns + "Application"])
            languages = []
            for name in package.namelist():
                if name.startswith("word/") and name.endswith(".xml"):
                    part = ET.fromstring(package.read(name))
                    languages.extend(e.get("{" + NS["w"] + "}val") for e in part.findall(".//w:lang", NS))
                    for tag in ("ins", "del", "moveFrom", "moveTo", "commentRangeStart", "commentReference"):
                        self.assertFalse(part.findall(".//w:" + tag, NS))
                if name.endswith(".rels"):
                    self.assertNotIn(b'TargetMode="External"', package.read(name))
            self.assertTrue(languages)
            self.assertEqual(set(languages), {"en-GB"})
            footer = " ".join("".join(ET.fromstring(package.read(n)).itertext()) for n in package.namelist() if re.fullmatch(r"word/footer\d+\.xml", n))
            self.assertIn("formative local self-check; review trigger, not verdict", footer)

    def test_current_guidance_does_not_restore_the_replaced_claims(self):
        for relative in ("calibration/README.md", "docs/06-calibration-guide.md", "educator/01-student-quick-start.md",
                         "educator/02-student-announcement.md", "educator/07-course-integration.md", "educator/09-project-kit-notice.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(document=relative):
                self.assertNotIn("deterministic pseudonyms unless", text)
                self.assertNotRegex(text, r"(?i)(?:score|result) (?:is )?above (?:the )?(?:active )?(?:review )?trigger")
                self.assertNotRegex(text, r"python3? (?:codeprobe/)?tools/")
        for relative in ("calibration/README.md", "docs/06-calibration-guide.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("UUID4", text)
            self.assertIn("not anonymisation", text)
            self.assertIn("four", text)


if __name__ == "__main__":
    unittest.main()
