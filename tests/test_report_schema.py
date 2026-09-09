from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402


class PhaseTwoReportSchemaTests(unittest.TestCase):
    def test_json_entrypoint_report_contains_stable_phase_two_fields(self) -> None:
        payload = {
            "code": "def add(left, right):\n    return left + right\n",
            "filename": "sample.py",
            "language_hint": "python",
            "profile": "default",
        }
        bundle = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
        self.assertIn("report", bundle)
        self.assertIn("text", bundle)
        report = bundle["report"]
        for key in [
            "app_name",
            "app_version",
            "schema_version",
            "filename",
            "language",
            "loc",
            "sloc",
            "overall_score",
            "overall_percent",
            "overall_applicable",
            "confidence",
            "verdict",
            "verdict_class",
            "profile",
            "duration_seconds",
            "notes",
            "warnings",
            "metrics",
        ]:
            self.assertIn(key, report)
        self.assertEqual(report["app_name"], engine.APP_NAME)
        self.assertEqual(report["app_version"], engine.APP_VERSION)
        self.assertEqual(report["schema_version"], "2.2.0")
        self.assertIsInstance(report["metrics"], list)
        self.assertTrue(report["metrics"])
        for metric in report["metrics"]:
            self.assertIn("group", metric)
            self.assertIn("contributes_to_overall", metric)
            self.assertIn(metric["group"], {"stylometry", "context", "quality", "documentation"})

    def test_invalid_override_surfaces_as_error(self) -> None:
        payload = {
            "code": "def add(a, b):\n    return a + b\n",
            "filename": "sample.py",
            "language_hint": "python",
            "profile": "default",
            "config_override": {"comment_density": {"group": "invalid"}},
        }
        with self.assertRaises(ValueError):
            engine.codeprobe_analyze(json.dumps(payload))

class IntakeProvenanceSchemaTests(unittest.TestCase):
    provenance = {"encoding": "latin-1", "normalisation": "newlines", "warnings": ["Decoded as latin-1; review the file encoding."]}

    def test_file_provenance_survives_json_and_text_as_a_caller_declaration(self):
        bundle = json.loads(engine.codeprobe_analyze(json.dumps({"code": "print('café')\n", "filename": "cafe.py", "intake_provenance": self.provenance})))
        self.assertEqual(bundle["report"]["intake_provenance"], {**self.provenance, "source": "caller-reported"})
        self.assertIn(self.provenance["warnings"][0], bundle["text"])
        self.assertIn("cafe.py: caller-reported", bundle["text"])

    def test_project_provenance_retains_paths_included_children_and_text(self):
        report = engine.analyse_project_payload({"files": [{"path": "src/cafe.py", "content": "print('café')\n", "intake_provenance": self.provenance}]})
        self.assertEqual(report["intake_provenance"], [{"path": "src/cafe.py", **self.provenance, "source": "caller-reported"}])
        self.assertEqual(report["files"][0]["intake_provenance"]["source"], "caller-reported")
        self.assertIn(self.provenance["warnings"][0], report["files"][0]["warnings"][-1])
        self.assertIn(self.provenance["warnings"][0], engine.format_project_report_text(report))

    def test_native_and_caller_provenance_are_distinct_and_utf8_gets_no_false_warning(self):
        valid = {"encoding": "utf-8", "normalisation": "none", "warnings": []}
        native = engine._NativeProjectFile(path="main.py", content="print(1)\n", size_bytes=9, intake_provenance=valid)
        report = engine.analyse_project_payload({"files": engine._NativeProjectFiles([native], unexpanded_directories=["node_modules"])})
        self.assertEqual(report["files"][0]["intake_provenance"]["source"], "native-intake")
        self.assertEqual(report["input_packaging"]["unexpanded_directories"], ["node_modules"])
        self.assertFalse(any("intake:" in warning for warning in report["warnings"]))
        empty = engine.analyse_project_payload({"files": engine._NativeProjectFiles(unexpanded_directories=["node_modules"])})
        self.assertEqual(empty["input_packaging"]["source"], "native-folder")

    def test_invalid_provenance_fails_before_file_or_project_collection(self):
        cases = [None, [], {}, {**self.provenance, "source": "native-intake"}, {**self.provenance, "encoding": []},
                 {**self.provenance, "normalisation": "unknown"}, {**self.provenance, "warnings": "text"},
                 {**self.provenance, "warnings": ["x"] * 9}, {**self.provenance, "warnings": ["x" * 513]},
                 {**self.provenance, "warnings": ["😀" * 513]}, {**self.provenance, "warnings": ["bad\x00"]},
                 {**self.provenance, "warnings": ["bad\x85"]}, {**self.provenance, "warnings": ["\ud800"]}]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                engine.validate_analysis_payload({"code": "print(1)", "intake_provenance": raw})
            with self.subTest(project_raw=raw), self.assertRaises(ValueError):
                engine.validate_analysis_payload({"files": [{"path": "main.py", "content": "print(1)", "intake_provenance": raw}]}, "project")

    def test_markup_is_retained_as_text_and_metadata_does_not_relax_content_limits(self):
        boundary = {**self.provenance, "warnings": ["😀" * 512]}
        self.assertEqual(engine.validate_intake_provenance(boundary), boundary)
        provenance = {**self.provenance, "warnings": ["<img src=x onerror=alert(1)>"]}
        bundle = json.loads(engine.codeprobe_analyze(json.dumps({"code": "print(1)\n", "filename": "main.py", "intake_provenance": provenance})))
        self.assertEqual(bundle["report"]["intake_provenance"]["warnings"], provenance["warnings"])
        report = engine.analyse_project_payload({"max_file_bytes": 1, "files": [{"path": "main.py", "content": "print(1)\n", "size_bytes": 0, "intake_provenance": provenance}]})
        self.assertEqual(report["excluded_files"][0]["reason"], "file_too_large")
        self.assertEqual(report["excluded_files"][0]["size_bytes"], 9)


class ScriptDiagnosticReportTests(unittest.TestCase):
    def test_unclosed_script_diagnostics_survive_file_project_json_and_text(self):
        cases = (("broken.js", 'const message = "unfinished', "JS_UNTERMINATED_STRING"),
                 ("comment.js", 'function f() {}\n/* unfinished', "JS_UNTERMINATED_COMMENT"),
                 ("template.js", 'const message = `unfinished', "JS_UNTERMINATED_TEMPLATE"),
                 ("broken.sh", "echo 'unfinished", "BASH_UNTERMINATED_STRING"))
        for filename, source, diagnostic in cases:
            with self.subTest(filename=filename):
                file_bundle = json.loads(engine.codeprobe_analyze(json.dumps({"code": source, "filename": filename})))
                project_bundle = json.loads(engine.codeprobe_analyze_project(json.dumps({"files": [{"path": filename, "content": source}]})))
                reports = (file_bundle["report"], project_bundle["report"]["included_files"][0])
                for report in reports:
                    self.assertTrue(any(diagnostic in warning for warning in report["warnings"]))
                    metrics = {item["name"]: item for item in report["metrics"]}
                    for name in ("cyclomatic_complexity", "halstead_difficulty"):
                        self.assertFalse(metrics[name]["applicable"])
                        self.assertIsNone(metrics[name]["value"])
                    self.assertNotIn("parse_success", report)
                self.assertIn(diagnostic, file_bundle["text"])
                self.assertIn(diagnostic, project_bundle["text"])
                self.assertTrue(any(filename + ":" in warning and diagnostic in warning for warning in project_bundle["report"]["warnings"]))

    def test_script_feature_requirement_is_a_strict_boolean_before_analysis(self):
        for value in (None, "false", 0, 1, []):
            for kind, entry in (("file", engine.codeprobe_analyze), ("project", engine.codeprobe_analyze_project)):
                with self.subTest(value=value, kind=kind), mock.patch.object(engine, "build_analysis_context") as analyse:
                    with self.assertRaisesRegex(ValueError, "require_script_features"):
                        entry(json.dumps({"require_script_features": value}))
                    analyse.assert_not_called()

    def test_required_and_bound_script_features_refuse_partial_file_and_project_inputs(self):
        config = engine.merged_metric_config("default")
        profile = {"profile_id": "owned-script-contract", "scoring_contract": engine.scoring_contract("default", config)}
        cases = (("broken.js", 'const value = "unfinished'),
                 ("typed.ts", "function make(): {value: number} { return {value: 1}; }\n"),
                 ("broken.sh", "cat <<'EOF'\nunfinished\n"))
        controls = ({"require_script_features": True}, {"calibration_profile": profile, "require_script_features": False})
        for filename, source in cases:
            for control in controls:
                with self.subTest(filename=filename, control=control):
                    with self.assertRaisesRegex(ValueError, "(?i)script.*features|javascript.*features|bash.*features"):
                        engine.codeprobe_analyze(json.dumps({"code": source, "filename": filename, **control}))
                    with self.assertRaisesRegex(ValueError, "(?i)script.*features|javascript.*features|bash.*features"):
                        engine.codeprobe_analyze_project(json.dumps({"files": [{"path": filename, "content": source}], **control}))
        for filename, source in (("ordinary.js", "function f() { return 1; }\n"), ("ordinary.sh", "f() { echo ok; }\n")):
            for control in controls:
                with self.subTest(ordinary=filename, control=control):
                    report = json.loads(engine.codeprobe_analyze(json.dumps({"code": source, "filename": filename, **control})))["report"]
                    self.assertEqual(report["filename"], filename)
                    project = json.loads(engine.codeprobe_analyze_project(json.dumps({"files": [{"path": filename, "content": source}], **control})))["report"]
                    self.assertEqual(project["included_file_count"], 1)


class CyclomaticMethodSchemaTests(unittest.TestCase):
    def test_three_cyclomatic_methods_keep_their_values_and_export_exact_units(self):
        cases = (
            ("def first():\n    return 0\n\ndef second(a, b):\n    if a:\n        return 1\n    if b:\n        return 2\n    return 0\n", "fixture.py", 2, 1.0,
             "python_ast_function_mean", "decisions_per_function", "recognised_functions"),
            ("int first(void) {\n    return 0;\n}\nint second(int a, int b) {\n    if (a) a++;\n    if (b) b++;\n    return a + b;\n}\n", "fixture.c", 2, 1.0,
             "lexical_function_mean", "decisions_per_function", "recognised_functions"),
            ("if (a) ready();\nif (b) ready();\n" + "ready();\n" * 8, "fixture.js", 4, 51/121,
             "lexical_branch_density", "branches_per_20_code_lines", "cleaned_file_code"),
        )
        for source, filename, value, score, method, unit, domain in cases:
            for operation, payload, project in (
                (engine.codeprobe_analyze, {"code": source, "filename": filename}, False),
                (engine.codeprobe_analyze_project, {"files": [{"path": filename, "content": source}]}, True),
            ):
                with self.subTest(method=method, project=project):
                    bundle = json.loads(operation(json.dumps(payload)))
                    report = bundle["report"]["files"][0] if project else bundle["report"]
                    result = next(item for item in report["metrics"] if item["name"] == "cyclomatic_complexity")
                    self.assertEqual(result["value"], value)
                    self.assertAlmostEqual(result["score"], round(score, 4))
                    self.assertEqual((result["method"], result["unit"], result["domain"]), (method, unit, domain))
                    self.assertEqual(result["group"], "context")
                    self.assertFalse(result["contributes_to_overall"])
                    for label, text in (("method", method), ("unit", unit), ("domain", domain)):
                        self.assertIn(label + "=" + text, result["detail"])
                        self.assertIn(text, bundle["text"])

    def test_unavailable_cyclomatic_metrics_do_not_claim_a_measurement_method(self):
        for source, filename in (("value = 1\n", "fixture.py"), ('const value = "unterminated\n', "fixture.js")):
            bundle = json.loads(engine.codeprobe_analyze(json.dumps({"code": source, "filename": filename})))
            result = next(item for item in bundle["report"]["metrics"] if item["name"] == "cyclomatic_complexity")
            self.assertFalse(result["applicable"])
            self.assertIsNone(result["value"])
            self.assertTrue(result["explanation"])
            for key in ("method", "unit", "domain"):
                self.assertFalse(result.get(key))



class EvidenceCoverageReportingTests(unittest.TestCase):
    SOURCE = "\n".join(f'def scale_{i}(value):\n    """Return a scaled value."""\n    result = value * {i + 2}\n    return result\n' for i in range(8))

    def file_bundle(self, source=None, filename="sample.py", **extra):
        return json.loads(engine.codeprobe_analyze(json.dumps({
            "code": self.SOURCE if source is None else source, "filename": filename, **extra})))

    def test_file_category_alias_factors_and_text_are_consistent(self):
        bundle = self.file_bundle()
        report = bundle["report"]
        basis = report["evidence_coverage_basis"]
        self.assertEqual(report["evidence_coverage"], report["confidence"])
        self.assertEqual(basis["category"], report["confidence"])
        self.assertEqual(basis["factors"]["sloc"], report["sloc"])
        eligible = [m for m in report["metrics"] if m["applicable"] and m["weight"] > 0 and m["contributes_to_overall"]]
        self.assertTrue(eligible)
        self.assertEqual(basis["factors"]["applicable_contributors"], len(eligible))
        self.assertIn("not a probability", basis["interpretation"])
        self.assertIn("Evidence coverage: " + report["confidence"], bundle["text"])
        self.assertNotIn("Confidence:", bundle["text"])
        self.assertIn("Nominal configured weight: 0.31", bundle["text"])
        self.assertIn(f"eligible metric denominator: {report['aggregation']['effective_weight']:.6g}", bundle["text"])

    def test_sparse_and_markdown_reports_do_not_apply_an_ineligible_aggregate(self):
        override = {"markdown_heading_structure": {"contributes_to_overall": True, "weight": 0.5}}
        for source, name, options, category in (
            ("value = 1\n", "tiny.py", {}, "Limited"),
            ("# Title\n## Detail\n", "notes.md", {"config_override": override}, "N/A"),
        ):
            with self.subTest(name=name):
                report = self.file_bundle(source, name, **options)["report"]
                self.assertEqual(report["evidence_coverage"], category)
                self.assertFalse(report["overall_applicable"])
                self.assertEqual(report["aggregation"]["aggregate_applied_weight"], 0)
                self.assertGreater(report["aggregation"]["effective_weight"], 0)

    def test_project_and_child_factors_keep_late_exclusion_warning_separate(self):
        bundle = json.loads(engine.codeprobe_analyze_project(json.dumps({
            "project_name": "coverage-fixture", "files": [
                {"path": f"module_{i}.py", "content": self.SOURCE} for i in range(3)
            ] + [{"path": "README.md", "content": "# Documentation\n"}]})))
        report = bundle["report"]
        basis = report["evidence_coverage_basis"]
        self.assertEqual(report["evidence_coverage"], report["confidence"])
        self.assertEqual(basis["factors"]["included_files"], 3)
        self.assertEqual(report["excluded_file_count"], 1)
        self.assertGreater(len(report["warnings"]), basis["factors"]["warning_count_at_classification"])
        self.assertIn("later", basis["warning_timing"])
        self.assertEqual(report["aggregation"]["effective_weight_sloc"],
                         sum(item["weight"] for item in report["aggregation"]["contributors"]))
        for child in report["files"]:
            self.assertEqual(child["confidence"], child["evidence_coverage"])
            self.assertEqual(child["evidence_coverage_basis"]["factors"]["sloc"], child["sloc"])
        self.assertIn("Nominal configured weight: 0.31", bundle["text"])

    def test_project_category_rule_boundaries_remain_the_retained_rules(self):
        cases = ((0, 0, 0, 0, "Limited"), (79, 2, 2, 0, "Limited"),
                 (80, 2, 2, 0, "Moderate"), (249, 5, 5, 0, "Moderate"),
                 (250, 5, 5, 4, "High"), (250, 5, 5, 5, "Moderate"),
                 (1000, 8, 0, 0, "Limited"))
        for sloc, included, contributing, warnings, expected in cases:
            with self.subTest(values=(sloc, included, contributing, warnings)):
                self.assertEqual(engine.project_confidence(sloc, included, contributing, warnings), expected)


class SourceProxyReportingTests(unittest.TestCase):
    SOURCE = "int sum(int *items, int n) {\n  int total = 0;\n  int scratch[10];\n  for (int i=0; i<n; i++) { total += items[i] + items[i]; }\n  return total;\n}\n"

    def test_memory_proxy_values_remain_visible_with_bounded_meanings(self):
        expected = {"register_pressure": (2/13, "peak_scalar_names_per_13"),
                    "stack_frame_depth": (48, "estimated_bytes"),
                    "redundant_memory_access": (20/3, "cues_per_20_function_lines")}
        for project in (False, True):
            with self.subTest(project=project):
                payload = {"files": [{"path": "sample.c", "content": self.SOURCE}]} if project else {"filename": "sample.c", "code": self.SOURCE}
                bundle = json.loads((engine.codeprobe_analyze_project if project else engine.codeprobe_analyze)(json.dumps(payload)))
                report = bundle["report"]["files"][0] if project else bundle["report"]
                metrics = {item["name"]: item for item in report["metrics"]}
                for name, (value, unit) in expected.items():
                    metric = metrics[name]
                    self.assertTrue(metric["applicable"])
                    self.assertAlmostEqual(metric["value"], value)
                    self.assertEqual(metric["unit"], unit)
                    self.assertEqual(metric["domain"], "recognised_functions")
                    self.assertIn("source", metric["explanation"].lower())
                    self.assertIn("not", metric["explanation"].lower())
                    self.assertIn(metric["explanation"], bundle["text"])
                    self.assertTrue(metric["reference_usage"])
                    self.assertEqual([x["citation"] for x in metric["reference_usage"]], metric["references"])
                    for reference in metric["reference_usage"]:
                        self.assertIn(reference["role"], {"definition", "motivation", "context"})
                        self.assertTrue(reference["scope"])

    def test_unavailable_proxy_does_not_claim_a_measurement_method(self):
        report = engine.report_to_dict(engine.AnalysisEngine(engine.merged_metric_config("default")).analyse("int value;\n", "no_functions.c"))
        for metric in report["metrics"]:
            if metric["name"] in {"register_pressure", "stack_frame_depth", "redundant_memory_access"}:
                self.assertFalse(metric["applicable"])
                self.assertIsNone(metric["value"])
                self.assertFalse(metric.get("method"))


if __name__ == "__main__":
    unittest.main()
