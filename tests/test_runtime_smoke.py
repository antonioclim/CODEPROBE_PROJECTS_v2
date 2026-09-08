from __future__ import annotations

import base64
import io
import json
import math
import sys
import tokenize
import unittest
import zipfile
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402
from codeprobe_engine import api  # noqa: E402


class PhaseOneSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analysis_engine = engine.AnalysisEngine(engine.merged_metric_config("default"))

    def test_version_is_current_phase_release(self) -> None:
        self.assertEqual(engine.APP_VERSION, "2.2.0")

    def test_markdown_is_documentation_only(self) -> None:
        markdown = """# Project notes

This short document explains how the program is launched.

```python
print("hello")
```

See [course page](https://example.invalid/course).
"""
        report = self.analysis_engine.analyse(markdown, "README.md", "markdown")
        self.assertEqual(report.verdict_class, "documentation")
        self.assertFalse(report.overall_applicable)
        markdown_metrics = [item for item in report.metrics if item.group == "documentation"]
        self.assertTrue(markdown_metrics)
        self.assertTrue(all(not item.contributes_to_overall for item in markdown_metrics))

    def test_quality_practice_metrics_do_not_contribute_to_ai_score(self) -> None:
        source = '''
from __future__ import annotations


def add(left: int, right: int) -> int:
    """Return the sum of two integers."""
    return left + right


def subtract(left: int, right: int) -> int:
    """Return the difference between two integers."""
    return left - right
'''
        report = self.analysis_engine.analyse(source, "calculator.py", "python")
        metrics = {item.name: item for item in report.metrics}
        for name in ["docstring_coverage", "type_hint_coverage", "used_import_ratio", "indentation_consistency"]:
            if name in metrics and metrics[name].applicable:
                self.assertEqual(metrics[name].group, "quality")
                self.assertFalse(metrics[name].contributes_to_overall)

    def test_ambiguous_structure_metrics_are_context_only(self) -> None:
        source = """
from __future__ import annotations


def main(argv: list[str]) -> int:
    try:
        if argv:
            return len(argv)
        return 0
    except Exception:
        return 1
"""
        report = self.analysis_engine.analyse(source, "runner.py", "python")
        metrics = {item.name: item for item in report.metrics}
        for name in ["error_handling_density", "boilerplate_presence", "cyclomatic_complexity", "defensive_programming"]:
            if name in metrics and metrics[name].applicable:
                self.assertEqual(metrics[name].group, "context")
                self.assertFalse(metrics[name].contributes_to_overall)

    def test_config_override_rejects_unknown_metric(self) -> None:
        with self.assertRaises(ValueError):
            engine.merged_metric_config("default", {"not_a_metric": {"weight": 0.1}})

    def test_config_override_rejects_unknown_key(self) -> None:
        with self.assertRaises(ValueError):
            engine.merged_metric_config("default", {"comment_to_code_ratio": {"banana": 0.1}})

    def test_json_entrypoint_exposes_overall_applicability(self) -> None:
        payload = {
            "code": "# Title\n\nA short Markdown note with a code block.\n",
            "filename": "README.md",
            "language_hint": "markdown",
            "profile": "default",
        }
        output = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
        self.assertFalse(output["report"]["overall_applicable"])
        self.assertEqual(output["report"]["verdict_class"], "documentation")


class RuntimeInputContractTests(unittest.TestCase):
    SOURCE = "def add(left, right):\n    return left + right\n"
    ENTRYPOINTS = {
        "file": engine.codeprobe_analyze,
        "project": engine.codeprobe_analyze_project,
        "metadata": engine.codeprobe_engine_metadata,
    }

    def assert_rejected_before_resources(self, raw, kind="file", *, direct=False):
        with ExitStack() as stack:
            probes = [stack.enter_context(mock.patch.object(engine, name)) for name in
                      ("engine_source_fingerprint", "detect_language", "collect_project_files")]
            probes.append(stack.enter_context(mock.patch.object(engine.base64, "b64decode")))
            with self.assertRaises(ValueError):
                if direct:
                    engine.analyse_project_payload(raw)
                else:
                    self.ENTRYPOINTS[kind](raw)
            for probe in probes:
                probe.assert_not_called()

    def test_non_object_roots_are_rejected_before_resources(self):
        for kind in self.ENTRYPOINTS:
            for raw in ("null", "[]", '"source"', "17", "true"):
                with self.subTest(kind=kind, raw=raw):
                    self.assert_rejected_before_resources(raw, kind)
        for raw in (None, [], "source", 17, True):
            with self.subTest(direct=raw):
                self.assert_rejected_before_resources(raw, "project", direct=True)

    def test_ambiguous_and_nonfinite_json_is_rejected_for_every_entry(self):
        inputs = ('{"extra":1,"extra":2}', '{"extra":{"a":1,"a":2}}',
                  '{"extra":NaN}', '{"extra":Infinity}', '{"extra":-Infinity}',
                  '{"extra":1e999}', '{"extra":-1e999}', '{broken')
        for kind in self.ENTRYPOINTS:
            for raw in inputs:
                with self.subTest(kind=kind, raw=raw):
                    self.assert_rejected_before_resources(raw, kind)

    def test_file_fields_have_explicit_types(self):
        fields = {
            "code": (None, 17, {}, []), "filename": (None, 17, {}),
            "language_hint": (17, [], {}), "profile": (17, [], "unknown"),
            "require_python_ast": (None, 1, "false"),
        }
        for name, values in fields.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    self.assert_rejected_before_resources(json.dumps({name: value}))

    def test_project_fields_and_all_entries_are_checked_before_collection(self):
        invalid = ({"project_name": 17}, {"include_documentation": "false"},
                   {"zip_base64": 17}, {"ignore_text": []}, {"files": None},
                   {"files": {}}, {"files": [None]},
                   {"files": [{"path": 17, "content": ""}]},
                   {"files": [{"name": [], "text": ""}]},
                   {"files": [{"path": "a.py", "content": 17}]},
                   {"files": [{"path": "a.py", "text": []}]},
                   {"files": [{"path": "a.py", "content": self.SOURCE},
                              {"path": "b.py", "content": 17}]})
        for payload in invalid:
            with self.subTest(payload=payload):
                self.assert_rejected_before_resources(payload, "project", direct=True)
                self.assert_rejected_before_resources(json.dumps(payload), "project")

    def test_invalid_declared_sizes_cannot_reach_resources(self):
        for size in (True, -1, 1.9, "1.9", float("nan"), float("inf"), [], {}):
            payload = {"files": [{"path": "a.py", "content": self.SOURCE, "size_bytes": size}]}
            with self.subTest(size=size):
                self.assert_rejected_before_resources(payload, "project", direct=True)

    def test_invalid_metadata_only_records_fail_during_preflight(self):
        valid = {"path": "large.py", "size_bytes": 1000001,
                 "intake_rejection": {"reason": "file_too_large"}}
        for changes in ({"size_bytes": "1000001"}, {"size_bytes": 1000001.0},
                        {"size_bytes": 2**53}, {"content": "print(1)"},
                        {"intake_rejection": {"reason": "unknown"}},
                        {"intake_rejection": {"reason": "file_too_large", "extra": True}}):
            with self.subTest(changes=changes):
                self.assert_rejected_before_resources({"files": [dict(valid, **changes)]}, "project", direct=True)

    def test_invalid_configuration_is_not_replaced_by_defaults(self):
        invalid = ([], "{}", {"unknown": {}}, {"comment_density": {"group": []}},
                   {"comment_density": {"weight": float("nan")}},
                   {"comment_density": {"thresholds": {"ai_low": float("inf")}}})
        for override in invalid:
            for kind in self.ENTRYPOINTS:
                with self.subTest(override=override, kind=kind):
                    self.assert_rejected_before_resources(json.dumps({"config_override": override}), kind)
        self.assert_rejected_before_resources({"config_override": invalid[-1]}, "project", direct=True)

    def test_embedded_calibration_json_uses_the_strict_parser(self):
        invalid = ('{"profile_id":"one","profile_id":"two"}', "null", "[]",
                   '{"validation":{"sample_count":NaN}}', '{broken')
        invalid_policy_aliases = (
            {"review_policy": []}, {"review_thresholds": False}, {"review_bands": 0},
            {"language_review_policy": []}, {"review_policy_by_language": ""},
            {"language_review_policy": {"python": []}},
            {"review_policy_by_language": {"invalid": {}}},
            {"language_review_policy": {"python": {}}, "review_policy_by_language": {"python": False}},
            {"review_policy": {}, "review_thresholds": []},
        )
        for field in ("calibration_profile", "calibration_profile_json"):
            for value in (*invalid, [], True, 17, {"metric_overrides": []}, *invalid_policy_aliases):
                with self.subTest(field=field, value=value):
                    self.assert_rejected_before_resources(json.dumps({field: value}))

    def test_metadata_optional_defaults_and_fingerprint_types(self):
        default = json.loads(engine.codeprobe_engine_metadata())
        self.assertEqual(json.loads(engine.codeprobe_engine_metadata("")), default)
        self.assertEqual(json.loads(engine.codeprobe_engine_metadata('{"engine_fingerprint":null}')), default)
        for value in (None, [], 17):
            with self.subTest(argument=value):
                self.assert_rejected_before_resources(value, "metadata")
        for fingerprint in ([], 17, {"value": []}, {"available": "yes"}, {"source": 17}):
            with self.subTest(fingerprint=fingerprint):
                self.assert_rejected_before_resources(json.dumps({"engine_fingerprint": fingerprint}), "metadata")

    def test_ordinary_file_payload_and_null_controls_preserve_reports(self):
        payload = {"code": self.SOURCE, "filename": "sum.py", "language_hint": None,
                   "profile": None, "config_override": None, "calibration_profile": None}
        output = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
        report = output["report"]
        self.assertEqual((report["filename"], report["language"], report["profile"]),
                         ("sum.py", "python", "default"))
        self.assertIn("File: sum.py", output["text"])
        self.assertEqual(report["metric_config_digest"], engine.metric_config_digest(engine.merged_metric_config("default")))
        payload["calibration_profile"] = {"review_policy": {}, "review_thresholds": None,
                                          "review_bands": {}, "language_review_policy": None,
                                          "review_policy_by_language": {"python": {}}}
        default_policy_report = json.loads(engine.codeprobe_analyze(json.dumps(payload)))["report"]
        self.assertEqual(default_policy_report["review_policy"], report["review_policy"])
        self.assertEqual(default_policy_report["metric_config_digest"], report["metric_config_digest"])
        empty = json.loads(engine.codeprobe_analyze("{}"))["report"]
        self.assertEqual((empty["filename"], empty["loc"]), ("fragment.py", 0))

    def test_project_aliases_text_alias_and_browser_rejections_remain_valid(self):
        payload = {"project_name": "exercise", "profile": None, "config_override": None,
                   "calibration_profile": None, "include_documentation": False,
                   "files": [{"path": "sum.py", "content": self.SOURCE, "size_bytes": 1.0},
                             {"name": "copy.py", "content": None, "text": self.SOURCE},
                             {"path": "large.py", "size_bytes": 1000001,
                              "intake_rejection": {"reason": "file_too_large"}}]}
        before = json.dumps(payload, sort_keys=True)
        output = json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
        self.assertEqual(output["report"], output["project_report"])
        self.assertIn("Project: exercise", output["text"])
        self.assertEqual({item["path"] for item in output["report"]["included_files"]}, {"sum.py", "copy.py"})
        self.assertEqual(output["report"]["excluded_files"][0]["reason"], "browser_file_too_large")
        self.assertTrue(any("actual UTF-8 size" in item for item in output["report"]["warnings"]))
        self.assertEqual(json.dumps(payload, sort_keys=True), before)
        empty = json.loads(engine.codeprobe_analyze_project("{}"))
        self.assertEqual(empty["report"], empty["project_report"])
        self.assertEqual((empty["report"]["project_name"], empty["report"]["candidate_file_count"]), ("project", 0))

    def test_integer_compatibility_is_explicit_and_never_truncates(self):
        accepted = ((0, 0), (0.0, 0), (1, 1), (1.0, 1), (" +1 ", 1),
                    ("1_000", 1000), ("١", 1))
        for raw, expected in accepted:
            with self.subTest(raw=raw):
                self.assertEqual(engine.integer_value(raw, "limit"), expected)
        for raw in (True, False, 1.9, "1.9", "1e0", float("nan"), float("inf"),
                    "nan", "inf", None, b"1", [], {}):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                engine.integer_value(raw, "limit")

    def test_every_project_integer_limit_is_checked_before_resources(self):
        keys = ("max_files", "max_file_bytes", "max_total_bytes", "max_zip_bytes",
                "max_zip_entries", "max_ignore_bytes", "max_ignore_rules")
        for key in keys:
            for value in (True, 0, 1.9, "1.9", float("nan"), float("inf")):
                with self.subTest(key=key, value=value):
                    self.assert_rejected_before_resources({key: value}, "project", direct=True)

    def test_project_limit_endpoints_and_integral_forms_remain_compatible(self):
        maximums = {"max_files": 10000, "max_file_bytes": 16000000,
                    "max_total_bytes": 256000000, "max_zip_bytes": 64000000,
                    "max_zip_entries": 20000, "max_ignore_bytes": 1000000,
                    "max_ignore_rules": 10000}
        for key, maximum in maximums.items():
            for value in (1, 1.0, " +1 ", maximum, float(maximum), str(maximum)):
                with self.subTest(key=key, value=value):
                    self.assertEqual(engine.project_limits({key: value})[key], int(value))
            for value in (0, maximum + 1):
                with self.subTest(key=key, rejected=value), self.assertRaises(ValueError):
                    engine.project_limits({key: value})

    def compressed_fixture(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("blank.py", "\n" * 4096)
        return base64.b64encode(buffer.getvalue()).decode("ascii")

    def test_nonfinite_ratio_is_refused_before_zip_decoding_or_member_reads(self):
        encoded = self.compressed_fixture()
        for value in (float("nan"), float("inf"), -float("inf"), "nan", "Infinity", "-inf", "1e999", True):
            payload = {"zip_base64": encoded, "max_compression_ratio": value}
            with self.subTest(value=value), mock.patch.object(engine, "_read_zip_member_bounded") as read:
                self.assert_rejected_before_resources(payload, "project", direct=True)
                self.assert_rejected_before_resources(json.dumps(payload), "project")
                read.assert_not_called()

    def test_finite_ratio_controls_keep_the_declared_zip_exclusion(self):
        encoded = self.compressed_fixture()
        for ratio, expected_reads, reason in ((None, 0, "compression_ratio_exceeded"),
                                              (1, 0, "compression_ratio_exceeded"),
                                              (1000, 1, "empty_file")):
            payload = {"zip_base64": encoded}
            if ratio is not None:
                payload["max_compression_ratio"] = ratio
            with self.subTest(ratio=ratio), mock.patch.object(engine, "_read_zip_member_bounded", wraps=engine._read_zip_member_bounded) as read:
                report = engine.analyse_project_payload(payload)
                self.assertEqual(read.call_count, expected_reads)
                self.assertEqual(report["excluded_files"][0]["reason"], reason)
                limits = report["input_packaging"]["limits"]
                self.assertEqual(limits["max_compression_ratio"], 100 if ratio is None else ratio)
                self.assertTrue(all(math.isfinite(value) for value in limits.values()))
                json.dumps(report, allow_nan=False)

    def test_bound_calibration_replay_keeps_the_engine_identity_check(self):
        config = engine.merged_metric_config("strict")
        profile = {"profile_id": "owned-runtime-fixture",
                   "scoring_contract": engine.scoring_contract("strict", config)}
        payload = {"code": self.SOURCE, "filename": "sum.py", "calibration_profile": profile}
        report = json.loads(engine.codeprobe_analyze(json.dumps(payload)))["report"]
        self.assertEqual((report["profile"], report["calibration_profile_id"]), ("strict", "owned-runtime-fixture"))
        self.assertEqual(report["metric_config_digest"], engine.metric_config_digest(config))
        profile["scoring_contract"]["engine_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "engine identity.*recalibrate"):
            engine.codeprobe_analyze(json.dumps(payload))


class PythonStructuralContractTests(unittest.TestCase):
    """Finite source fixtures are inspected, never executed."""

    def assert_tokenizer_diagnostic(self, source, actual):
        # Invalid-source locations belong to the installed Python tokenizer.
        with self.assertRaises(tokenize.TokenError) as raised:
            list(tokenize.generate_tokens(io.StringIO(source).readline))
        message, (line, column) = raised.exception.args
        self.assertEqual(actual, f"TokenError at line {line}, column {column + 1}: {message}")

    def test_lexical_dedent_errors_are_controlled_by_both_tokenisers(self):
        source = "def broken():\n    if True:\n        return 1\n  return 0\n"
        scan = engine.scan_python(source)
        identifiers, operators, operands, diagnostic = engine.python_tokens_and_identifiers(source)
        self.assertRegex(scan.tokenizer_error, r"^IndentationError at line 4, column [1-9][0-9]*:")
        self.assertEqual(scan.tokenizer_error, diagnostic)
        self.assertIn("broken", identifiers)
        self.assertIn("def", operators)
        self.assertIn("1", operands)
        context = engine.build_analysis_context(source, "broken.py", "python")
        self.assertIsNone(context.ast_tree)
        self.assertEqual(context.functions, [])
        self.assertEqual(context.tokenizer_error, diagnostic)
        self.assertRegex(context.ast_error, r"^IndentationError at line 4,")
        self.assertEqual(context.notes.count("Tokenizer warning: " + diagnostic), 1)

    def test_invalid_python_diagnostics_reach_json_text_and_python_api(self):
        cases = (
            ("if True:\n\tpass\n        pass\n", "TabError", 3),
            ("value = (\n    1,\n", "SyntaxError", 1),
        )
        for source, category, line in cases:
            with self.subTest(category=category):
                context = engine.build_analysis_context(source, "invalid.py", "python")
                self.assertIsNone(context.ast_tree)
                self.assertRegex(context.ast_error, rf"^{category} at line {line}, column [1-9][0-9]*:")
                if category == "SyntaxError":
                    self.assert_tokenizer_diagnostic(source, context.tokenizer_error)
                payload = {"code": source, "filename": "invalid.py", "language_hint": "python"}
                for entry in (api.analyse_file, lambda item: json.loads(engine.codeprobe_analyze(json.dumps(item)))):
                    result = entry(payload)
                    diagnostic = "AST warning: " + context.ast_error
                    self.assertIn(diagnostic, result["report"]["warnings"])
                    self.assertIn(diagnostic, result["text"])
                    self.assertFalse(result["report"]["overall_applicable"])
                    with self.assertRaisesRegex(ValueError, "requires a successful AST parse"):
                        entry({**payload, "require_python_ast": True})

    def test_soft_keyword_identifiers_and_lexical_noise_are_distinguished(self):
        source = 'match = 1\ncase = 2\ntype = 3\nvalue = match + case + type\n# match case type\nlabel = "match case type"\n'
        context = engine.build_analysis_context(source, "names.py", "python")
        self.assertIsNotNone(context.ast_tree)
        for name in ("match", "case", "type"):
            self.assertEqual(context.identifiers.count(name), 2)
            self.assertNotIn(name, context.tokens_operators)
        self.assertEqual(context.identifiers, ["match", "case", "type", "value", "match", "case", "type", "label"])
        unfinished = "match = (\ncase = type\n"
        invalid = engine.build_analysis_context(unfinished, "unfinished.py", "python")
        self.assertIsNone(invalid.ast_tree)
        self.assertEqual(invalid.identifiers, ["match", "case", "type"])
        self.assert_tokenizer_diagnostic(unfinished, invalid.tokenizer_error)

    def test_pattern_keywords_and_capture_names_keep_their_source_roles(self):
        source = 'match caf\u00e9:\n    case {"\u00e9": match}:\n        case = match\n    case _:\n        case = 0\n'
        context = engine.build_analysis_context(source, "patterns.py", "python")
        self.assertIsNotNone(context.ast_tree)
        self.assertEqual(context.identifiers.count("match"), 2)
        self.assertEqual(context.identifiers.count("case"), 2)
        self.assertEqual(context.identifiers.count("caf\u00e9"), 1)
        self.assertEqual(context.tokens_operators.count("match"), 1)
        self.assertEqual(context.tokens_operators.count("case"), 2)

    def test_type_alias_keyword_tracks_the_actual_interpreter_grammar(self):
        context = engine.build_analysis_context("type Alias = tuple[int, str]\n", "alias.py", "python")
        if sys.version_info >= (3, 12):
            self.assertIsNotNone(context.ast_tree)
            self.assertNotIn("type", context.identifiers)
            self.assertEqual(context.tokens_operators.count("type"), 1)
        else:
            self.assertIsNone(context.ast_tree)
            self.assertRegex(context.ast_error, r"^SyntaxError at line 1,")
            self.assertIn("type", context.identifiers)
        self.assertIn("Alias", context.identifiers)

    def test_parameter_order_and_decorated_async_ranges_are_source_faithful(self):
        source = ('@decorator\n'
                  'async def work(first: int, /, second: str = "x", *items: float, flag: bool = False, **options: int) -> int:\n'
                  '    return first\n\n'
                  'def simple(left, *, right):\n    return left + right\n')
        context = engine.build_analysis_context(source, "parameters.py", "python")
        self.assertEqual([item.name for item in context.functions], ["work", "simple"])
        work, simple = context.functions
        self.assertEqual(work.parameters, ["first", "second", "items", "flag", "options"])
        self.assertEqual(simple.parameters, ["left", "right"])
        self.assertEqual((work.lineno, work.end_lineno, work.length), (1, 3, 3))
        self.assertEqual((simple.lineno, simple.end_lineno, simple.length), (5, 6, 2))
        self.assertTrue(work.has_type_hints)
        self.assertFalse(simple.has_type_hints)
        self.assertEqual([item.cyclomatic for item in context.functions], [1, 1])

    def test_comment_masks_preserve_unicode_crlf_and_last_line_coordinates(self):
        cases = (
            ('# first\r\n\r\ncaf\u00e9 = "# literal"  # tail\r\n# last',
             '       \r\n\r\ncaf\u00e9 = "# literal"        \r\n      ', {1, 3, 4}, {3}, ['# first', '# tail', '# last']),
            ('\u03c0 = 1 # \u03a9\n\n# eof', '\u03c0 = 1    \n\n     ', {1, 3}, {1}, ['# \u03a9', '# eof']),
        )
        for source, masked, comment_lines, code_lines, comments in cases:
            with self.subTest(source=source):
                scan = engine.scan_python(source)
                self.assertEqual(scan.cleaned_code, masked)
                self.assertEqual(scan.comment_line_numbers, comment_lines)
                self.assertEqual(scan.code_line_numbers, code_lines)
                self.assertEqual(scan.comment_texts, comments)
                self.assertEqual(len(scan.cleaned_code), len(source))
                context = engine.build_analysis_context(source, "comments.py", "python")
                self.assertEqual(context.cleaned_code, masked.replace("\r\n", "\n"))

    def test_nested_callable_complexity_is_separate_from_structural_signature(self):
        source = ('def outer():\n    def inner(flag):\n        if flag:\n            return 1\n'
                  '        return 0\n    return inner\n')
        functions = engine.build_analysis_context(source, "nested.py", "python").functions
        self.assertEqual([(item.name, item.cyclomatic) for item in functions], [("outer", 1), ("inner", 2)])
        self.assertEqual(dict(functions[0].ast_signature), {
            "FunctionDef": 2, "arguments": 2, "arg": 1, "If": 1,
            "Name": 2, "Load": 2, "Return": 3, "Constant": 2,
        })
        inverse = 'def outer(flag):\n    if flag:\n        return 1\n    def inner():\n        return 0\n    return inner\n'
        self.assertEqual([(item.name, item.cyclomatic) for item in engine.build_analysis_context(inverse, "inverse.py").functions], [("outer", 2), ("inner", 1)])

    def test_definition_time_expressions_belong_to_the_enclosing_callable(self):
        cases = (
            ('def outer(value=1 if flag else 0):\n    return value\n', {"outer": 1}),
            ('def outer(flag):\n    def inner(value=1 if flag else 0):\n        return value\n    return inner\n', {"outer": 2, "inner": 1}),
            ('def outer(flag):\n    @decorate(1 if flag else 0)\n    def inner():\n        return 1\n    return inner\n', {"outer": 2, "inner": 1}),
            ('def outer(flag):\n    return lambda value: 1 if value else 0\n', {"outer": 1}),
            ('def outer(flag):\n    return lambda value=(1 if flag else 0): value\n', {"outer": 2}),
            ('def outer(flag):\n    class Inner:\n        if flag:\n            value = 1\n    return Inner\n', {"outer": 1}),
            ('def outer(flag):\n    class Inner(Left if flag else Right):\n        pass\n    return Inner\n', {"outer": 2}),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                context = engine.build_analysis_context(source, "definitions.py", "python")
                self.assertEqual({item.name: item.cyclomatic for item in context.functions}, expected)


if __name__ == "__main__":
    unittest.main()
