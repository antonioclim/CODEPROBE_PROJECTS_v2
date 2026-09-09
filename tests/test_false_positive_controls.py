from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402


class PhaseTwoFalsePositiveControls(unittest.TestCase):
    def setUp(self) -> None:
        self.analysis_engine = engine.AnalysisEngine(engine.merged_metric_config("default"))

    def test_clean_formatter_shaped_python_is_low_concern(self) -> None:
        source = '''
from __future__ import annotations


def normalise_label(raw: str) -> str:
    parts = []
    for chunk in raw.strip().split():
        cleaned = chunk.strip("-_.,")
        if cleaned:
            parts.append(cleaned.lower())
    return "-".join(parts)


def count_valid_rows(rows: list[dict[str, str]]) -> int:
    total = 0
    for row in rows:
        if not row:
            continue
        name = row.get("name", "").strip()
        score = row.get("score", "").strip()
        if name and score.isdigit():
            total += 1
    return total


def build_summary(rows: list[dict[str, str]]) -> dict[str, int]:
    summary = {"valid": 0, "empty": 0}
    for row in rows:
        if row:
            summary["valid"] += count_valid_rows([row])
        else:
            summary["empty"] += 1
    return summary


def main() -> None:
    rows = [
        {"name": "Ana", "score": "10"},
        {"name": "", "score": ""},
    ]
    print(build_summary(rows))


if __name__ == "__main__":
    main()
'''
        report = self.analysis_engine.analyse(source, "clean_student.py", "python")
        self.assertTrue(report.overall_applicable)
        self.assertEqual(report.verdict_class, "low")
        self.assertLess(report.overall_score, 0.28)
        metrics = {item.name: item for item in report.metrics}
        for name in ["blank_line_regularity", "function_length", "identifier_style", "structural_self_similarity"]:
            self.assertEqual(metrics[name].group, "context")
            self.assertFalse(metrics[name].contributes_to_overall)

    def test_json_report_contains_engine_version_and_schema(self) -> None:
        payload = {
            "code": "function answer() { return 42; }\n",
            "filename": "answer.js",
            "language_hint": "javascript",
            "profile": "default",
        }
        output = json.loads(engine.codeprobe_analyze(json.dumps(payload)))
        self.assertEqual(output["report"]["app_version"], engine.APP_VERSION)
        self.assertEqual(output["report"]["schema_version"], "2.2.0")

    def test_config_override_rejects_non_numeric_thresholds(self) -> None:
        with self.assertRaises(ValueError):
            engine.merged_metric_config("default", {"line_length_uniformity": {"thresholds": {"ai_low": "small"}}})


class PythonImportBindingTests(unittest.TestCase):
    def metric(self, source):
        report = engine.AnalysisEngine(engine.merged_metric_config("default")).analyse(source, "imports.py", "python")
        return next(item for item in report.metrics if item.name == "used_import_ratio")

    def test_import_reads_are_distinct_from_writes_deletes_and_rebinding(self):
        cases = (
            ("import os\nos.getcwd()\n", 1.0),
            ("import os as system\nsystem.getcwd()\n", 1.0),
            ("from os import getcwd as current\ncurrent()\n", 1.0),
            ("import os.path\nos.path.join('a', 'b')\n", 1.0),
            ("import os\nos = os.getcwd()\n", 1.0),
            ("import os\nos += 1\n", 1.0),
            ("import os\nos.value += (os := replacement)\n", 1.0),
            ("import os\ndata = {'first': (os := 3), os: 0}\n", 0.0),
            ("import os\nos = 3\n", 0.0),
            ("import os\ndel os\n", 0.0),
            ("import os\nos = 3\nprint(os)\n", 0.0),
            ("import os\nos.getcwd()\nos = 3\n", 1.0),
            ('import os\n# os.getcwd()\nlabel = "os"\n', 0.0),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                metric = self.metric(source)
                self.assertTrue(metric.applicable, metric.detail)
                self.assertEqual(metric.value, expected)
                self.assertEqual(metric.group, "quality")
                self.assertFalse(metric.contributes_to_overall)
        context = engine.build_analysis_context("import os\nos = 3\ndel os\n", "writes.py", "python")
        self.assertNotIn("os", context.used_names)

    def test_scope_shadowing_does_not_attribute_a_local_read_to_an_outer_import(self):
        cases = (
            ("import os\ndef read():\n    return os.getcwd()\n", 1.0),
            ("def read():\n    return os.getcwd()\nimport os\n", 1.0),
            ("import os\ndef read(os):\n    return os.getcwd()\n", 0.0),
            ("import os\ndef read():\n    os = 3\n    return os\n", 0.0),
            ("import os\ndef read():\n    result = os\n    os = 3\n    return result\n", 0.0),
            ("import os\ndef read():\n    import sys as os\n    return os.version\n", 0.5),
            ("def outer():\n    import os\n    def inner():\n        return os.getcwd()\n    return inner\n", 1.0),
            ("import os\ngen = (item for item in os.listdir('.'))\nos = 3\n", 1.0),
            ("import os\ngen = (os.getcwd() for item in items)\n", 1.0),
            ("import os\ngen = (os for os in items)\n", 0.0),
            ("import os\nvalues = [os.getcwd() for item in items]\nos = 3\n", 1.0),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                metric = self.metric(source)
                self.assertTrue(metric.applicable, metric.detail)
                self.assertEqual(metric.value, expected)

    def test_each_import_binding_keeps_its_own_usage_denominator(self):
        cases = (
            ("import os, sys\nos.getcwd()\n", 0.5),
            ("import os as item\nitem.getcwd()\nimport sys as item\n", 0.5),
            ("import os as item\nitem.getcwd()\nimport sys as item\nitem.version\n", 1.0),
            ("import os as item\nimport sys as item\nitem.version\n", 0.5),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                metric = self.metric(source)
                self.assertTrue(metric.applicable, metric.detail)
                self.assertEqual(metric.value, expected)

    def test_dynamic_and_ambiguous_import_resolution_is_explicitly_unavailable(self):
        cases = (
            "import os\ndef read():\n    global os\n    return os.getcwd()\n",
            "def outer():\n    import os\n    def inner():\n        nonlocal os\n        return os.getcwd()\n    return inner\n",
            "from os import *\ngetcwd()\n",
            "import os\nexec('os = 3')\nos.getcwd()\n",
            "import os\nvalue = globals()['os']\n",
            "import os\ndef read():\n    return os.getcwd()\nos = 3\n",
            "import os\ngen = (os.getcwd() for item in items)\nos = 3\n",
            "import os\nvalue = flag and (os := replacement)\nresult = os.getcwd()\n",
            "import os\nvalue = (os := replacement) if flag else fallback\nresult = os.getcwd()\n",
            "import os\nvalue = 0 < flag < (os := 3)\nlater = os\n",
            "import os\nassert (os := replacement)\nresult = os.getcwd()\n",
            "import os\nassert flag, (os := replacement)\nresult = os.getcwd()\n",
        )
        for source in cases:
            with self.subTest(source=source):
                metric = self.metric(source)
                self.assertFalse(metric.applicable)
                self.assertIsNone(metric.value)
                self.assertRegex(metric.explanation + " " + metric.detail, "(?i)unavailable|ambiguous|dynamic|conservative")


class ScriptComplexityControls(unittest.TestCase):
    """Inert text and executable decisions are separate source facts."""

    def assert_complexity(self, source, language, expected):
        filename = "fixture.js" if language == "javascript" else "fixture.sh"
        context = engine.build_analysis_context(source, filename, language)
        self.assertEqual([(f.name, f.cyclomatic) for f in context.functions], [("f", expected)])
        self.assertEqual(context.functions[0].body, source.rstrip("\n"))
        report = engine.AnalysisEngine(engine.merged_metric_config("default")).analyse(source, filename, language)
        metric = next(item for item in report.metrics if item.name == "cyclomatic_complexity")
        self.assertTrue(metric.applicable)
        self.assertEqual(metric.value, expected)
        self.assertEqual(metric.group, "context")
        self.assertFalse(metric.contributes_to_overall)

    def test_javascript_inert_comments_strings_regex_and_templates_do_not_add_decisions(self):
        bodies = (" return 1;", " // if for while catch && ||\n return 1;",
                  ' return "if for while catch && ||";', ' return /if|for|while|catch|&&|\\|\\|/;',
                  ' return `if for while catch && ||`;')
        for body in bodies:
            with self.subTest(body=body):
                self.assert_complexity("function f() {\n" + body + "\n}\n", "javascript", 1)
        self.assert_complexity("function f(ok) {\n if (ok) return 1;\n return 0;\n}\n", "javascript", 2)

    def test_bash_inert_comments_strings_and_heredocs_do_not_add_decisions(self):
        bodies = (" echo ok", " # if for while until && ||\n echo ok",
                  ' echo "if for while until && ||"', " cat <<'EOF'\nif for while until && ||\nEOF")
        for body in bodies:
            with self.subTest(body=body):
                self.assert_complexity("f() {\n" + body + "\n}\n", "bash", 1)
        self.assert_complexity('f() {\n if test -n "$value"; then\n  echo ok\n fi\n}\n', "bash", 2)


if __name__ == "__main__":
    unittest.main()
