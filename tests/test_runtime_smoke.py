from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
