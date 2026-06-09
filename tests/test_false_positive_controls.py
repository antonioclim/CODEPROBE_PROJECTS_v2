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


if __name__ == "__main__":
    unittest.main()
