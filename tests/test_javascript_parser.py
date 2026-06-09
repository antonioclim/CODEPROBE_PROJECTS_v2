from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import codeprobe_runtime as engine  # noqa: E402


class PhaseTwoJavaScriptParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analysis_engine = engine.AnalysisEngine(engine.merged_metric_config("default"))

    def test_regex_literal_braces_are_masked_before_brace_matching(self) -> None:
        source = r'''
const escapeRegex = value => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function after(value) {
  return value + 1;
}
'''
        scan = engine.scan_javascript(source)
        first_line = scan.cleaned_code.split("\n")[1]
        self.assertNotIn("${}", first_line)
        self.assertEqual(scan.cleaned_code.count("{"), 1)
        self.assertEqual(scan.cleaned_code.count("}"), 1)
        functions = engine.extract_generic_functions(source.split("\n"), scan.cleaned_code, "javascript")
        self.assertEqual([item.name for item in functions], ["after"])
        self.assertEqual(functions[0].lineno, 4)

    def test_javascript_function_extraction_covers_common_declarations(self) -> None:
        source = r'''
async function loadData(url) {
  return fetch(url);
}

const handler = async (event) => {
  if (event.ok) {
    return event.value;
  }
  return null;
};

class Runner {
  async run(input) {
    return /[{}]/.test(input) ? input : "";
  }
}

const object = {
  parse(text) {
    return text.trim();
  },
  emit: (value) => {
    return value;
  }
};
'''
        scan = engine.scan_javascript(source)
        functions = engine.extract_generic_functions(source.split("\n"), scan.cleaned_code, "javascript")
        names = [item.name for item in functions]
        self.assertEqual(names, ["loadData", "handler", "run", "parse", "emit"])
        line_map = {item.name: item.lineno for item in functions}
        self.assertEqual(line_map["loadData"], 2)
        self.assertEqual(line_map["handler"], 6)
        self.assertEqual(line_map["run"], 14)
        self.assertEqual(line_map["parse"], 20)
        self.assertEqual(line_map["emit"], 23)

    def test_function_start_line_does_not_include_previous_semicolon_line(self) -> None:
        source = "const value = 1;\n\nfunction compute() {\n  return value;\n}\n"
        scan = engine.scan_javascript(source)
        functions = engine.extract_generic_functions(source.split("\n"), scan.cleaned_code, "javascript")
        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0].name, "compute")
        self.assertEqual(functions[0].lineno, 3)


    def test_division_operator_is_not_masked_as_regex(self) -> None:
        source = "function ratio(a, b) {\n  return a / b;\n}\n"
        scan = engine.scan_javascript(source)
        self.assertIn("a / b", scan.cleaned_code)
        functions = engine.extract_generic_functions(source.split("\n"), scan.cleaned_code, "javascript")
        self.assertEqual([item.name for item in functions], ["ratio"])

    def test_clean_javascript_fixture_stays_below_review_trigger(self) -> None:
        source = r'''
const normaliseItems = (items) => {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const key = String(item.id).trim();
    if (!key || seen.has(key)) {
      continue;
    }
    seen.add(key);
    output.push({ id: key, label: String(item.label || key) });
  }
  return output;
};

function renderItems(items, target) {
  const rows = normaliseItems(items).map(item => `<li data-id="${item.id}">${item.label}</li>`);
  target.innerHTML = rows.join("");
  return rows.length;
}
'''
        report = self.analysis_engine.analyse(source, "clean_ui.js", "javascript")
        self.assertTrue(report.overall_applicable)
        self.assertLess(report.overall_score, 0.60)
        self.assertNotEqual(report.verdict_class, "high")


if __name__ == "__main__":
    unittest.main()
