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


class JavaScriptLexicalContractTests(unittest.TestCase):
    """Literal fixtures are source data; no JavaScript program is executed."""

    def context(self, source, filename="fixture.js"):
        return engine.build_analysis_context(source, filename, "javascript")

    def test_control_parenthesis_regex_and_call_division_keep_function_ranges(self):
        cases = (
            ("function f(ok, x) {\n if (ok) /[}]/.test(x);\n return x;\n}\n", "f", 4, 2),
            ("function ratio(a, b) {\n return get(a) / b;\n}\n", "ratio", 3, 1),
        )
        for source, name, end, complexity in cases:
            with self.subTest(name=name):
                context = self.context(source)
                self.assertEqual([(f.name, f.lineno, f.end_lineno, f.cyclomatic) for f in context.functions],
                                 [(name, 1, end, complexity)])
                self.assertFalse(context.tokenizer_error)
                self.assertEqual(context.functions[0].body, source.rstrip("\n"))
                self.assertEqual(len(context.cleaned_code), len(source))
        self.assertIn("get(a) / b", self.context(cases[1][0]).cleaned_code)
        self.assertNotIn("[}]", self.context(cases[0][0]).cleaned_code)

    def test_exported_function_and_destructured_arrow_have_exact_names(self):
        cases = (("export function add(a, b) {\n return a + b;\n}\n", "add"),
                 ("const pick = ({value}) => {\n return value;\n};\n", "pick"))
        for source, name in cases:
            with self.subTest(name=name):
                context = self.context(source)
                self.assertEqual([(f.name, f.lineno, f.end_lineno, f.length) for f in context.functions], [(name, 1, 3, 3)])
                self.assertFalse(context.tokenizer_error)

    def test_dollar_unicode_and_combining_spellings_remain_distinct(self):
        source = "const $count = 1, count = 2, café = 3, cafe\u0301 = 4;\n$count + count + café + cafe\u0301;\n"
        self.assertEqual(self.context(source).identifiers,
                         ["$count", "count", "café", "cafe\u0301", "$count", "count", "café", "cafe\u0301"])
        context = self.context("function λ(value) {\n return value;\n}\n")
        self.assertEqual([(f.name, f.lineno, f.end_lineno) for f in context.functions], [("λ", 1, 3)])
        self.assertEqual(context.identifiers, ["λ", "value", "value"])
        joiners = self.context("const a\u200cb = 1, a\u200db = 2;\na\u200cb + a\u200db;\n")
        self.assertEqual(joiners.identifiers, ["a\u200cb", "a\u200db", "a\u200cb", "a\u200db"])

    def test_template_substitution_retains_executable_tokens(self):
        source = 'const text = `value: ${lookup(value)}`;\n'
        context = self.context(source)
        self.assertEqual(context.identifiers, ["text", "lookup", "value"])
        self.assertIn("lookup(value)", context.cleaned_code)
        self.assertFalse(context.tokenizer_error)
        self.assertNotIn("value:", context.cleaned_code)

    def test_typescript_and_jsx_omissions_are_qualified_with_later_recovery(self):
        cases = (
            ("function identity<T>(value: T): T {\n return value;\n}\n", "generic.ts", "JS_UNSUPPORTED_TYPESCRIPT"),
            ("function make(): {value: number} {\n return {value: 1};\n}\n", "object.ts", "JS_UNSUPPORTED_TYPESCRIPT"),
            ("function render() {\n return <p>don't stop</p>;\n}\n", "render.jsx", "JS_UNSUPPORTED_JSX"),
        )
        for prefix, filename, diagnostic in cases:
            with self.subTest(filename=filename):
                context = self.context(prefix + "function after() {\n return 1;\n}\n", filename)
                self.assertEqual([(f.name, f.lineno, f.end_lineno) for f in context.functions], [("after", 4, 6)])
                self.assertIn(diagnostic, " ".join(context.notes))
                self.assertFalse(context.tokenizer_error)

    def test_unsupported_identifier_forms_do_not_yield_suffix_names(self):
        for source in (r"function caf\u00e9() { return 1; }", "function bad😀name() { return 1; }"):
            with self.subTest(source=source):
                context = self.context(source)
                self.assertEqual(context.functions, [])
                self.assertIn("JS_UNSUPPORTED_IDENTIFIER", context.tokenizer_error)

    def test_javascript_delimiter_template_and_header_endpoints_are_explicit(self):
        for depth in (31, 32, 33):
            with self.subTest(delimiter_depth=depth):
                context = self.context("const value = " + "(" * depth + "1" + ")" * depth + ";\n")
                self.assertEqual(bool(context.tokenizer_error), depth > 32)
                if depth > 32:
                    self.assertIn("JS_DELIMITER_LIMIT", context.tokenizer_error)
        for depth in (15, 16, 17):
            value = "1"
            for _ in range(depth):
                value = "`text ${" + value + "}`"
            with self.subTest(template_depth=depth):
                context = self.context("const value = " + value + ";\n")
                self.assertEqual(bool(context.tokenizer_error), depth > 16)
                if depth > 16:
                    self.assertIn("JS_TEMPLATE_LIMIT", context.tokenizer_error)
        for width in (2047, 2048, 2049):
            left, right = "function boundary(", "value) "
            header = left + " " * (width - len(left) - len(right)) + right
            self.assertEqual(len(header), width)
            with self.subTest(header_width=width):
                context = self.context(header + "{\n return value;\n}\n")
                self.assertEqual([f.name for f in context.functions], ["boundary"] if width <= 2048 else [])
                if width > 2048:
                    self.assertIn("JS_FUNCTION_HEADER_LIMIT", " ".join(context.notes))


if __name__ == "__main__":
    unittest.main()
