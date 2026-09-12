"""Independent, deliberately compact S02 reference oracles.

These oracles share the Python language runtime but not the production helper
functions. Agreement therefore supports computational conformance within the
declared runtime; it is not evidence of construct validity.
"""

from __future__ import annotations

import ast
import io
import math
import re
import tokenize
from typing import Any


def _decode(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def _lines(text: str) -> list[str]:
    if not text:
        return []
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    return lines


def _r(value: float) -> float:
    value = round(float(value), 12)
    return 0.0 if value == -0.0 else value


def generic_reference(raw: bytes) -> dict[str, Any]:
    text = _decode(raw)
    lines = _lines(text)
    lengths = [len(line) for line in lines]
    nonblank = sum(1 for line in lines if line.strip())
    blank = len(lines) - nonblank
    trailing = sum(1 for line in lines if re.search(r"[ \t]+$", line))
    mixed = 0
    max_blank = run = 0
    for line in lines:
        if line.strip():
            run = 0
            prefix = line[:len(line) - len(line.lstrip(" \t"))]
            mixed += int(" " in prefix and "\t" in prefix)
        else:
            run += 1
            max_blank = max(max_blank, run)
    result: dict[str, Any] = {
        "source.byte_count": len(raw),
        "source.normalized_codepoint_count": len(text),
        "source.physical_line_count": len(lines),
        "source.nonblank_line_count": nonblank,
        "source.blank_line_count": blank,
        "source.trailing_whitespace_line_count": trailing,
        "source.mixed_indentation_line_count": mixed,
        "source.max_blank_line_run_length": max_blank,
        "source.max_line_length_codepoints": max(lengths) if lengths else None,
        "source.mean_line_length_codepoints": _r(math.fsum(lengths) / len(lengths)) if lengths else None,
    }
    if len(lengths) >= 2:
        mean = math.fsum(lengths) / len(lengths)
        sd = math.sqrt(math.fsum((x - mean) ** 2 for x in lengths) / len(lengths))
        result["source.population_sd_line_length_codepoints"] = _r(sd)
        result["source.line_length_cv"] = None if mean == 0 else _r(sd / mean)
    else:
        result["source.population_sd_line_length_codepoints"] = None
        result["source.line_length_cv"] = None
    return result


def _functions(tree: ast.AST) -> list[ast.AST]:
    return sorted(
        (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))),
        key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0), getattr(n, "name", "")),
    )


def python_ast_reference(text: str) -> dict[str, Any]:
    tree = ast.parse(text, type_comments=True)
    nodes = list(ast.walk(tree))
    functions = _functions(tree)
    imports = [n for n in nodes if isinstance(n, (ast.Import, ast.ImportFrom))]
    bindings = 0
    wildcard = 0
    for node in imports:
        for alias in node.names:
            if isinstance(node, ast.ImportFrom) and alias.name == "*":
                wildcard += 1
            else:
                bindings += 1
    numeric = sum(
        isinstance(n, ast.Constant) and isinstance(n.value, (int, float, complex)) and not isinstance(n.value, bool)
        for n in nodes
    )
    eligible = [n for n in nodes if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
    docstrings = sum(ast.get_docstring(n, clean=False) is not None for n in eligible)
    annotation_slots = annotation_present = 0
    for fn in functions:
        args = fn.args
        parameters = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        if args.vararg is not None:
            parameters.append(args.vararg)
        if args.kwarg is not None:
            parameters.append(args.kwarg)
        annotation_slots += len(parameters) + 1
        annotation_present += sum(p.annotation is not None for p in parameters)
        annotation_present += int(fn.returns is not None)
    return {
        "python.parse_status": "parsed",
        "python.function_definition_count": sum(isinstance(n, ast.FunctionDef) for n in nodes),
        "python.async_function_definition_count": sum(isinstance(n, ast.AsyncFunctionDef) for n in nodes),
        "python.class_definition_count": sum(isinstance(n, ast.ClassDef) for n in nodes),
        "python.import_statement_count": len(imports),
        "python.imported_binding_count": bindings,
        "python.wildcard_import_count": wildcard,
        "python.numeric_literal_count": numeric,
        "python.exception_handler_count": sum(isinstance(n, ast.ExceptHandler) for n in nodes),
        "python.raise_statement_count": sum(isinstance(n, ast.Raise) for n in nodes),
        "python.docstring_eligible_definition_count": len(eligible),
        "python.docstring_present_definition_count": docstrings,
        "python.docstring_coverage_proportion": None if not eligible else _r(docstrings / len(eligible)),
        "python.annotation_eligible_slot_count": annotation_slots,
        "python.annotation_present_slot_count": annotation_present,
        "python.annotation_coverage_proportion": None if not annotation_slots else _r(annotation_present / annotation_slots),
    }


def markdown_reference(text: str) -> dict[str, Any]:
    lines = _lines(text)
    fence_char = None
    fence_len = 0
    fences = atx = setext = 0
    levels: list[int] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if fence_char is not None:
            match = re.match(r"^[ ]{0,3}([`~]+)[ \t]*$", line)
            if match and match.group(1)[0] == fence_char and len(match.group(1)) >= fence_len:
                fence_char = None
                fence_len = 0
            index += 1
            continue
        opener = re.match(r"^[ ]{0,3}(`{3,}|~{3,})(.*)$", line)
        if opener and (opener.group(1)[0] != "`" or "`" not in opener.group(2)):
            fence_char = opener.group(1)[0]
            fence_len = len(opener.group(1))
            fences += 1
            index += 1
            continue
        heading = re.match(r"^[ ]{0,3}(#{1,6})(?:[ \t]+|$)", line)
        if heading:
            atx += 1
            levels.append(len(heading.group(1)))
            index += 1
            continue
        if line.strip() and index + 1 < len(lines):
            underline = re.match(r"^[ ]{0,3}(=+|-+)[ \t]*$", lines[index + 1])
            if underline:
                setext += 1
                levels.append(1 if underline.group(1).startswith("=") else 2)
                index += 2
                continue
        index += 1
    return {
        "markdown.parse_status": "unclosed_fence" if fence_char else "complete",
        "markdown.atx_heading_count": atx,
        "markdown.setext_heading_count": setext,
        "markdown.fenced_code_block_count": fences,
        "markdown.heading_level_jump_count": sum(b - a > 1 for a, b in zip(levels, levels[1:])),
    }
