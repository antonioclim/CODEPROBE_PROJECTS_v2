"""Independent finite S03 oracles. No production-kernel imports.

CPython AST is shared with the product: traversal independence is not parser
independence. Analytic generator counts provide a second, non-parser oracle.
"""
from __future__ import annotations
import ast
import decimal
import io
import tokenize


def lines_of(text):
    lines, current = [], []
    for char in text:
        if char == '\n':
            lines.append(''.join(current)); current = []
        else:
            current.append(char)
    if current:
        lines.append(''.join(current))
    return lines


def generic(data):
    text = data.decode('utf-8-sig').replace('\r\n', '\n').replace('\r', '\n')
    lines = lines_of(text)
    lengths = [len(line) for line in lines]
    blank = [not line.strip() for line in lines]
    run = longest = mixed = 0
    for line, is_blank in zip(lines, blank):
        run = run + 1 if is_blank else 0
        longest = max(longest, run)
        prefix = ''
        for ch in line:
            if ch not in ' \t': break
            prefix += ch
        mixed += int(not is_blank and ' ' in prefix and '\t' in prefix)
    values = {'byte_count': len(data), 'normalized_codepoint_count': len(text), 'physical_line_count': len(lines), 'nonblank_line_count': len(lines) - sum(blank), 'blank_line_count': sum(blank), 'trailing_whitespace_line_count': sum(line.endswith((' ', '\t')) for line in lines), 'mixed_indentation_line_count': mixed, 'max_blank_line_run_length': longest, 'max_line_length_codepoints': max(lengths) if lengths else None}
    with decimal.localcontext() as ctx:
        ctx.prec = 60
        D = decimal.Decimal
        mean = sum(map(D, lengths), D(0)) / D(len(lengths)) if lengths else None
        variance = sum(((D(n) - mean) ** 2 for n in lengths), D(0)) / D(len(lengths)) if len(lengths) >= 2 else None
        sd = variance.sqrt() if variance is not None else None
        values['mean_line_length_codepoints'] = float(mean) if mean is not None else None
        values['population_sd_line_length_codepoints'] = float(sd) if sd is not None else None
        values['line_length_cv'] = float(sd / mean) if sd is not None and mean else None
    return {'source.' + key: value for key, value in values.items()}


def python_counts(text):
    """Iterative independent AST traversal and callable accounting."""
    root = ast.parse(text, type_comments=True)
    nodes, todo = [], [root]
    while todo:
        node = todo.pop(); nodes.append(node)
        todo.extend(ast.iter_child_nodes(node))
    fs = sorted((n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), key=lambda n: (n.lineno, n.col_offset, n.name))
    defs = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    imports = [n for n in nodes if isinstance(n, (ast.Import, ast.ImportFrom))]
    eligible = present = 0
    for fn in fs:
        args = fn.args
        params = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs) + ([args.vararg] if args.vararg else []) + ([args.kwarg] if args.kwarg else [])
        eligible += len(params) + 1
        present += sum(a.annotation is not None for a in params) + int(fn.returns is not None)
    documented = sum(bool(n.body) and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant) and isinstance(n.body[0].value.value, str) for n in defs)
    values = {
        'parse_status': 'parsed', 'function_definition_count': sum(type(n) is ast.FunctionDef for n in nodes),
        'async_function_definition_count': sum(type(n) is ast.AsyncFunctionDef for n in nodes),
        'class_definition_count': sum(type(n) is ast.ClassDef for n in nodes), 'import_statement_count': len(imports),
        'imported_binding_count': sum(a.name != '*' for n in imports for a in n.names), 'wildcard_import_count': sum(a.name == '*' for n in imports for a in n.names),
        'numeric_literal_count': sum(isinstance(n, ast.Constant) and type(n.value) in (int, float, complex) for n in nodes),
        'exception_handler_count': sum(type(n) is ast.ExceptHandler for n in nodes), 'raise_statement_count': sum(type(n) is ast.Raise for n in nodes),
        'docstring_eligible_definition_count': len(defs), 'docstring_present_definition_count': documented,
        'docstring_coverage_proportion': documented / len(defs) if defs else None,
        'annotation_eligible_slot_count': eligible, 'annotation_present_slot_count': present,
        'annotation_coverage_proportion': present / eligible if eligible else None,
    }
    comments = [t for t in tokenize.generate_tokens(io.StringIO(text).readline) if t.type == tokenize.COMMENT]
    lines = lines_of(text)
    ncomment = len({t.start[0] for t in comments})
    values.update(comment_token_count=len(comments), comment_physical_line_count=ncomment, comment_line_proportion=ncomment / len(lines) if lines else None)
    out = {(f'python.{k}', 0): v for k, v in values.items()}
    containers = {'If', 'For', 'AsyncFor', 'While', 'Try', 'TryStar', 'With', 'AsyncWith', 'Match'}
    for ordinal, fn in enumerate(fs, 1):
        todo, decision, depth_max = [(fn, 0)], 0, 0
        while todo:
            node, depth = todo.pop()
            if node is not fn and type(node).__name__ in {'FunctionDef', 'AsyncFunctionDef', 'ClassDef', 'Lambda'}:
                continue
            name = type(node).__name__
            depth += int(name in containers)
            depth_max = max(depth, depth_max)
            if name in {'If', 'For', 'AsyncFor', 'While', 'IfExp'}: decision += 1
            elif name == 'BoolOp': decision += len(node.values) - 1
            elif name in {'Try', 'TryStar'}: decision += len(node.handlers)
            elif name == 'Match': decision += len(node.cases)
            elif name in {'ListComp', 'SetComp', 'DictComp', 'GeneratorExp'}: decision += sum(1 + len(g.ifs) for g in node.generators)
            todo.extend((child, depth) for child in ast.iter_child_nodes(node))
        for key, value in [('physical_span_lines', fn.end_lineno - fn.lineno + 1), ('decision_point_count', decision), ('mccabe_complexity', decision + 1), ('max_control_nesting_depth', depth_max)]:
            out[(f'python.callable.{key}', ordinal)] = value
    return out


def markdown(text):
    """Character-state oracle for the finite subset, not CommonMark generally."""
    lines = lines_of(text)
    fence = None
    headings = []
    atx = setext = blocks = i = 0
    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip(' '))
        raw = line[indent:] if indent <= 3 else line
        if fence:
            marker, width = fence
            body = raw.rstrip(' \t')
            if indent <= 3 and len(body) >= width and body and all(c == marker for c in body): fence = None
            i += 1; continue
        run = 0
        if indent <= 3 and raw and raw[0] in '`~':
            while run < len(raw) and raw[run] == raw[0]: run += 1
            if run >= 3 and (raw[0] != '`' or '`' not in raw[run:]):
                fence = (raw[0], run); blocks += 1; i += 1; continue
        run = 0
        if indent <= 3:
            while run < len(raw) and raw[run] == '#': run += 1
        if 1 <= run <= 6 and (run == len(raw) or raw[run] in ' \t'):
            atx += 1; headings.append(run); i += 1; continue
        if line.strip() and i + 1 < len(lines):
            under = lines[i + 1]
            pad = len(under) - len(under.lstrip(' '))
            body = under[pad:].rstrip(' \t')
            if pad <= 3 and body and body[0] in '=-' and all(c == body[0] for c in body):
                setext += 1; headings.append(1 if body[0] == '=' else 2); i += 2; continue
        i += 1
    return {'markdown.parse_status': 'unclosed_fence' if fence else 'complete', 'markdown.atx_heading_count': atx, 'markdown.setext_heading_count': setext, 'markdown.fenced_code_block_count': blocks, 'markdown.heading_level_jump_count': sum(b - a > 1 for a, b in zip(headings, headings[1:]))}
