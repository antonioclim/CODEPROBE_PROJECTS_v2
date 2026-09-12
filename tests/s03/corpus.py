"""Deterministic S03 generators; fixtures are parsed but never executed.

Author: Antonio Clim. Standard-library only. No production-kernel imports.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import io
import json
import tokenize

SEED = 20260912


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stream(index, count):
    out = bytearray()
    block = 0
    while len(out) < count:
        out.extend(hashlib.sha256(f'S03:{SEED}:{index}:{block}'.encode()).digest())
        block += 1
    return bytes(out[:count])


def python_source(i):
    """Six finite grammar families with analytic module-count expectations."""
    bodies = [
        ['if gen_arg > 0 and gen_kw:', '    return gen_arg + 1', 'return 0'],
        ['for gen_item in range(3):', '    if gen_item:', '        gen_arg += 1', 'return gen_arg'],
        ['while gen_arg > 0:', '    gen_arg -= 1', 'return gen_arg if gen_kw else 0'],
        ['try:', '    return [gen_item for gen_item in range(4) if gen_item > 0]', 'except ValueError:', "    raise RuntimeError('x')"],
        ["with open('fixture-never-executed') as gen_handle:", '    gen_value = 1', 'return gen_value'],
        ['match gen_arg:', '    case 0:', '        return 1', '    case _:', '        return 2'],
    ]
    family = i % 6
    async_outer = bool(i % 2)
    inner = bool((i // 2) % 2)
    klass = bool((i // 4) % 2)
    documented = bool((i // 8) % 2)
    lines = ['# deterministic synthetic fixture', 'import os, sys', 'from math import sin, cos', f'gen_seed = {i}', '']
    lines += [('async ' if async_outer else '') + f'def gen_func_{i}(gen_arg: int, *gen_rest, gen_kw: str = "x", **gen_opts) -> int:']
    if documented:
        lines += ['    """Synthetic documentation, not a quality judgement."""']
    if inner:
        lines += ['    def gen_inner(gen_local):', '        return gen_local if gen_local else 1']
    lines += ['    ' + line for line in bodies[family]]
    if klass:
        lines += ['', f'class gen_class_{i}:', '    """Synthetic class."""', '    def gen_method(self, gen_arg):', '        return gen_arg']
    # Deliberately vary terminal newlines and trailing layout, not executable meaning.
    if i % 3 == 0:
        lines[3] += '  '
    text = '\n'.join(lines) + ('\n' if i % 4 else '')
    expected = {
        'python.function_definition_count': int(not async_outer) + int(inner) + int(klass),
        'python.async_function_definition_count': int(async_outer),
        'python.class_definition_count': int(klass),
        'python.import_statement_count': 2,
        'python.imported_binding_count': 4,
        'python.wildcard_import_count': 0,
        'python.numeric_literal_count': [3, 2, 3, 2, 1, 3][family] + 1 + int(inner),
        'python.exception_handler_count': int(family == 3),
        'python.raise_statement_count': int(family == 3),
        'python.docstring_eligible_definition_count': 1 + int(inner) + 2 * int(klass),
        'python.docstring_present_definition_count': int(documented) + int(klass),
        'python.annotation_eligible_slot_count': 5 + 2 * int(inner) + 3 * int(klass),
        'python.annotation_present_slot_count': 3,
    }
    return text.encode(), expected


def markdown_source(i):
    marker = '~' if i % 2 else '`'
    close = marker * (3 + i % 3)
    lines = ['# Heading', f'Item {i}', '', '### A level jump', 'Ordinary title', '---', marker * 3 + 'text', '# not a heading', close, '', '## Last']
    if i % 5 == 0:
        lines += [marker * 4, 'unclosed block']
    return ('\n'.join(lines) + ('\n' if i % 3 else '')).encode()


def text_source(i):
    choices = ['', '\n', '  \n\t\n', 'alpha', 'alpha\nbeta\n', 'șțîâ é e\u0301\n漢字', '\u2028\u2029\x0b\x0c\n', ' \talpha\t\n\n\nbeta  ', '0\n00\n000\n', '\ufeffinternal\n']
    # A leading BOM is not admitted in core fixtures: the BOM transform adds one.
    value = choices[i % len(choices)]
    if value.startswith('\ufeff'):
        value = 'x' + value
    return (value + ('\n' * (i // len(choices)))).encode()


def token_transform(data, rename=False):
    tokens = list(tokenize.generate_tokens(io.StringIO(data.decode()).readline))
    if rename:
        changed = [t._replace(string=t.string + '_renamed') if t.type == tokenize.NAME and t.string.startswith('gen_') else t for t in tokens]
        rendered = tokenize.untokenize(changed)
        inverse = [t._replace(string=t.string[:-8]) if t.type == tokenize.NAME and t.string.startswith('gen_') and t.string.endswith('_renamed') else t for t in tokenize.generate_tokens(io.StringIO(rendered).readline)]
        restored = tokenize.untokenize(inverse)
        assert ast.dump(ast.parse(restored), include_attributes=False) == ast.dump(ast.parse(data.decode()), include_attributes=False), 'alpha inverse precondition'
    else:
        rendered = tokenize.untokenize([(t.type, t.string) for t in tokens])
        assert ast.dump(ast.parse(rendered), include_attributes=False) == ast.dump(ast.parse(data.decode()), include_attributes=False), 'formatter AST precondition'
    return rendered.encode()


def make_case(cid, kind, data, language, **extra):
    return dict(case_id=cid, kind=kind, language=language, bytes_b64=base64.b64encode(data).decode(), byte_count=len(data), sha256=digest(data), **extra)


def generate():
    cases = []
    core = []
    for i in range(48):
        data, expected = python_source(i)
        core.append(make_case(f'core-py-{i:03}', 'core', data, 'python', analytic=expected))
    core.extend(make_case(f'core-md-{i:03}', 'core', markdown_source(i), 'markdown') for i in range(16))
    core.extend(make_case(f'core-tx-{i:03}', 'core', text_source(i), 'text') for i in range(16))
    cases.extend(core)
    for case in core:
        data = base64.b64decode(case['bytes_b64'])
        transforms = {1: data, 2: data.replace(b'\n', b'\r\n'), 3: b'\xef\xbb\xbf' + data, 7: data}
        if case['language'] == 'python':
            transforms.update({4: token_transform(data, True), 5: b'# S03 deterministic neutral comment\n' + data, 6: token_transform(data), 8: data + b'\nif :\n'})
        for number, transformed in sorted(transforms.items()):
            cases.append(make_case(f'{case["case_id"]}-H{number:02}', 'transformation', transformed, 'c' if number == 7 else case['language'], parent=case['case_id'], hypothesis=f'H-S03-{number:02}'))
    for i in range(256):
        data, expected = python_source(i + 1000)
        cases.append(make_case(f'prop-py-{i:03}', 'property', data, 'python', analytic=expected))
    alphabet = ' abcXYZ09\t\n\rșțé漢\u2028\u00a0'
    for i in range(256):
        raw = stream(i + 2000, 800)
        text = ''.join(alphabet[b % len(alphabet)] for b in raw[:int.from_bytes(raw[:2], 'big') % 800])
        cases.append(make_case(f'prop-tx-{i:03}', 'property', text.encode(), 'text'))
    md_lines = ['', '# A', '### B', 'Title', '---', '===', '```', '~~~', '````', '```~~', '~~~``', '    # indented', 'text', '###### C', '#not', '  ~~~']
    for i in range(128):
        text = '\n'.join(md_lines[b % len(md_lines)] for b in stream(i + 3000, 20)) + '\n'
        cases.append(make_case(f'prop-md-{i:03}', 'property', text.encode(), 'markdown'))
    for i in range(512):
        raw = stream(i + 4000, 128)
        data = raw[1:1 + raw[0] % 128]
        if i % 2:
            data = bytes(b % 128 for b in data)
        cases.append(make_case(f'fuzz-byte-{i:03}', 'fuzz_bytes', data, ['text', 'python', 'markdown'][i % 3]))
    for i in range(256):
        data, _ = python_source(i)
        raw = stream(i + 5000, 8)
        position = int.from_bytes(raw[:2], 'big') % len(data)
        replacement = b':"\n[]@#()' [raw[2] % 9:raw[2] % 9 + 1]
        data = data[:position] + replacement + data[position + 1:]
        cases.append(make_case(f'fuzz-py-{i:03}', 'fuzz_python', data, 'python'))
    assert len(cases) == 2000
    assert len({c['case_id'] for c in cases}) == len(cases)
    return cases


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    payload = ''.join(canonical(c) + '\n' for c in generate()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(canonical({'cases': 2000, 'sha256': digest(payload), 'generator_sha256': digest(Path(__file__).read_bytes())}))
