#!/usr/bin/env python3
"""Execute the locked S03 finite experiment, retaining every case and negative result.

Author: Antonio Clim. Fixtures are data and are never executed. Standard library
only. Rates describe this dependent synthetic corpus, not a population.
"""
from __future__ import annotations
import argparse
import ast
import base64
import collections
import copy
import datetime
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'tests' / 's03'))
import corpus
import oracles

EXPECTED_CORPUS = '7dc4f4bf0ff6260fa0e8f4aef7673f2a9c659eab4f76316a53441d8f9adac089'
LOCK_HASH = 'e5ee95190a74e9f84e12450cd2b27dc3a2ac241409e5b41c384a7f920123c6e0'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def clean_paths(value):
    if isinstance(value, dict):
        return {k: clean_paths(v) for k, v in value.items() if k != 'path'}
    if isinstance(value, list): return [clean_paths(v) for v in value]
    return value


def records(result):
    out = {}
    for record in result['observations']:
        ordinal = int(record['entity']['entity_id'].split(':')[1]) if record['entity']['entity_kind'] == 'python_callable' else 0
        out[(record['observation_id'], ordinal)] = record
    return out


def normalised(data):
    return data.decode('utf-8-sig').replace('\r\n', '\n').replace('\r', '\n')


def outcome(kernel, data, language, path='fixture'):
    try:
        return {'status': 'ok', 'result': kernel.measure_bytes(data, language=language, path=path)}
    except kernel.MeasurementError as exc:
        return {'status': 'refused', 'code': exc.code, 'type': type(exc).__name__}
    except Exception as exc:
        return {'status': 'exception', 'type': type(exc).__name__, 'message': str(exc)}


class Checks:
    def __init__(self, journal=None):
        self.journal = journal
        self.groups = collections.defaultdict(lambda: {'checks': 0, 'failed_checks': 0, 'eligible_cases': set(), 'failed_cases': set(), 'max_abs_error': 0.0, 'max_rel_error': 0.0})
        self.failures = []
        self.case = ''
        self.group = ''
    def check(self, label, actual, expected, numeric=False):
        g = self.groups[self.group]
        g['checks'] += 1; g['eligible_cases'].add(self.case)
        ok = type(actual) is type(expected) and actual == expected
        if numeric and isinstance(actual, (int, float)) and not isinstance(actual, bool) and isinstance(expected, (int, float)) and not isinstance(expected, bool):
            ae = abs(actual - expected); re = ae / max(abs(actual), abs(expected)) if actual or expected else 0.0
            g['max_abs_error'] = max(g['max_abs_error'], ae); g['max_rel_error'] = max(g['max_rel_error'], re)
            ok = math.isfinite(actual) and ae <= max(1e-10, 1e-12 * max(abs(actual), abs(expected)))
            if isinstance(expected, int): ok = isinstance(actual, int) and not isinstance(actual, bool) and actual == expected
        if not ok:
            g['failed_checks'] += 1; g['failed_cases'].add(self.case)
            self.failures.append({'case_id': self.case, 'group': self.group, 'check': label, 'actual': actual, 'expected': expected})
            if self.journal:
                self.journal.write(json.dumps(self.failures[-1], ensure_ascii=False, default=str) + '\n'); self.journal.flush()
        return ok
    def value(self, record, expected, label):
        if record is None: return self.check(label + ':present', False, True)
        self.check(label + ':value', record['value'], expected, numeric=isinstance(expected, (int, float)))
        self.check(label + ':state', record['applicability']['state'], 'insufficient_evidence' if expected is None else 'observed')
    def summary(self):
        return {name: dict(g, eligible_cases=len(g['eligible_cases']), failed_cases=len(g['failed_cases']), case_violation_proportion=len(g['failed_cases']) / len(g['eligible_cases']) if g['eligible_cases'] else None, check_discrepancy_proportion=g['failed_checks'] / g['checks'] if g['checks'] else None) for name, g in sorted(self.groups.items())}


def evaluate_case(case, output, ck, kernel, catalogue):
    data = base64.b64decode(case['bytes_b64']); lang = case['language']
    ck.case = case['case_id']; ck.group = 'intake-and-totality'
    if lang == 'c':
        ck.check('unsupported-language', (output['status'], output.get('code')), ('refused', 'ME-008')); return
    invalid = None
    if b'\0' in data: invalid = 'ME-004'
    else:
        try: text = normalised(data)
        except UnicodeDecodeError: invalid = 'ME-003'
    if invalid:
        ck.check('invalid-input-refusal', (output['status'], output.get('code')), ('refused', invalid)); return
    if not ck.check('valid-input-totality', output['status'], 'ok'): return
    result = output['result']; rs = records(result)
    try:
        kernel.validate_kernel_result(result); kernel.verify_result_against_catalogue(result, catalogue)
        ck.check('output-contract', True, True)
    except Exception as exc:
        ck.check('output-contract', type(exc).__name__ + ':' + str(exc), 'accepted')
    ck.group = 'generic-differential'
    for oid, expected in oracles.generic(data).items(): ck.value(rs.get((oid, 0)), expected, oid)
    ck.group = 'source-binding'
    ck.check('raw-sha256', result['artifact']['raw_sha256'], corpus.digest(data))
    ck.check('normalised-sha256', result['artifact']['normalised_sha256'], corpus.digest(text.encode()))
    if lang == 'python':
        ck.group = 'python-differential'
        try: expected = oracles.python_counts(text)
        except (SyntaxError, ValueError, IndentationError):
            ck.value(rs.get(('python.parse_status', 0)), 'syntax_error', 'parse-status')
            return
        except Exception as exc:
            ck.group = 'oracle-error'; ck.check('oracle-totality', type(exc).__name__, 'completed'); return
        for key, value in expected.items(): ck.value(rs.get(key), value, ':'.join(map(str, key)))
        if 'analytic' in case:
            ck.group = 'python-analytic'
            for oid, value in case['analytic'].items(): ck.value(rs.get((oid, 0)), value, oid)
    if lang == 'markdown':
        ck.group = 'markdown-differential'
        for oid, value in oracles.markdown(text).items(): ck.value(rs.get((oid, 0)), value, oid)


def hypotheses(case, output, parent, ck, adapter):
    hid = case['hypothesis']; number = int(hid[-2:]); ck.case = case['case_id']; ck.group = hid
    if number == 7:
        ck.check('unsupported-is-typed', (output['status'], output.get('code')), ('refused', 'ME-008')); return
    if not ck.check('transformed-totality', output['status'], 'ok'): return
    if not ck.check('parent-totality', parent['status'], 'ok'): return
    current = output['result']; baseline = parent['result']; a, b = records(current), records(baseline)
    if number == 8:
        ck.value(a.get(('python.parse_status', 0)), 'syntax_error', 'parse-status')
        ast_keys = [k for k in a if k[0].startswith('python.') and not k[0].startswith('python.comment') and k[0] != 'python.parse_status']
        ck.check('ast-singletons', len(ast_keys), 15)
        for key in ast_keys:
            ck.check(str(key) + ':typed-missing', (a[key]['value'], a[key]['applicability']['state'], a[key]['applicability']['reason_code']), (None, 'unavailable', 'ME-006'))
        return
    ck.check('observation-correspondence', sorted(a), sorted(b))
    for key in sorted(set(a) & set(b)):
        oid = key[0]
        include = True
        if number in (2, 3) and oid == 'source.byte_count': include = False
        if number in (4, 5, 6):
            include = oid.startswith('python.')
            if number in (5, 6): include = include and not oid.startswith('python.comment') and oid != 'python.callable.physical_span_lines'
        if include:
            ck.check(str(key) + ':value', a[key]['value'], b[key]['value'], numeric=True)
            ck.check(str(key) + ':state', a[key]['applicability']['state'], b[key]['applicability']['state'])
        if number in (1, 2, 3):
            ck.check(str(key) + ':record-identity', a[key]['record_id'], b[key]['record_id'])
            ck.check(str(key) + ':evidence-identity', a[key]['source_evidence_ids'], b[key]['source_evidence_ids'])
            if include:
                ck.check(str(key) + ':adapter-fingerprint', adapter.adapt_observation(a[key])['fingerprint'], adapter.adapt_observation(b[key])['fingerprint'])
    if number in (1, 2, 3): ck.check('normalised-hash', current['artifact']['normalised_sha256'], baseline['artifact']['normalised_sha256'])
    if number == 1: ck.check('measurement-digest', current['measurement_digest'], baseline['measurement_digest'])
    if number in (2, 3):
        original = base64.b64decode(case['_parent_bytes'])
        delta = original.count(b'\n') if number == 2 else 3
        ck.check('exact-byte-delta', a[('source.byte_count', 0)]['value'] - b[('source.byte_count', 0)]['value'], delta)
        if number == 3: ck.check('bom-encoding', current['artifact']['encoding'], 'utf-8-sig')
    if number == 5:
        for oid in ('python.comment_token_count', 'python.comment_physical_line_count'):
            ck.check(oid + ':exact-delta', a[(oid, 0)]['value'] - b[(oid, 0)]['value'], 1)


def resource_worker(root, name):
    cap = 'timeout-only'
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024)); cap = 'address-space-512MiB'
    except (ImportError, ValueError, OSError): pass
    sys.path.insert(0, str(root / 'src'))
    kernel = load('codeprobe_measurement_kernel', root / 'src/codeprobe_measurement_kernel.py')
    data = {
        'deep-expression-1500': b'def f():\n    return ' + b'1+' * 1500 + b'1\n',
        'deep-expression-6000': b'def f():\n    return ' + b'1+' * 6000 + b'1\n',
        'deep-brackets-1000': b'x=' + b'[' * 1000 + b'0' + b']' * 1000,
        'long-bounded-text': b'a' * 999999,
        'many-bounded-lines': b'x=0\n' * 50000,
    }[name]
    output = outcome(kernel, data, 'text' if name == 'long-bounded-text' else 'python')
    brief = {'status': output['status'], 'code': output.get('code'), 'type': output.get('type'), 'cap': cap, 'source_sha256': corpus.digest(data), 'source_bytes': len(data)}
    if output['status'] == 'ok':
        brief['digest'] = output['result']['measurement_digest']
        brief['result'] = output['result']
    print(corpus.canonical(brief))


def adversarial(root, kernel, adapter, ck, outdir):
    output = []
    def probe(name, call, acceptable=(ValueError,), note='contract rejection'):
        ck.case = 'adv-' + name; ck.group = 'adversarial'
        try: result = call(); accepted = False; detail = {'status': 'false_acceptance', 'returned_type': type(result).__name__}
        except Exception as exc:
            accepted = isinstance(exc, acceptable); detail = {'status': 'rejected' if accepted else 'unexpected_exception', 'type': type(exc).__name__, 'code': getattr(exc, 'code', None)}
        ck.check(note, accepted, True); output.append(dict(case_id=ck.case, **detail, expected=note))
    for name, data in [('invalid-utf8', b'\xff'), ('nul', b'a\0'), ('overlong-utf8', b'\xc0\x80'), ('surrogate-utf8', b'\xed\xa0\x80')]:
        probe(name, lambda data=data: kernel.measure_bytes(data, language='python'), (kernel.MeasurementError,))
    for budget in (0, -1, True, 1.5, '2', None):
        probe('invalid-budget-' + str(budget), lambda budget=budget: kernel.measure_bytes(b'x', language='text', max_bytes=budget))
    probe('byte-budget-exceeded', lambda: kernel.measure_bytes(b'abc', language='text', max_bytes=2), (kernel.MeasurementError,))
    probe('non-byte-input', lambda: kernel.measure_bytes('x', language='text'), (TypeError,))
    probe('unsupported', lambda: kernel.measure_bytes(b'x', language='javascript'), (kernel.MeasurementError,))
    base = kernel.measure_bytes(b'def f(x):\n    return x if x else 1\n', language='python', path='owned.py')
    record = copy.deepcopy(next(r for r in base['observations'] if r['observation_id'] == 'source.byte_count'))
    def change_result(change):
        altered = copy.deepcopy(base); altered.pop('measurement_digest'); change(altered); kernel.validate_kernel_result(altered)
    result_mutations = {
        'evidence-path': lambda x: x['source_evidence'][0].update(path='foreign.py'),
        'evidence-coordinate': lambda x: x['source_evidence'][0].update(end_line=x['source_evidence'][0]['end_line'] + 2),
        'record-path': lambda x: x['observations'][0]['entity'].update(path='foreign.py'),
        'record-identity': lambda x: x['observations'][0].update(record_id='observation:' + '0' * 64),
        'prohibited-ai-score': lambda x: x.update(aiProbability=0.9),
        'prohibited-misconduct': lambda x: x.update(misconduct_decision=True),
    }
    for name, change in result_mutations.items(): probe(name, lambda change=change: change_result(change))
    def change_record(change, adapt=False):
        altered = copy.deepcopy(record); change(altered)
        return adapter.adapt_observation(altered) if adapt else kernel.validate_observation_record(altered)
    for name, value in [('negative-count', -1), ('fractional-count', 1.5), ('boolean-count', True), ('string-count', '1'), ('bytes-count', b'x'), ('complex-count', 1j), ('nan-count', float('nan')), ('list-count', [1])]:
        probe(name, lambda value=value: change_record(lambda x: x.update(value=value)))
    probe('adapter-invalid-identity', lambda: change_record(lambda x: x.update(record_id='bad'), True))
    probe('adapter-invalid-value', lambda: change_record(lambda x: x.update(value=-1), True))
    probe('adapter-invalid-entity', lambda: change_record(lambda x: x['entity'].update(entity_kind='arbitrary'), True))
    original_parse = kernel.ast.parse
    for failure in (MemoryError, RecursionError):
        def throw(*args, failure=failure, **kwargs): raise failure('S03 explicit fault injection')
        kernel.ast.parse = throw
        try: probe('injected-' + failure.__name__, lambda: kernel.measure_bytes(b'x=1\n', language='python'), (kernel.MeasurementError,), 'typed resource failure')
        finally: kernel.ast.parse = original_parse
    with tempfile.TemporaryDirectory() as td:
        td = Path(td); target = td / 'source.py'; target.write_bytes(b'x=1\n')
        probe('directory-input', lambda: kernel.measure_file(td, language='python'), (kernel.MeasurementError,))
        probe('missing-file', lambda: kernel.measure_file(td / 'missing.py', language='python'), (kernel.MeasurementError,))
        try:
            os.symlink(target, td / 'link.py')
        except (OSError, NotImplementedError) as exc:
            output.append({'case_id': 'adv-symlink', 'status': 'not_executed', 'reason': type(exc).__name__})
        else: probe('symlink', lambda: kernel.measure_file(td / 'link.py', language='python'), (kernel.MeasurementError,))
    for name in ('deep-expression-1500', 'deep-expression-6000', 'deep-brackets-1000', 'long-bounded-text', 'many-bounded-lines'):
        ck.case = 'adv-' + name; ck.group = 'resource-adversarial'
        command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--root', str(root), '--worker', name]
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=15)
            detail = json.loads(result.stdout) if result.returncode == 0 else {'status': 'process_failure', 'returncode': result.returncode, 'stderr': result.stderr[-2000:]}
        except subprocess.TimeoutExpired: detail = {'status': 'timeout', 'timeout_seconds': 15}
        except json.JSONDecodeError: detail = {'status': 'invalid-worker-output', 'stdout': result.stdout, 'stderr': result.stderr}
        ck.check('bounded-typed-completion', detail['status'] in ('ok', 'refused'), True)
        if detail['status'] == 'refused':
            ck.check('resource-refusal-code', detail.get('code'), 'ME-015')
        elif detail['status'] == 'ok':
            rs = records(detail['result'])
            ck.value(rs.get(('source.byte_count', 0)), detail['source_bytes'], 'source-byte-count')
            if name == 'deep-brackets-1000':
                ck.value(rs.get(('python.parse_status', 0)), 'syntax_error', 'parse-status')
                missing = [r for (oid, _) , r in rs.items() if oid.startswith('python.') and not oid.startswith('python.comment') and oid != 'python.parse_status']
                ck.check('ast-missing-count', len(missing), 15)
                for record in missing:
                    ck.check(record['observation_id'] + ':typed-missing', (record['value'], record['applicability']['state'], record['applicability']['reason_code']), (None, 'unavailable', 'ME-006'))
            elif name != 'long-bounded-text':
                ck.value(rs.get(('python.parse_status', 0)), 'parsed', 'parse-status')
                expected_literals = {'deep-expression-1500': 1501, 'deep-expression-6000': 6001, 'many-bounded-lines': 50000}[name]
                ck.value(rs.get(('python.numeric_literal_count', 0)), expected_literals, 'analytic-literal-count')
        output.append(dict(case_id=ck.case, **detail))
    # Minimal counterexample for a homogeneous closer required by the specification.
    data = b'```\nx\n```~\n# Heading\n'; ck.case = 'adv-mixed-fence-closer'; ck.group = 'adversarial'
    r = kernel.measure_bytes(data, language='markdown'); rs = records(r)
    for oid, expected in oracles.markdown(normalised(data)).items(): ck.value(rs.get((oid, 0)), expected, oid)
    output.append({'case_id': ck.case, 'status': 'measured', 'source_b64': base64.b64encode(data).decode(), 'result': r})
    (outdir / 'adversarial.json').write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding='utf-8')
    return output


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--root', type=Path, required=True); parser.add_argument('--output', type=Path); parser.add_argument('--strict', action='store_true'); parser.add_argument('--worker'); args = parser.parse_args()
    root = args.root.resolve()
    if args.worker:
        resource_worker(root, args.worker); return 0
    outdir = args.output.resolve(); outdir.mkdir(parents=True, exist_ok=True)
    lock = HERE / 'research/s03/resumption-protocol.v1.json'
    if corpus.digest(lock.read_bytes()) != LOCK_HASH: raise SystemExit('Locked protocol bytes changed')
    cases = corpus.generate(); manifest = ''.join(corpus.canonical(c) + '\n' for c in cases).encode()
    if corpus.digest(manifest) != EXPECTED_CORPUS: raise SystemExit('Corpus hash differs from locked implementation manifest')
    (outdir / 'corpus.jsonl').write_bytes(manifest)
    sys.path.insert(0, str(root / 'src'))
    kernel = load('codeprobe_measurement_kernel', root / 'src/codeprobe_measurement_kernel.py')
    adapter = load('codeprobe_s01_observation_adapter', root / 'src/codeprobe_s01_observation_adapter.py')
    catalogue = json.loads((root / 'research/observation-catalogue.v1.json').read_text(encoding='utf-8'))
    journal = open(outdir / 'negative-journal.jsonl', 'w', encoding='utf-8')
    ck = Checks(journal); parents = {}; core = []; counts = collections.Counter(); started = datetime.datetime.now(datetime.timezone.utc).isoformat(); t0 = time.monotonic()
    with open(outdir / 'outcomes.jsonl.gz', 'wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as gz:
            for index, case in enumerate(cases):
                if index % 50 == 0:
                    print(json.dumps({'progress': index, 'failures': len(ck.failures), 'elapsed': round(time.monotonic() - t0, 2)}), flush=True)
                    (outdir / 'checkpoint.json').write_text(json.dumps({'cases_started': index, 'failures': len(ck.failures), 'groups': ck.summary()}, indent=2), encoding='utf-8')
                data = base64.b64decode(case['bytes_b64'])
                output = outcome(kernel, data, case['language'], path='renamed/' + case['case_id'] if case.get('hypothesis') == 'H-S03-01' else case['case_id'])
                counts[output['status']] += 1
                evaluate_case(case, output, ck, kernel, catalogue)
                if case['kind'] == 'core': parents[case['case_id']] = (output, case['bytes_b64']); core.append({'case_id': case['case_id'], 'outcome': clean_paths(output)})
                if case['kind'] == 'transformation':
                    parent, payload = parents[case['parent']]; local = dict(case, _parent_bytes=payload)
                    hypotheses(local, output, parent, ck, adapter)
                gz.write((corpus.canonical({'case_id': case['case_id'], 'outcome': output}) + '\n').encode())
    ck.group = 'route-equivalence'
    with tempfile.TemporaryDirectory() as td:
        for cid, (output, b64) in parents.items():
            ck.case = cid; path = Path(td) / cid; path.write_bytes(base64.b64decode(b64))
            language = output['result']['artifact']['language']
            try:
                viafile = kernel.measure_file(path, language=language)
                ck.check('bytes-versus-file', clean_paths(viafile), clean_paths(output['result']))
                for record in viafile['observations']:
                    adapted = adapter.adapt_observation(record)
                    ck.check(record['observation_id'] + ':adapter-state', adapted['applicability']['status'], record['applicability']['state'])
                    ck.check(record['observation_id'] + ':adapter-value', adapted['value'], record['value'], numeric=True)
            except Exception as exc: ck.check('file-route-exception', type(exc).__name__, 'none')
    adv = adversarial(root, kernel, adapter, ck, outdir)
    (outdir / 'core-canonical.json').write_text(corpus.canonical(core) + '\n', encoding='utf-8', newline='\n')
    source_files = ['src/codeprobe_measurement_kernel.py', 'src/codeprobe_s01_observation_adapter.py']
    source_hashes = {p: corpus.digest((root / p).read_bytes()) for p in source_files}
    try: commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError): commit = None
    report = {'schema': 'codeprobe-s03-experiment/v1', 'started_at_utc': started, 'elapsed_seconds': round(time.monotonic() - t0, 3), 'python': platform.python_version(), 'platform': platform.platform(), 'system': platform.system(), 'machine': platform.machine(), 'git_head': commit, 'source_sha256': source_hashes, 'protocol_sha256': LOCK_HASH, 'corpus_sha256': EXPECTED_CORPUS, 'generator_sha256': corpus.digest((HERE / 'tests/s03/corpus.py').read_bytes()), 'oracle_sha256': corpus.digest((HERE / 'tests/s03/oracles.py').read_bytes()), 'runner_sha256': corpus.digest(Path(__file__).read_bytes()), 'case_count': len(cases), 'outcome_counts': dict(counts), 'adversarial_count': len(adv), 'groups': ck.summary(), 'failure_count': len(ck.failures), 'failed_cases': len({f['case_id'] for f in ck.failures}), 'core_canonical_sha256': corpus.digest((outdir / 'core-canonical.json').read_bytes()), 'limitations': ['Dependent synthetic cases; not a population sample', 'Independent AST traversal shares CPython parser', 'No fixture execution or browser-route validation', 'Local OS/Python evidence only; platform matrix reported separately']}
    (outdir / 'discrepancies.json').write_text(json.dumps(ck.failures, indent=2, ensure_ascii=False, default=str), encoding='utf-8')
    (outdir / 'summary.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    journal.close()
    print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
    return int(bool(ck.failures) and args.strict)


if __name__ == '__main__':
    raise SystemExit(main())
