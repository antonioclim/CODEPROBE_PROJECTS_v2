#!/usr/bin/env python3
"""S03 exact-candidate check and matrix comparison. Author: Antonio Clim."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def compare_matrix(directory, expected_sha):
    paths = sorted(directory.glob('s03-*/summary.json'))
    if len(paths) != 4: raise SystemExit(f'Expected four distinct matrix cells, found {len(paths)}')
    reports = [json.loads(path.read_text(encoding='utf-8')) for path in paths]
    required = {('ubuntu-24.04', '3.10.21'), ('ubuntu-24.04', '3.14.7'), ('windows-2025', '3.14.7'), ('macos-15', '3.14.7')}
    received = set()
    shared = ['source_sha256', 'protocol_sha256', 'corpus_sha256', 'generator_sha256', 'oracle_sha256', 'runner_sha256', 'core_canonical_sha256']
    for path, report in zip(paths, reports):
        cell = json.loads((path.parent / 'cell.json').read_text(encoding='utf-8'))
        received.add((cell['os'], report['python']))
        system, architectures = {'ubuntu-24.04': ('Linux', {'x86_64'}), 'windows-2025': ('Windows', {'amd64', 'x86_64'}), 'macos-15': ('Darwin', {'arm64'})}[cell['os']]
        if report['system'] != system or report['machine'].lower() not in architectures: raise SystemExit('Actual interpreter platform differs from the declared matrix cell')
        if report['git_head'] != expected_sha or cell['git_sha'] != expected_sha: raise SystemExit('Matrix cell ran a different source commit')
        if report['failure_count'] != 0 or report['case_count'] != 2000 or report['adversarial_count'] != 41: raise SystemExit('Cell failed or changed corpus coverage')
        if any(report[k] != reports[0][k] for k in shared): raise SystemExit('Cross-platform source or core-output discrepancy')
        data = (path.parent / 'core-canonical.json').read_bytes()
        if hashlib.sha256(data).hexdigest() != report['core_canonical_sha256'] or len(json.loads(data)) != 80: raise SystemExit('Core result bytes do not match the cell manifest')
        frontiers = json.loads((path.parent / 'grammar-frontiers.json').read_text(encoding='utf-8'))
        if len(frontiers) != 3 or not all(x['passed'] for x in frontiers): raise SystemExit('Runtime grammar frontier mismatch')
    if received != required: raise SystemExit(f'Matrix coverage differs: {received ^ required}')
    verdict = {'status': 'PASS', 'exact_sha': expected_sha, 'matrix_cells': sorted([list(x) for x in received]), 'common_core_cases': 80, 'core_canonical_sha256': reports[0]['core_canonical_sha256'], 'scope': 'Finite native corpus only. Grammar frontiers and OS-specific resource/symlink limits are separate.'}
    (directory / 'MATRIX_VERDICT.json').write_text(json.dumps(verdict, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(verdict, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path); parser.add_argument('--compare', type=Path); parser.add_argument('--sha'); args = parser.parse_args()
    if args.compare:
        compare_matrix(args.compare, args.sha); return
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    commands = [
        ('s02-regression', [sys.executable, '-I', '-S', '-B', '-X', f'pycache_prefix={output / "pycache"}', str(ROOT / 'tools/check_s02_measurement_kernel.py'), '--root', str(ROOT)]),
        ('s03-regression', [sys.executable, '-I', '-S', '-B', str(ROOT / 'tests/s03/test_contract.py')]),
        ('experiment', [sys.executable, '-I', '-S', '-B', str(ROOT / 'tools/run_s03_robustness.py'), '--root', str(ROOT), '--output', str(output), '--strict']),
    ]
    failures = []
    for name, command in commands:
        with (output / (name + '.log')).open('w', encoding='utf-8') as handle:
            try:
                result = subprocess.run(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, timeout=240)
                code = result.returncode
            except subprocess.TimeoutExpired: code = 'timeout-240s'
        print(json.dumps({'check': name, 'returncode': code}), flush=True)
        if code != 0: failures.append((name, code))
    sys.path[:0] = [str(ROOT / 'tests/s03'), str(ROOT / 'src'), str(ROOT / 'tools')]
    import test_contract
    frontiers = test_contract.grammar_frontiers()
    (output / 'grammar-frontiers.json').write_text(json.dumps(frontiers, indent=2) + '\n', encoding='utf-8')
    if not all(x['passed'] for x in frontiers): failures.append(('grammar-frontiers', 'mismatch'))
    sha = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    (output / 'cell.json').write_text(json.dumps({'os': os.environ.get('S03_OS', 'local-development'), 'git_sha': sha, 'python': sys.version.split()[0]}, sort_keys=True) + '\n', encoding='utf-8')
    # Compilation caches are deliberately outside the source and are not evidence.
    import shutil
    shutil.rmtree(output / 'pycache', ignore_errors=True)
    # Portable evidence in the job log complements the complete uploaded files.
    # Print even failed-cell summaries; missing files remain explicit absences.
    for filename in ['summary.json', 'cell.json', 'grammar-frontiers.json', 'discrepancies.json', 'adversarial.json']:
        path = output / filename
        if path.is_file():
            value = json.loads(path.read_text(encoding='utf-8'))
            if filename == 'adversarial.json':
                value = [{k: v for k, v in item.items() if k != 'result'} for item in value]
            print('S03_EVIDENCE ' + filename + ' ' + json.dumps(value, sort_keys=True), flush=True)
        else:
            print('S03_EVIDENCE_MISSING ' + filename, flush=True)
    if failures: raise SystemExit(json.dumps({'failed': failures}))
    print('PASS: S03 scoped experiment, corrective regressions and grammar-frontier checks')


if __name__ == '__main__': main()
