#!/usr/bin/env python3
"""S04 exact-candidate checker and matrix comparison. Author: Antonio Clim."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE='5e8036489a830afcf557e8accded80c85eea01bc'
LOCK='fd883a13c705fdddae8814f2759027afb92bd5f5'
LOCK_HASH='2402c6812ff44f84cd5237d3648338a5aed72f2cb9b8c4fc0ae5a6624f1328c4'
CELLS={('ubuntu-24.04','3.10.21'),('ubuntu-24.04','3.14.7'),('windows-2025','3.14.7'),('macos-15','3.14.7')}


def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True,timeout=10).strip()


def compare(directory,sha):
    paths=sorted(directory.glob('s04-*/summary.json'))
    if len(paths)!=4:raise SystemExit('exactly four cell summaries required')
    reports=[json.loads(p.read_text(encoding='utf-8')) for p in paths];received=set()
    for path,report in zip(paths,reports):
        cell=json.loads((path.parent/'cell.json').read_text(encoding='utf-8'));r=report['build']['runtime'];received.add((cell['os'],r['python']))
        system,machines={'ubuntu-24.04':('Linux',{'x86_64'}),'windows-2025':('Windows',{'amd64','x86_64'}),'macos-15':('Darwin',{'arm64'})}[cell['os']]
        if r['system']!=system or r['machine'].lower() not in machines:raise SystemExit('actual platform mismatch')
        if report['build']['git_anchor_commit']!=sha or cell['sha']!=sha or report['build']['checkout_state']!='clean_checkout':raise SystemExit('candidate SHA or checkout mismatch')
        if report['failure_count'] or cell['failed_checks']:raise SystemExit('a cell failed')
        expected_counts = {'boundary_cases':504, 'base_source_cases':21, 'interpretation_executions':369, 'metamorphic_comparisons':306}
        if any(report[key] != value for key, value in expected_counts.items()):raise SystemExit('finite coverage changed')
        if json.loads((path.parent/'discrepancies.json').read_text(encoding='utf-8')) != []:raise SystemExit('nonempty discrepancy ledger')
        with gzip.open(path.parent/'capsules.jsonl.gz', 'rt', encoding='utf-8') as handle:
            capsules = [json.loads(line) for line in handle]
        if len(capsules) != 369 or len({x['case_id'] for x in capsules}) != 369 or any('capsule' not in x for x in capsules):raise SystemExit('raw capsule coverage mismatch')
        if len(json.loads((path.parent/'analytic-boundaries.json').read_text(encoding='utf-8'))) != 504:raise SystemExit('boundary evidence missing')
        for field in ('boundary_cases','base_source_cases','interpretation_executions','metamorphic_comparisons','source_cases_sha256','decision_projections_sha256','profiles'):
            if report[field]!=reports[0][field]:raise SystemExit('matrix discrepancy: '+field)
        if report['build']['implementation_digest']!=reports[0]['build']['implementation_digest']:raise SystemExit('implementation mismatch')
        for name,key in [('source-cases.jsonl','source_cases_sha256'),('decision-projections.json','decision_projections_sha256')]:
            data=(path.parent/name).read_bytes()
            if hashlib.sha256(data).hexdigest()!=report[key]:raise SystemExit('artefact bytes mismatch')
            if data!=(paths[0].parent/name).read_bytes():raise SystemExit('exact byte comparison failed')
            if len(data.splitlines() if name.endswith('.jsonl') else json.loads(data)) != 369:raise SystemExit('manifest/projection coverage mismatch')
    if received!=CELLS:raise SystemExit('incomplete platform matrix')
    verdict=dict(status='PASS',candidate_sha=sha,cells=sorted(received),interpretation_executions_per_cell=reports[0]['interpretation_executions'],decision_projections_sha256=reports[0]['decision_projections_sha256'],scope='Native finite interpretation comparison; no empirical calibration or browser evidence.')
    (directory/'MATRIX_VERDICT.json').write_text(json.dumps(verdict,indent=2)+'\n',encoding='utf-8');print(json.dumps(verdict))


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);p.add_argument('--compare',type=Path);p.add_argument('--sha');a=p.parse_args()
    if a.compare:compare(a.compare,a.sha);return
    out=a.output.resolve()
    if out==ROOT or ROOT in out.parents:raise SystemExit('output must be outside source')
    out.mkdir(parents=True,exist_ok=True)
    sha=git('rev-parse','HEAD')
    if a.sha and sha!=a.sha:raise SystemExit('wrong candidate SHA')
    if git('status','--porcelain','--untracked-files=all'):raise SystemExit('exact candidate must be clean')
    if git('rev-parse','HEAD^')!=LOCK:raise SystemExit('candidate parent differs from prospective lock')
    changed=git('diff','--name-status',BASE,'HEAD').splitlines()
    if any(not line.startswith('A\t') for line in changed):raise SystemExit('S04 must leave inherited S03 files unchanged')
    if hashlib.sha256((ROOT/'research/s04/acceptance-lock.v1.json').read_bytes()).hexdigest()!=LOCK_HASH:raise SystemExit('prospective lock changed')
    commands=[('s02-s01-regression',[sys.executable,'-I','-S','-B','-X',f'pycache_prefix={out/"cache"}','tools/check_s02_measurement_kernel.py','--root',str(ROOT)]),
              ('s03-corrective-regression',[sys.executable,'-I','-S','-B','tests/s03/test_contract.py']),
              ('s04-unit',[sys.executable,'-I','-S','-B','tests/s04/test_interpretation.py']),
              ('s04-finite',[sys.executable,'-I','-S','-B','tools/run_s04_interpretation.py','--output',str(out)])]
    failures=[];statuses=[]
    for name,command in commands:
        with (out/(name+'.log')).open('w',encoding='utf-8') as handle:
            try:code=subprocess.run(command,cwd=ROOT,stdout=handle,stderr=subprocess.STDOUT,timeout=180).returncode
            except subprocess.TimeoutExpired:code='timeout-180s'
        statuses.append(dict(check=name,returncode=code));print(json.dumps(statuses[-1]),flush=True)
        if code!=0:failures.append(statuses[-1])
    import shutil
    shutil.rmtree(out/'cache',ignore_errors=True)
    if git('status','--porcelain','--untracked-files=all'):failures.append(dict(check='clean-checkout-after',returncode=1))
    cell=dict(os=os.environ.get('S04_OS','local-development'),sha=sha,python=platform.python_version(),checks=statuses,failed_checks=failures)
    (out/'cell.json').write_text(json.dumps(cell,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(cell),flush=True)
    if failures:raise SystemExit(1)
    print('PASS: S04 exact candidate, inherited regressions and finite interpretation checks')


if __name__=='__main__':main()
