#!/usr/bin/env python3
"""Exact S05 candidate checks and independent evidence-matrix admission.

Author: Antonio Clim. Regression, finite reporting and browser evidence are
separate. No green historical experiment is repeated for reassurance.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = '03163d557969d49c53a43ed5805733b13c4a1950'
LOCK = 'cbc7ea89d89fbdac6569c2dbd2b058c9e85cc42d'
LOCK_HASH = 'a1fc2d39880a2a44a8a3d62f89eaadd17a39d2d20865fe39905be5edfda57acc'
CELLS = {('ubuntu-24.04','3.10.21'), ('ubuntu-24.04','3.14.7'),
         ('windows-2025','3.14.7'), ('macos-15','3.14.7')}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',',':'), allow_nan=False).encode('utf-8')


def digest(data): return hashlib.sha256(data).hexdigest()
def git(*args): return subprocess.check_output(['git','-C',str(ROOT),*args], text=True, timeout=15).strip()
def read(path): return json.loads(path.read_text(encoding='utf-8'))


def validate_cell(path, sha):
    cell = read(path/'cell.json'); summary = read(path/'finite/summary.json')
    if cell['sha'] != sha or cell['failed_checks']: raise ValueError('failed cell or wrong candidate')
    runtime = summary['build']['runtime']; osname = cell['os']
    system, machines = {'ubuntu-24.04':('Linux',{'x86_64'}), 'windows-2025':('Windows',{'amd64','x86_64'}), 'macos-15':('Darwin',{'arm64'})}[osname]
    if runtime['system'] != system or runtime['machine'].lower() not in machines: raise ValueError('actual runtime differs from cell')
    if summary['build']['git_anchor_commit'] != sha or summary['build']['checkout_state'] != 'clean_checkout': raise ValueError('dirty or mismatched build')
    if summary['reports'] != 54 or summary['source_cases'] != 18 or summary['unique_source_payloads'] != 18 or summary['failure_count']: raise ValueError('finite coverage mismatch')
    if read(path/'finite/discrepancies.json') != []: raise ValueError('nonempty discrepancy ledger')
    manifest_bytes = (path/'finite/cases.jsonl').read_bytes(); manifest = [json.loads(s) for s in manifest_bytes.splitlines()]
    projections_bytes = (path/'finite/view-projections.json').read_bytes()
    if digest(manifest_bytes) != summary['source_case_manifest_sha256'] or digest(projections_bytes) != summary['view_projections_sha256']: raise ValueError('manifest hash mismatch')
    if len(manifest) != 54 or len({x['case_id'] for x in manifest}) != 54 or len(json.loads(projections_bytes)) != 54: raise ValueError('duplicate or missing finite cases')
    with gzip.open(path/'finite/bundles.jsonl.gz','rt',encoding='utf-8') as stream: bundles = [json.loads(line) for line in stream]
    if len(bundles) != 54 or len({x['case_id'] for x in bundles}) != 54: raise ValueError('raw bundle coverage mismatch')
    byid = {x['case_id']:x['bundle'] for x in bundles}
    for case in manifest:
        bundle = byid[case['case_id']]; cap = bundle['capsule']
        if bundle['digest'] != digest(canonical({k:v for k,v in bundle.items() if k!='digest'})): raise ValueError('bundle digest mismatch')
        if cap['digest'] != digest(canonical({k:v for k,v in cap.items() if k!='digest'})): raise ValueError('capsule digest mismatch')
        if bundle['digest'] != case['bundle_digest'] or cap['build'] != summary['build'] or bundle['presentation_build'] != summary['presentation_build']: raise ValueError('bundle identity mismatch')
        if digest(base64.b64decode(case['source_b64'],validate=True)) != case['source_sha256']: raise ValueError('source payload hash mismatch')
        if digest((path/'finite/html'/(case['case_id']+'.html')).read_bytes()) != case['html_sha256']: raise ValueError('HTML bytes mismatch')
        if cap['profile']['profile_id'] != case['context']['profile_id'] or cap['profile']['sha256'] != case['context']['profile_sha256']: raise ValueError('profile identity mismatch')
    # Manifests containing full-report digests differ legitimately by runtime.
    inputs = [{k:v for k,v in case.items() if k not in ('bundle_digest','html_sha256')} for case in manifest]
    return (osname,runtime['python']), summary, canonical(inputs), projections_bytes


def compare(directory, sha):
    paths = sorted(p.parent for p in directory.glob('s05-native-*/cell.json'))
    if len(paths) != 4: raise ValueError('exactly four native cells required')
    items = [validate_cell(path,sha) for path in paths]
    if {item[0] for item in items} != CELLS: raise ValueError('native matrix coverage mismatch')
    for _,summary,inputs,projections in items:
        if inputs != items[0][2] or projections != items[0][3]: raise ValueError('cross-platform input or decision bytes differ')
        if summary['presentation_build'] != items[0][1]['presentation_build'] or summary['build']['implementation_digest'] != items[0][1]['build']['implementation_digest']: raise ValueError('component identity differs')
    bp = directory/'s05-browser'
    browser = read(bp/'browser/browser-summary.json'); meta = read(bp/'browser-cell.json')
    if meta['sha'] != sha or meta['checkout_state'] != 'clean_checkout': raise ValueError('browser candidate mismatch')
    if browser['failure_count'] or browser['transport'] != 'file' or not browser['checks']: raise ValueError('actual standalone-file browser evidence required')
    names = {x['check'] for x in browser['checks'] if x['passed']}
    if not all(any(name.startswith('J'+str(n).zfill(2)+'-') for name in names) for n in range(1,13)): raise ValueError('incomplete browser journeys')
    if len(browser['checks']) != 41 or len(names) != 41: raise ValueError('browser check inventory mismatch')
    browser_finite = read(bp/'finite/summary.json')
    if browser_finite['build']['git_anchor_commit'] != sha or browser_finite['failure_count'] or browser_finite['view_projections_sha256'] != items[0][1]['view_projections_sha256']: raise ValueError('browser inputs/interpretation identity differs')
    for label,values in [('native',items[0][1]['presentation_build']['component_sha256']),('interpretation',items[0][1]['build']['component_sha256'])]:
        for name,expected in values.items():
            if digest((ROOT/name).read_bytes()) != expected: raise ValueError(label+' component differs from checkout')
    verdict = {'schema':'codeprobe-s05-matrix-verdict/v1','status':'PASS','candidate_sha':sha,
        'cells':sorted(CELLS),'reports_per_cell':54,'base_source_cases':18,'browser_checks':41,
        'browser':browser['browser'],'browser_transport':'file','view_projections_sha256':items[0][1]['view_projections_sha256'],
        'scope':'Finite native-to-standalone reporting and automated Chromium only. Not legacy Pyodide, manual assistive-technology testing, authentication or empirical validity.'}
    (directory/'MATRIX_VERDICT.json').write_bytes(canonical(verdict)+b'\n');print(json.dumps(verdict,indent=2))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);parser.add_argument('--compare',type=Path);parser.add_argument('--sha');a=parser.parse_args()
    if a.compare: compare(a.compare,a.sha); return
    out=a.output.resolve()
    if out==ROOT or ROOT in out.parents: raise ValueError('output must be outside source')
    out.mkdir(parents=True,exist_ok=True);sha=git('rev-parse','HEAD')
    if a.sha and sha!=a.sha: raise ValueError('wrong candidate SHA')
    if git('status','--porcelain','--untracked-files=all'): raise ValueError('candidate must be clean')
    if git('rev-parse','HEAD^') != LOCK: raise ValueError('wrong lock parent')
    if digest((ROOT/'research/s05/acceptance-lock.v1.json').read_bytes()) != LOCK_HASH: raise ValueError('acceptance lock changed')
    changes=git('diff','--name-status',BASE,'HEAD').splitlines()
    if not changes or any(not row.startswith('A\t') for row in changes): raise ValueError('inherited S04 bytes changed')
    commands=[('s02-s01-regression',[sys.executable,'-I','-S','-B','-X',f'pycache_prefix={out/"cache"}','tools/check_s02_measurement_kernel.py','--root',str(ROOT)],38),
              ('s03-corrective',[sys.executable,'-I','-S','-B','tests/s03/test_contract.py'],19),
              ('s04-unit',[sys.executable,'-I','-S','-B','tests/s04/test_interpretation.py'],46),
              ('s05-unit',[sys.executable,'-I','-S','-B','tests/s05/test_reporting.py'],36),
              ('s05-finite',[sys.executable,'-I','-S','-B','tools/run_s05_reporting.py','--output',str(out/'finite')],None)]
    failures=[];statuses=[]
    for name,command,expected in commands:
        logfile=out/(name+'.log')
        with logfile.open('w',encoding='utf-8') as f:
            try: code=subprocess.run(command,cwd=ROOT,stdout=f,stderr=subprocess.STDOUT,timeout=240).returncode
            except subprocess.TimeoutExpired: code='timeout-240s'
        text=logfile.read_text(encoding='utf-8'); counts=[int(x) for x in re.findall(r'Ran (\d+) tests? in',text)]
        accepted=code==0 and (expected is None or expected in counts) and 'skipped=' not in text
        row={'check':name,'returncode':code,'unit_counts_in_log':counts,'expected_primary_unit_count':expected,'accepted':accepted}
        statuses.append(row)
        if not accepted: failures.append(row)
        print(json.dumps(row),flush=True)
    shutil.rmtree(out/'cache',ignore_errors=True)
    if git('status','--porcelain','--untracked-files=all'): failures.append({'check':'clean-checkout-after','returncode':1})
    cell={'os':os.environ.get('S05_OS','local-development'),'sha':sha,'tree':git('rev-parse','HEAD^{tree}'),
          'python':platform.python_version(),'checks':statuses,'failed_checks':failures,'inherited_changes':changes}
    (out/'cell.json').write_bytes(canonical(cell)+b'\n');print(json.dumps(cell),flush=True)
    if failures: raise SystemExit(1)
    print('PASS: S05 exact candidate, inherited contracts and finite reporting')


if __name__=='__main__': main()
