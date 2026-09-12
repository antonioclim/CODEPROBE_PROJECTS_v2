#!/usr/bin/env python3
"""Record exact-candidate browser execution. Author: Antonio Clim."""
from __future__ import annotations
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def git(*args): return subprocess.check_output(['git','-C',str(ROOT),*args],text=True,timeout=15).strip()


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--sha');p.add_argument('--executable');p.add_argument('--transport',choices=['file','loopback','dom'],default='file');a=p.parse_args()
    out=a.output.resolve()
    if out==ROOT or ROOT in out.parents:raise ValueError('output must be outside source')
    out.mkdir(parents=True,exist_ok=True);sha=git('rev-parse','HEAD')
    if a.sha and sha!=a.sha:raise ValueError('wrong candidate')
    if git('status','--porcelain','--untracked-files=all'):raise ValueError('browser candidate must be clean')
    cmd=[sys.executable,'-I','-B','tools/test_s05_browser.py','--evidence',str(out/'finite'),'--output',str(out/'browser'),'--transport',a.transport]
    if a.executable:cmd+=['--executable',a.executable]
    commands=[('finite',[sys.executable,'-I','-S','-B','tools/run_s05_reporting.py','--output',str(out/'finite')]),('browser',cmd)]
    statuses=[]
    for name,command in commands:
        with (out/(name+'.log')).open('w',encoding='utf-8') as handle:
            try:code=subprocess.run(command,cwd=ROOT,stdout=handle,stderr=subprocess.STDOUT,timeout=300).returncode
            except subprocess.TimeoutExpired:code='timeout-300s'
        statuses.append({'check':name,'returncode':code});print(json.dumps(statuses[-1]),flush=True)
        if code!=0:break
    dirty=bool(git('status','--porcelain','--untracked-files=all'))
    meta={'sha':sha,'tree':git('rev-parse','HEAD^{tree}'),'checkout_state':'working_tree' if dirty else 'clean_checkout',
          'checks':statuses,'transport':a.transport,'dependencies':{name:importlib.metadata.version(name) for name in ('playwright','pyee','greenlet')},
          'python':sys.version.split()[0],'executable_override':a.executable,'scope':'Browser test acquisition is distinct from runtime processing; no manual accessibility evaluation.'}
    (out/'browser-cell.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
    if dirty or any(x['returncode']!=0 for x in statuses):raise SystemExit(1)


if __name__=='__main__':main()
