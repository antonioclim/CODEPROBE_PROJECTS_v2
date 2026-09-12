#!/usr/bin/env python3
"""Finite S04 analytic and metamorphic checks; preserve every observed outcome."""
from __future__ import annotations
import argparse
import base64
import gzip
import itertools
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests/s03')]
import corpus
import codeprobe_interpretation as mod


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    if out==ROOT or ROOT in out.parents:raise SystemExit('Evidence must be outside the source tree')
    failures=[];records=[];boundary_count=0
    # Independent oracle: enumerate every integer threshold in the declared set.
    for lo in range(7):
        for nominal in range(lo,lo+3):
            for hi in range(nominal,nominal+3):
                for value in range(hi+3):
                    levels=dict(lower=lo,nominal=nominal,upper=hi)
                    predicates=sorted(set(value>threshold for threshold in range(lo,hi+1)))
                    status={ (False,):'no_rule_trigger', (True,):'review_opportunity', (False,True):'abstain'}[tuple(predicates)]
                    actual=mod.threshold_decision(value,levels)
                    expected=dict(nominal_predicate=value>nominal,possible_predicates=predicates,status=status,
                                  policy_sensitivity='boundary_sensitive' if len(predicates)==2 else 'stable_over_declared_threshold_set')
                    passed=actual==expected;boundary_count+=1
                    row=dict(case_id=f'boundary-{lo}-{nominal}-{hi}-{value}',family='analytic_boundary',levels=levels,value=value,expected=expected,actual=actual,passed=passed)
                    records.append(row)
                    if not passed:failures.append(row)
    fixtures=[]
    for i in range(8):fixtures.append((f'python-{i}','python',corpus.python_source(i)[0]))
    for i in range(4):fixtures.append((f'markdown-{i}','markdown',corpus.markdown_source(i)))
    for i in range(4):fixtures.append((f'text-{i}','text',corpus.text_source(i)))
    # These analytic sources deliberately cross the illustrative action boundaries.
    for n in (7,9,11,13,17):
        fixtures.append((f'branching-{n}','python',('def f(x):\n'+''.join(f'    if x == {i}: return {i}\n' for i in range(n))).encode()))
    profiles=mod.available_profiles();projection_records=[];source_cases=[];report_count=0;comparisons=0
    with (out/'capsules.jsonl.gz').open('wb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as handle:
            for cid,language,source in fixtures:
                transforms=[('original',source,cid),('path',source,'renamed/'+cid),('crlf',source.replace(b'\n',b'\r\n'),cid),('bom',b'\xef\xbb\xbf'+source,cid)]
                if language=='python':
                    transforms.extend([('alpha',corpus.token_transform(source,True),cid),('comment',b'# neutral comment\n'+source,cid),('spacing',corpus.token_transform(source),cid)])
                for profile in profiles:
                    reference=None
                    for name,data,path in transforms:
                        case_id=cid+':'+profile['profile_id']+':'+name
                        case=dict(case_id=case_id,language=language,profile_id=profile['profile_id'],profile_sha256=profile['sha256'],path=path,source_b64=base64.b64encode(data).decode(),source_sha256=mod.digest(data))
                        source_cases.append(case)
                        try:
                            report=mod.interpret_bytes(data,language=language,profile_id=profile['profile_id'],profile_sha256=profile['sha256'],task_family='source_inspection',path=path)
                            projection=mod.decision_projection(report)
                            if reference is None:reference=projection
                            else:
                                comparisons+=1
                                if projection!=reference:failures.append(dict(case_id=case_id,family='policy_metamorphic',expected=reference,actual=projection))
                            projection_records.append(dict(case_id=case_id,projection=projection))
                            handle.write(mod.canonical(dict(case_id=case_id,capsule=report))+b'\n')
                        except Exception as exc:
                            failure=dict(case_id=case_id,family='unexpected_exception',type=type(exc).__name__,message=str(exc));failures.append(failure);handle.write(mod.canonical(failure)+b'\n')
                        report_count+=1
    payload=b''.join(mod.canonical(x)+b'\n' for x in source_cases)
    (out/'source-cases.jsonl').write_bytes(payload)
    (out/'analytic-boundaries.json').write_bytes(mod.canonical(records)+b'\n')
    semantic=mod.canonical(projection_records)+b'\n';(out/'decision-projections.json').write_bytes(semantic)
    (out/'discrepancies.json').write_bytes(mod.canonical(failures)+b'\n')
    summary={'schema':'codeprobe-s04-finite-checks/v1','boundary_cases':boundary_count,'base_source_cases':len(fixtures),
             'interpretation_executions':report_count,'metamorphic_comparisons':comparisons,'failure_count':len(failures),
             'source_cases_sha256':mod.digest(payload),'decision_projections_sha256':mod.digest(semantic),
             'build':mod.build_identity(),'profiles':profiles,
             'scope':'Dependent finite synthetic cases; no population calibration or construct validity.'}
    (out/'summary.json').write_bytes(mod.canonical(summary)+b'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('build','profiles')},sort_keys=True),flush=True)
    return int(bool(failures))


if __name__=='__main__':raise SystemExit(main())
