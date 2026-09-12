#!/usr/bin/env python3
"""Retain the finite S05 report corpus and semantic projections. Author: Antonio Clim."""
from __future__ import annotations
import argparse
import base64
import gzip
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests/s05')]
import codeprobe_interpretation as i
import codeprobe_reporting as r
import fixtures
from view_oracle import audit_html


def run(out):
    out=out.resolve()
    if out==ROOT or ROOT in out.parents:raise ValueError('evidence must be outside source')
    out.mkdir(parents=True,exist_ok=True);(out/'html').mkdir(exist_ok=True)
    manifest=[];projections=[];discrepancies=[];profiles=i.available_profiles()
    with open(out/'bundles.jsonl.gz','wb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as stream:
            for name,data,language in fixtures.cases():
                for profile in profiles:
                    cid=name+'--'+profile['profile_id']
                    context=dict(language=language,profile_id=profile['profile_id'],profile_sha256=profile['sha256'],include_source=name in {'unicode-bom-crlf','hostile-markup','directional'})
                    bundle=r.make_bundle(data,**context)
                    rendered=r.render_html(bundle,data,**context)
                    # Reordered JSON is equivalent input and must not change HTML bytes.
                    replay=r.render_html(i.strict_json(i.canonical(bundle)),data,**context)
                    errors=audit_html(rendered,bundle)
                    if replay!=rendered:errors.append('canonical JSON round-trip changed rendered bytes')
                    for error in errors:discrepancies.append({'case_id':cid,'error':error})
                    (out/'html'/(cid+'.html')).write_bytes(rendered)
                    manifest.append({'case_id':cid,'base_case':name,'source_b64':base64.b64encode(data).decode(),'source_sha256':i.digest(data),'context':context,'bundle_digest':bundle['digest'],'html_sha256':i.digest(rendered)})
                    projections.append({'case_id':cid,'profile':profile,'source_sha256':i.digest(data),
                        'decisions':i.decision_projection(bundle['capsule']),
                        'privacy':bundle['privacy'],'evidence_ids':[x['evidence_id'] for x in bundle['capsule']['measurement']['source_evidence']]})
                    stream.write(i.canonical({'case_id':cid,'bundle':bundle})+b'\n')
                    print(cid+': '+('PASS' if not errors else 'FAIL'),flush=True)
    manifest_bytes=b''.join(i.canonical(row)+b'\n' for row in manifest)
    projection_bytes=i.canonical(projections)+b'\n'
    (out/'cases.jsonl').write_bytes(manifest_bytes);(out/'view-projections.json').write_bytes(projection_bytes)
    (out/'discrepancies.json').write_bytes(i.canonical(discrepancies)+b'\n')
    summary={'schema':'codeprobe-s05-finite-evidence/v1','source_cases':len(fixtures.cases()),'reports':len(manifest),
        'unique_source_payloads':len({x['source_sha256'] for x in manifest}),'profiles':profiles,
        'failure_count':len(discrepancies),'source_case_manifest_sha256':i.digest(manifest_bytes),
        'view_projections_sha256':i.digest(projection_bytes),'build':i.build_identity(),'presentation_build':r.presentation_identity(),
        'scope':'Finite dependent source/profile combinations; not participants or population error estimates.'}
    (out/'summary.json').write_bytes(i.canonical(summary)+b'\n')
    if discrepancies:raise SystemExit(1)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);run(p.parse_args().output)
