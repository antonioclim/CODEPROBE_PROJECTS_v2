"""S05 replay, semantic, privacy and CLI tests. Author: Antonio Clim."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).parent)]
import codeprobe_reporting as r
import codeprobe_interpretation as i
import codeprobe_report_cli as cli
import fixtures
from view_oracle import audit_html, Scan


class ReportingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=fixtures.branching(13)
        cls.profile=next(p for p in i.available_profiles() if p['profile_id']=='structural-review')
        cls.ctx=dict(language='python',profile_id=cls.profile['profile_id'],profile_sha256=cls.profile['sha256'])
        cls.bundle=r.make_bundle(cls.data,**cls.ctx)
        cls.html=r.render_html(cls.bundle,cls.data,**cls.ctx)

    def test_complete_capsule_is_retained(self):
        self.assertEqual(self.bundle['capsule'],i.interpret_bytes(self.data,language='python',profile_id=self.profile['profile_id'],profile_sha256=self.profile['sha256'],task_family='source_inspection',path=r.NEUTRAL_PATH))
    def test_valid_replay(self): r.verify_bundle(self.bundle,self.data,**self.ctx)
    def test_report_and_capsule_are_not_s01(self):
        self.assertEqual(r.SCHEMA,self.bundle['schema']);self.assertFalse(self.bundle['compatibility']['s01_complete_report'])
    def test_all_dimensions_and_withheld_states(self):
        self.assertEqual([],audit_html(self.html,self.bundle))
    def test_source_mismatch_rejected(self):
        with self.assertRaises(ValueError):r.verify_bundle(self.bundle,b'x=1\n',**self.ctx)
    def test_profile_mismatch_rejected(self):
        c=dict(self.ctx,profile_id='observation-only')
        with self.assertRaises(ValueError):r.verify_bundle(self.bundle,self.data,**c)
    def test_profile_digest_mismatch_rejected(self):
        with self.assertRaises(ValueError):r.verify_bundle(self.bundle,self.data,**dict(self.ctx,profile_sha256='0'*64))
    def test_language_mismatch_rejected(self):
        with self.assertRaises(ValueError):r.verify_bundle(self.bundle,self.data,**dict(self.ctx,language='text'))
    def test_path_mismatch_rejected(self):
        with self.assertRaises(ValueError):r.verify_bundle(self.bundle,self.data,**dict(self.ctx,path='foreign'))
    def test_source_inclusion_mismatch_rejected(self):
        with self.assertRaises(ValueError):r.verify_bundle(self.bundle,self.data,**dict(self.ctx,include_source=True))
    def test_recomputed_forged_capsules_rejected(self):
        changes=[lambda b:next(d for d in b['capsule']['dimensions'] if d['basis']=='no_licensed_mapping').update(status='evidence_available'),
                 lambda b:b['capsule']['measurement']['observations'][0].update(value=777),
                 lambda b:b['capsule']['measurement']['source_evidence'][0].update(path='foreign'),
                 lambda b:b['capsule']['non_inferences'].append('UNSUPPORTED'),
                 lambda b:b['capsule']['context'].update(task_family='grading'),
                 lambda b:b['capsule']['build'].update(implementation_digest='0'*64),
                 lambda b:b['presentation_build'].update(digest='0'*64),
                 lambda b:b['privacy'].update(literal_source='included_by_request')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                b=copy.deepcopy(self.bundle);change(b)
                self.assertNotEqual(i.canonical(b),i.canonical(self.bundle),'negative control must change its target')
                cap=b['capsule'];cap.pop('digest');cap['digest']=i.digest(i.canonical(cap))
                b.pop('digest');b['digest']=i.digest(i.canonical(b))
                with self.assertRaises(ValueError):r.render_html(b,self.data,**self.ctx)
    def test_atomic_bundle_no_extra_fields(self):
        b=copy.deepcopy(self.bundle);b['feedback']=[]
        with self.assertRaises(ValueError):r.verify_bundle(b,self.data,**self.ctx)
    def test_feedback_does_not_mutate_bundle(self):
        before=i.canonical(self.bundle);oid=next(iter(r.opportunity_map(self.bundle)))
        j={'schema':r.FEEDBACK_SCHEMA,'report_digest':self.bundle['digest'],'responses':[{'opportunity_id':oid,'state':'declined','actor_role':'reviewer','rationale':'No change justified.'}]}
        r.validate_feedback(j,self.bundle,self.data,**self.ctx);self.assertEqual(before,i.canonical(self.bundle))
    def test_cli_argument_values_are_not_echoed(self):
        command = [sys.executable, '-I', '-B', str(ROOT/'tools/codeprobe_s05.py')]
        for args in [['PRIVATE_ARGUMENT_83f5'], ['profiles', '--PRIVATE_ARGUMENT_83f5']]:
            result = subprocess.run(command+args, capture_output=True, timeout=15)
            self.assertEqual(2, result.returncode)
            self.assertNotIn(b'PRIVATE_ARGUMENT_83f5', result.stderr)
            self.assertEqual('argument_admission', json.loads(result.stderr)['operation'])
    def test_unicode_rationale_counts_codepoints(self):
        oid=next(iter(r.opportunity_map(self.bundle)))
        journal={'schema':r.FEEDBACK_SCHEMA,'report_digest':self.bundle['digest'], 'responses':[
            {'opportunity_id':oid,'state':'accepted','actor_role':'reviewer','rationale':'😀'*2000}]}
        r.validate_feedback(journal,self.bundle,self.data,**self.ctx)
        journal['responses'][0]['rationale'] += '😀'
        with self.assertRaises(ValueError):r.validate_feedback(journal,self.bundle,self.data,**self.ctx)
    def test_empty_feedback_valid(self):
        r.validate_feedback({'schema':r.FEEDBACK_SCHEMA,'report_digest':self.bundle['digest'],'responses':[]},self.bundle,self.data,**self.ctx)
    def test_feedback_rejects_foreign_duplicate_role_state_rationale(self):
        oid=next(iter(r.opportunity_map(self.bundle)));entry={'opportunity_id':oid,'state':'deferred','actor_role':'educator','rationale':None}
        mutations=[{'opportunity_id':'opportunity.'+'0'*64},{'state':'convicted'},{'actor_role':'administrator'},{'rationale':'x'*2001},{'rationale':'x\x7f'},{'rationale':'\ud800'},{'rationale':'\x00'}]
        for change in mutations:
            with self.subTest(change=str(change)[:60]):
                j={'schema':r.FEEDBACK_SCHEMA,'report_digest':self.bundle['digest'],'responses':[dict(entry,**change)]}
                with self.assertRaises(ValueError):r.validate_feedback(j,self.bundle,self.data,**self.ctx)
        for responses in [[entry,entry],None,{}]:
            with self.assertRaises(ValueError):r.validate_feedback({'schema':r.FEEDBACK_SCHEMA,'report_digest':self.bundle['digest'],'responses':responses},self.bundle,self.data,**self.ctx)
    def test_feedback_old_report_rejected(self):
        with self.assertRaises(ValueError):r.validate_feedback({'schema':r.FEEDBACK_SCHEMA,'report_digest':'0'*64,'responses':[]},self.bundle,self.data,**self.ctx)
    def test_no_feedback_for_abstention(self):
        b=r.make_bundle(fixtures.branching(11),**self.ctx);self.assertFalse(r.opportunity_map(b))
    def test_native_schema_rejects_duplicate_and_nonfinite_json(self):
        for s in [b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":1e1000}']:
            with self.assertRaises(ValueError):i.strict_json(s)
    def test_missing_is_never_rendered_as_zero(self):
        data=b'def broken(:\n';b=r.make_bundle(data,**self.ctx);h=r.render_html(b,data,**self.ctx)
        self.assertIn(b'Unavailable',h);self.assertIn(b'Not available (null)',h)
    def test_exact_hand_specified_complexity_decisions(self):
        expected={8:'no_rule_trigger',9:'abstain',10:'abstain',11:'abstain',12:'abstain',13:'review_opportunity'}
        for value,state in expected.items():
            b=r.make_bundle(fixtures.branching(value),**self.ctx)
            item=next(x for d in b['capsule']['dimensions'] for x in d['items'] if x['rule_id']=='mccabe_complexity')
            self.assertEqual(value,item['value']);self.assertEqual(state,item['decision']['status'])
    def test_default_path_and_literal_source_minimisation(self):
        data=b'def confidential_name(x):\n    return "SECRET_LITERAL_5ac7"\n';b=r.make_bundle(data,**self.ctx);h=r.render_html(b,data,**self.ctx)
        self.assertEqual('<source>',b['capsule']['measurement']['artifact']['path']);self.assertIsNone(b['normalised_source'])
        self.assertNotIn(b'SECRET_LITERAL_5ac7',h);self.assertNotIn(b'confidential_name',h)
        self.assertIn('confidential_name',i.canonical(b).decode()) # disclosed residual, not anonymisation
    def test_explicit_source_is_escaped(self):
        data=next(v for name,v,_ in fixtures.cases() if name=='hostile-markup');c=dict(self.ctx,include_source=True,path='</title><img src=x onerror=alert(1)>')
        b=r.make_bundle(data,**c);h=r.render_html(b,data,**c);s=Scan();s.feed(h.decode())
        self.assertFalse(s.errors);self.assertIn('&lt;img',h.decode());self.assertNotIn('<img',h.decode())
    def test_unicode_bom_crlf_line_ownership(self):
        data=next(v for n,v,_ in fixtures.cases() if n=='unicode-bom-crlf');c=dict(self.ctx,include_source=True)
        b=r.make_bundle(data,**c);h=r.render_html(b,data,**c)
        self.assertIn('1: def gen_șir',h.decode());self.assertIn('source-line-2',h.decode());self.assertNotIn('\r',b['normalised_source'])
        self.assertEqual([],audit_html(h,b))
    def test_control_code_display_not_execution(self):
        self.assertEqual('\\u{202E}x\\u{202C}',r.display_text('\u202ex\u202c'))
    def test_empty_evidence_does_not_fabricate_line(self):
        b=r.make_bundle(b'',**dict(self.ctx,include_source=True));h=r.render_html(b,b'',**dict(self.ctx,include_source=True))
        self.assertIn(b'no physical source line exists',h);self.assertNotIn(b'id="source-line-1"',h)
    def test_negative_oracle_detects_favourable_and_missing_labels(self):
        mutants=[self.html.replace(b'Interpretation withheld',b'Quality certified'),
                 self.html.replace(b'class="withheld"',b'class="hidden"',1),
                 self.html.replace(b'data-state="insufficient_evidence"',b'data-state="evidence_available"',1),
                 self.html.replace(b'No rule trigger is not evidence of quality',b'Fine'),
                 self.html.replace(b'href="#evidence-',b'href="#nonexistent-',1),
                 self.html.replace(b'</main>',b'<img src="https://invalid.example/x"></main>')]
        for n,mutant in enumerate(mutants):
            with self.subTest(mutant=n):self.assertTrue(audit_html(mutant,self.bundle))
    def test_csp_hashes_bind_actual_runtime(self):
        import base64
        s=Scan();s.feed(self.html.decode());policy=next(a['content'] for tag,a in s.tags if tag=='meta' and a.get('http-equiv')=='Content-Security-Policy')
        for content in [s.scripts[0],s.styles[0]]:
            self.assertIn("'sha256-"+base64.b64encode(hashlib.sha256(content.encode()).digest()).decode()+"'",policy)
        self.assertIn("connect-src 'none'",policy)
    def test_presentation_drift_rejected(self):
        old=r._LOADED
        try:
            r._LOADED=dict(old);r._LOADED['app/s05/reader.js']='0'*64
            with self.assertRaises(ValueError):r.presentation_identity()
        finally:r._LOADED=old
    def test_input_type_size_and_language_refusals(self):
        for data,context in [(b'x'*1_000_001,self.ctx),(b'\xff',self.ctx),(b'\0',self.ctx),(b'x',dict(self.ctx,language='javascript')),(b'x',dict(self.ctx,include_source=1))]:
            with self.subTest(length=len(data)):
                with self.assertRaises(ValueError):r.make_bundle(data,**context)
    def test_file_size_regular_and_missing(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();p=root/'input';p.write_bytes(b'abc')
            self.assertEqual(b'abc',cli.read_regular(p,3))
            with self.assertRaises(ValueError):cli.read_regular(p,2)
            with self.assertRaises((OSError,ValueError)):cli.read_regular(root,10)
            with self.assertRaises((OSError,ValueError)):cli.read_regular(root/'missing',10)
    def test_leaf_and_parent_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();p=root/'input';p.write_bytes(b'x');(root/'dir').mkdir();(root/'dir'/'x').write_bytes(b'x')
            try:os.symlink(p,root/'link');os.symlink(root/'dir',root/'dirlink',target_is_directory=True)
            except (OSError,NotImplementedError):self.skipTest('symlink creation unavailable; not passed')
            for path in [root/'link',root/'dirlink'/'x']:
                with self.assertRaises(ValueError):cli.read_regular(path,10)
    def test_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();(root/'sentinel').write_bytes(b'keep')
            with self.assertRaises(OSError):cli.write_outputs(root,self.bundle,self.html)
            self.assertEqual(b'keep',(root/'sentinel').read_bytes())
    def test_source_tree_output_rejected(self):
        with self.assertRaises(ValueError):cli.write_outputs(ROOT/'invalid-report',self.bundle,self.html)
    def test_cli_generate_render_verify_and_failure_recovery(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();src=root/'private-source.py';src.write_bytes(self.data)
            cmd=[sys.executable,'-I','-B',str(ROOT/'tools/codeprobe_s05.py')]
            common=['--source',str(src),'--language','python','--profile',self.profile['profile_id'],'--profile-sha',self.profile['sha256']]
            result=subprocess.run(cmd+['generate']+common+['--output-dir',str(root/'reports')],capture_output=True,timeout=30)
            self.assertEqual(0,result.returncode,result.stderr);self.assertNotIn(str(src).encode(),(root/'reports/report.json').read_bytes())
            verify=subprocess.run(cmd+['verify']+common+['--bundle',str(root/'reports/report.json')],capture_output=True,timeout=30)
            self.assertEqual(0,verify.returncode,verify.stderr)
            fail=subprocess.run(cmd+['generate']+common+['--output-dir',str(root/'reports')],capture_output=True,timeout=30)
            self.assertEqual(2,fail.returncode);self.assertNotIn(str(src).encode(),fail.stderr);self.assertNotIn(b'Traceback',fail.stderr)
            render=subprocess.run(cmd+['render']+common+['--bundle',str(root/'reports/report.json'),'--output-dir',str(root/'rendered')],capture_output=True,timeout=30)
            self.assertEqual(0,render.returncode,render.stderr);self.assertEqual((root/'reports/report.html').read_bytes(),(root/'rendered/report.html').read_bytes())


if __name__=='__main__':unittest.main(verbosity=2)
