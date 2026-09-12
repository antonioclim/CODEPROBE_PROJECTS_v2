"""Finite S04 contract tests; no participant or calibration outcomes.

Author: Antonio Clim. Fault injection and forged data are synthetic negative
controls. They are never represented as source-authorship experiments.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
import codeprobe_interpretation as mod
import codeprobe_calibration_admission as cal


def profiles():
    return {p['profile_id']: p['sha256'] for p in mod.available_profiles()}


def capsule(data=b'def f(x):\n    return x\n', language='python', profile='structural-review', path='<memory>'):
    return mod.interpret_bytes(data, language=language, profile_id=profile, profile_sha256=profiles()[profile], task_family='source_inspection', path=path)


def dimension(report, name=mod.STRUCTURE):
    return next(d for d in report['dimensions'] if d['dimension_id'] == name)


def split_manifest():
    rows = []
    for i, split in enumerate(('training','tuning','evaluation')):
        rows.append({'unit_id': f'u{i}', 'raw_sha256': mod.digest(f'raw{i}'.encode()),
                     'normalised_sha256': mod.digest(f'normal{i}'.encode()), 'lineage_group': f'l{i}',
                     'contributor_group': f'c{i}', 'task_family': 'source_inspection', 'split': split,
                     'label_access': 'sealed' if split == 'evaluation' else 'open'})
    return {'schema':'codeprobe-calibration-split-manifest/v1','data_kind':'synthetic_conformance',
            'profile_id':'structural-review','profile_sha256':profiles()['structural-review'],
            'target':'false_prompting','units':rows}


class S04Tests(unittest.TestCase):
    def test_available_dimension_uncertainty_does_not_deny_its_evidence(self):
        report = capsule()
        for dim in report['dimensions']:
            if dim['status'] == 'evidence_available':
                self.assertNotIn('No admissible observation is available', ' '.join(dim['uncertainty']['limitations']))
                self.assertIsNone(dim['uncertainty']['measurement_interval'])

    def test_profile_registry_has_three_unique_versioned_profiles(self):
        self.assertEqual(3, len(profiles()))
        self.assertEqual(3, len(set(profiles().values())))
        for p in mod.available_profiles(): self.assertEqual('1.0.0', p['version'])

    def test_profiles_match_pre_execution_threshold_lock(self):
        lock=mod._document('research/s04/acceptance-lock.v1.json')
        for pid, levels in lock['decisions']['initial_threshold_sets'].items():
            p=mod.resolve_profile(pid,profiles()[pid])
            self.assertEqual(set(levels),{r['rule_id'] for r in p['rules']})
            for r in p['rules']:
                self.assertEqual(levels[r['rule_id']],[r['threshold_set'][k] for k in ('lower','nominal','upper')])

    def test_profile_digest_mismatch_is_rejected(self):
        with self.assertRaises(mod.InterpretationError): mod.resolve_profile('structural-review','0'*64)

    def test_missing_or_unknown_profile_is_rejected(self):
        for pid in ('ai', 'human', 'overall-score', '', None, []):
            with self.subTest(pid=pid), self.assertRaises(mod.InterpretationError): mod.resolve_profile(pid,'0'*64)

    def test_profile_closed_fields_reject_scalar_and_labels(self):
        original = mod._document('research/s04/profiles.v1.json')
        for key in ('overall_score','aiProbability','misconduct_verdict','weights','labels'):
            data = copy.deepcopy(original); p = data['profiles'][1]; p[key] = 'prohibited'
            with patch.object(mod, '_document', return_value=data), self.assertRaises(mod.InterpretationError):
                mod.resolve_profile(p['profile_id'],mod.digest(mod.canonical(p)))

    def test_profile_cannot_assert_empirical_evaluation(self):
        data = mod._document('research/s04/profiles.v1.json'); p = data['profiles'][1]; p['evidence_status'] = 'evaluated_for_declared_scope'
        with patch.object(mod, '_document', return_value=data), self.assertRaises(mod.InterpretationError): mod.resolve_profile(p['profile_id'],mod.digest(mod.canonical(p)))

    def test_unlicensed_action_and_observation_are_rejected(self):
        original = mod._document('research/s04/profiles.v1.json')
        for key, value in [('action_id','grade_student'),('observation_id','python.comment_line_proportion'),('dimension_id','clarity_naming'),('operator','gte')]:
            data = copy.deepcopy(original); p = data['profiles'][1]; p['rules'][0][key] = value
            with patch.object(mod,'_document',return_value=data), self.assertRaises(mod.InterpretationError): mod.resolve_profile(p['profile_id'],mod.digest(mod.canonical(p)))

    def test_duplicate_rule_is_rejected(self):
        data=mod._document('research/s04/profiles.v1.json'); p=data['profiles'][1]; p['rules'][1]=copy.deepcopy(p['rules'][0])
        with patch.object(mod,'_document',return_value=data), self.assertRaises(mod.InterpretationError): mod.resolve_profile(p['profile_id'],mod.digest(mod.canonical(p)))

    def test_threshold_handworked_boundaries(self):
        levels=dict(lower=8,nominal=10,upper=12)
        expected={7:('no_rule_trigger',False),8:('no_rule_trigger',False),9:('abstain',False),10:('abstain',False),11:('abstain',True),12:('abstain',True),13:('review_opportunity',True)}
        for x, (state,nominal) in expected.items():
            actual=mod.threshold_decision(x,levels);self.assertEqual(state,actual['status']);self.assertEqual(nominal,actual['nominal_predicate'])

    def test_degenerate_threshold_is_exact_not_uncertain(self):
        self.assertEqual('no_rule_trigger',mod.threshold_decision(0,dict(lower=0,nominal=0,upper=0))['status'])
        self.assertEqual('review_opportunity',mod.threshold_decision(1,dict(lower=0,nominal=0,upper=0))['status'])

    def test_threshold_invalid_values_and_order(self):
        for value in (None,True,1.0,-1,float('nan'),'1',1j):
            with self.subTest(value=repr(value)),self.assertRaises(mod.InterpretationError):mod.threshold_decision(value,dict(lower=1,nominal=2,upper=3))
        for levels in [dict(lower=2,nominal=1,upper=3),dict(lower=0,nominal=1,upper=10001),dict(lower=False,nominal=1,upper=3),dict(lower=0,nominal=1,upper=3,weight=2)]:
            with self.assertRaises(mod.InterpretationError):mod.threshold_decision(2,levels)

    def test_seven_dimensions_and_five_explicit_abstentions(self):
        report=capsule(); self.assertEqual(7,len(report['dimensions']))
        withheld=[d for d in report['dimensions'] if d['basis']=='no_licensed_mapping'];self.assertEqual(5,len(withheld))
        self.assertTrue(all(d['status']=='insufficient_evidence' and d['items']==[] for d in withheld))

    def test_empty_python_has_no_callable_series_not_favourable_zero(self):
        d=dimension(capsule(b''));self.assertEqual('insufficient_evidence',d['status']);self.assertEqual('no_callable_entities',d['basis']);self.assertEqual([],d['items'])

    def test_non_python_structure_is_not_applicable(self):
        for lang in ('text','markdown'):
            d=dimension(capsule(b'# Text',lang));self.assertEqual('not_applicable',d['status']);self.assertEqual([],d['items'])

    def test_syntax_failure_propagates_as_unavailable(self):
        report=capsule(b'if :\n');self.assertEqual('unavailable',dimension(report)['status'])
        values=[r for r in report['measurement']['observations'] if r['applicability']['reason_code']=='ME-006']
        self.assertEqual(15,len(values));self.assertTrue(all(r['value'] is None for r in values))

    def test_each_interpretation_carries_uncertainty(self):
        for d in capsule()['dimensions']:
            self.assertEqual('not_established',d['uncertainty']['empirical_calibration'])
            self.assertIsNone(d['uncertainty']['measurement_interval'])
            for item in d['items']:self.assertEqual('not_established',item['uncertainty']['empirical_calibration'])

    def test_four_applicability_states_are_preserved(self):
        record=next(r for r in capsule()['measurement']['observations'] if r['observation_id']=='python.callable.physical_span_lines')
        rule=mod.resolve_profile('structural-review',profiles()['structural-review'])['rules'][2]
        for state,code in [('observed',''),('unavailable','ME-013'),('insufficient_evidence','ME-012'),('not_applicable','language_not_python')]:
            r=copy.deepcopy(record);r['applicability']=dict(state=state,reason_code=code,reason='synthetic state' if code else '');r['value']=None if code else 2
            item=mod._item(r,rule);self.assertEqual(state,item['applicability']['state'])
            if code:self.assertIsNone(item['value']);self.assertIsNone(item['decision']);self.assertIsNone(item['opportunity'])

    def test_unavailable_span_and_absent_rules_remain_explicit(self):
        original=mod.kernel.ast.parse
        def truncated(*args,**kwargs):
            tree=original(*args,**kwargs)
            for node in mod.kernel.ast.walk(tree):
                if isinstance(node,mod.kernel.ast.FunctionDef):node.end_lineno=None
            return tree
        with patch.object(mod.kernel.ast,'parse',side_effect=truncated):report=capsule()
        d=dimension(report);self.assertEqual('unavailable',d['status']);self.assertEqual(2,len(d['absences']))
        self.assertEqual('codeprobe.condition.callable_source_span_unavailable',d['items'][0]['condition']['condition_id'])

    def test_non_compensation_preserves_conflicting_rules(self):
        data=('def f(x):\n'+''.join(f'    if x == {i}: return {i}\n' for i in range(15))).encode()
        states={i['rule_id']:i['decision']['status'] for i in dimension(capsule(data))['items']}
        self.assertEqual('review_opportunity',states['mccabe_complexity']);self.assertEqual('no_rule_trigger',states['max_control_nesting_depth'])

    def test_policy_sensitive_never_emits_an_opportunity(self):
        data=('def f(x):\n'+''.join(f'    if x == {i}: return {i}\n' for i in range(10))).encode()
        item=next(i for i in dimension(capsule(data))['items'] if i['rule_id']=='mccabe_complexity')
        self.assertEqual('abstain',item['decision']['status']);self.assertTrue(item['decision']['nominal_predicate']);self.assertIsNone(item['opportunity'])

    def test_profile_change_is_visible_not_silent(self):
        data=('def f(x):\n'+''.join(f'    if x == {i}: return {i}\n' for i in range(15))).encode()
        a=capsule(data);b=capsule(data,profile='structural-review-conservative')
        self.assertNotEqual(a['profile'],b['profile']);self.assertNotEqual(a['digest'],b['digest']);self.assertNotEqual(mod.decision_projection(a),mod.decision_projection(b))

    def test_observation_only_does_not_surface_actions(self):
        r=capsule(profile='observation-only');self.assertTrue(all(i['opportunity'] is None and i['decision'] is None for d in r['dimensions'] for i in d['items']))

    def test_markdown_scope_is_disclosed_without_quality_verdict(self):
        r=capsule(b'```\nx\n','markdown');d=dimension(r,mod.PARSER)
        self.assertIn('Markdown is a finite subset', ' '.join(d['limitations']));self.assertTrue(all(i['opportunity'] is None for i in d['items']))

    def test_opportunities_own_their_observations_and_evidence(self):
        data=('def f(x):\n'+''.join(f'    if x == {i}: return {i}\n' for i in range(15))).encode();r=capsule(data)
        records={x['record_id']:x for x in r['measurement']['observations']};evidence={x['evidence_id'] for x in r['measurement']['source_evidence']}
        for d in r['dimensions']:
            for i in d['items']:
                self.assertEqual(records[i['record_ref']]['source_evidence_ids'],i['source_evidence_refs']);self.assertTrue(set(i['source_evidence_refs'])<=evidence)
                if i['opportunity']:self.assertTrue(i['opportunity']['reversible'])

    def test_source_refusal_remains_typed(self):
        for data,code in [(b'\xff','ME-003'),(b'\0','ME-004'),(b'a'*1000001,'ME-002')]:
            with self.assertRaises(mod.kernel.MeasurementError) as caught:capsule(data)
            self.assertEqual(code,caught.exception.code)

    def test_unsupported_context_and_path_are_rejected(self):
        for lang in ('javascript','PYTHON',None,[]):
            with self.assertRaises(mod.InterpretationError):capsule(language=lang)
        with self.assertRaises(mod.InterpretationError):mod.interpret_bytes(b'x',language='text',profile_id='structural-review',profile_sha256=profiles()['structural-review'],task_family='grading')
        with self.assertRaises(mod.InterpretationError):capsule(path='bad\x00path')

    def test_capsule_source_replay_roundtrip(self):
        r=capsule();mod.verify_capsule(r,b'def f(x):\n    return x\n',language='python',profile_id='structural-review',profile_sha256=profiles()['structural-review'],task_family='source_inspection')

    def test_forged_report_and_recomputed_digest_are_rejected(self):
        r=capsule()
        mutations=[lambda x:x.update(overall_score=100),lambda x:x['dimensions'][0].update(status='unavailable'),lambda x:x['measurement']['observations'][0].update(value=999),lambda x:x['build'].update(implementation_digest='0'*64),lambda x:x['profile'].update(version='2.0.0'),lambda x:x['non_inferences'].clear()]
        for mutate in mutations:
            x=copy.deepcopy(r);mutate(x);x.pop('digest');x['digest']=mod.digest(mod.canonical(x))
            with self.assertRaises(mod.InterpretationError):mod.verify_capsule(x,b'def f(x):\n    return x\n',language='python',profile_id='structural-review',profile_sha256=profiles()['structural-review'],task_family='source_inspection')

    def test_wrong_source_cannot_validate_a_capsule(self):
        with self.assertRaises(mod.InterpretationError):mod.verify_capsule(capsule(),b'x=1',language='python',profile_id='structural-review',profile_sha256=profiles()['structural-review'],task_family='source_inspection')

    def test_build_identifies_components_not_only_spec_version(self):
        b=mod.build_identity();self.assertEqual(15,len(b['component_sha256']));self.assertEqual(mod.digest(mod.canonical(b['component_sha256'])),b['implementation_digest'])
        self.assertIn(b['checkout_state'],('working_tree','clean_checkout'));self.assertEqual(mod.kernel.KERNEL_VERSION,capsule()['measurement_specification']['kernel_contract_version'])

    def test_migration_me008_is_namespace_qualified(self):
        a=mod.migrate_condition('s03-kernel/exception','ME-008');b=mod.migrate_condition('measurement-error-register/1.0.0','ME-008')
        self.assertNotEqual(a['condition_id'],b['condition_id']);self.assertEqual('refused',a['disposition']);self.assertEqual('observed_with_limitation',b['disposition'])
        for namespace in ('',None,'guessed'):
            with self.assertRaises(mod.InterpretationError):mod.migrate_condition(namespace,'ME-008')

    def test_migration_also_separates_me013_collision(self):
        a=mod.migrate_condition('s03-kernel/observation','ME-013');b=mod.migrate_condition('measurement-error-register/1.0.0','ME-013')
        self.assertNotEqual(a['condition_id'],b['condition_id']);self.assertEqual('unavailable',a['disposition'])

    def test_migration_pairs_are_unique_and_complete(self):
        data=mod._document('research/s04/condition-migration.v1.json')['entries'];self.assertEqual(27,len(data));self.assertEqual(27,len({(x['legacy_namespace'],x['legacy_code']) for x in data}))
        for row in data:self.assertEqual(row,mod.migrate_condition(row['legacy_namespace'],row['legacy_code']))

    def test_strict_json_rejects_duplicates_nonfinite_and_deep_input(self):
        for data in [b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e400}',b'\xff',b'['*2000+b']'*2000]:
            with self.assertRaises(mod.InterpretationError):mod.strict_json(data)

    def test_manifest_admission_never_claims_calibration(self):
        result=cal.admit_manifest(split_manifest(),expected_profile_sha256=profiles()['structural-review'])
        self.assertEqual('not_established',result['empirical_calibration']);self.assertEqual('not_verified_by_this_interface',result['authorisation'])

    def test_all_four_leakage_keys_reject_cross_split_reuse(self):
        for key in ('raw_sha256','normalised_sha256','lineage_group','contributor_group'):
            data=split_manifest();data['units'][2][key]=data['units'][0][key]
            with self.subTest(key=key),self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])

    def test_within_split_grouping_is_not_false_leakage(self):
        data=split_manifest();row=copy.deepcopy(data['units'][0]);row['unit_id']='another';data['units'].append(row)
        self.assertEqual(2,cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])['split_counts']['training'])

    def test_evaluation_labels_must_remain_sealed(self):
        data=split_manifest();data['units'][2]['label_access']='open'
        with self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])

    def test_labels_and_authorisation_flags_not_accepted_as_metadata(self):
        for key in ('outcome','origin','authorship','approved','labels'):
            data=split_manifest();data['units'][0][key]=True
            with self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])

    def test_provenance_calibration_target_refused(self):
        data=split_manifest();data['target']='authorship_accuracy'
        with self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])

    def test_manifest_profile_drift_and_missing_groups_refused(self):
        data=split_manifest();data['profile_sha256']='0'*64
        with self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])
        data=split_manifest();data['units'][0]['contributor_group']=''
        with self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])

    def test_missing_split_duplicate_unit_and_bad_hash_rejected(self):
        for mutate in [lambda m:m['units'][2].update(split='training'),lambda m:m['units'][2].update(unit_id='u0'),lambda m:m['units'][2].update(raw_sha256='invalid')]:
            data=split_manifest();mutate(data)
            with self.assertRaises(mod.InterpretationError):cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])

    def test_distribution_shift_is_disclosed_not_hidden(self):
        data=split_manifest();data['units'][2]['task_family']='new-task'
        self.assertEqual(['new-task'],cal.admit_manifest(data,expected_profile_sha256=profiles()['structural-review'])['evaluation_only_task_families'])

    def test_unversioned_export_and_post_import_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for relative in mod._COMPONENTS:
                dst=root/relative;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,dst)
            prefix=f'import sys;sys.path.insert(0,{str(root / "src")!r});import codeprobe_interpretation as m;'
            a=subprocess.run([sys.executable,'-I','-S','-B','-c',prefix+'print(m.build_identity()["checkout_state"])'],capture_output=True,text=True,timeout=20)
            self.assertEqual(0,a.returncode,a.stderr);self.assertEqual('unversioned_source',a.stdout.strip())
            script=prefix+'p=m.ROOT/"research/s04/profiles.v1.json";p.write_bytes(p.read_bytes()+b" ");m.build_identity()'
            b=subprocess.run([sys.executable,'-I','-S','-B','-c',script],capture_output=True,text=True,timeout=20)
            self.assertNotEqual(0,b.returncode);self.assertIn('implementation changed after module admission',b.stderr)

    def test_inherited_kernel_mutation_is_rejected_at_admission(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for relative in mod._COMPONENTS:
                dst=root/relative;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,dst)
            p=root/'src/codeprobe_measurement_kernel.py';p.write_bytes(p.read_bytes()+b'\n# negative control\n')
            script=f'import sys;sys.path.insert(0,{str(root / "src")!r});import codeprobe_interpretation'
            run=subprocess.run([sys.executable,'-I','-S','-B','-c',script],capture_output=True,text=True,timeout=20)
            self.assertNotEqual(0,run.returncode);self.assertIn('inherited S03 component changed',run.stderr)


if __name__ == '__main__':unittest.main(verbosity=2)
