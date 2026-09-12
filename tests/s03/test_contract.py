"""S03 regression, oracle negative controls and runtime grammar-frontier probes.

Author: Antonio Clim. Added after the baseline observation; these are corrective
regressions and disclosed supplementary checks, not new confirmatory hypotheses.
"""
from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'src'), str(Path(__file__).resolve().parent), str(ROOT / 'tools')]
import codeprobe_measurement_kernel as kernel
import codeprobe_s01_observation_adapter as adapter
import oracles
import run_s03_robustness as runner


class S03ContractTests(unittest.TestCase):
    def setUp(self):
        self.result = kernel.measure_bytes(b'def f(x: int) -> int:\n    return x if x else 1\n', language='python', path='owned.py')
        self.record = next(r for r in self.result['observations'] if r['observation_id'] == 'source.byte_count')

    def test_declared_value_contracts_match_all_forty_specs(self):
        catalogue = json.loads((ROOT / 'research/observation-catalogue.v1.json').read_text(encoding='utf-8'))
        self.assertEqual({x['observation_id'] for x in catalogue['observations']}, set(kernel._VALUE_CONTRACTS))
        for spec in catalogue['observations']:
            domain = spec['codomain']; types = domain['type']; dtype = next(t for t in types if t != 'null') if isinstance(types, list) else types
            self.assertEqual((dtype, spec['unit'], domain.get('minimum'), domain.get('maximum'), tuple(domain.get('enum', ()))), kernel._VALUE_CONTRACTS[spec['observation_id']])

    def test_unit_and_scale_are_specification_bound(self):
        for key, value in [('unit', 'arbitrary'), ('measurement_scale', 'nominal')]:
            record = copy.deepcopy(self.record); record[key] = value
            with self.assertRaises(ValueError): kernel.validate_observation_record(record)

    def test_count_rejects_boolean_negative_fraction_and_non_json_scalar(self):
        for value in [True, False, -1, 0.5, '1', b'1', 1j, {}, [], float('inf'), float('nan')]:
            with self.subTest(value=repr(value)):
                record = copy.deepcopy(self.record); record['value'] = value
                with self.assertRaises(ValueError): kernel.validate_observation_record(record)

    def test_every_observed_domain_rejects_an_outside_value(self):
        examples = [self.result, kernel.measure_bytes(b'# H\n', language='markdown')]
        seen = set()
        for example in examples:
            for original in example['observations']:
                if original['value'] is None: continue
                seen.add(original['observation_id']); record = copy.deepcopy(original)
                record['value'] = 'invalid-category' if type(record['value']) is str else -1
                with self.assertRaises(ValueError): kernel.validate_observation_record(record)
        self.assertEqual(40, len(seen))

    def test_proportions_have_upper_bound(self):
        for original in self.result['observations']:
            if original['unit'] != 'proportion': continue
            record = copy.deepcopy(original); record['value'] = 1.01
            with self.assertRaises(ValueError): kernel.validate_observation_record(record)

    def test_record_identity_is_recomputed(self):
        record = copy.deepcopy(self.record); record['record_id'] = 'observation:' + 'f' * 64
        with self.assertRaises(ValueError): kernel.validate_observation_record(record)
        with self.assertRaises(ValueError): adapter.adapt_observation(record)

    def test_all_evidence_coordinates_are_bound(self):
        for coordinate in ['start_line', 'end_line', 'start_column', 'end_column']:
            result = copy.deepcopy(self.result); result.pop('measurement_digest')
            result['source_evidence'][0][coordinate] += 1
            with self.assertRaises(ValueError): kernel.validate_kernel_result(result)

    def test_result_and_record_paths_are_owned(self):
        for layer in ['source_evidence', 'observations']:
            result = copy.deepcopy(self.result); result.pop('measurement_digest')
            target = result[layer][0] if layer == 'source_evidence' else result[layer][0]['entity']
            target['path'] = 'foreign.py'
            with self.assertRaises(ValueError): kernel.validate_kernel_result(result)

    def test_entity_kind_and_identity_are_specification_bound(self):
        for key, value in [('entity_kind', 'markdown_document'), ('entity_id', 'alien')]:
            record = copy.deepcopy(self.record); record['entity'][key] = value
            record['record_id'] = kernel._record_id(record['specification_id'], record['entity']['entity_id'], record['source_evidence_ids'])
            with self.assertRaises(ValueError): kernel.validate_observation_record(record)

    def test_record_evidence_scope_cannot_be_substituted(self):
        result = copy.deepcopy(self.result); result.pop('measurement_digest')
        record = next(r for r in result['observations'] if r['observation_id'] == 'source.byte_count')
        evidence = next(e for e in result['source_evidence'] if e['scope'] == 'python_callable')
        record['source_evidence_ids'] = [evidence['evidence_id']]
        record['record_id'] = kernel._record_id(record['specification_id'], record['entity']['entity_id'], record['source_evidence_ids'])
        with self.assertRaises(ValueError): kernel.validate_kernel_result(result)

    def test_unavailable_parser_span_preserves_the_declared_fallback(self):
        original = kernel.ast.parse
        def incomplete(*args, **kwargs):
            tree = original(*args, **kwargs)
            for node in kernel.ast.walk(tree):
                if isinstance(node, kernel.ast.FunctionDef): node.end_lineno = None
            return tree
        kernel.ast.parse = incomplete
        try:
            result = kernel.measure_bytes(b'def f():\n    return 1\n', language='python')
        finally: kernel.ast.parse = original
        records = [r for r in result['observations'] if r['entity']['entity_kind'] == 'python_callable']
        self.assertEqual(1, len(records))
        self.assertIsNone(records[0]['value'])
        self.assertEqual('unavailable', records[0]['applicability']['state'])
        self.assertEqual('ME-013', records[0]['applicability']['reason_code'])
        evidence = {e['evidence_id']: e for e in result['source_evidence']}
        self.assertEqual('whole_artifact', evidence[records[0]['source_evidence_ids'][0]]['scope'])
        kernel.validate_kernel_result(result)
        self.assertIsInstance(adapter.adapt_observation(records[0]), dict)

    def test_mixed_markdown_delimiter_is_not_a_closer(self):
        for source in [b'```\nx\n```~\n# Outside?\n', b'~~~\nx\n~~~`\n# Outside?\n']:
            result = runner.records(kernel.measure_bytes(source, language='markdown'))
            self.assertEqual('unclosed_fence', result[('markdown.parse_status', 0)]['value'])
            self.assertEqual(0, result[('markdown.atx_heading_count', 0)]['value'])

    def test_uniform_longer_delimiter_still_closes(self):
        result = runner.records(kernel.measure_bytes(b'```\nx\n`````\n# H\n', language='markdown'))
        self.assertEqual('complete', result[('markdown.parse_status', 0)]['value'])
        self.assertEqual(1, result[('markdown.atx_heading_count', 0)]['value'])

    def test_resource_failure_is_not_syntax_missingness_or_zero(self):
        extension = json.loads((ROOT / 'research/s03/error-register-extension.v1.json').read_text(encoding='utf-8'))
        self.assertEqual('ME-015', extension['errors'][0]['error_id'])
        original = kernel.ast.parse
        for exc_type in [MemoryError, RecursionError]:
            def fail(*args, **kwargs): raise exc_type('explicit synthetic fault')
            kernel.ast.parse = fail
            try:
                with self.assertRaises(kernel.MeasurementError) as caught: kernel.measure_bytes(b'x=1', language='python')
                self.assertEqual('ME-015', caught.exception.code)
            finally: kernel.ast.parse = original

    def test_generic_oracle_has_analytic_positive_control(self):
        values = oracles.generic(b'a\nbbb\n')
        self.assertEqual(2.0, values['source.mean_line_length_codepoints'])
        self.assertEqual(1.0, values['source.population_sd_line_length_codepoints'])
        self.assertEqual(0.5, values['source.line_length_cv'])

    def test_python_oracle_has_analytic_positive_control(self):
        values = oracles.python_counts('def f(x: int) -> int:\n    return 1\n')
        self.assertEqual(2, values[('python.annotation_eligible_slot_count', 0)])
        self.assertEqual(2, values[('python.annotation_present_slot_count', 0)])
        self.assertEqual(1, values[('python.callable.mccabe_complexity', 1)])

    def test_differential_checker_detects_deliberate_metric_mutation(self):
        checks = runner.Checks(); checks.case = 'negative-control'; checks.group = 'mutant'
        record = copy.deepcopy(self.record); record['value'] += 1
        checks.value(record, self.record['value'], 'byte-count')
        self.assertEqual(1, checks.summary()['mutant']['failed_cases'])

    def test_hypothesis_checker_detects_deliberate_value_mutation(self):
        checks = runner.Checks(); mutated = copy.deepcopy(self.result)
        target = next(r for r in mutated['observations'] if r['observation_id'] == 'python.function_definition_count')
        target['value'] += 1
        runner.hypotheses({'case_id': 'negative-control', 'hypothesis': 'H-S03-04'}, {'status': 'ok', 'result': mutated}, {'status': 'ok', 'result': self.result}, checks, adapter)
        self.assertGreater(len(checks.failures), 0)

    def test_tolerance_is_combined_absolute_relative_not_relative_only(self):
        checks = runner.Checks(); checks.case = 'tol'; checks.group = 'tolerance'
        self.assertTrue(checks.check('within-absolute', 0.01 + 5e-13, 0.01, numeric=True))
        self.assertFalse(checks.check('outside-both', 0.01 + 5e-9, 0.01, numeric=True))
        self.assertFalse(checks.check('integer-exact', 2.00000000000001, 2, numeric=True))


FRONTIERS = [
    ('exception-groups', (3, 11), b'try:\n    pass\nexcept* ValueError:\n    pass\n'),
    ('type-alias', (3, 12), b'type Alias = int\n'),
    ('generic-function', (3, 12), b'def f[T](x: T) -> T:\n    return x\n'),
]


def grammar_frontiers():
    observations = []
    for name, minimum, source in FRONTIERS:
        result = runner.records(kernel.measure_bytes(source, language='python'))
        actual = result[('python.parse_status', 0)]['value']
        expected = 'parsed' if sys.version_info[:2] >= minimum else 'syntax_error'
        observations.append({'case_id': name, 'minimum_python': list(minimum), 'source_hex': source.hex(), 'parse_status': actual, 'expected_runtime_status': expected, 'passed': actual == expected, 'interpretation': 'Declared grammar frontier, not unexpected cross-platform drift'})
    return observations


if __name__ == '__main__': unittest.main(verbosity=2)
