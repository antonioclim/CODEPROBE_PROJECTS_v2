"""S04 native interpretation capsule. Author: Antonio Clim.

The public v2 application is not changed. Profiles are explicit illustrative
policies, not calibrated models. Input source is parsed, never executed.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import platform
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any

import codeprobe_measurement_kernel as kernel
from codeprobe_review_contract import REQUIRED_NON_INFERENCES

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'codeprobe-interpretation-capsule/v1'
STRUCTURE = 'structural_complexity_dispersion'
PARSER = 'parser_scope_unsupported_construct_burden'
PROFILE_IDS = {'observation-only', 'structural-review', 'structural-review-conservative'}
ACTIONS = {
    'inspect_branching': 'Consider whether the identified function would benefit from simpler branching or targeted tests.',
    'inspect_nesting': 'Consider whether the identified nesting can be made easier to inspect without obscuring domain logic.',
    'inspect_function_span': 'Consider whether the identified function span warrants a cohesion review; length alone does not establish a defect.',
}
RULES = dict(zip(['mccabe_complexity', 'max_control_nesting_depth', 'physical_span_lines'], ACTIONS))


class InterpretationError(ValueError):
    """Rejected policy, source identity or interpretation contract."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes) -> Any:
    if type(data) is not bytes or len(data) > 4_000_000:
        raise InterpretationError('JSON must be bytes within the four-million-byte limit')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InterpretationError('duplicate JSON key')
            result[key] = value
        return result
    def nonfinite(value):
        raise InterpretationError('non-finite JSON constant')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=nonfinite)
        pending = [(value, 0)]; visited = 0
        while pending:
            node, depth = pending.pop(); visited += 1
            if depth > 64 or visited > 200000:
                raise InterpretationError('JSON depth or node budget exceeded')
            if isinstance(node, float) and not math.isfinite(node):
                raise InterpretationError('non-finite JSON number')
            if isinstance(node, dict):
                pending.extend((child, depth + 1) for child in node.values())
            elif isinstance(node, list):
                pending.extend((child, depth + 1) for child in node)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InterpretationError('invalid or excessively nested JSON') from exc


def fields(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise InterpretationError(label + ': closed-field contract failed')


def sha(value: Any) -> None:
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise InterpretationError('invalid SHA-256')


def _read(relative: str) -> bytes:
    target = ROOT / relative
    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != ROOT and ROOT in parent.parents) or not target.is_file():
        raise InterpretationError('implementation component must be a regular non-symlink file')
    return target.read_bytes()


_INVENTORY = strict_json(_read('research/s04/component-inventory.v1.json'))
_COMPONENTS = tuple(_INVENTORY['components'])
if len(_COMPONENTS) != len(set(_COMPONENTS)) or any(Path(p).is_absolute() or '..' in Path(p).parts for p in _COMPONENTS):
    raise InterpretationError('invalid component inventory')
_LOADED = {p: digest(_read(p)) for p in _COMPONENTS}
if any(_LOADED.get(p) != h for p, h in _INVENTORY['inherited_sha256'].items()):
    raise InterpretationError('inherited S03 component changed')


def _unchanged() -> None:
    if any(digest(_read(p)) != h for p, h in _LOADED.items()):
        raise InterpretationError('implementation changed after module admission; reload an audited build')


def _document(path: str) -> Any:
    _unchanged()
    return strict_json(_read(path))


def build_identity() -> dict[str, Any]:
    """Identify actual admitted files; Git is an anchor, not an attestation."""
    _unchanged()
    commit = tree = None
    state = 'unversioned_source'
    try:
        def git(*args):
            return subprocess.check_output(['git', '-C', str(ROOT), *args], stderr=subprocess.DEVNULL, timeout=10).decode().strip()
        # Do not inherit a parent repository's identity for an exported subfolder.
        if Path(git('rev-parse', '--show-toplevel')).resolve() != ROOT:
            raise InterpretationError('source directory is not the Git worktree root')
        commit = git('rev-parse', 'HEAD'); tree = git('rev-parse', 'HEAD^{tree}')
        tracked = set(git('ls-files').splitlines())
        state = 'clean_checkout' if not git('status', '--porcelain', '--untracked-files=all') and set(_COMPONENTS) <= tracked else 'working_tree'
    except (subprocess.SubprocessError, FileNotFoundError, InterpretationError):
        commit = tree = None
    return {'schema': 'codeprobe-build-identity/v1', 'component_sha256': dict(_LOADED),
            'implementation_digest': digest(canonical(_LOADED)), 'git_anchor_commit': commit,
            'git_anchor_tree': tree, 'checkout_state': state,
            'runtime': {'implementation': sys.implementation.name, 'python': platform.python_version(),
                        'unicode': unicodedata.unidata_version, 'system': platform.system(), 'machine': platform.machine()},
            'qualification': 'File-set consistency only; neither source authorship nor a hostile runtime is authenticated.'}


def available_profiles() -> list[dict[str, str]]:
    registry = _document('research/s04/profiles.v1.json')
    return [{'profile_id': p['profile_id'], 'version': p['version'], 'sha256': digest(canonical(p))} for p in registry['profiles']]


def resolve_profile(profile_id: str, expected_sha256: str) -> dict[str, Any]:
    sha(expected_sha256)
    if type(profile_id) is not str or profile_id not in PROFILE_IDS:
        raise InterpretationError('unsupported explicit profile identifier')
    registry = _document('research/s04/profiles.v1.json')
    profiles = [p for p in registry['profiles'] if p['profile_id'] == profile_id]
    if len(profiles) != 1:
        raise InterpretationError('profile identity is not unique')
    p = profiles[0]
    fields(p, {'schema','profile_id','version','purpose','languages','task_families','evidence_status','threshold_basis','rules'}, 'profile')
    if (p['schema'], p['version'], p['purpose'], p['evidence_status'], p['threshold_basis']) != ('codeprobe-formative-interpretation-profile/v1','1.0.0','formative_review','not_yet_established','illustrative_policy_choice_not_empirical_calibration'):
        raise InterpretationError('unsupported profile semantics')
    if p['languages'] != ['python','markdown','text'] or p['task_families'] != ['source_inspection']:
        raise InterpretationError('undeclared profile scope')
    if type(p['rules']) is not list or len(p['rules']) != (0 if profile_id == 'observation-only' else 3):
        raise InterpretationError('profile rule inventory mismatch')
    seen = set()
    for rule in p['rules']:
        fields(rule, {'rule_id','observation_id','dimension_id','operator','threshold_set','action_id'}, 'rule')
        rid = rule['rule_id']
        if rid not in RULES or rid in seen or rule['observation_id'] != 'python.callable.' + rid or rule['dimension_id'] != STRUCTURE or rule['operator'] != 'gt' or rule['action_id'] != RULES[rid]:
            raise InterpretationError('unlicensed rule or action')
        seen.add(rid)
        _levels(rule['threshold_set'])
    if digest(canonical(p)) != expected_sha256:
        raise InterpretationError('profile digest mismatch; no silent profile drift')
    return copy.deepcopy(p)


def _levels(levels: dict[str, Any]) -> tuple[int, int, int]:
    fields(levels, {'lower','nominal','upper'}, 'threshold set')
    lo, nominal, hi = (levels[k] for k in ('lower','nominal','upper'))
    if not all(type(v) is int and 0 <= v <= 10000 for v in (lo, nominal, hi)) or not lo <= nominal <= hi:
        raise InterpretationError('threshold set must be ordered finite non-negative integers')
    return lo, nominal, hi


def threshold_decision(value: int, levels: dict[str, Any]) -> dict[str, Any]:
    """Exact greater-than policy envelope, not a statistical interval."""
    lo, nominal, hi = _levels(levels)
    if type(value) is not int or value < 0:
        raise InterpretationError('structural policy requires a non-negative integer')
    possible = [False] if value <= lo else [True] if value > hi else [False, True]
    return {'nominal_predicate': value > nominal, 'possible_predicates': possible,
            'status': 'no_rule_trigger' if possible == [False] else 'review_opportunity' if possible == [True] else 'abstain',
            'policy_sensitivity': 'boundary_sensitive' if len(possible) == 2 else 'stable_over_declared_threshold_set'}


def migrate_condition(legacy_namespace: str, legacy_code: str) -> dict[str, str]:
    if type(legacy_namespace) is not str or type(legacy_code) is not str:
        raise InterpretationError('explicit legacy namespace and code required')
    migration = _document('research/s04/condition-migration.v1.json')
    found = [x for x in migration['entries'] if (x['legacy_namespace'], x['legacy_code']) == (legacy_namespace, legacy_code)]
    if len(found) != 1:
        raise InterpretationError('unknown or unqualified condition; no guessed code migration')
    return copy.deepcopy(found[0])


def _uncertainty(record: dict[str, Any] | None, sensitivity: str) -> dict[str, Any]:
    return {'measurement_interval': None, 'measurement_interval_status': 'not_estimated',
            'computational_scope': 'finite_s03_measurement_contract', 'runtime_dependence': 'declared_parser_and_runtime',
            'policy_sensitivity': sensitivity, 'empirical_calibration': 'not_established',
            'limitations': copy.deepcopy(record['limitations']) if record is not None else ['No admissible observation is available for this interpretation.']}


def _item(record: dict[str, Any], rule: dict[str, Any] | None) -> dict[str, Any]:
    app = record['applicability']
    result = {'rule_id': rule['rule_id'] if rule else 'descriptive', 'record_ref': record['record_id'],
              'observation_id': record['observation_id'], 'entity_id': record['entity']['entity_id'],
              'source_evidence_refs': copy.deepcopy(record['source_evidence_ids']), 'applicability': copy.deepcopy(app),
              'value': record['value'], 'decision': None, 'opportunity': None,
              'condition': migrate_condition('s03-kernel/observation', app['reason_code']) if app['state'] != 'observed' else None}
    if app['state'] == 'observed' and rule is not None:
        result['decision'] = threshold_decision(record['value'], rule['threshold_set'])
        if result['decision']['status'] == 'review_opportunity':
            result['opportunity'] = {'action_id': rule['action_id'], 'question': ACTIONS[rule['action_id']],
                                    'reversible': True, 'qualification': 'Optional inspection under an illustrative policy, not a demonstrated defect or benefit.',
                                    'trade_off': 'Preserve domain cohesion and behaviour; a rewrite may be unnecessary.'}
    sensitivity = result['decision']['policy_sensitivity'] if result['decision'] else 'not_evaluated'
    result['uncertainty'] = _uncertainty(record, sensitivity)
    return result


def _vector(result: dict[str, Any], profile: dict[str, Any]) -> list[dict[str, Any]]:
    definitions = _document('research/construct-map.v1.json')['dimensions']
    language = result['artifact']['language']
    observations = result['observations']
    by_id = {r['observation_id']: r for r in observations if r['entity']['entity_kind'] != 'python_callable'}
    callable_records = [r for r in observations if r['entity']['entity_kind'] == 'python_callable']
    if len(callable_records) > 4096:
        raise InterpretationError('interpretation exceeds the declared 4096-callable-record budget; no truncation')
    dimensions = []
    for definition in definitions:
        did = definition['dimension_id']
        dim = {'dimension_id': did, 'spec_version': '1.0.0', 'status': 'insufficient_evidence',
               'basis': 'no_licensed_mapping', 'items': [], 'absences': [],
               'interpretation': 'The current measurements do not establish this candidate construct; interpretation is withheld.',
               'limitations': ['Construct validity and formative utility remain unestablished.'],
               'uncertainty': _uncertainty(None, 'not_evaluated')}
        if did == STRUCTURE:
            dim['limitations'] += ['Per-callable finite syntactic observations only; project dispersion is not estimated.', 'No rule trigger is not evidence of quality or of absence of defects.']
            if language != 'python':
                dim.update(status='not_applicable', basis='language_not_python')
            elif by_id['python.parse_status']['value'] != 'parsed':
                dim.update(status='unavailable', basis='python_syntax_error')
            elif not callable_records:
                dim.update(basis='no_callable_entities')
            else:
                dim.update(status='evidence_available' if any(r['applicability']['state'] == 'observed' for r in callable_records) else 'unavailable', basis='per_callable_structural_evidence',
                           interpretation='Each entity-rule result is separate; no rule or dimension cancels another.')
                if profile['rules']:
                    entities = sorted({r['entity']['entity_id'] for r in callable_records})
                    lookup = {(r['entity']['entity_id'], r['observation_id']): r for r in callable_records}
                    for entity in entities:
                        for rule in profile['rules']:
                            record = lookup.get((entity, rule['observation_id']))
                            if record is None:
                                dim['absences'].append({'entity_id': entity, 'rule_id': rule['rule_id'], 'status': 'unavailable', 'reason': 'Callable observation absent; no zero or favourable decision substituted.'})
                            else:
                                dim['items'].append(_item(record, rule))
                else:
                    dim['items'] = [_item(record, None) for record in callable_records]
        elif did == PARSER:
            dim.update(status='evidence_available', basis='declared_parser_scope',
                       interpretation='Parser status qualifies the analysis route; it is not a source-quality judgement.')
            dim['items'] = [_item(by_id['python.parse_status'], None), _item(by_id['markdown.parse_status'], None)]
            dim['limitations'] += ['Text has no structural parser.', 'Markdown is a finite subset, not a complete CommonMark implementation.', 'Successful parsing does not establish successful execution.']
        dim['uncertainty']['limitations'] = copy.deepcopy(dim['limitations'])
        dimensions.append(dim)
    return dimensions


def interpret_bytes(data: bytes, *, language: str, profile_id: str, profile_sha256: str,
                    task_family: str, path: str = '<memory>') -> dict[str, Any]:
    """Generate a capsule; malformed source retains the kernel's typed refusal."""
    profile = resolve_profile(profile_id, profile_sha256)
    if type(language) is not str or language not in profile['languages'] or type(task_family) is not str or task_family not in profile['task_families']:
        raise InterpretationError('language or task family lies outside the selected profile')
    if type(path) is not str or len(path) > 4096 or '\x00' in path:
        raise InterpretationError('invalid source path metadata')
    if type(data) is not bytes:
        raise InterpretationError('source must be immutable bytes')
    measurement = kernel.measure_bytes(data, language=language, path=path)
    catalogue = _document('research/observation-catalogue.v1.json')
    kernel.verify_result_against_catalogue(measurement, catalogue)
    report = {'schema': SCHEMA, 'contract_version': '1.0.0',
              'measurement_specification': {'kernel_contract_version': kernel.KERNEL_VERSION, 'catalogue_sha256': _LOADED['research/observation-catalogue.v1.json']},
              'build': build_identity(), 'profile': {'profile_id': profile_id, 'version': profile['version'], 'sha256': profile_sha256},
              'context': {'task_family': task_family}, 'measurement': measurement,
              'composition_rule': 'vector_only_non_compensatory', 'dimensions': _vector(measurement, profile),
              'empirical_calibration': 'not_established', 'non_inferences': list(REQUIRED_NON_INFERENCES)}
    report['digest'] = digest(canonical(report))
    return report


def verify_capsule(report: dict[str, Any], data: bytes, *, language: str, profile_id: str,
                   profile_sha256: str, task_family: str, path: str = '<memory>') -> None:
    """Replay supplied bytes; do not trust a transported result's own digest."""
    expected = interpret_bytes(data, language=language, profile_id=profile_id, profile_sha256=profile_sha256, task_family=task_family, path=path)
    try:
        encoded = canonical(report)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise InterpretationError('capsule is not admitted JSON data') from exc
    if encoded != canonical(expected):
        raise InterpretationError('capsule differs from source replay, selected profile or actual build')


def decision_projection(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Comparison view only: never an authentication or report-validation API."""
    out = []
    for dim in report['dimensions']:
        items = []
        for item in dim['items']:
            eid = item['entity_id']
            ordinal = int(eid.split(':')[1]) if eid.startswith('python_callable:') else 0
            items.append({'ordinal': ordinal, 'observation_id': item['observation_id'], 'rule_id': item['rule_id'],
                          'value': item['value'], 'state': item['applicability']['state'],
                          'decision': item['decision'], 'action_id': item['opportunity']['action_id'] if item['opportunity'] else None})
        out.append({'dimension_id': dim['dimension_id'], 'status': dim['status'], 'basis': dim['basis'],
                    'items': sorted(items, key=lambda x: (x['ordinal'], x['observation_id'], x['rule_id'])),
                    'absent_rule_ids': sorted(a['rule_id'] for a in dim['absences'])})
    return out
