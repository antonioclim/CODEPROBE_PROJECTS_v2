"""Prospective split-manifest admission, not empirical calibration.

Author: Antonio Clim. No outcomes are accepted, no authorisation is certified
and no statistical result is manufactured from declared metadata.
"""
from __future__ import annotations
import re
from typing import Any

from codeprobe_interpretation import InterpretationError, canonical, digest, fields, resolve_profile, sha, _document


def admit_manifest(manifest: dict[str, Any], *, expected_profile_sha256: str) -> dict[str, Any]:
    fields(manifest, {'schema','data_kind','profile_id','profile_sha256','target','units'}, 'calibration admission manifest')
    if manifest['schema'] != 'codeprobe-calibration-split-manifest/v1' or manifest['data_kind'] not in ('synthetic_conformance', 'declared_observational_metadata'):
        raise InterpretationError('unsupported manifest purpose')
    if manifest['profile_sha256'] != expected_profile_sha256:
        raise InterpretationError('evaluation profile changed after freeze')
    resolve_profile(manifest['profile_id'], expected_profile_sha256)
    design = _document('research/s04/calibration-design.v1.json')
    if manifest['target'] not in design['targets']:
        raise InterpretationError('target is not a declared formative estimand')
    units = manifest['units']
    if type(units) is not list or not 3 <= len(units) <= design['maximum_manifest_rows']:
        raise InterpretationError('manifest requires three to 4096 units')
    seen = set(); split_counts = {s: 0 for s in design['split_roles']}
    groups = {key: {} for key in design['partition_fields']}
    for row in units:
        fields(row, {'unit_id','raw_sha256','normalised_sha256','lineage_group','contributor_group','task_family','split','label_access'}, 'unit metadata')
        for key in ('unit_id','lineage_group','contributor_group','task_family'):
            if type(row[key]) is not str or re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', row[key]) is None:
                raise InterpretationError('non-opaque or missing grouping identifier')
        if row['unit_id'] in seen:
            raise InterpretationError('duplicate unit identifier')
        seen.add(row['unit_id'])
        sha(row['raw_sha256']); sha(row['normalised_sha256'])
        split = row['split']
        if type(split) is not str or split not in split_counts or row['label_access'] not in ('open','sealed'):
            raise InterpretationError('invalid split or label access')
        if split == 'evaluation' and row['label_access'] != 'sealed':
            raise InterpretationError('evaluation labels must remain sealed')
        split_counts[split] += 1
        for key, assignments in groups.items():
            value = row[key]
            if value in assignments and assignments[value] != split:
                raise InterpretationError('declared leakage across splits: ' + key)
            assignments[value] = split
    if not all(split_counts.values()):
        raise InterpretationError('training, tuning and evaluation splits are required')
    tasks = {s: {u['task_family'] for u in units if u['split'] == s} for s in split_counts}
    supported = tasks['training'] | tasks['tuning']
    return {'schema': 'codeprobe-calibration-admission-result/v1', 'status': 'structural_checks_passed_only',
            'manifest_sha256': digest(canonical(manifest)), 'profile_sha256': expected_profile_sha256,
            'split_counts': split_counts, 'evaluation_only_task_families': sorted(tasks['evaluation'] - supported),
            'empirical_calibration': 'not_established', 'authorisation': 'not_verified_by_this_interface',
            'limitations': ['Declared hashes and groups only; hidden near-duplicates and undisclosed relationships are not detected.',
                           'No outcomes, estimates, rater evidence or study approval have been validated.',
                           'Structural admission does not authorise collection, tuning or label unsealing.']}
