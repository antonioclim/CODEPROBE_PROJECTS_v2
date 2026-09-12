"""Replay-checked S05 reporting bridge. Author: Antonio Clim.

Native measurement and immutable reports are separate from the offline reader's
mutable feedback. This is not the legacy S01 complete-report schema.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import html
import json
from pathlib import Path
import re
import unicodedata
from typing import Any
import codeprobe_interpretation as interpretation

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'codeprobe-review-bundle/v1'
FEEDBACK_SCHEMA = 'codeprobe-feedback-journal/v1'
NEUTRAL_PATH = '<source>'
MAX_BUNDLE_BYTES = 4_000_000
MAX_HTML_BYTES = 12_000_000
PRESENTATION_FILES = (
    'src/codeprobe_reporting.py', 'src/codeprobe_report_cli.py',
    'app/s05/reader.css', 'app/s05/reader.js',
    'research/s05/acceptance-lock.v1.json',
    'research/s05/BRIDGE_PRIVACY_ACCESSIBILITY.md',
    'schemas/codeprobe-review-bundle-v1.schema.json',
    'schemas/codeprobe-feedback-journal-v1.schema.json',
)
STATES = {
    'evidence_available': 'Evidence available within the declared scope',
    'observed': 'Observed',
    'insufficient_evidence': 'Insufficient evidence',
    'unavailable': 'Unavailable',
    'not_applicable': 'Not applicable',
    'descriptive': 'Descriptive observation only',
    'no_rule_trigger': 'No rule trigger — not a quality judgement',
    'abstain': 'Abstention — sensitive to the selected threshold',
    'review_opportunity': 'Optional review opportunity — not a demonstrated defect',
}
ROLES = {'learner', 'educator', 'reviewer', 'other'}
RESPONSES = {'accepted', 'declined', 'not_applicable', 'deferred'}


class ReportingError(ValueError):
    """Rejected source, report, output or feedback admission."""


def component_bytes(name: str) -> bytes:
    p = ROOT / name
    if p.is_symlink() or any(q.is_symlink() for q in p.parents if q != ROOT and ROOT in q.parents) or not p.is_file():
        raise ReportingError('presentation component is not a regular local file')
    return p.read_bytes()


_LOADED = {p: interpretation.digest(component_bytes(p)) for p in PRESENTATION_FILES}


def presentation_identity() -> dict[str, Any]:
    current = {p: interpretation.digest(component_bytes(p)) for p in PRESENTATION_FILES}
    if current != _LOADED:
        raise ReportingError('presentation changed after admission; reload an audited build')
    return {'schema': 'codeprobe-presentation-build/v1', 'component_sha256': current,
            'digest': interpretation.digest(interpretation.canonical(current)),
            'qualification': 'File-set identity only; no signed authenticity or hostile-process guarantee.'}


def make_bundle(data: bytes, *, language: str, profile_id: str, profile_sha256: str,
                path: str = NEUTRAL_PATH, include_source: bool = False) -> dict[str, Any]:
    if type(include_source) is not bool:
        raise ReportingError('source inclusion must be an explicit Boolean')
    capsule = interpretation.interpret_bytes(data, language=language, profile_id=profile_id,
        profile_sha256=profile_sha256, task_family='source_inspection', path=path)
    bundle = {'schema': SCHEMA, 'bridge_version': '1.0.0', 'capsule': capsule,
              'presentation_build': presentation_identity(),
              'privacy': {'path': 'neutral_label' if path == NEUTRAL_PATH else 'explicit_disclosure',
                          'literal_source': 'included_by_request' if include_source else 'omitted',
                          'residual': 'Source-derived identifiers, hashes and coordinates may be sensitive; not anonymised.'},
              'normalised_source': interpretation.kernel.intake_from_bytes(data).text if include_source else None,
              'compatibility': {'s01_complete_report': False, 's04_capsule_unchanged': True,
                                'browser_role': 'presentation_snapshot_not_source_replay'}}
    bundle['digest'] = interpretation.digest(interpretation.canonical(bundle))
    if len(interpretation.canonical(bundle)) > MAX_BUNDLE_BYTES:
        raise ReportingError('report exceeds the declared four-million-byte budget; no truncation')
    return bundle


def verify_bundle(bundle: dict[str, Any], data: bytes, **context: Any) -> None:
    """Replay independently supplied source and context, never a self-signed hash."""
    expected = make_bundle(data, **context)
    try:
        actual = interpretation.canonical(bundle)
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ReportingError('report is not admitted JSON') from exc
    if actual != interpretation.canonical(expected):
        raise ReportingError('report differs from source, context, profile or build replay')


def opportunity_map(bundle: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Internal mapping for an already replay-checked bundle, not an admission API."""
    result = {}
    for dim in bundle['capsule']['dimensions']:
        for item in dim['items']:
            if item['opportunity'] is not None:
                token = bundle['digest'] + '|' + item['record_ref'] + '|' + item['rule_id']
                oid = 'opportunity.' + interpretation.digest(token.encode())
                result[oid] = {'record_ref': item['record_ref'], 'rule_id': item['rule_id'],
                               'action_id': item['opportunity']['action_id']}
    return result


def validate_feedback(journal: dict[str, Any], bundle: dict[str, Any], data: bytes,
                      **context: Any) -> None:
    verify_bundle(bundle, data, **context)
    interpretation.fields(journal, {'schema', 'report_digest', 'responses'}, 'feedback journal')
    if journal['schema'] != FEEDBACK_SCHEMA or journal['report_digest'] != bundle['digest']:
        raise ReportingError('feedback belongs to a different report or schema')
    entries = journal['responses']; allowed = opportunity_map(bundle); seen = set()
    if type(entries) is not list or len(entries) > len(allowed):
        raise ReportingError('invalid feedback inventory')
    for entry in entries:
        interpretation.fields(entry, {'opportunity_id','state','actor_role','rationale'}, 'response')
        oid = entry['opportunity_id']
        if type(oid) is not str or oid not in allowed or oid in seen:
            raise ReportingError('foreign, stale, duplicate or non-opportunity feedback reference')
        seen.add(oid)
        if type(entry['state']) is not str or entry['state'] not in RESPONSES or type(entry['actor_role']) is not str or entry['actor_role'] not in ROLES:
            raise ReportingError('invalid response state or role')
        text = entry['rationale']
        if text is not None and (type(text) is not str or len(text) > 2000 or any((ord(c) < 32 and c not in '\n\t') or ord(c) == 127 or unicodedata.category(c) == 'Cs' for c in text)):
            raise ReportingError('invalid rationale; maximum 2000 characters and no control codes')


def display_text(value: Any) -> str:
    text = str(value)
    # Never let directional/control characters masquerade as trusted UI labels.
    return ''.join('\\u{%04X}' % ord(c) if (unicodedata.category(c) in {'Cc','Cf','Cs'} and c not in '\n\t') else c for c in text)


def esc(value: Any) -> str:
    return html.escape(display_text(value), quote=True)


def anchor(evidence_id: str) -> str:
    return 'evidence-' + interpretation.digest(evidence_id.encode())


def _details(title: str, value: Any) -> str:
    return '<details><summary>' + esc(title) + '</summary><pre>' + esc(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)) + '</pre></details>'


def render_html(bundle: dict[str, Any], data: bytes, **context: Any) -> bytes:
    """Render only after source replay. HTML remains an unauthenticated snapshot."""
    verify_bundle(bundle, data, **context)
    capsule = bundle['capsule']; measurement = capsule['measurement']
    evidence = {e['evidence_id']: e for e in measurement['source_evidence']}
    records = {r['record_id']: r for r in measurement['observations']}
    opportunities = opportunity_map(bundle)
    reverse = {(v['record_ref'],v['rule_id']): key for key,v in opportunities.items()}
    css = component_bytes('app/s05/reader.css').decode('utf-8')
    script = component_bytes('app/s05/reader.js').decode('utf-8')
    def integrity(text): return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
    csp = ("default-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; "
           "base-uri 'none'; form-action 'none'; object-src 'none'; "
           "style-src 'sha256-" + integrity(css) + "'; script-src 'sha256-" + integrity(script) + "'")
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width,initial-scale=1">',
           '<meta name="referrer" content="no-referrer">',
           '<meta http-equiv="Content-Security-Policy" content="' + esc(csp) + '">',
           '<title>CodeProbe — evidence-bounded review</title><style>' + css + '</style></head>',
           '<body data-report-digest="' + bundle['digest'] + '"><a class="skip" href="#main">Skip to report</a>',
           '<header><p class="eyebrow">CODEPROBE / RESEARCH CANDIDATE S05</p><h1>Evidence-bounded review</h1>',
           '<p class="lede">Observations and optional questions, not a score or a verdict.</p></header>',
           '<main id="main" tabindex="-1"><section aria-labelledby="limits-title"><h2 id="limits-title">Interpretation limits</h2>',
           '<p id="non-certification">No rule trigger is not evidence of quality or absence of defects. Empirical calibration, construct validity, educational utility and fairness are not established.</p>',
           '<p>No authorship inference, misconduct decision, automatic grading or sanctions are produced.</p>',
           '<p id="snapshot-limit">Native source replay was performed at generation. This HTML is a presentation snapshot, not an authenticated measurement. Reverify the JSON bundle and source in the same admitted build/runtime.</p>',
           '</section><section aria-labelledby="identity-title"><h2 id="identity-title">Source, profile and build</h2>',
           '<dl><dt>Source label</dt><dd>' + esc(measurement['artifact']['path']) + '</dd>',
           '<dt>Language</dt><dd>' + esc(measurement['artifact']['language']) + '</dd>',
           '<dt>Profile</dt><dd id="profile-id">' + esc(capsule['profile']['profile_id']) + '</dd>',
           '<dt>Profile SHA-256</dt><dd>' + capsule['profile']['sha256'] + '</dd>',
           '<dt>Report SHA-256</dt><dd id="report-digest">' + bundle['digest'] + '</dd>',
           '<dt>Measurement specification</dt><dd>' + esc(capsule['measurement_specification']['kernel_contract_version']) + '</dd>',
           '<dt>Source SHA-256</dt><dd>' + measurement['artifact']['raw_sha256'] + '</dd></dl>',
           _details('Full build and runtime identity', {'measurement_build': capsule['build'], 'presentation_build': bundle['presentation_build']}),
           _details('Selected illustrative policy (not empirically calibrated)', interpretation.resolve_profile(capsule['profile']['profile_id'],capsule['profile']['sha256'])),
           '</section><section aria-labelledby="dimensions-title"><h2 id="dimensions-title">Separate dimensions</h2>']
    for dim in capsule['dimensions']:
        did = dim['dimension_id']
        out += ['<section class="dimension" data-dimension="' + esc(did) + '" data-state="' + esc(dim['status']) + '" data-basis="' + esc(dim['basis']) + '">',
                '<h3>' + esc(did.replace('_',' ').capitalize()) + '</h3>',
                '<p class="state">' + esc(STATES[dim['status']]) + '</p>']
        if dim['basis'] == 'no_licensed_mapping':
            out.append('<p class="withheld">Interpretation withheld — no licensed mapping. This does not mean low risk or good quality.</p>')
        out += ['<p>' + esc(dim['interpretation']) + '</p>', _details('Dimension limitations and uncertainty', {'limitations':dim['limitations'], 'uncertainty':dim['uncertainty']})]
        for absence in dim['absences']:
            out.append('<p class="absence" data-state="' + esc(absence['status']) + '">' + esc(absence['rule_id']) + ': ' + esc(absence['reason']) + '</p>')
        for item in dim['items']:
            record = records[item['record_ref']]
            iid = 'item-' + interpretation.digest((item['record_ref'] + '|' + item['rule_id']).encode())
            status = item['decision']['status'] if item['decision'] else ('descriptive' if item['applicability']['state']=='observed' else item['applicability']['state'])
            entity = record['entity']['entity_id']; label = 'Callable ' + entity.split(':')[1] if entity.startswith('python_callable:') else 'Source artefact'
            out += ['<article class="observation" id="' + iid + '" tabindex="-1" data-record="' + item['record_ref'] + '" data-decision="' + esc(status) + '">',
                    '<h4>' + esc(label + ' / ' + item['observation_id']) + '</h4>',
                    '<p class="decision">' + esc(STATES[status]) + '</p>',
                    '<dl><dt>Observation state</dt><dd class="applicability">' + esc(item['applicability']['state']) + '</dd>',
                    '<dt>Value</dt><dd class="value">' + ('Not available (null)' if item['value'] is None else esc(item['value'])) + '</dd>',
                    '<dt>Unit</dt><dd>' + esc(record['unit']) + '</dd><dt>Rule</dt><dd>' + esc(item['rule_id']) + '</dd></dl>']
            if item['applicability']['reason']:
                out.append('<p>' + esc(item['applicability']['reason']) + '</p>')
            for ref in item['source_evidence_refs']:
                if ref not in evidence: raise ReportingError('unresolved evidence')
                e = evidence[ref]
                out.append('<a class="evidence-link" data-jump href="#' + anchor(ref) + '">Inspect owned evidence: lines ' + str(e['start_line']) + '–' + str(e['end_line']) + '</a> ')
            out += [_details('Exact references, condition and uncertainty', {'record_ref':item['record_ref'], 'source_evidence_refs':item['source_evidence_refs'], 'condition':item['condition'], 'decision':item['decision'], 'uncertainty':item['uncertainty']})]
            if item['opportunity']:
                opp = item['opportunity']; oid = reverse[(item['record_ref'],item['rule_id'])]
                out += ['<p class="question">' + esc(opp['question']) + '</p><p>' + esc(opp['qualification']) + ' ' + esc(opp['trade_off']) + '</p>',
                        '<fieldset disabled data-opportunity="' + oid + '"><legend>Optional response: ' + esc(label + ' / ' + item['rule_id']) + '</legend>',
                        '<label for="state-' + oid + '">Response</label><select id="state-' + oid + '" class="response-state" autocomplete="off"><option value="">No response</option>',
                        ''.join('<option value="' + s + '">' + esc(s.replace('_',' ').capitalize()) + '</option>' for s in ('accepted','declined','not_applicable','deferred')) + '</select>',
                        '<label for="role-' + oid + '">Your role</label><select id="role-' + oid + '" class="actor-role" autocomplete="off"><option value="">Select role</option>',
                        ''.join('<option value="' + s + '">' + s.capitalize() + '</option>' for s in ('learner','educator','reviewer','other')) + '</select>',
                        '<label for="note-' + oid + '">Rationale (optional; no secrets; at most 2000 characters)</label><textarea id="note-' + oid + '" class="rationale" rows="3" maxlength="4000" autocomplete="off" spellcheck="false"></textarea></fieldset>']
            out.append('</article>')
        out.append('</section>')
    out += ['</section><section aria-labelledby="evidence-title"><h2 id="evidence-title">Owned source evidence</h2>',
            '<p>Coordinates refer to normalised physical lines, inclusive and one-based. C0-C0 are sentinels, not token highlights.</p>']
    source = bundle['normalised_source']; lines = interpretation.kernel.intake_from_bytes(data).physical_lines
    for ref,e in evidence.items():
        out += ['<section class="evidence" id="' + anchor(ref) + '" tabindex="-1"><h3>' + esc(e['scope']) + ': lines ' + str(e['start_line']) + '–' + str(e['end_line']) + '</h3><p class="reference">' + esc(ref) + '</p>']
        if not lines: out.append('<p>Empty artefact: no physical source line exists.</p>')
        elif source is not None:
            out.append('<a data-jump href="#source-line-' + str(e['start_line']) + '">Go to the included source line</a>')
        else: out.append('<p>Literal source omitted by default. Use the original source and these line coordinates; no excerpt is fabricated.</p>')
        out.append('<a data-jump href="#dimensions-title">Return to dimensions</a></section>')
    out.append('</section>')
    if source is not None:
        out += ['<section aria-labelledby="source-title"><h2 id="source-title">Source included by explicit request</h2><p>Potentially sensitive content. Directional and control characters are displayed as escaped Unicode code points.</p><pre class="source">']
        out += ['<span id="source-line-' + str(n) + '" tabindex="-1">' + str(n) + ': ' + esc(line) + '</span>\n' for n,line in enumerate(lines,1)]
        out.append('</pre></section>')
    out += ['<section aria-labelledby="feedback-title"><h2 id="feedback-title">Separate feedback</h2>',
            '<p>Responses are not evidence of correctness or utility. Nothing is sent to a server. Export writes a separate file only when requested.</p>',
            '<p id="feedback-error" role="alert" tabindex="-1"></p><p id="feedback-status" role="status" aria-live="polite"></p>',
            '<button id="export-feedback" disabled type="button">Export responses</button> <button id="clear-feedback" disabled type="button">Clear active responses</button>',
            '<noscript><p>JavaScript is disabled: the evidence report remains readable, but interactive feedback export is unavailable.</p></noscript></section>',
            '<section aria-labelledby="privacy-title"><h2 id="privacy-title">Privacy and deletion limits</h2>',
            '<p id="privacy-disclosure">Source-path mode: ' + esc(bundle['privacy']['path']) + '. Literal source: ' + esc(bundle['privacy']['literal_source']) + '. Hashes, coordinates and source-derived identifiers in the JSON bundle may be sensitive. This is not anonymised data.</p>',
            '<p id="deletion-limits">Clear removes active responses only. It does not securely erase downloaded files, original reports/source, browser or operating-system caches, backups, snapshots or extension data. Reloading this file restores its original report.</p>',
            '<p>The standalone reader has no external runtime acquisition. This statement does not describe the unchanged legacy Pyodide application.</p>',
            _details('Retained non-inferences',capsule['non_inferences']),
            '</section></main><footer>Antonio Clim · Research candidate, not public-product validation</footer>',
            '<script>' + script + '</script></body></html>']
    payload = ''.join(out).encode('utf-8')
    if len(payload) > MAX_HTML_BYTES: raise ReportingError('HTML exceeds the declared display budget; no truncation')
    return payload
