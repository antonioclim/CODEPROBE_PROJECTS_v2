#!/usr/bin/env python3
"""Publish an unchanged, verified CodeProbe snapshot as a full GitHub release."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

REPO = 'antonioclim/CODEPROBE_PROJECTS_v2'
API = 'https://api.github.com/repos/' + REPO
SOURCE = '2d38fbd3772a9f415dfcc52ab2840aadd15575e3'
TREE = '519581a051029a774f4f77998a62fec8bd3524ca'
TAG = 'v2.2.0'
OLD_TAG = 'v2.2.0-rc.1'
CI_RUN = 34035926105
ZIP_HASH = '8452f78c56f55e833d8f2003fad6120e7601d979da901b5af415c30664750700'
KIT = 'CodeProbe_Project_Kit_v2.2.0.zip'
ROOT = 'CodeProbe_Project_Kit_v2.2.0/'
OLD_HASHES = {
    'CodeProbe_Project_Kit_v2.2.0-rc.1.zip': ZIP_HASH,
    'CodeProbe_Project_Kit_v2.2.0-rc.1.zip.sha256.txt': 'cd3d7f48aa569dde811c42c48802d29ce891863fe4b1de4fe499ebe32a853e92',
    'CodeProbe_Project_Kit_v2.2.0-rc.1.zip.package_audit.json': '53a6b16549b6430832b37a45073a7a949e78be34eeae6d3d0ab75321ffdf091c',
    'RELEASE_NOTES.md': 'b05278fa8fd56bf896487c62534ecdfab9488e72de6cc25ed1d3791140438267',
    'RELEASE_PROVENANCE.json': '8eb54ab57b66ba5eed2567e85c6238711ad9fbf4eceddd6327c98cc730127e02',
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == 'https', 'Non-HTTPS redirect refused')
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            new.remove_header('Authorization')
        return new


def request(endpoint, *, method='GET', payload=None, raw=None, content_type=None, accept=None, allow404=False):
    url = endpoint if endpoint.startswith('https://') else API + endpoint
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https', 'Only HTTPS is permitted')
    require(parsed.hostname in {'api.github.com', 'uploads.github.com', 'github.com'}, 'Unapproved request host')
    headers = {'Accept': accept or 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'CodeProbe-release-verifier'}
    if parsed.hostname in {'api.github.com', 'uploads.github.com'}:
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    if payload is not None:
        raw = encoded(payload)
        headers['Content-Type'] = 'application/json'
    if content_type:
        headers['Content-Type'] = content_type
    req = urllib.request.Request(url, data=raw, method=method, headers=headers)
    try:
        with urllib.request.build_opener(SafeRedirect()).open(req, timeout=60) as response:
            data = response.read(32_000_001)
    except urllib.error.HTTPError as exc:
        if allow404 and exc.code == 404:
            return None
        raise RuntimeError(f'GitHub {method} returned HTTP {exc.code} for {parsed.path}') from None
    require(len(data) <= 32_000_000, 'Response exceeds the collection limit')
    return data


def api(endpoint, **kwargs):
    data = request(endpoint, **kwargs)
    return None if data is None else json.loads(data)


def pages(endpoint):
    result = []
    for page in range(1, 21):
        separator = '&' if '?' in endpoint else '?'
        batch = api(f'{endpoint}{separator}per_page=100&page={page}')
        require(isinstance(batch, list), 'Expected an API list')
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise RuntimeError('Pagination limit reached; completeness not established')


def zip_audit(data, name):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [{'path': i.filename, 'size_bytes': i.file_size, 'compressed_size_bytes': i.compress_size, 'crc32': f'{i.CRC:08x}'} for i in sorted(archive.infolist(), key=lambda i: i.filename) if not i.is_dir()]
    unpacked = sum(i['size_bytes'] for i in members)
    compressed = sum(i['compressed_size_bytes'] for i in members)
    return {'schema_version': 'codeprobe-zip-package-audit/v1', 'zip_name': name, 'zip_size_bytes': len(data), 'zip_sha256': digest(data), 'file_count': len(members), 'total_uncompressed_member_bytes': unpacked, 'total_compressed_member_bytes': compressed, 'zip_container_overhead_bytes': len(data) - compressed, 'compression_ratio': round(compressed / unpacked, 6) if unpacked else None, 'members': members}


def verify_source(data, tree):
    require(digest(data) == ZIP_HASH, 'Kit digest differs from the published candidate')
    require(tree['sha'] == TREE and tree.get('truncated') is False, 'Incomplete or incorrect Git tree')
    blobs = {i['path']: i for i in tree['tree'] if i['type'] == 'blob'}
    require(len(blobs) == 149, 'Unexpected source membership')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        require(len(infos) == 149 and len({i.filename for i in infos}) == 149, 'Unexpected or duplicate ZIP entries')
        require(sum(i.file_size for i in infos) < 5_000_000, 'Unexpected expanded source size')
        source = {}
        for info in infos:
            require(info.filename.startswith(ROOT), 'Unexpected archive root')
            path = info.filename[len(ROOT):]
            require(path and '..' not in PurePosixPath(path).parts and '\\' not in path and not path.startswith('/'), 'Unsafe archive path')
            require(stat.S_ISREG(info.external_attr >> 16), 'Non-regular ZIP entry')
            content = archive.read(info)
            source[path] = content
            blob = hashlib.sha1(b'blob ' + str(len(content)).encode('ascii') + b'\0' + content).hexdigest()
            require(path in blobs and blobs[path]['sha'] == blob and blobs[path]['size'] == len(content), 'Source differs from Git: ' + path)
            mode = int(blobs[path]['mode'], 8)
            require(stat.S_IMODE(info.external_attr >> 16) == stat.S_IMODE(mode), 'Source mode differs from Git: ' + path)
        require(set(source) == set(blobs), 'Git and ZIP membership differ')
        manifest = json.loads(source['release/release-manifest.json'])
        require(manifest['file_count'] == 148 and len(manifest['files']) == 148, 'Unexpected manifest count')
        require({i['path'] for i in manifest['files']} == set(source) - {'release/release-manifest.json'}, 'Manifest membership differs')
        for item in manifest['files']:
            require(item['size_bytes'] == len(source[item['path']]) and item['sha256'] == digest(source[item['path']]), 'Manifest entry differs')
        canonical = json.dumps({k: v for k, v in manifest.items() if k != 'manifest_sha256'}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        require(digest(canonical) == manifest['manifest_sha256'], 'Manifest self-description digest differs')
        require(manifest['total_source_size_bytes'] == sum(len(source[i['path']]) for i in manifest['files']), 'Manifest aggregate differs')
    return {'source_commit': SOURCE, 'source_tree': TREE, 'source_files': len(source), 'source_manifest_entries': len(manifest['files']), 'all_blob_hashes_and_modes_match': True}


def main():
    work = Path(os.environ['RELEASE_WORK'])
    assets = work / 'assets'
    evidence = work / 'evidence'
    assets.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    old = api('/releases/tags/' + OLD_TAG)
    require(old['id'] == 383626590 and not old['draft'] and old['prerelease'], 'Candidate release changed')
    old_assets = {a['name']: a for a in old['assets']}
    require(set(old_assets) == set(OLD_HASHES), 'Candidate assets changed')
    old_tag = api('/git/ref/tags/' + OLD_TAG)
    require(old_tag['object']['type'] == 'commit' and old_tag['object']['sha'] == SOURCE, 'Candidate tag changed')
    refs = {name: api('/git/ref/heads/' + name) for name in ('main', 'audit/codeprobe-hostile-remediation')}
    require(refs['audit/codeprobe-hostile-remediation']['object']['sha'] == SOURCE, 'Audit branch has advanced; reconcile before publication')
    release_collision = [r for r in pages('/releases') if r['tag_name'] == TAG]
    require(not release_collision, 'New release already exists; inspect instead of overwriting')
    new_tag = api('/git/ref/tags/' + TAG, allow404=True)
    if new_tag is not None:
        require(new_tag['object']['type'] == 'commit' and new_tag['object']['sha'] == SOURCE, 'Existing tag targets different source')
    commit = api('/git/commits/' + SOURCE)
    require(commit['tree']['sha'] == TREE, 'Commit tree mismatch')
    tree = api('/git/trees/' + TREE + '?recursive=1')
    run = api('/actions/runs/' + str(CI_RUN))
    require(run['status'] == 'completed' and run['conclusion'] == 'success' and run['head_sha'] == SOURCE, 'Canonical CI does not support this source')
    jobs = api(f'/actions/runs/{CI_RUN}/jobs?per_page=100')
    require(jobs['total_count'] == len(jobs['jobs']) == 12 and all(j['conclusion'] == 'success' for j in jobs['jobs']), 'Canonical CI job set is not wholly successful')
    payloads = {}
    for name, expected in OLD_HASHES.items():
        asset = old_assets[name]
        data = request(asset['browser_download_url'])
        require(len(data) == asset['size'] and digest(data) == expected and asset['digest'] == 'sha256:' + expected, 'Candidate asset mismatch: ' + name)
        payloads[name] = data
    kit = payloads['CodeProbe_Project_Kit_v2.2.0-rc.1.zip']
    source_check = verify_source(kit, tree)
    require(payloads['CodeProbe_Project_Kit_v2.2.0-rc.1.zip.sha256.txt'] == (ZIP_HASH + '  CodeProbe_Project_Kit_v2.2.0-rc.1.zip\n').encode(), 'Candidate checksum sidecar differs')
    require(json.loads(payloads['CodeProbe_Project_Kit_v2.2.0-rc.1.zip.package_audit.json']) == zip_audit(kit, 'CodeProbe_Project_Kit_v2.2.0-rc.1.zip'), 'Candidate accounting differs')
    (assets / KIT).write_bytes(kit)
    (assets / (KIT + '.sha256.txt')).write_text(ZIP_HASH + '  ' + KIT + '\n', encoding='utf-8')
    (assets / (KIT + '.package_audit.json')).write_bytes(encoded(zip_audit(kit, KIT)))
    snapshots = {'candidate-release.json': old, 'candidate-tag.json': old_tag, 'source-commit.json': commit, 'source-tree.json': tree, 'source-verification.json': source_check, 'ci-run.json': run, 'ci-jobs.json': jobs, 'refs-before.json': refs, 'pull-request.json': api('/pulls/1'), 'pull-request-comments.json': pages('/issues/1/comments')}
    for name, value in snapshots.items():
        (evidence / name).write_bytes(encoded(value))
    for job in jobs['jobs']:
        (evidence / f'ci-job-{job["id"]}.log').write_bytes(request(f'/actions/jobs/{job["id"]}/logs'))
    (evidence / 'README.md').write_text('Historical audit evidence for the exact released source. The public PR and comments are snapshots and can contain superseded state declarations. CI #96 is inherited evidence, not rerun by this publication. This archive is not the full private chat history and does not include the new audit prompt.\n', encoding='utf-8')
    record_manifest = {p.name: {'size_bytes': p.stat().st_size, 'sha256': digest(p.read_bytes())} for p in sorted(evidence.iterdir()) if p.is_file()}
    (evidence / 'MANIFEST_SHA256.json').write_bytes(encoded(record_manifest))
    audit_name = 'CodeProbe_Audit_Record_v2.2.0.zip'
    with zipfile.ZipFile(assets / audit_name, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for p in sorted(evidence.iterdir()):
            archive.write(p, 'CodeProbe_Audit_Record_v2.2.0/' + p.name)
    notes = f'''# CodeProbe 2.2.0 — audited formative code-review kit

This is the full GitHub release of the integrated work completed before the new audit prompt. It is published with `prerelease: false` and marked **Latest**. It contains exactly the same verified product bytes as `v2.2.0-rc.1`; the candidate release remains unchanged. This is a distribution-channel correction, not a claim of new code or newly repeated tests.

## Complete product and audit material

The kit contains all **149 product files** at commit `{SOURCE}`, Git tree `{TREE}`: browser interfaces, worker, Python engine, native tools, maintained tests, runtime configuration, templates, examples, technical and educator documentation, the educator DOCX, preview resources, licence and citation metadata. The source root, engine and report schema remain `2.2.0`.

The integrated work covers bounded file/folder/ZIP intake; parser and score contracts; separated calibration fit/evaluation; authenticated runtime and engine bytes; worker cancellation, deadlines and retry; accessible interface interactions; provenance and report identity; output-alias protection; privacy teardown despite storage failures; finite numeric configuration; reproducible packets and crash-recovery handling. Synthetic test labels are not empirical authorship observations.

`{audit_name}` additionally preserves the public PR discussion and the canonical CI metadata/logs. Historical statements in that evidence retain their original dates and scope. Chat-only handovers, obsolete local alternatives and the subsequent master prompt are not production files and are not silently inserted into the kit.

## Verification and provenance

[CI #96](https://github.com/{REPO}/actions/runs/{CI_RUN}) passed all 12 jobs for this exact source, with 481 maintained unittest cases and the documented platform conditions. Its matrix covers Linux/Python 3.10–3.14, Windows and macOS/Python 3.14.7, supported line coverage, reproducibility, real Chromium/Pyodide functionality, accessibility and Required CI. The prior candidate-publication workflow also reran the full read-only gate before publishing.

This publication independently rechecks the successful CI, downloads and hashes the existing public assets, verifies every source blob and file mode against the Git tree, checks the complete source manifest and recomputes ZIP accounting. It does not execute product or test code with its publishing credentials and does not relabel inherited tests as fresh tests.

Kit SHA-256: `{ZIP_HASH}`.

Download `{KIT}` and its two matching sidecars. GitHub's automatic Source code archives are separate containers and have different container hashes. After extraction, run `python3 -I -S -B tools/validate_release.py --skip-tests`, then `python3 -I -S -B tools/run_local_server.py`. Reports must be outside the analysed project and their parent directories must exist.

## Scope and unchanged limits

This full release is an inspectable formative/research tool for authorised source code, **not a validated LLM detector, authorship probability or basis for misconduct findings**. Institutional deployment, grading and sanctions are not certified. MIT and the existing attribution are unchanged.

Pyodide stays at 0.25.0 and no complete offline runtime or comprehensive current vulnerability clearance is claimed. Manual-engine replacement remains explicitly unverified. Browser resource/timer limits, persistent-erasure uncertainty and filesystem concurrency/power-loss limits remain documented. Old bound profiles must be refitted after an engine change. Full-release and Latest labels identify distribution, not universal safety or scientific validation.

No merge, main update, audit-branch update or administrative protection change is included. PR #1 remains the audit record; main is a separate, older source state. The release is tied to the explicit commit rather than main. The next audit prompt describes future work, not improvements already implemented in this release.
'''
    (assets / 'RELEASE_NOTES.md').write_text(notes, encoding='utf-8')
    provenance = {'schema': 'codeprobe-release-provenance/v2', 'prepared_at_utc': stamp, 'repository': REPO, 'tag': TAG, 'channel': 'full-release', 'make_latest_requested': True, 'source': source_check, 'kit_sha256': ZIP_HASH, 'prior_candidate_release': {'id': old['id'], 'tag': OLD_TAG, 'unchanged': True}, 'canonical_ci': {'id': CI_RUN, 'head_sha': SOURCE, 'successful_jobs': 12, 'maintained_unittest_cases': 481, 'rerun_by_this_publication': False}, 'publication_workflow_run_id': os.environ.get('GITHUB_RUN_ID'), 'verification_runtime': platform.python_version(), 'source_changed': False, 'main_update_authorised': False, 'licence_changed': False, 'notes': 'Full release of unchanged audited formative software. Predictive or institutional validation is not inferred.'}
    provenance['assets_except_provenance_and_checksum_list'] = {p.name: {'size_bytes': p.stat().st_size, 'sha256': digest(p.read_bytes())} for p in sorted(assets.iterdir())}
    (assets / 'RELEASE_PROVENANCE.json').write_bytes(encoded(provenance))
    hashes = {p.name: digest(p.read_bytes()) for p in sorted(assets.iterdir())}
    (assets / 'ASSET_SHA256SUMS.txt').write_text(''.join(f'{value}  {name}\n' for name, value in hashes.items()), encoding='utf-8')
    expected = {p.name: {'sha256': digest(p.read_bytes()), 'size': p.stat().st_size} for p in sorted(assets.iterdir())}
    (work / 'asset-manifest.json').write_bytes(encoded(expected))
    require(len(expected) == 7, 'Unexpected new asset set')
    for name, before in refs.items():
        require(api('/git/ref/heads/' + name)['object']['sha'] == before['object']['sha'], 'Concurrent branch change; publication paused')
    if new_tag is None:
        api('/git/refs', method='POST', payload={'ref': 'refs/tags/' + TAG, 'sha': SOURCE})
    require(api('/git/ref/tags/' + TAG)['object']['sha'] == SOURCE, 'Tag readback failed')
    release = api('/releases', method='POST', payload={'tag_name': TAG, 'target_commitish': SOURCE, 'name': 'CodeProbe 2.2.0 — audited formative code-review kit', 'body': notes, 'draft': True, 'prerelease': False, 'make_latest': 'false'})
    (work / 'created-draft.json').write_bytes(encoded(release))
    upload_url = release['upload_url'].split('{', 1)[0]
    for p in sorted(assets.iterdir()):
        content_type = 'application/zip' if p.suffix == '.zip' else ('application/json' if p.suffix == '.json' else 'text/plain; charset=utf-8')
        uploaded = api(upload_url + '?name=' + urllib.parse.quote(p.name), method='POST', raw=p.read_bytes(), content_type=content_type)
        require(uploaded['size'] == expected[p.name]['size'], 'Upload size differs')
    def verify_assets(snapshot, public):
        listed = {a['name']: a for a in snapshot['assets']}
        require(set(listed) == set(expected), 'Published asset set differs')
        for name, item in listed.items():
            require(item['state'] == 'uploaded' and item['size'] == expected[name]['size'] and item.get('digest') == 'sha256:' + expected[name]['sha256'], 'Asset metadata differs: ' + name)
            data = request(item['browser_download_url']) if public else request(item['url'], accept='application/octet-stream')
            require(digest(data) == expected[name]['sha256'], 'Downloaded asset differs: ' + name)
    draft = api('/releases/' + str(release['id']))
    verify_assets(draft, False)
    api('/releases/' + str(release['id']), method='PATCH', payload={'draft': False, 'prerelease': False, 'make_latest': 'true'})
    published = api('/releases/tags/' + TAG)
    require(published['id'] == release['id'] and not published['draft'] and not published['prerelease'], 'Publication state differs')
    verify_assets(published, True)
    latest = api('/releases/latest')
    require(latest['id'] == release['id'] and latest['tag_name'] == TAG, 'Latest does not point to new release')
    for name, before in refs.items():
        require(api('/git/ref/heads/' + name)['object']['sha'] == before['object']['sha'], 'Branch advanced during publication; review required')
    preserved = api('/releases/tags/' + OLD_TAG)
    require(preserved['id'] == old['id'] and preserved['prerelease'] == old['prerelease'] and preserved['body'] == old['body'], 'Previous candidate metadata changed')
    require({a['name']: a['digest'] for a in preserved['assets']} == {a['name']: a['digest'] for a in old['assets']}, 'Previous assets changed')
    (work / 'published-release.json').write_bytes(encoded(published))
    (work / 'latest-release.json').write_bytes(encoded(latest))
    result = {'status': 'PUBLISHED_LATEST_VERIFIED', 'release_id': published['id'], 'tag': TAG, 'url': published['html_url'], 'published_at': published['published_at'], 'source_commit': SOURCE, 'source_tree': TREE, 'source_files': 149, 'assets_downloaded_and_verified_before_and_after_publication': len(expected), 'kit_sha256': ZIP_HASH, 'main_and_audit_unchanged': True, 'previous_candidate_unchanged': True, 'tests_rerun': False}
    (work / 'RESULT.json').write_bytes(encoded(result))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
