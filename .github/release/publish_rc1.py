#!/usr/bin/env python3
"""Publish one authorised, immutable-source CodeProbe release candidate."""
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import platform
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

REPO = "antonioclim/CODEPROBE_PROJECTS_v2"
HEAD = "2d38fbd3772a9f415dfcc52ab2840aadd15575e3"
TREE = "519581a051029a774f4f77998a62fec8bd3524ca"
TAG = "v2.2.0-rc.1"
CI_RUN = 34035926105
ZIP_DIGEST = "8452f78c56f55e833d8f2003fad6120e7601d979da901b5af415c30664750700"
ZIP_NAME = "CodeProbe_Project_Kit_v2.2.0-rc.1.zip"
API = "https://api.github.com/repos/" + REPO
MAX_RESPONSE = 20_000_000

NOTES = """# CodeProbe 2.2.0-rc.1 — audited research candidate

This is a **published pre-release**, authorised by the repository owner on 6 September 2026. It packages the exact audited 4K source without merging PR #1, changing main, changing MIT or claiming stable institutional deployment approval.

## Source and version identity

- Tag: `v2.2.0-rc.1`.
- Source commit: `2d38fbd3772a9f415dfcc52ab2840aadd15575e3`.
- Git tree: `519581a051029a774f4f77998a62fec8bd3524ca`.
- Source membership: 149 files; 148 source-manifest entries because the manifest does not hash itself.
- The packaged engine and report schema remain **2.2.0** and the archive root remains `CodeProbe_Project_Kit_v2.2.0/`. The `rc.1` suffix identifies this release channel; it does not imply an untested code-version change.

## Included engineering work

The audited source incorporates bounded file/ZIP intake, fit/evaluation separation, authenticated Pyodide and engine bytes, worker isolation with cancellation and deadlines, report/input provenance, deterministic release-packet recovery and accessible browser interactions.

The final 4K changes reject conflicting report destinations before writes, complete session privacy teardown even when persistent storage fails and reject nonfinite numeric configuration and non-conforming generated JSON. Reports must be outside the analysed project and their parent directories must already exist. Individual report replacements are atomic; the pair is not a single transaction.

## Verification

[Canonical CI #96](https://github.com/antonioclim/CODEPROBE_PROJECTS_v2/actions/runs/34035926105) passed all 12 jobs for the exact source: Linux/Python 3.10–3.14, Windows and macOS/Python 3.14.7, supported-code coverage, release reproducibility, actual Chromium/Pyodide functional integrity, accessibility and Required CI. The maintained suite contains 481 unittest cases; platform-specific conditions retain their scope.

The publication workflow rechecks that CI evidence, reruns the complete read-only gate and rebuilds the unchanged source packet. It does not relabel the earlier browser or cross-platform jobs as fresh publication-run executions. SHA-256 of the packaged ZIP is:

`8452f78c56f55e833d8f2003fad6120e7601d979da901b5af415c30664750700`

Download the named kit ZIP and both matching sidecars. After checksum verification and extraction, run `python3 -I -S -B tools/validate_release.py --skip-tests`. Launch with `python3 -I -S -B tools/run_local_server.py`. GitHub's automatically generated source archives are separate containers and are not covered by the kit ZIP checksum.

## Intended use and limitations

Use as inspectable formative research software on synthetic or authorised source code. The concern score is not an authorship probability, evidence of misconduct or a validated LLM detector. Sensitivity, specificity and external validity are not established. No grading, sanctions or institutional processing approval is supplied by this release.

Pyodide remains fixed at 0.25.0 and is not bundled as a complete offline runtime. No comprehensive current vulnerability clearance is claimed. Initialisation requires the configured authenticated runtime resources. The manual-engine route remains explicitly unverified. Browser timers, resource exhaustion, main-thread preparation/rendering, persistent-storage refusal and filesystem concurrency/power-loss limits remain as documented. Existing bound profiles must be refitted after engine-source changes, not edited by replacing their hashes.

The last administrative observation found main unprotected and no repository rulesets; the connector could not apply administrative protections. That condition is disclosed, not claimed resolved or used to fabricate a merge. The release/tag is not claimed cryptographically signed or immutable by repository policy.

## Licence

MIT and the existing CodeProbe contributors attribution are unchanged. The intended-use statement is not an additional licence restriction, an exclusive-ownership declaration or institutional/legal clearance. Existing source documentation, SECURITY.md and CITATION.cff are included. No DOI, publication, reviewer or dataset has been invented.
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8", newline="\n")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == "https", "Refused a non-HTTPS redirect")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            new.remove_header("Authorization")
        return new


def request(url: str, *, method: str = "GET", payload=None, binary: bytes | None = None, accept: str = "application/vnd.github+json", content_type: str = "application/json", missing_ok: bool = False):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc in {"api.github.com", "uploads.github.com"}, "Refused unexpected request host")
    require(parsed.path.startswith("/repos/" + REPO + "/"), "Refused request outside the authorised repository")
    token = os.environ.get("GH_TOKEN")
    require(bool(token), "Repository-scoped workflow authentication is unavailable")
    data = binary if binary is not None else (json.dumps(payload, allow_nan=False).encode("utf-8") if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method, headers={"Authorization": "Bearer " + token, "Accept": accept, "Content-Type": content_type, "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.build_opener(SafeRedirect()).open(req, timeout=60) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        if missing_ok and exc.code == 404:
            return None
        detail = exc.read(8192).decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub {method} {parsed.path} returned {exc.code}: {detail}") from None
    require(len(raw) <= MAX_RESPONSE, "Response exceeds the bounded download size")
    return raw if accept == "application/octet-stream" else json.loads(raw)


def api(endpoint: str, **options):
    return request(API + endpoint, **options)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, timeout=30).strip()


def source_check() -> None:
    require(git("rev-parse", "HEAD") == HEAD, "Unexpected checkout commit")
    require(git("rev-parse", "HEAD^{tree}") == TREE, "Unexpected checkout tree")
    require(git("status", "--porcelain=v1", "--untracked-files=all") == "", "Product checkout is not clean")
    require(len(git("ls-tree", "-r", "--name-only", "HEAD").splitlines()) == 149, "Unexpected source membership")


def preflight(work: Path) -> None:
    source_check()
    head = api("/git/ref/heads/audit/codeprobe-hostile-remediation")
    require(head["object"]["sha"] == HEAD, "Audit head moved; do not publish a superseded source")
    run = api(f"/actions/runs/{CI_RUN}")
    jobs = api(f"/actions/runs/{CI_RUN}/jobs?per_page=100")
    checks = api(f"/commits/{HEAD}/check-runs?check_name=Required%20CI&per_page=100")
    require(run["head_sha"] == HEAD and run["status"] == "completed" and run["conclusion"] == "success", "Canonical CI is not successful for this exact source")
    require(jobs["total_count"] == len(jobs["jobs"]) == 12 and all(j["head_sha"] == HEAD and j["conclusion"] == "success" for j in jobs["jobs"]), "Canonical CI job evidence is incomplete")
    require(any(c["head_sha"] == HEAD and c["conclusion"] == "success" and c["app"]["id"] == 15368 for c in checks["check_runs"]), "Required CI identity or result is wrong")
    save(work / "preflight.json", {"audit_ref": head, "canonical_run": run, "jobs": jobs, "required_checks": checks})
    print("PREFLIGHT_PASS", HEAD, TREE, "canonical jobs=12/12")


def prepare(work: Path) -> None:
    source_check()
    gate = json.loads((work / "fresh-gate.json").read_text(encoding="utf-8"))
    require(len(gate["results"]) == 17 and all(r["ok"] and not r.get("skipped", False) for r in gate["results"]), "Fresh complete read-only gate did not pass")
    assets = work / "assets"
    packet = assets / ZIP_NAME
    require(digest(packet.read_bytes()) == ZIP_DIGEST, "Built packet does not match canonical CI digest")
    with zipfile.ZipFile(packet) as archive:
        require(archive.testzip() is None and len(archive.infolist()) == 149, "Invalid kit ZIP")
        prefix = "CodeProbe_Project_Kit_v2.2.0/"
        for name in archive.namelist():
            require(name.startswith(prefix), "Unexpected kit archive root")
            relative = name[len(prefix):]
            require(archive.read(name) == Path(relative).read_bytes(), "Packet member differs from source: " + relative)
    require((assets / (ZIP_NAME + ".sha256.txt")).read_text(encoding="utf-8") == f"{ZIP_DIGEST}  {ZIP_NAME}\n", "Wrong checksum sidecar")
    audit = json.loads((assets / (ZIP_NAME + ".package_audit.json")).read_text(encoding="utf-8"))
    require(audit["zip_sha256"] == ZIP_DIGEST, "Wrong package audit identity")
    (assets / "RELEASE_NOTES.md").write_text(NOTES, encoding="utf-8", newline="\n")
    package_records = {p.name: {"size_bytes": p.stat().st_size, "sha256": digest(p.read_bytes())} for p in sorted(assets.iterdir()) if p.is_file()}
    save(assets / "RELEASE_PROVENANCE.json", {"schema": "codeprobe-published-candidate-provenance/v1", "repository": REPO, "tag": TAG, "classification": "prerelease", "source_commit": HEAD, "source_tree": TREE, "engine_version": "2.2.0", "source_files": 149, "maintained_unittest_cases": 481, "canonical_ci_run_id": CI_RUN, "canonical_ci_jobs_passed": 12, "fresh_full_gate_controls": 17, "publication_workflow_run_id": os.environ.get("GITHUB_RUN_ID"), "publication_python": platform.python_version(), "assets_excluding_this_provenance_file": package_records, "licence": "MIT_UNCHANGED", "main_merge": False, "governance_clearance": False, "detector_validation": False, "cryptographic_signature_claimed": False})
    save(work / "asset-manifest.json", {p.name: {"size_bytes": p.stat().st_size, "sha256": digest(p.read_bytes())} for p in sorted(assets.iterdir()) if p.is_file()})
    source_check()
    print("PREPARE_PASS", ZIP_DIGEST, "149 source members; 5 release assets")


def publish(work: Path) -> None:
    source_check()
    preflight(work)
    assets = work / "assets"
    expected = json.loads((work / "asset-manifest.json").read_text(encoding="utf-8"))
    require(len(expected) == 5, "Unexpected release asset count")
    for name, record in expected.items():
        require(digest((assets / name).read_bytes()) == record["sha256"], "Local release asset changed")
    # Normal contents-authorised tag/release publication, never an administration workaround.
    tag = api("/git/ref/tags/" + TAG, missing_ok=True)
    if tag is None:
        tag = api("/git/refs", method="POST", payload={"ref": "refs/tags/" + TAG, "sha": HEAD})
    require(tag["object"]["type"] == "commit" and tag["object"]["sha"] == HEAD, "Existing tag is not the authorised exact commit")
    releases = api("/releases?per_page=100")
    require(len(releases) < 100, "Release listing needs explicit pagination")
    matching = [r for r in releases if r["tag_name"] == TAG]
    require(len(matching) <= 1, "Ambiguous release identity")
    if matching:
        release = matching[0]
        require(release["prerelease"] and release["body"] == NOTES, "Existing release differs; no overwrite is authorised")
    else:
        release = api("/releases", method="POST", payload={"tag_name": TAG, "target_commitish": HEAD, "name": "CodeProbe 2.2.0-rc.1 — audited research candidate", "body": NOTES, "draft": True, "prerelease": True, "make_latest": "false", "generate_release_notes": False})
    release_id = release["id"]
    save(work / "release-before-publication.json", release)
    remote_assets = api(f"/releases/{release_id}/assets?per_page=100")
    require(set(a["name"] for a in remote_assets) <= set(expected), "Unexpected assets in existing release")
    for name, record in expected.items():
        matches = [a for a in remote_assets if a["name"] == name]
        require(len(matches) <= 1, "Duplicate release asset")
        if matches:
            asset = matches[0]
        else:
            require(release["draft"], "Do not alter an already published asset set")
            upload = release["upload_url"].split("{", 1)[0] + "?name=" + urllib.parse.quote(name, safe="")
            asset = request(upload, method="POST", binary=(assets / name).read_bytes(), content_type=mimetypes.guess_type(name)[0] or "application/octet-stream")
        require(asset["state"] == "uploaded" and asset["size"] == record["size_bytes"], "Uploaded asset has wrong state or size")
        if asset.get("digest"):
            require(asset["digest"] == "sha256:" + record["sha256"], "Uploaded asset digest mismatch")
        received = api(f'/releases/assets/{asset["id"]}', accept="application/octet-stream")
        require(digest(received) == record["sha256"], "Downloaded asset does not match local bytes")
    tag = api("/git/ref/tags/" + TAG)
    require(tag["object"]["sha"] == HEAD, "Tag changed before publication")
    require(api("/git/ref/heads/audit/codeprobe-hostile-remediation")["object"]["sha"] == HEAD, "Audit head moved before publication")
    if release["draft"]:
        release = api(f"/releases/{release_id}", method="PATCH", payload={"draft": False, "prerelease": True, "make_latest": "false"})
    release = api(f"/releases/{release_id}")
    require(not release["draft"] and release["prerelease"] and release["tag_name"] == TAG and bool(release["published_at"]), "Release publication was not confirmed")
    require(len(release["assets"]) == 5, "Published release has wrong asset count")
    downloads = []
    for asset in release["assets"]:
        record = expected[asset["name"]]
        received = api(f'/releases/assets/{asset["id"]}', accept="application/octet-stream")
        require(digest(received) == record["sha256"], "Published asset readback mismatch")
        downloads.append({"name": asset["name"], "id": asset["id"], "browser_download_url": asset["browser_download_url"], **record})
    receipt = {"status": "PUBLISHED_PRERELEASE_ASSETS_DOWNLOADED_AND_VERIFIED", "release_id": release_id, "release_url": release["html_url"], "published_at": release["published_at"], "tag": TAG, "source_commit": HEAD, "source_tree": TREE, "assets": downloads, "main_or_audit_ref_updated": False, "licence_changed": False, "governance_applied": False}
    save(work / "release-final.json", release)
    save(work / "publication-receipt.json", receipt)
    source_check()
    print("PUBLICATION_RECEIPT", json.dumps(receipt, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("preflight", "prepare", "publish"))
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    {"preflight": preflight, "prepare": prepare, "publish": publish}[args.operation](args.work)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"PUBLICATION_FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
