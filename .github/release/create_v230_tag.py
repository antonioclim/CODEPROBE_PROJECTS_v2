#!/usr/bin/env python3
"""Create one exact lightweight release tag and qualify its exact ref with CI.

This publication-orchestration script intentionally creates no GitHub Release
and uploads no release asset. It is designed for one reviewed branch commit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

REPO = "antonioclim/CODEPROBE_PROJECTS_v2"
API = "https://api.github.com/repos/" + REPO
SOURCE = "0a1262a0e42b89fdac0e2cdb462a612fb7bab71a"
TREE = "a2316806ed6a76a89c41352e6f0d93bb90eb3757"
TAG = "v2.3.0"
TAG_REF = "refs/tags/" + TAG
MAIN_CI_RUN = 35215583781
EXPECTED_JOB_COUNT = 12
CI_WORKFLOW = "ci.yml"
CI_WORKFLOW_BLOB = "4a80fcc322be2aa81e54408eced199820d1d8fec"
ORCHESTRATION_BRANCH = "release/tag-v2.3.0-20260917"
ORCHESTRATION_PATHS = {
    ".github/workflows/create-v2.3.0-tag.yml",
    ".github/release/create_v230_tag.py",
}
EXPECTED_BRANCHES = {
    "ce20-v2.3.0-release-metadata-clean-2026-09-17":
        "eb872d86bc0b7d0e1c0ea9ce6d86ddcb7013231c",
    "ce20-v2.3.0-release-metadata-2026-09-17":
        "6f0d895bc56977bb82772fb7724f394169f818bf",
    "ce19-source-only-2026-09-16":
        "8f5f4603e182c21fbc6fb07f0b059b1819000fb5",
}
EXPECTED_JOB_NAMES = {
    "Release reproducibility",
    "Browser accessibility (Chromium)",
    "Browser functional integrity (Chromium)",
    "Supported-code coverage",
    "Validation (ubuntu-24.04, Python 3.10.21)",
    "Validation (ubuntu-24.04, Python 3.11.16)",
    "Validation (ubuntu-24.04, Python 3.12.14)",
    "Validation (ubuntu-24.04, Python 3.13.15)",
    "Validation (ubuntu-24.04, Python 3.14.7)",
    "Validation (windows-2025, Python 3.14.7)",
    "Validation (macos-15, Python 3.14.7)",
    "Required CI",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value))


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https", "Non-HTTPS redirect refused")
        new_request = super().redirect_request(
            req, fp, code, msg, headers, newurl
        )
        if (
            new_request is not None
            and urllib.parse.urlsplit(req.full_url).netloc != parsed.netloc
        ):
            new_request.remove_header("Authorization")
        return new_request


def request(
    endpoint: str,
    *,
    method: str = "GET",
    payload: object | None = None,
    allow404: bool = False,
) -> tuple[int, bytes]:
    url = endpoint if endpoint.startswith("https://") else API + endpoint
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https", "Only HTTPS is permitted")
    require(
        parsed.hostname in {"api.github.com", "github.com"},
        f"Unapproved request host: {parsed.hostname}",
    )

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "CodeProbe-v2.3.0-tag-orchestrator",
    }
    raw = None
    if payload is not None:
        raw = canonical_json(payload)
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url,
        data=raw,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.build_opener(SafeRedirect()).open(
            req, timeout=60
        ) as response:
            data = response.read(32_000_001)
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        if allow404 and exc.code == 404:
            return 404, b""
        detail = exc.read(16_384).decode("utf-8", "replace")
        raise RuntimeError(
            f"GitHub {method} returned HTTP {exc.code} for "
            f"{parsed.path}: {detail[:2000]}"
        ) from None

    require(len(data) <= 32_000_000, "Response exceeds collection limit")
    return status, data


def api(
    endpoint: str,
    *,
    method: str = "GET",
    payload: object | None = None,
    allow404: bool = False,
):
    status, data = request(
        endpoint,
        method=method,
        payload=payload,
        allow404=allow404,
    )
    if status == 404:
        return None
    if not data:
        return None
    return json.loads(data)


def ref(kind: str, name: str):
    return api(
        "/git/ref/"
        + kind
        + "/"
        + urllib.parse.quote(name, safe="")
    )


def require_successful_ci(run_id: int) -> tuple[dict, dict]:
    run = api(f"/actions/runs/{run_id}")
    require(
        run["status"] == "completed"
        and run["conclusion"] == "success",
        f"CI run {run_id} is not completed/success",
    )
    require(
        run["head_sha"] == SOURCE,
        f"CI run {run_id} does not qualify exact source",
    )
    jobs = api(f"/actions/runs/{run_id}/jobs?per_page=100")
    require(
        jobs["total_count"] == len(jobs["jobs"]) == EXPECTED_JOB_COUNT,
        f"CI run {run_id} does not expose exactly 12 jobs",
    )
    names = {job["name"] for job in jobs["jobs"]}
    require(
        names == EXPECTED_JOB_NAMES,
        f"CI job-name set differs: {sorted(names ^ EXPECTED_JOB_NAMES)}",
    )
    require(
        all(
            job["status"] == "completed"
            and job["conclusion"] == "success"
            for job in jobs["jobs"]
        ),
        f"CI run {run_id} has a non-success job",
    )
    required = [
        job for job in jobs["jobs"] if job["name"] == "Required CI"
    ]
    require(
        len(required) == 1 and required[0]["conclusion"] == "success",
        f"CI run {run_id} lacks successful Required CI",
    )
    return run, jobs


def execute(work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    evidence = work / "evidence"
    evidence.mkdir(exist_ok=True)

    require(os.environ.get("GITHUB_REPOSITORY") == REPO, "Wrong repository")
    require(os.environ.get("GITHUB_EVENT_NAME") == "push", "Wrong event")
    require(
        os.environ.get("GITHUB_REF")
        == "refs/heads/" + ORCHESTRATION_BRANCH,
        "Wrong orchestration branch",
    )
    orchestration_sha = os.environ["GITHUB_SHA"]

    repository = api("")
    write_json(evidence / "repository-before.json", repository)
    require(repository["private"] is False, "Repository is not public")
    require(repository["default_branch"] == "main", "Default branch changed")

    main_ref = ref("heads", "main")
    write_json(evidence / "main-ref-before.json", main_ref)
    require(
        main_ref["object"]["type"] == "commit"
        and main_ref["object"]["sha"] == SOURCE,
        "main identity drift",
    )

    source_commit = api("/git/commits/" + SOURCE)
    write_json(evidence / "source-commit.json", source_commit)
    require(source_commit["tree"]["sha"] == TREE, "Source tree drift")
    require(
        source_commit["verification"]["verified"] is True
        and source_commit["verification"]["reason"] == "valid",
        "Source merge commit is not GitHub-verified",
    )

    pull = api("/pulls/8")
    write_json(evidence / "pull-request-8.json", pull)
    require(
        pull["merged"] is True
        and pull["merge_commit_sha"] == SOURCE,
        "PR #8 merge identity drift",
    )

    pre_ci, pre_jobs = require_successful_ci(MAIN_CI_RUN)
    require(pre_ci["event"] == "push", "Pre-tag CI event differs")
    write_json(evidence / "pre-tag-main-ci-run.json", pre_ci)
    write_json(evidence / "pre-tag-main-ci-jobs.json", pre_jobs)

    workflow = api(
        "/contents/.github/workflows/ci.yml?ref=" + SOURCE
    )
    write_json(evidence / "ci-workflow-content-record.json", workflow)
    require(
        workflow["sha"] == CI_WORKFLOW_BLOB,
        "CI workflow identity drift",
    )

    retained_branches = {}
    for name, expected_sha in EXPECTED_BRANCHES.items():
        branch_ref = ref("heads", name)
        require(
            branch_ref["object"]["type"] == "commit"
            and branch_ref["object"]["sha"] == expected_sha,
            f"Retained branch drift: {name}",
        )
        retained_branches[name] = branch_ref
    write_json(evidence / "retained-branches-before.json", retained_branches)

    tag_before = api("/git/ref/tags/" + TAG, allow404=True)
    release_before = api("/releases/tags/" + TAG, allow404=True)
    require(tag_before is None, "v2.3.0 tag already exists")
    require(release_before is None, "v2.3.0 release already exists")

    orchestration_commit = api("/git/commits/" + orchestration_sha)
    write_json(
        evidence / "orchestration-commit.json", orchestration_commit
    )
    require(
        len(orchestration_commit["parents"]) == 1
        and orchestration_commit["parents"][0]["sha"] == SOURCE,
        "Orchestration commit is not a single child of exact main",
    )

    branch_ref = ref("heads", ORCHESTRATION_BRANCH)
    require(
        branch_ref["object"]["sha"] == orchestration_sha,
        "Orchestration branch ref drift",
    )
    write_json(evidence / "orchestration-branch.json", branch_ref)

    comparison = api(f"/compare/{SOURCE}...{orchestration_sha}")
    write_json(evidence / "orchestration-compare.json", comparison)
    changed = {item["filename"] for item in comparison["files"]}
    require(
        comparison["ahead_by"] == 1
        and comparison["behind_by"] == 0
        and comparison["total_commits"] == 1,
        "Orchestration branch is not exactly one commit ahead",
    )
    require(
        changed == ORCHESTRATION_PATHS,
        f"Unexpected orchestration paths: {sorted(changed)}",
    )
    require(
        all(item["status"] == "added" for item in comparison["files"]),
        "Orchestration paths are not both newly added",
    )

    prior_runs = api(
        f"/actions/workflows/{CI_WORKFLOW}/runs"
        "?event=workflow_dispatch&per_page=100"
    )
    prior_ids = {
        int(item["id"]) for item in prior_runs.get("workflow_runs", [])
    }
    write_json(evidence / "workflow-dispatch-runs-before.json", prior_runs)

    created_tag = api(
        "/git/refs",
        method="POST",
        payload={"ref": TAG_REF, "sha": SOURCE},
    )
    write_json(evidence / "tag-create-response.json", created_tag)
    require(
        created_tag["ref"] == TAG_REF
        and created_tag["object"]["type"] == "commit"
        and created_tag["object"]["sha"] == SOURCE,
        "Tag create response differs from contract",
    )

    tag_after_create = ref("tags", TAG)
    write_json(evidence / "tag-readback-after-create.json", tag_after_create)
    require(
        tag_after_create["object"]["type"] == "commit"
        and tag_after_create["object"]["sha"] == SOURCE,
        "Created tag is not the exact lightweight ref",
    )

    dispatched_at = datetime.now(timezone.utc)
    request(
        f"/actions/workflows/{CI_WORKFLOW}/dispatches",
        method="POST",
        payload={"ref": TAG},
    )
    write_json(
        evidence / "dispatch-receipt.json",
        {
            "workflow": CI_WORKFLOW,
            "ref": TAG,
            "requested_at_utc": dispatched_at.isoformat(),
            "status": "ACCEPTED_204",
        },
    )

    run = None
    discovery_deadline = time.monotonic() + 300
    while time.monotonic() < discovery_deadline:
        listing = api(
            f"/actions/workflows/{CI_WORKFLOW}/runs"
            "?event=workflow_dispatch&per_page=100"
        )
        candidates = [
            item
            for item in listing.get("workflow_runs", [])
            if int(item["id"]) not in prior_ids
            and item["event"] == "workflow_dispatch"
            and item["head_sha"] == SOURCE
        ]
        if candidates:
            run = max(candidates, key=lambda item: int(item["id"]))
            break
        time.sleep(5)

    require(run is not None, "Dispatched tag-ref CI run was not discovered")
    run_id = int(run["id"])
    write_json(evidence / "tag-ref-ci-run-discovered.json", run)

    completion_deadline = time.monotonic() + 1_800
    while time.monotonic() < completion_deadline:
        run = api(f"/actions/runs/{run_id}")
        write_json(evidence / "tag-ref-ci-run-latest.json", run)
        if run["status"] == "completed":
            break
        time.sleep(10)

    require(
        run["status"] == "completed",
        "Tag-ref CI did not complete within 30 minutes",
    )
    require(
        run["conclusion"] == "success",
        f"Tag-ref CI conclusion is {run['conclusion']!r}",
    )
    require(
        run["event"] == "workflow_dispatch"
        and run["head_sha"] == SOURCE,
        "Tag-ref CI identity differs",
    )

    tag_ci_run, tag_ci_jobs = require_successful_ci(run_id)
    write_json(evidence / "tag-ref-ci-run-final.json", tag_ci_run)
    write_json(evidence / "tag-ref-ci-jobs-final.json", tag_ci_jobs)

    artifacts = api(f"/actions/runs/{run_id}/artifacts?per_page=100")
    write_json(evidence / "tag-ref-ci-artifacts.json", artifacts)
    require(
        artifacts["total_count"] == 0,
        "Canonical CI unexpectedly published workflow artifacts",
    )

    tag_final = ref("tags", TAG)
    main_final = ref("heads", "main")
    release_final = api("/releases/tags/" + TAG, allow404=True)
    retained_final = {
        name: ref("heads", name) for name in EXPECTED_BRANCHES
    }
    write_json(evidence / "tag-final.json", tag_final)
    write_json(evidence / "main-final.json", main_final)
    write_json(evidence / "retained-branches-final.json", retained_final)

    require(
        tag_final["object"]["type"] == "commit"
        and tag_final["object"]["sha"] == SOURCE,
        "Final tag identity drift",
    )
    require(
        main_final["object"]["sha"] == SOURCE,
        "main changed during tag qualification",
    )
    require(release_final is None, "A GitHub Release was created unexpectedly")
    for name, expected_sha in EXPECTED_BRANCHES.items():
        require(
            retained_final[name]["object"]["sha"] == expected_sha,
            f"Retained branch changed during tag qualification: {name}",
        )

    result = {
        "schema": "codeprobe-ce20-rel05-r01a-result/v1",
        "status": "PASS_EXACT_LIGHTWEIGHT_TAG_AND_TAG_REF_CI",
        "repository": REPO,
        "tag": {
            "name": TAG,
            "ref": TAG_REF,
            "object_type": "commit",
            "target_commit": SOURCE,
            "target_tree": TREE,
            "annotated_tag_object_created": False,
        },
        "qualification": {
            "method": "workflow_dispatch targeted at the exact v2.3.0 tag",
            "reason": (
                "A tag created with GITHUB_TOKEN does not recursively trigger "
                "push workflows; workflow_dispatch is the documented exception."
            ),
            "run_id": run_id,
            "run_number": tag_ci_run["run_number"],
            "event": tag_ci_run["event"],
            "head_branch": tag_ci_run["head_branch"],
            "head_sha": tag_ci_run["head_sha"],
            "check_suite_id": tag_ci_run["check_suite_id"],
            "conclusion": tag_ci_run["conclusion"],
            "jobs_success": EXPECTED_JOB_COUNT,
            "jobs_total": EXPECTED_JOB_COUNT,
            "required_ci": "success",
            "artifacts_total": artifacts["total_count"],
        },
        "negative_controls": {
            "github_release_created": False,
            "release_assets_uploaded": 0,
            "main_changed": False,
            "retained_branches_changed": False,
            "tag_deleted_or_moved": False,
            "manual_rerun": False,
        },
        "orchestration": {
            "branch": ORCHESTRATION_BRANCH,
            "commit": orchestration_sha,
            "changed_paths": sorted(ORCHESTRATION_PATHS),
        },
    }
    write_json(work / "CE20_REL05_R01A_RESULT.json", result)
    return result


def main() -> None:
    work = Path(os.environ["RELEASE_WORK"]).resolve()
    try:
        result = execute(work)
    except Exception as exc:
        failure = {
            "schema": "codeprobe-ce20-rel05-r01a-failure/v1",
            "status": "STOPPED_FAIL_CLOSED",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "compensating_write_attempted": False,
            "tag_deletion_attempted": False,
            "retry_attempted": False,
        }
        work.mkdir(parents=True, exist_ok=True)
        write_json(work / "CE20_REL05_R01A_FAILURE.json", failure)
        print(json.dumps(failure, indent=2), flush=True)
        raise
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
