#!/usr/bin/env python3
"""Validate the explicit support lifecycle for the pinned browser runtime."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "app" / "pyodide-support-policy.json"
POLICY_SCHEMA = "codeprobe-pyodide-support-policy/v1"
PROVENANCE_SCHEMA = "codeprobe-pyodide-provenance/v1"


class LifecycleError(RuntimeError):
    """Raised when the pinned runtime's lifecycle policy is invalid or stale."""


def _date(value: object, label: str) -> dt.date:
    if not isinstance(value, str):
        raise LifecycleError(f"{label} must be an ISO calendar date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise LifecycleError(f"{label} must be an ISO calendar date") from exc


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LifecycleError(f"{label} must be a positive integer")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise LifecycleError(f"{path} must contain a JSON object")
    return payload


def validate_policy(
    policy: dict[str, Any],
    *,
    today: dt.date,
    provenance: dict[str, Any] | None = None,
    require_release_approval: bool = False,
) -> dict[str, Any]:
    if policy.get("schema") != POLICY_SCHEMA:
        raise LifecycleError("unsupported Pyodide lifecycle-policy schema")
    pinned = policy.get("pinned_version")
    if not isinstance(pinned, str) or not pinned:
        raise LifecycleError("pinned_version must be a non-empty string")
    reviewed_at = _date(policy.get("reviewed_at"), "reviewed_at")
    next_review = _date(policy.get("next_review_by"), "next_review_by")
    supported_until = _date(policy.get("supported_until"), "supported_until")
    interval = _positive_integer(
        policy.get("maximum_review_interval_days"),
        "maximum_review_interval_days",
    )
    if next_review < reviewed_at:
        raise LifecycleError("next_review_by precedes reviewed_at")
    if (next_review - reviewed_at).days > interval:
        raise LifecycleError("the declared review interval exceeds its policy ceiling")
    if supported_until < next_review:
        raise LifecycleError("supported_until precedes next_review_by")
    if today > next_review:
        raise LifecycleError(
            f"Pyodide lifecycle review expired on {next_review.isoformat()}"
        )
    assurance = policy.get("assurance_boundary")
    if not isinstance(assurance, dict):
        raise LifecycleError("assurance_boundary must be an object")
    required_boolean_limits = {
        "core_startup_set_only": True,
        "optional_packages_supported": False,
        "future_cdn_bytes_covered": False,
        "current_advisory_absence_claimed": False,
    }
    for key, expected in required_boolean_limits.items():
        if assurance.get(key) is not expected:
            raise LifecycleError(
                f"assurance_boundary.{key} must be {str(expected).lower()}"
            )
    observed = policy.get("observed_upstream")
    if not isinstance(observed, dict):
        raise LifecycleError("observed_upstream must be an object")
    _date(observed.get("published_at"), "observed_upstream.published_at")
    observed_at = _date(observed.get("observed_at"), "observed_upstream.observed_at")
    if observed_at < reviewed_at:
        raise LifecycleError("upstream observation predates the lifecycle review")
    if observed.get("source") != "official-github-release":
        raise LifecycleError("upstream observation must identify its official source")
    if provenance is not None:
        if provenance.get("schema") != PROVENANCE_SCHEMA:
            raise LifecycleError("unsupported Pyodide provenance schema")
        if provenance.get("version") != pinned:
            raise LifecycleError(
                "lifecycle pinned_version does not match Pyodide provenance"
            )
    if require_release_approval:
        if policy.get("upgrade_required_before_public_release") is not False:
            raise LifecycleError(
                "the pinned Pyodide runtime is not approved for a public release"
            )
        if policy.get("public_release_status") != "approved":
            raise LifecycleError(
                "public_release_status must be approved for a public release"
            )
        if today > supported_until:
            raise LifecycleError(
                f"Pyodide release support expired on {supported_until.isoformat()}"
            )
    return {
        "pinned_version": pinned,
        "reviewed_at": reviewed_at.isoformat(),
        "next_review_by": next_review.isoformat(),
        "supported_until": supported_until.isoformat(),
        "public_release_status": policy.get("public_release_status"),
        "upgrade_required_before_public_release": policy.get(
            "upgrade_required_before_public_release"
        ),
    }


def check_policy(
    policy_path: Path = DEFAULT_POLICY,
    *,
    today: dt.date | None = None,
    require_release_approval: bool = False,
) -> dict[str, Any]:
    policy = load_json(policy_path)
    provenance_path = policy_path.with_name("pyodide-provenance.json")
    provenance = load_json(provenance_path) if provenance_path.exists() else None
    return validate_policy(
        policy,
        today=today or dt.date.today(),
        provenance=provenance,
        require_release_approval=require_release_approval,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument(
        "--today",
        type=dt.date.fromisoformat,
        help="Override today's date for deterministic tests.",
    )
    parser.add_argument(
        "--require-release-approval",
        action="store_true",
        help="Also require the pinned runtime to be approved for public release.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = check_policy(
            args.policy,
            today=args.today,
            require_release_approval=args.require_release_approval,
        )
    except LifecycleError as exc:
        print(f"[FAIL] pyodide-lifecycle: {exc}", file=sys.stderr)
        return 1
    print(
        "[PASS] pyodide-lifecycle: "
        f"{result['pinned_version']} reviewed {result['reviewed_at']}; "
        f"next review {result['next_review_by']}; "
        f"release status {result['public_release_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
