#!/usr/bin/env python3
"""Create a read-only, explicitly non-equivalent envelope for a CodeProbe v2 report."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path


def load_contract(root: Path):
    path = root / "src/codeprobe_review_contract.py"
    spec = importlib.util.spec_from_file_location("codeprobe_review_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load report-contract module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def distinct_paths(source: Path, destination: Path) -> None:
    if source.resolve(strict=True) == destination.resolve(strict=False):
        raise ValueError("output path must not replace the source report")
    if destination.exists() and os.path.samefile(source, destination):
        raise ValueError("output path aliases the source report")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--policy-profile", type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root)
    source = args.source.resolve(strict=True)
    output = args.output.resolve(strict=False)
    distinct_paths(source, output)
    report = contract.read_strict_json(source, label="legacy report")
    profile = (
        contract.read_strict_json(args.policy_profile.resolve(strict=True), label="legacy policy profile")
        if args.policy_profile is not None
        else None
    )
    envelope = contract.migrate_legacy_report(report, policy_profile=profile)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(contract.canonical_json(envelope) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(output)
    print(f"Wrote non-equivalent legacy envelope: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
