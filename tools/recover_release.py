#!/usr/bin/env python3
"""Recover a CodeProbe release packet after an abrupt publication interruption."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codeprobe_engine.release_recovery import (  # noqa: E402
    ReleaseRecoveryError,
    recover_pending_transaction,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory containing the release ZIP and sidecars.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = recover_pending_transaction(args.output_dir)
    except (OSError, ReleaseRecoveryError) as exc:
        print(f"[FAIL] release-recovery: {exc}", file=sys.stderr)
        return 1
    print(f"[PASS] release-recovery: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
