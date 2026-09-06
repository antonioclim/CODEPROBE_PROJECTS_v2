#!/usr/bin/env python3
"""Private subprocess driver for abrupt release-publication fault injection."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "tools"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import build_release  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("publish", "recover"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--fault", required=True)
    args = parser.parse_args()

    def fault(point: str) -> None:
        if point == args.fault:
            os._exit(97)

    if args.action == "publish":
        build_release.publish_release(
            args.root,
            args.out,
            app_version=args.version,
            _fault_hook=fault,
        )
    else:
        build_release.recover_release(
            args.root,
            args.out,
            app_version=args.version,
            _fault_hook=fault,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
