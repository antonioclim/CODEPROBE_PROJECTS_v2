#!/usr/bin/env python3
"""Compatibility wrapper for the release checker."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import check_release


if __name__ == "__main__":
    raise SystemExit(check_release.main())
