"""Path helpers shared by local release and CLI utilities."""

from __future__ import annotations

from pathlib import Path


def relative_posix(path: Path, root: Path) -> str:
    """Return a stable POSIX path relative to ``root``."""
    return path.resolve().relative_to(root.resolve()).as_posix()
