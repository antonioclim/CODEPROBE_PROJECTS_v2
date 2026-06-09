"""Path helpers shared by local release and CLI utilities."""

from __future__ import annotations

from pathlib import Path


def project_root_from_file(file: str | Path) -> Path:
    """Return the repository root when called from a file under ``src``."""
    path = Path(file).resolve()
    if path.name == "__init__.py":
        return path.parents[2]
    if path.parent.name == "codeprobe_engine":
        return path.parents[2]
    if path.parent.name == "src":
        return path.parents[1]
    return path.parent


def relative_posix(path: Path, root: Path) -> str:
    """Return a stable POSIX path relative to ``root``."""
    return path.resolve().relative_to(root.resolve()).as_posix()
