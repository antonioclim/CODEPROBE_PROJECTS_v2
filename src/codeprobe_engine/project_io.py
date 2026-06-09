"""Shared project-input helpers for CodeProbe command-line tools."""

from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import codeprobe_runtime as engine

WarningSink = Optional[Callable[[str], None]]


def stderr_warning(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def read_folder_files(
    root: Path,
    *,
    include_binary_placeholders: bool = True,
    warning_sink: WarningSink = None,
) -> List[Dict[str, Any]]:
    """Return CodeProbe project-file payload records for a folder.

    Binary or unreadable files can be kept as empty placeholders so the project
    report records their exclusion explicitly instead of hiding them from the
    inventory. Calibration utilities may disable placeholders when they want a
    smaller source-only payload.
    """
    root = root.resolve()
    files: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        try:
            data = path.read_bytes()
        except OSError as exc:
            if warning_sink:
                warning_sink(f"could not read {path}: {exc}")
            if include_binary_placeholders:
                files.append({"path": relative, "content": "", "size_bytes": 0})
            continue
        text, warning = engine.decode_text_bytes(data)
        if text is None:
            if warning_sink:
                warning_sink(f"{relative}: {warning}")
            if include_binary_placeholders:
                files.append({"path": relative, "content": "", "size_bytes": len(data)})
            continue
        if warning and warning_sink:
            warning_sink(f"{relative}: {warning}")
        files.append({"path": relative, "content": text, "size_bytes": len(data)})
    return files


def project_payload_from_path(path: Path, *, include_binary_placeholders: bool = True) -> Dict[str, Any]:
    """Build an engine project payload from a folder or ZIP archive."""
    path = path.resolve()
    if path.is_dir():
        return {
            "project_name": path.name,
            "files": read_folder_files(path, include_binary_placeholders=include_binary_placeholders),
        }
    if path.suffix.lower() == ".zip":
        return {
            "project_name": path.stem,
            "zip_base64": base64.b64encode(path.read_bytes()).decode("ascii"),
        }
    raise ValueError(f"project sample must be a directory or ZIP archive: {path}")
