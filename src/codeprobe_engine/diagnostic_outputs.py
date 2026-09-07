"""Read-only admission of diagnostic destinations before tool work begins.

Keep this boundary independent of release packaging so coverage preflight does
not import the measured release module before its existing monitor starts.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Sequence


class DiagnosticOutputError(ValueError):
    """Raised when a diagnostic destination cannot be safely admitted."""


def _safe_text(value: object) -> str:
    text = os.fspath(value) if isinstance(value, (Path, os.PathLike)) else str(value)
    return ascii(text)[1:-1]


def validate_diagnostic_outputs(
    outputs: Sequence[Path], *, inputs: Iterable[Path]
) -> tuple[Path, ...]:
    """Admit distinct report files without creating directories or files.

    Both resolved names and existing file identities are protected. Callers
    supply their complete consumed input set and recheck before publication;
    this admission check is not a transaction against concurrent path changes.
    """
    try:
        protected_names: set[Path] = set()
        protected_files: set[tuple[int, int]] = set()
        for source in inputs:
            source = Path(source)
            protected_names.add(source.resolve())
            try:
                metadata = source.stat()
            except FileNotFoundError:
                continue
            protected_files.add((metadata.st_dev, metadata.st_ino))

        admitted: list[Path] = []
        output_files: set[tuple[int, int]] = set()
        for output in outputs:
            output = Path(output)
            str(output).encode("utf-8")
            try:
                metadata = output.lstat()
            except FileNotFoundError:
                metadata = None
            if metadata is not None and not stat.S_ISREG(metadata.st_mode):
                raise DiagnosticOutputError(f"diagnostic output is not a regular file: {_safe_text(output)}")
            resolved = output.resolve()
            if resolved in protected_names:
                raise DiagnosticOutputError(f"diagnostic output aliases an input: {_safe_text(output)}")
            if any(resolved == other or resolved in other.parents or other in resolved.parents
                   for other in admitted):
                raise DiagnosticOutputError(f"diagnostic outputs overlap: {_safe_text(output)}")
            if metadata is not None:
                identity = (metadata.st_dev, metadata.st_ino)
                if identity in protected_files or identity in output_files:
                    raise DiagnosticOutputError(f"diagnostic output aliases an input or another output: {_safe_text(output)}")
                output_files.add(identity)
            for parent in resolved.parents:
                try:
                    parent_metadata = parent.stat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISDIR(parent_metadata.st_mode):
                    raise DiagnosticOutputError(f"diagnostic output ancestor is not a directory: {_safe_text(parent)}")
            admitted.append(resolved)
        return tuple(admitted)
    except DiagnosticOutputError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise DiagnosticOutputError(f"cannot admit diagnostic output paths: {_safe_text(exc)}") from exc
