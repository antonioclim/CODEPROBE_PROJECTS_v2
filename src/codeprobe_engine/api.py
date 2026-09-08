"""Small Python API wrappers around the browser-compatible JSON entry points."""

from __future__ import annotations

import json
from typing import Any, Dict

import codeprobe_runtime as engine


def analyse_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return the JSON entry point's report/text envelope.

    Unbound Python syntax errors remain warning-bearing diagnostics. A bound
    profile or ``require_python_ast`` rejects an unsuccessful AST parse with
    ``ValueError``; this wrapper does not convert that refusal into a report.
    """
    return json.loads(engine.codeprobe_analyze(json.dumps(payload)))


def analyse_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return the project report/text envelope with member diagnostics.

    When required by the request or bound profile, strict Python parsing
    applies to every included Python member. A refusal propagates before a
    complete envelope is returned.
    """
    return json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
