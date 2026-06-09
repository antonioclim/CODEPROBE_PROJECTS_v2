"""Small Python API wrappers around the browser-compatible JSON entry points."""

from __future__ import annotations

import json
from typing import Any, Dict

import codeprobe_runtime as engine


def analyse_file(payload: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(engine.codeprobe_analyze(json.dumps(payload)))


def analyse_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(engine.codeprobe_analyze_project(json.dumps(payload)))
