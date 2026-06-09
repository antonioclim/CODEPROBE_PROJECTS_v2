"""Metric inventory helpers for release validation and documentation."""

from __future__ import annotations

from typing import Any, Dict, List

import codeprobe_runtime as engine


def metric_inventory() -> List[Dict[str, Any]]:
    """Return a compact inventory of configured metrics and their roles."""
    class_names = {metric.name: metric.__name__ for metric in engine.MetricRegistry.metric_classes()}
    inventory: List[Dict[str, Any]] = []
    for name, config in sorted(engine.METRIC_CONFIG.items()):
        inventory.append({
            "name": name,
            "class_name": class_names.get(name, ""),
            "group": config.get("group", "stylometry"),
            "enabled": bool(config.get("enabled", True)),
            "weight": float(config.get("weight", 0.0) or 0.0),
            "contributes_to_overall": bool(config.get("contributes_to_overall", True)),
        })
    return inventory
