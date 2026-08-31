#!/usr/bin/env python3
"""Compare two CodeProbe release ZIPs at package and member level."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site
):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for _path in (SRC, TOOLS):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

from codeprobe_engine.release import zip_summary  # noqa: E402


def _normalise_member_path(path: str) -> str:
    parts = path.split("/")
    return "/".join(parts[1:]) if len(parts) > 1 else path


def compare_zip_packages(old_zip: Path, new_zip: Path) -> dict:
    old_summary = zip_summary(old_zip)
    new_summary = zip_summary(new_zip)
    old_members = {_normalise_member_path(item["path"]): item for item in old_summary["members"]}
    new_members = {_normalise_member_path(item["path"]): item for item in new_summary["members"]}
    added = sorted(set(new_members) - set(old_members))
    removed = sorted(set(old_members) - set(new_members))
    changed = []
    for key in sorted(set(old_members) & set(new_members)):
        old_item = old_members[key]
        new_item = new_members[key]
        if old_item["crc32"] != new_item["crc32"] or old_item["size_bytes"] != new_item["size_bytes"]:
            changed.append({
                "path": key,
                "old_size_bytes": old_item["size_bytes"],
                "new_size_bytes": new_item["size_bytes"],
                "delta_size_bytes": new_item["size_bytes"] - old_item["size_bytes"],
                "old_compressed_size_bytes": old_item["compressed_size_bytes"],
                "new_compressed_size_bytes": new_item["compressed_size_bytes"],
                "delta_compressed_size_bytes": new_item["compressed_size_bytes"] - old_item["compressed_size_bytes"],
            })
    return {
        "schema_version": "codeprobe-release-comparison/v1",
        "old_zip": old_summary,
        "new_zip": new_summary,
        "deltas": {
            "zip_size_bytes": new_summary["zip_size_bytes"] - old_summary["zip_size_bytes"],
            "file_count": new_summary["file_count"] - old_summary["file_count"],
            "total_uncompressed_member_bytes": new_summary["total_uncompressed_member_bytes"] - old_summary["total_uncompressed_member_bytes"],
            "total_compressed_member_bytes": new_summary["total_compressed_member_bytes"] - old_summary["total_compressed_member_bytes"],
        },
        "added_paths": added,
        "removed_paths": removed,
        "changed_paths": changed,
    }


def render_markdown(comparison: dict) -> str:
    deltas = comparison["deltas"]
    lines = [
        "# CodeProbe release ZIP comparison",
        "",
        "This report compares package-level size, member-level size and file membership. It is intended for release audit when two downloaded ZIP files appear to differ unexpectedly.",
        "",
        "## Package summary",
        "",
        "| Field | Delta |",
        "|---|---:|",
        f"| ZIP size | {deltas['zip_size_bytes']:+d} bytes |",
        f"| File count | {deltas['file_count']:+d} |",
        f"| Uncompressed member bytes | {deltas['total_uncompressed_member_bytes']:+d} bytes |",
        f"| Compressed member bytes | {deltas['total_compressed_member_bytes']:+d} bytes |",
        "",
        "## Added paths",
        "",
    ]
    lines.extend([f"- `{path}`" for path in comparison["added_paths"]] or ["None."])
    lines.extend(["", "## Removed paths", ""])
    lines.extend([f"- `{path}`" for path in comparison["removed_paths"]] or ["None."])
    lines.extend(["", "## Changed paths with largest uncompressed deltas", ""])
    changed = sorted(comparison["changed_paths"], key=lambda item: abs(item["delta_size_bytes"]), reverse=True)[:20]
    if changed:
        lines.extend(["| Path | Delta bytes | Delta compressed bytes |", "|---|---:|---:|"])
        for item in changed:
            lines.append(f"| `{item['path']}` | {item['delta_size_bytes']:+d} | {item['delta_compressed_size_bytes']:+d} |")
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two CodeProbe release ZIPs.")
    parser.add_argument("old_zip")
    parser.add_argument("new_zip")
    parser.add_argument("--json-out")
    parser.add_argument("--md-out")
    args = parser.parse_args(argv)

    comparison = compare_zip_packages(Path(args.old_zip), Path(args.new_zip))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(comparison, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.md_out:
        Path(args.md_out).write_text(render_markdown(comparison), encoding="utf-8")
    if not args.json_out and not args.md_out:
        print(render_markdown(comparison))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
