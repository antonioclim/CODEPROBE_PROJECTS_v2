#!/usr/bin/env python3
"""Validate and build a deterministic source ZIP for a CodeProbe release."""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import codeprobe_runtime as engine  # noqa: E402
import check_release  # noqa: E402
from codeprobe_engine.release import MANIFEST_NAME, iter_release_files, sha256_file, write_zip_summary  # noqa: E402

# ZIP headers are normalised so that two builds from the same source tree are
# byte-for-byte comparable. The chosen date is arbitrary but valid for the ZIP
# format and avoids leaking local filesystem timestamps into institutional
# release artefacts.
DETERMINISTIC_ZIP_DATETIME = (2020, 1, 1, 0, 0, 0)


def _write_deterministic_file(archive: zipfile.ZipFile, source: Path, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname, date_time=DETERMINISTIC_ZIP_DATETIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    # Conservative regular-file permissions: readable by all, writable by owner.
    info.external_attr = 0o644 << 16
    archive.writestr(info, source.read_bytes())


def build_zip(root: Path, output: Path) -> Path:
    """Build a deterministic release ZIP from ``root``."""
    output.parent.mkdir(parents=True, exist_ok=True)
    base = root.name
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in iter_release_files(root):
            rel = path.relative_to(root).as_posix()
            _write_deterministic_file(archive, path, f"{base}/{rel}")
        manifest = root / MANIFEST_NAME
        if manifest.exists():
            _write_deterministic_file(archive, manifest, f"{base}/{MANIFEST_NAME}")
    return output


def write_sidecars(output: Path) -> None:
    """Write SHA-256 and package-audit sidecars next to the release ZIP."""
    output.with_suffix(output.suffix + ".sha256.txt").write_text(
        f"{sha256_file(output)}  {output.name}\n", encoding="utf-8"
    )
    write_zip_summary(output, output.with_suffix(output.suffix + ".package_audit.json"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and build a deterministic CodeProbe source release ZIP.")
    parser.add_argument("--out", help="Output ZIP path. Defaults to dist/CodeProbe_Project_Kit_v<version>.zip.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip unittest discovery during release validation.")
    parser.add_argument("--no-sidecars", action="store_true", help="Do not write .sha256.txt and .package_audit.json next to the ZIP.")
    args = parser.parse_args(argv)

    results = check_release.run_checks(skip_tests=args.skip_tests)
    for result in results:
        status = "SKIP" if result.skipped else ("PASS" if result.ok else "FAIL")
        print(f"[{status}] {result.name}: {result.detail}")
    if not all(result.ok for result in results):
        return 1

    output = Path(args.out) if args.out else ROOT / "dist" / f"CodeProbe_Project_Kit_v{engine.APP_VERSION}.zip"
    build_zip(ROOT, output)
    print(f"release: {output}")
    print(f"sha256: {sha256_file(output)}")
    if not args.no_sidecars:
        write_sidecars(output)
        print(f"sha256 sidecar: {output.with_suffix(output.suffix + '.sha256.txt')}")
        print(f"package audit: {output.with_suffix(output.suffix + '.package_audit.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
