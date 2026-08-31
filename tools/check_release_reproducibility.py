#!/usr/bin/env python3
"""Check Git checkout, archive and release-packet reproducibility.

This is an integration gate for CI.  It deliberately remains separate from
``tools/check_release.py`` and unittest discovery because it invokes the
release checker and builder in child source trees.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated and sys.flags.no_site
):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))

from codeprobe_engine.release import ReleaseSetError, read_regular_file  # noqa: E402

ACTIVE_ENVIRONMENT_VARIABLE = "CODEPROBE_REPRO_GATE_ACTIVE"
MANIFEST_PATH = "release/release-manifest.json"
PACKET_BASENAME = "release.zip"
PACKET_FILENAMES = (
    PACKET_BASENAME,
    PACKET_BASENAME + ".sha256.txt",
    PACKET_BASENAME + ".package_audit.json",
)
DETERMINISTIC_ZIP_DATETIME = (2020, 1, 1, 0, 0, 0)
MAX_DIAGNOSTICS = 20
MAX_COMMAND_OUTPUT = 16_000
COMMAND_TIMEOUT_SECONDS = 600
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class ReproducibilityError(RuntimeError):
    """Raised when a reproducibility invariant is not satisfied."""


@dataclass(frozen=True)
class GitLeaf:
    """One leaf returned by ``git ls-tree``."""

    path: str
    mode: str
    object_type: str
    object_id: str


@dataclass(frozen=True)
class TreeEntry:
    """A platform-neutral source-tree inventory entry."""

    kind: str
    size: int | None = None
    sha256: str | None = None
    git_mode: str | None = None


@dataclass(frozen=True)
class GitSnapshot:
    """The expected Git tree and exact bytes for every tracked file."""

    entries: Mapping[str, TreeEntry]
    contents: Mapping[str, bytes]


@dataclass(frozen=True)
class PacketPaths:
    """The three mandatory release packet paths."""

    zip_path: Path
    checksum_path: Path
    audit_path: Path

    def all(self) -> tuple[Path, Path, Path]:
        return self.zip_path, self.checksum_path, self.audit_path


def _safe_text(value: object) -> str:
    return ascii(os.fspath(value) if isinstance(value, os.PathLike) else str(value))


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _bounded_output(content: bytes) -> str:
    text = content.decode("utf-8", errors="backslashreplace")
    if len(text) <= MAX_COMMAND_OUTPUT:
        return text
    omitted = len(text) - MAX_COMMAND_OUTPUT
    return text[:MAX_COMMAND_OUTPUT] + f"\n... {omitted} character(s) omitted"


def _command_display(command: Sequence[object]) -> str:
    return " ".join(_safe_text(item) for item in command)


def run_command(
    command: Sequence[object],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
    replace_environment: bool = False,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> bytes:
    """Run one bounded child command and return its standard output."""
    argv = [os.fspath(item) for item in command]
    child_environment = dict(environment) if replace_environment and environment is not None else os.environ.copy()
    if environment and not replace_environment:
        child_environment.update(environment)
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=child_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReproducibilityError(
            f"command could not complete in {_safe_text(cwd)}: {_command_display(command)}: {_safe_text(exc)}"
        ) from exc
    if completed.returncode != 0:
        raise ReproducibilityError(
            "command failed "
            f"(exit {completed.returncode}) in {_safe_text(cwd)}: {_command_display(command)}\n"
            f"stdout:\n{_bounded_output(completed.stdout)}\n"
            f"stderr:\n{_bounded_output(completed.stderr)}"
        )
    return completed.stdout


def _git_environment() -> dict[str, str]:
    """Return a deterministic Git environment without user attribute rules."""
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment.update({
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return environment


def run_git(repository: Path, arguments: Sequence[object]) -> bytes:
    return run_command(
        ["git", "-C", repository, *arguments],
        cwd=repository,
        environment=_git_environment(),
        replace_environment=True,
    )


def validate_relative_path(value: str) -> str:
    """Validate a portable, canonical relative POSIX path."""
    if not value:
        raise ReproducibilityError("an empty path is not permitted")
    if value != unicodedata.normalize("NFC", value):
        raise ReproducibilityError(f"path is not NFC-normalised: {_safe_text(value)}")
    if "\\" in value:
        raise ReproducibilityError(f"path contains a backslash: {_safe_text(value)}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ReproducibilityError(f"path contains a control character: {_safe_text(value)}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ReproducibilityError(f"path is not canonical and relative: {_safe_text(value)}")
    forbidden = set('<>:"|?*')
    for part in path.parts:
        if any(character in forbidden for character in part):
            raise ReproducibilityError(f"path is not portable: {_safe_text(value)}")
        if part.endswith((".", " ")):
            raise ReproducibilityError(f"path component ends with a dot or space: {_safe_text(value)}")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
            raise ReproducibilityError(f"path uses a reserved device name: {_safe_text(value)}")
        if len(part.encode("utf-8")) > 255:
            raise ReproducibilityError(f"path component exceeds 255 UTF-8 bytes: {_safe_text(value)}")
    return value


def local_path(root: Path, relative: str) -> Path:
    """Map a validated POSIX path to the host filesystem explicitly."""
    validated = validate_relative_path(relative)
    return root.joinpath(*PurePosixPath(validated).parts)


def parse_ls_tree_z(payload: bytes) -> list[GitLeaf]:
    """Parse NUL-delimited ``git ls-tree -r -z`` output without path loss."""
    leaves: list[GitLeaf] = []
    seen: set[str] = set()
    portable_seen: dict[str, str] = {}
    records = payload.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            fields = header.split(b" ")
            if len(fields) != 3:
                raise ValueError("tree metadata does not contain three fields")
            raw_mode, raw_type, raw_object_id = fields
            mode = raw_mode.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_id = raw_object_id.decode("ascii")
            path = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ReproducibilityError(f"invalid git ls-tree record: {_safe_text(record)}: {_safe_text(exc)}") from exc
        if not re.fullmatch(r"[0-7]{6}", mode):
            raise ReproducibilityError(f"invalid Git mode for {_safe_text(path)}: {_safe_text(mode)}")
        if not re.fullmatch(r"[0-9a-fA-F]{4,128}", object_id):
            raise ReproducibilityError(f"invalid Git object identifier for {_safe_text(path)}")
        validate_relative_path(path)
        if path in seen:
            raise ReproducibilityError(f"duplicate Git tree path: {_safe_text(path)}")
        portable_key = unicodedata.normalize("NFC", path).casefold()
        if portable_key in portable_seen:
            raise ReproducibilityError(
                "Git paths collide on a case-insensitive filesystem: "
                f"{_safe_text(portable_seen[portable_key])} and {_safe_text(path)}"
            )
        seen.add(path)
        portable_seen[portable_key] = path
        leaves.append(GitLeaf(path, mode, object_type, object_id.lower()))
    return leaves


def _derived_directories(paths: Sequence[str]) -> set[str]:
    directories: set[str] = set()
    for value in paths:
        parent = PurePosixPath(value).parent
        while parent.as_posix() != ".":
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def read_git_snapshot(repository: Path, commit: str) -> GitSnapshot:
    """Read exact regular-file bytes from one committed Git tree."""
    output = run_git(repository, ["ls-tree", "-r", "-z", "--full-tree", commit])
    leaves = parse_ls_tree_z(output)
    unsupported = [leaf for leaf in leaves if leaf.mode != "100644" or leaf.object_type != "blob"]
    if unsupported:
        rendered = ", ".join(
            f"{_safe_text(leaf.path)} ({leaf.mode} {leaf.object_type})" for leaf in unsupported[:MAX_DIAGNOSTICS]
        )
        if len(unsupported) > MAX_DIAGNOSTICS:
            rendered += f", ... {len(unsupported) - MAX_DIAGNOSTICS} more"
        raise ReproducibilityError(
            "the current release contract permits only 100644 Git blobs; unsupported entries: " + rendered
        )

    contents: dict[str, bytes] = {}
    entries: dict[str, TreeEntry] = {}
    for leaf in leaves:
        content = run_git(repository, ["cat-file", "blob", leaf.object_id])
        contents[leaf.path] = content
        entries[leaf.path] = TreeEntry("file", len(content), sha256_bytes(content), leaf.mode)
    for directory in _derived_directories([leaf.path for leaf in leaves]):
        if directory in entries:
            raise ReproducibilityError(f"Git path is both a directory and a file: {_safe_text(directory)}")
        entries[directory] = TreeEntry("directory")
    return GitSnapshot(dict(sorted(entries.items())), dict(sorted(contents.items())))


def read_stable_regular_file(path: Path) -> bytes:
    """Read a regular file while detecting replacement or mutation."""
    try:
        return read_regular_file(path)
    except (OSError, ReleaseSetError) as exc:
        raise ReproducibilityError(
            f"cannot read stable regular file {_safe_text(path)}: {_safe_text(exc)}"
        ) from exc


def inventory_tree(root: Path, *, exclude_git: bool = True) -> dict[str, TreeEntry]:
    """Inventory complete membership, entry types and regular-file bytes."""
    root = root.resolve()
    entries: dict[str, TreeEntry] = {}
    pending: list[tuple[Path, PurePosixPath | None]] = [(root, None)]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ReproducibilityError(f"cannot enumerate {_safe_text(directory)}: {_safe_text(exc)}") from exc
        for child in children:
            if relative_directory is None and exclude_git and child.name == ".git":
                continue
            relative = PurePosixPath(child.name) if relative_directory is None else relative_directory / child.name
            relative_text = relative.as_posix()
            validate_relative_path(relative_text)
            path = Path(child.path)
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReproducibilityError(f"cannot inspect {_safe_text(path)}: {_safe_text(exc)}") from exc
            if stat.S_ISDIR(metadata.st_mode):
                entries[relative_text] = TreeEntry("directory")
                pending.append((path, relative))
            elif stat.S_ISREG(metadata.st_mode):
                content = read_stable_regular_file(path)
                entries[relative_text] = TreeEntry("file", len(content), sha256_bytes(content))
            elif stat.S_ISLNK(metadata.st_mode):
                entries[relative_text] = TreeEntry("symlink", metadata.st_size)
            elif stat.S_ISFIFO(metadata.st_mode):
                entries[relative_text] = TreeEntry("fifo")
            elif stat.S_ISSOCK(metadata.st_mode):
                entries[relative_text] = TreeEntry("socket")
            elif stat.S_ISCHR(metadata.st_mode):
                entries[relative_text] = TreeEntry("character-device")
            elif stat.S_ISBLK(metadata.st_mode):
                entries[relative_text] = TreeEntry("block-device")
            else:
                entries[relative_text] = TreeEntry("other")
    return dict(sorted(entries.items()))


def _bounded_messages(messages: Sequence[str], limit: int = MAX_DIAGNOSTICS) -> list[str]:
    limited = list(messages[:limit])
    if len(messages) > limit:
        limited.append(f"... {len(messages) - limit} additional discrepancy/discrepancies omitted")
    return limited


def tree_mismatch_diagnostics(
    expected: Mapping[str, TreeEntry],
    actual: Mapping[str, TreeEntry],
    *,
    label: str,
    limit: int = MAX_DIAGNOSTICS,
) -> list[str]:
    """Return bounded, content-free diagnostics for two inventories."""
    messages: list[str] = []
    expected_paths = set(expected)
    actual_paths = set(actual)
    for path in sorted(expected_paths - actual_paths):
        messages.append(f"{label}: missing {_safe_text(path)} ({expected[path].kind})")
    for path in sorted(actual_paths - expected_paths):
        messages.append(f"{label}: unexpected {_safe_text(path)} ({actual[path].kind})")
    for path in sorted(expected_paths & actual_paths):
        left = expected[path]
        right = actual[path]
        if left.kind != right.kind:
            messages.append(f"{label}: type mismatch at {_safe_text(path)}: expected {left.kind}, observed {right.kind}")
        elif left.kind == "file" and (left.size != right.size or left.sha256 != right.sha256):
            messages.append(
                f"{label}: byte mismatch at {_safe_text(path)}: "
                f"expected size={left.size}, sha256={left.sha256}; "
                f"observed size={right.size}, sha256={right.sha256}"
            )
    return _bounded_messages(messages, limit)


def describe_byte_difference(expected: bytes, actual: bytes, *, label: str) -> str:
    """Describe the first byte difference without revealing file contents."""
    shared = min(len(expected), len(actual))
    offset = next((index for index in range(shared) if expected[index] != actual[index]), shared)
    return (
        f"{label}: first difference at byte offset {offset}; "
        f"expected size={len(expected)}, sha256={sha256_bytes(expected)}; "
        f"observed size={len(actual)}, sha256={sha256_bytes(actual)}"
    )


def require_matching_tree(
    expected: GitSnapshot,
    actual_root: Path,
    *,
    label: str,
    exclude_git: bool = True,
) -> dict[str, TreeEntry]:
    actual = inventory_tree(actual_root, exclude_git=exclude_git)
    diagnostics = tree_mismatch_diagnostics(expected.entries, actual, label=label)
    if diagnostics:
        for path in sorted(set(expected.contents) & set(actual)):
            entry = actual[path]
            expected_entry = expected.entries[path]
            if entry.kind == "file" and entry.sha256 != expected_entry.sha256:
                observed = read_stable_regular_file(local_path(actual_root, path))
                diagnostics.append(describe_byte_difference(expected.contents[path], observed, label=f"{label} {_safe_text(path)}"))
                break
        raise ReproducibilityError("\n".join(diagnostics))
    return actual


def _normalise_tar_name(member: tarfile.TarInfo) -> str:
    name = member.name.rstrip("/") if member.isdir() else member.name
    return validate_relative_path(name)


def extract_git_archive_safely(archive_path: Path, destination: Path, expected: GitSnapshot) -> None:
    """Validate and materialise an exact Git TAR without ``extractall``."""
    if destination.exists():
        raise ReproducibilityError(f"archive destination already exists: {_safe_text(destination)}")
    expected_files = set(expected.contents)
    expected_directories = {path for path, entry in expected.entries.items() if entry.kind == "directory"}
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    seen_casefold: dict[str, str] = {}
    member_count = 0
    try:
        archive = tarfile.open(archive_path, mode="r:")
    except (OSError, tarfile.TarError) as exc:
        raise ReproducibilityError(f"cannot open Git archive {_safe_text(archive_path)}: {_safe_text(exc)}") from exc
    with archive:
        for member in archive:
            member_count += 1
            if member_count > len(expected.entries) + 8:
                raise ReproducibilityError("Git archive contains more entries than the committed tree permits")
            if not member.isdir() and not member.isreg():
                raise ReproducibilityError(
                    f"Git archive contains a forbidden {member.type!r} entry: {_safe_text(member.name)}"
                )
            name = _normalise_tar_name(member)
            portable_key = unicodedata.normalize("NFC", name).casefold()
            if portable_key in seen_casefold:
                raise ReproducibilityError(
                    "Git archive contains a duplicate or case-fold collision: "
                    f"{_safe_text(seen_casefold[portable_key])} and {_safe_text(name)}"
                )
            seen_casefold[portable_key] = name
            if member.isdir():
                if name not in expected_directories:
                    raise ReproducibilityError(f"Git archive contains an unexpected directory: {_safe_text(name)}")
                directories.add(name)
                continue
            if name not in expected_files:
                raise ReproducibilityError(f"Git archive contains an unexpected file: {_safe_text(name)}")
            expected_content = expected.contents[name]
            if member.size != len(expected_content):
                raise ReproducibilityError(
                    f"Git archive size mismatch at {_safe_text(name)}: expected {len(expected_content)}, observed {member.size}"
                )
            # Git records only the executable distinction for ordinary blobs.
            # ``git archive`` applies its own tar umask (0664 by default), so
            # write/read bits are not a cross-installation invariant.
            if stat.S_IMODE(member.mode) & 0o111:
                raise ReproducibilityError(
                    f"Git archive unexpectedly marks a 100644 blob executable at {_safe_text(name)}: "
                    f"observed {stat.S_IMODE(member.mode):04o}"
                )
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ReproducibilityError(f"Git archive file cannot be read: {_safe_text(name)}")
            content = extracted.read(len(expected_content) + 1)
            if content != expected_content:
                raise ReproducibilityError(describe_byte_difference(expected_content, content, label=f"archive {_safe_text(name)}"))
            files[name] = content

    missing_files = sorted(expected_files - set(files))
    missing_directories = sorted(expected_directories - directories)
    if missing_files or missing_directories:
        messages = [f"Git archive is missing file {_safe_text(path)}" for path in missing_files]
        messages.extend(f"Git archive is missing directory {_safe_text(path)}" for path in missing_directories)
        raise ReproducibilityError("\n".join(_bounded_messages(messages)))

    destination.mkdir(parents=True)
    for directory in sorted(expected_directories, key=lambda value: (value.count("/"), value)):
        local_path(destination, directory).mkdir()
    for path, content in sorted(files.items()):
        target = local_path(destination, path)
        try:
            with target.open("xb") as handle:
                handle.write(content)
            os.chmod(target, 0o644)
        except OSError as exc:
            raise ReproducibilityError(f"cannot materialise archive file {_safe_text(path)}: {_safe_text(exc)}") from exc


def create_checkout(repository: Path, commit: str, destination: Path, *, forced_crlf: bool) -> None:
    """Create one detached, clean checkout with controlled line-ending settings."""
    environment = _git_environment()
    run_command(
        ["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", repository, destination],
        cwd=repository,
        environment=environment,
        replace_environment=True,
    )
    run_git(destination, ["config", "core.autocrlf", "true" if forced_crlf else "false"])
    run_git(destination, ["config", "core.eol", "crlf" if forced_crlf else "lf"])
    run_git(destination, ["config", "core.safecrlf", "true"])
    run_git(destination, ["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", commit])


def export_git_archive(repository: Path, commit: str, archive_path: Path) -> None:
    run_git(repository, ["archive", "--format=tar", "--output", archive_path, commit])


def require_clean_git_checkout(repository: Path, *, label: str) -> None:
    status = run_git(repository, ["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        raise ReproducibilityError(f"{label} is not Git-clean:\n{_bounded_output(status)}")


def require_normalised_eol(repository: Path, *, label: str) -> None:
    """Reject text index or worktree states containing CRLF or mixed endings."""
    output = run_git(repository, ["ls-files", "--eol", "-z"])
    errors: list[str] = []
    for raw_record in output.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            path = raw_path.decode("utf-8")
            fields = metadata.decode("ascii").split()
        except (UnicodeError, ValueError) as exc:
            raise ReproducibilityError(f"invalid git ls-files --eol record: {_safe_text(raw_record)}") from exc
        index_state = next((field for field in fields if field.startswith("i/")), "")
        worktree_state = next((field for field in fields if field.startswith("w/")), "")
        if index_state in {"i/crlf", "i/mixed"} or worktree_state in {"w/crlf", "w/mixed"}:
            errors.append(f"{label}: non-LF text state at {_safe_text(path)} ({index_state}, {worktree_state})")
    if errors:
        raise ReproducibilityError("\n".join(_bounded_messages(errors)))


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def load_unique_json(path: Path) -> Any:
    try:
        content = read_stable_regular_file(path)
        return json.loads(content.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReproducibilityError(f"invalid unambiguous JSON at {_safe_text(path)}: {_safe_text(exc)}") from exc


def _child_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }
    environment.update({
        ACTIVE_ENVIRONMENT_VARIABLE: "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    })
    return environment


def run_fast_gate(source_root: Path, result_path: Path) -> dict[str, Any]:
    run_command(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            source_root / "tools" / "check_release.py",
            "--skip-tests",
            "--json-out",
            result_path,
        ],
        cwd=source_root,
        environment=_child_environment(),
        replace_environment=True,
    )
    payload = load_unique_json(result_path)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ReproducibilityError(f"release gate produced an invalid result schema: {_safe_text(result_path)}")
    failures: list[str] = []
    for item in payload["results"]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            failures.append("release gate returned a malformed check result")
        elif item.get("ok") is not True:
            failures.append(f"release gate check failed: {_safe_text(item.get('name'))}")
        elif item.get("skipped") is True and item.get("name") != "unit-tests":
            failures.append(f"release gate check was skipped: {_safe_text(item.get('name'))}")
    if failures:
        raise ReproducibilityError("\n".join(_bounded_messages(failures)))
    return payload


def gate_semantics(payload: Mapping[str, Any]) -> tuple[object, tuple[tuple[object, object, object], ...]]:
    results = payload.get("results")
    if not isinstance(results, list):
        raise ReproducibilityError("release gate result list is missing")
    return payload.get("app_version"), tuple(
        (item.get("name"), item.get("ok"), item.get("skipped")) for item in results if isinstance(item, dict)
    )


def build_packet(source_root: Path, output_directory: Path) -> PacketPaths:
    output_directory.mkdir(parents=True)
    output = output_directory / PACKET_BASENAME
    run_command(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            source_root / "tools" / "build_release.py",
            "--skip-tests",
            "--out",
            output,
        ],
        cwd=source_root,
        environment=_child_environment(),
        replace_environment=True,
    )
    observed = sorted(path.name for path in output_directory.iterdir())
    if observed != sorted(PACKET_FILENAMES):
        raise ReproducibilityError(
            f"release builder did not publish exactly three files: expected {sorted(PACKET_FILENAMES)!r}, observed {observed!r}"
        )
    paths = PacketPaths(
        output,
        output_directory / (PACKET_BASENAME + ".sha256.txt"),
        output_directory / (PACKET_BASENAME + ".package_audit.json"),
    )
    for path in paths.all():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ReproducibilityError(f"release packet entry is not a regular file: {_safe_text(path)}")
    return paths


def _load_manifest_projection(source_roots: Mapping[str, Path]) -> tuple[dict[str, bytes], str]:
    manifest_bytes: bytes | None = None
    manifest: Any = None
    for label, root in source_roots.items():
        content = read_stable_regular_file(root / MANIFEST_PATH)
        if manifest_bytes is None:
            manifest_bytes = content
            try:
                manifest = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_json_object)
            except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise ReproducibilityError(f"manifest is invalid in {label}: {_safe_text(exc)}") from exc
        elif content != manifest_bytes:
            raise ReproducibilityError(describe_byte_difference(manifest_bytes, content, label=f"manifest in {label}"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ReproducibilityError("release manifest does not contain a files array")
    app_version = manifest.get("app_version")
    if not isinstance(app_version, str) or not app_version:
        raise ReproducibilityError("release manifest does not contain a valid app_version")

    projection: dict[str, bytes] = {}
    for index, item in enumerate(manifest["files"]):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ReproducibilityError(f"release manifest files[{index}] is malformed")
        path = validate_relative_path(item["path"])
        if path in projection:
            raise ReproducibilityError(f"duplicate release manifest path: {_safe_text(path)}")
        reference_content: bytes | None = None
        for label, root in source_roots.items():
            content = read_stable_regular_file(local_path(root, path))
            if reference_content is None:
                reference_content = content
            elif content != reference_content:
                raise ReproducibilityError(
                    describe_byte_difference(reference_content, content, label=f"manifest projection {label} {_safe_text(path)}")
                )
        assert reference_content is not None
        if item.get("size_bytes") != len(reference_content) or item.get("sha256") != sha256_bytes(reference_content):
            raise ReproducibilityError(f"manifest metadata does not describe {_safe_text(path)}")
        projection[path] = reference_content
    assert manifest_bytes is not None
    projection[MANIFEST_PATH] = manifest_bytes
    return projection, app_version


def summarise_zip(zip_path: Path) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            for info in sorted((item for item in archive.infolist() if not item.is_dir()), key=lambda item: item.filename):
                members.append(
                    {
                        "path": info.filename,
                        "size_bytes": info.file_size,
                        "compressed_size_bytes": info.compress_size,
                        "crc32": f"{info.CRC:08x}",
                    }
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReproducibilityError(f"cannot inspect ZIP {_safe_text(zip_path)}: {_safe_text(exc)}") from exc
    uncompressed = sum(item["size_bytes"] for item in members)
    compressed = sum(item["compressed_size_bytes"] for item in members)
    zip_content = read_stable_regular_file(zip_path)
    return {
        "schema_version": "codeprobe-zip-package-audit/v1",
        "zip_name": zip_path.name,
        "zip_size_bytes": len(zip_content),
        "zip_sha256": sha256_bytes(zip_content),
        "file_count": len(members),
        "total_uncompressed_member_bytes": uncompressed,
        "total_compressed_member_bytes": compressed,
        "zip_container_overhead_bytes": len(zip_content) - compressed,
        "compression_ratio": round((compressed / uncompressed), 6) if uncompressed else None,
        "members": members,
    }


def verify_packet(packet: PacketPaths, projection: Mapping[str, bytes], app_version: str, *, label: str) -> None:
    zip_content = read_stable_regular_file(packet.zip_path)
    checksum_content = read_stable_regular_file(packet.checksum_path)
    expected_checksum = f"{sha256_bytes(zip_content)}  {PACKET_BASENAME}\n".encode("ascii")
    if checksum_content != expected_checksum:
        raise ReproducibilityError(describe_byte_difference(expected_checksum, checksum_content, label=f"{label} checksum"))
    audit = load_unique_json(packet.audit_path)
    expected_audit = summarise_zip(packet.zip_path)
    if audit != expected_audit:
        expected_text = json.dumps(expected_audit, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
        actual_text = json.dumps(audit, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
        difference = list(difflib.unified_diff(expected_text, actual_text, fromfile="expected", tofile="observed", n=2))
        raise ReproducibilityError(
            f"{label} package-audit sidecar is inconsistent:\n" + "\n".join(_bounded_messages(difference))
        )

    package_root = f"CodeProbe_Project_Kit_v{app_version}"
    expected_names = [f"{package_root}/{path}" for path in projection]
    try:
        with zipfile.ZipFile(packet.zip_path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if names != expected_names or len(names) != len(set(names)):
                raise ReproducibilityError(
                    f"{label} ZIP membership or order differs from the manifest projection: "
                    f"expected {len(expected_names)}, observed {len(names)}"
                )
            bad_member = archive.testzip()
            if bad_member is not None:
                raise ReproducibilityError(f"{label} ZIP CRC failure at {_safe_text(bad_member)}")
            if archive.comment:
                raise ReproducibilityError(f"{label} ZIP has a non-empty archive comment")
            for info, (relative, content) in zip(infos, projection.items()):
                mode = info.external_attr >> 16
                if (
                    info.date_time != DETERMINISTIC_ZIP_DATETIME
                    or info.create_system != 3
                    or info.compress_type != zipfile.ZIP_DEFLATED
                    or info.flag_bits != 0
                    or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != 0o644
                    or info.extra
                    or info.comment
                ):
                    raise ReproducibilityError(f"{label} ZIP metadata is not canonical at {_safe_text(info.filename)}")
                observed = archive.read(info)
                if observed != content:
                    raise ReproducibilityError(
                        describe_byte_difference(content, observed, label=f"{label} ZIP member {_safe_text(relative)}")
                    )
    except zipfile.BadZipFile as exc:
        raise ReproducibilityError(f"{label} ZIP is invalid: {_safe_text(exc)}") from exc


def _zip_fingerprints(path: Path) -> list[tuple[object, ...]]:
    with zipfile.ZipFile(path, "r") as archive:
        return [
            (
                info.filename,
                info.date_time,
                info.create_system,
                info.external_attr,
                info.compress_type,
                info.flag_bits,
                info.CRC,
                info.file_size,
                info.compress_size,
                info.extra,
                info.comment,
                sha256_bytes(archive.read(info)),
            )
            for info in archive.infolist()
        ]


def describe_zip_difference(reference: Path, candidate: Path) -> str:
    """Describe the first semantic ZIP difference after a byte mismatch."""
    left = _zip_fingerprints(reference)
    right = _zip_fingerprints(candidate)
    if len(left) != len(right):
        return f"ZIP member count differs: expected {len(left)}, observed {len(right)}"
    for index, (left_item, right_item) in enumerate(zip(left, right)):
        if left_item != right_item:
            return (
                f"first ZIP member difference at index {index}: "
                f"expected name={_safe_text(left_item[0])}, size={left_item[7]}, "
                f"compressed={left_item[8]}, crc32={left_item[6]:08x}, content_sha256={left_item[11]}; "
                f"observed name={_safe_text(right_item[0])}, size={right_item[7]}, "
                f"compressed={right_item[8]}, crc32={right_item[6]:08x}, content_sha256={right_item[11]}"
            )
    return "ZIP member metadata and decompressed content agree; container or compressed-stream bytes differ"


def compare_packets(reference: PacketPaths, candidate: PacketPaths, *, label: str) -> None:
    for reference_path, candidate_path in zip(reference.all(), candidate.all()):
        expected = read_stable_regular_file(reference_path)
        actual = read_stable_regular_file(candidate_path)
        if expected != actual:
            detail = ""
            if reference_path == reference.zip_path:
                detail = "\n" + describe_zip_difference(reference_path, candidate_path)
            raise ReproducibilityError(
                describe_byte_difference(expected, actual, label=f"{label} {reference_path.name}") + detail
            )


def _remove_tree(path: Path) -> None:
    def make_writable(function, target: str, _error_info: object) -> None:
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        function(target)

    shutil.rmtree(path, onerror=make_writable)


def run_reproducibility_gate(repository: Path, commit: str, workspace: Path) -> dict[str, str]:
    """Run the complete same-commit, same-toolchain behavioural gate."""
    repository = repository.resolve()
    commit_id = run_git(repository, ["rev-parse", "--verify", f"{commit}^{{commit}}"]).decode("ascii").strip()
    require_clean_git_checkout(repository, label="source repository")
    expected = read_git_snapshot(repository, commit_id)
    original_before = require_matching_tree(expected, repository, label="source repository versus Git tree")

    lf_checkout = workspace / "checkout-lf"
    forced_checkout = workspace / "checkout-forced-crlf"
    archive_tar = workspace / "exact-git-archive.tar"
    archive_root = workspace / "archive-export"
    create_checkout(repository, commit_id, lf_checkout, forced_crlf=False)
    create_checkout(repository, commit_id, forced_checkout, forced_crlf=True)
    export_git_archive(repository, commit_id, archive_tar)
    extract_git_archive_safely(archive_tar, archive_root, expected)

    sources = {
        "LF checkout": lf_checkout,
        "forced-CRLF checkout": forced_checkout,
        "Git archive": archive_root,
    }
    inventories: dict[str, dict[str, TreeEntry]] = {}
    for label, root in sources.items():
        inventories[label] = require_matching_tree(
            expected,
            root,
            label=f"{label} versus Git tree",
            exclude_git=label != "Git archive",
        )
        if label != "Git archive":
            require_clean_git_checkout(root, label=label)
            require_normalised_eol(root, label=label)

    results_directory = workspace / "gate-results"
    results_directory.mkdir()
    gate_payloads: dict[str, dict[str, Any]] = {}
    for index, (label, root) in enumerate(sources.items()):
        gate_payloads[label] = run_fast_gate(root, results_directory / f"{index}.json")
    reference_semantics = gate_semantics(gate_payloads["LF checkout"])
    for label in ("forced-CRLF checkout", "Git archive"):
        if gate_semantics(gate_payloads[label]) != reference_semantics:
            raise ReproducibilityError(f"release-gate semantics differ for {label}")

    packet_root = workspace / "packets"
    packet_root.mkdir()
    packets: dict[str, PacketPaths] = {}
    for index, (label, root) in enumerate(sources.items()):
        packets[label] = build_packet(root, packet_root / str(index))
    projection, app_version = _load_manifest_projection(sources)
    for label, packet in packets.items():
        verify_packet(packet, projection, app_version, label=label)
    reference_packet = packets["LF checkout"]
    compare_packets(reference_packet, packets["forced-CRLF checkout"], label="forced-CRLF checkout")
    compare_packets(reference_packet, packets["Git archive"], label="Git archive")

    for label, root in sources.items():
        after = inventory_tree(root, exclude_git=label != "Git archive")
        diagnostics = tree_mismatch_diagnostics(inventories[label], after, label=f"{label} post-run tree")
        if diagnostics:
            raise ReproducibilityError("\n".join(diagnostics))
        if label != "Git archive":
            require_clean_git_checkout(root, label=label)
    original_after = inventory_tree(repository)
    diagnostics = tree_mismatch_diagnostics(original_before, original_after, label="source repository post-run tree")
    if diagnostics:
        raise ReproducibilityError("\n".join(diagnostics))
    require_clean_git_checkout(repository, label="source repository")

    return {
        "commit": commit_id,
        "zip_sha256": sha256_bytes(read_stable_regular_file(reference_packet.zip_path)),
        "checksum_sha256": sha256_bytes(read_stable_regular_file(reference_packet.checksum_path)),
        "audit_sha256": sha256_bytes(read_stable_regular_file(reference_packet.audit_path)),
        "git_file_count": str(len(expected.contents)),
        "release_file_count": str(len(projection)),
    }


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare exact Git checkout, archive and release-packet bytes on one toolchain."
    )
    parser.add_argument("--repository", type=Path, default=ROOT, help="Clean Git repository to verify (default: project root).")
    parser.add_argument("--commit", default="HEAD", help="Commit to verify (default: HEAD).")
    parser.add_argument("--keep-workdir", action="store_true", help="Retain the private integration workspace for inspection.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    if os.environ.get(ACTIVE_ENVIRONMENT_VARIABLE):
        print(f"[FAIL] reproducibility: recursive invocation rejected by {ACTIVE_ENVIRONMENT_VARIABLE}", file=sys.stderr)
        return 1
    arguments = _parse_arguments(argv)
    workspace = Path(tempfile.mkdtemp(prefix="codeprobe-reproducibility-"))
    try:
        result = run_reproducibility_gate(arguments.repository, arguments.commit, workspace)
    except (OSError, ReproducibilityError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"[FAIL] reproducibility: {exc}", file=sys.stderr)
        if arguments.keep_workdir:
            print(f"retained workspace: {workspace}", file=sys.stderr)
        else:
            try:
                _remove_tree(workspace)
            except OSError as cleanup_exc:
                print(f"[FAIL] workspace cleanup: {cleanup_exc}", file=sys.stderr)
        return 1

    print(f"[PASS] commit: {result['commit']}")
    print(f"[PASS] Git files: {result['git_file_count']}; release files: {result['release_file_count']}")
    print(f"[PASS] ZIP SHA-256: {result['zip_sha256']}")
    print(f"[PASS] checksum sidecar SHA-256: {result['checksum_sha256']}")
    print(f"[PASS] package-audit sidecar SHA-256: {result['audit_sha256']}")
    print(f"[PASS] Python: {sys.version.split()[0]}; zlib compile/runtime: {zlib.ZLIB_VERSION}/{zlib.ZLIB_RUNTIME_VERSION}")
    if arguments.keep_workdir:
        print(f"retained workspace: {workspace}")
    else:
        try:
            _remove_tree(workspace)
        except OSError as exc:
            print(f"[FAIL] workspace cleanup: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
