"""Bounded process execution for CodeProbe maintenance tools.

The browser application never launches native processes.  This module is the
single process boundary for repository-controlled Python tools: it rejects
shell execution, caps both output streams, enforces a wall-clock deadline and
terminates the process tree when a limit is crossed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_STDOUT_LIMIT = 4 * 1024 * 1024
DEFAULT_STDERR_LIMIT = 2 * 1024 * 1024
_READ_CHUNK = 64 * 1024
_TERMINATION_GRACE_SECONDS = 1.0


class ProcessControlError(RuntimeError):
    """Raised when a process cannot be launched or contained safely."""


@dataclass(frozen=True)
class ProcessResult:
    """Result of one bounded command."""

    args: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    timed_out: bool = False
    output_limit_exceeded: bool = False

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="backslashreplace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="backslashreplace")


@dataclass
class _CaptureState:
    limit: int
    chunks: list[bytes]
    received: int = 0
    stored: int = 0
    exceeded: bool = False

    def accept(self, chunk: bytes) -> None:
        self.received += len(chunk)
        remaining = self.limit - self.stored
        if remaining > 0:
            retained = chunk[:remaining]
            self.chunks.append(retained)
            self.stored += len(retained)
        if self.received > self.limit:
            self.exceeded = True

    def value(self) -> bytes:
        return b"".join(self.chunks)


class _WindowsJob:
    """Minimal Windows Job Object wrapper with kill-on-close semantics."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._handle = None
        self.error: Exception | None = None
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes

            class _IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class _BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class _EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BASIC_LIMIT_INFORMATION),
                    ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            information = _EXTENDED_LIMIT_INFORMATION()
            information.BasicLimitInformation.LimitFlags = 0x00002000  # KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                handle,
                9,  # JobObjectExtendedLimitInformation
                ctypes.byref(information),
                ctypes.sizeof(information),
            ):
                error = ctypes.get_last_error()
                kernel32.CloseHandle(handle)
                raise OSError(error, "SetInformationJobObject failed")
            process_handle = wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
            if not kernel32.AssignProcessToJobObject(handle, process_handle):
                error = ctypes.get_last_error()
                kernel32.CloseHandle(handle)
                raise OSError(error, "AssignProcessToJobObject failed")
            self._kernel32 = kernel32
            self._handle = handle
        except Exception as exc:
            self.error = exc
            self._handle = None

    @property
    def active(self) -> bool:
        return self._handle is not None

    def terminate(self) -> None:
        if self._handle is not None:
            self._kernel32.TerminateJobObject(self._handle, 1)

    def close(self) -> None:
        if self._handle is not None:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None



def _require_windows_containment(
    process: subprocess.Popen[bytes],
    job: _WindowsJob,
) -> None:
    if os.name != "nt" or job.active:
        return
    try:
        process.kill()
        process.wait(timeout=5)
    except Exception:
        pass
    detail = f": {job.error}" if job.error is not None else ""
    raise ProcessControlError(
        "could not assign the child to a Windows Job Object" + detail
    )

def _positive_limit(name: str, value: int | float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return float(value)


def _positive_byte_limit(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _normalise_command(command: Sequence[object]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes, bytearray)):
        raise TypeError("command must be a sequence of arguments, not a shell string")
    rendered: list[str] = []
    for item in command:
        if isinstance(item, bytes):
            raise TypeError("process arguments must be text or path-like values")
        value = os.fspath(item) if isinstance(item, os.PathLike) else str(item)
        if not value or "\x00" in value:
            raise ValueError("process arguments must be non-empty and contain no NUL bytes")
        rendered.append(value)
    if not rendered:
        raise ValueError("command must contain at least one argument")
    return tuple(rendered)


def _normalise_environment(
    environment: Mapping[str, str] | None,
    *,
    replace_environment: bool,
) -> dict[str, str]:
    target = {} if replace_environment else os.environ.copy()
    if environment is None:
        return target
    for raw_key, raw_value in environment.items():
        key = str(raw_key)
        value = str(raw_value)
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise ValueError("environment entries must be valid NUL-free name/value pairs")
        target[key] = value
    return target


def _capture_stream(
    stream: object,
    state: _CaptureState,
    overflow: threading.Event,
) -> None:
    reader = stream
    try:
        while True:
            chunk = reader.read(_READ_CHUNK)  # type: ignore[attr-defined]
            if not chunk:
                break
            state.accept(chunk)
            if state.exceeded:
                overflow.set()
    finally:
        try:
            reader.close()  # type: ignore[attr-defined]
        except Exception:
            pass


def _terminate_tree(process: subprocess.Popen[bytes], job: _WindowsJob) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        if job.active:
            job.terminate()
        else:
            # ``taskkill`` is used only inside this central process boundary.
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    shell=False,
                )
            except Exception:
                process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        process.terminate()
    deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            process.kill()


def run_bounded_process(
    command: Sequence[object],
    *,
    cwd: Path | str,
    environment: Mapping[str, str] | None = None,
    replace_environment: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    stdout_limit: int = DEFAULT_STDOUT_LIMIT,
    stderr_limit: int = DEFAULT_STDERR_LIMIT,
) -> ProcessResult:
    """Run ``command`` without a shell and enforce resource limits.

    The returned bytes are prefixes of the corresponding streams when a limit
    is exceeded.  Callers must inspect ``timed_out`` and
    ``output_limit_exceeded`` before treating the return code as meaningful.
    """

    argv = _normalise_command(command)
    timeout_seconds = _positive_limit("timeout", timeout)
    stdout_ceiling = _positive_byte_limit("stdout_limit", stdout_limit)
    stderr_ceiling = _positive_byte_limit("stderr_limit", stderr_limit)
    working_directory = Path(cwd)
    if not working_directory.is_dir():
        raise ProcessControlError(f"working directory is not a directory: {working_directory}")
    child_environment = _normalise_environment(
        environment,
        replace_environment=replace_environment,
    )

    creationflags = 0
    start_new_session = os.name != "nt"
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            argv,
            cwd=working_directory,
            env=child_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=start_new_session,
            creationflags=creationflags,
        )
    except OSError as exc:
        raise ProcessControlError(f"could not launch {argv[0]!r}: {exc}") from exc

    job = _WindowsJob(process)
    _require_windows_containment(process, job)
    stdout_state = _CaptureState(stdout_ceiling, [])
    stderr_state = _CaptureState(stderr_ceiling, [])
    overflow = threading.Event()
    stdout_thread = threading.Thread(
        target=_capture_stream,
        args=(process.stdout, stdout_state, overflow),
        name="codeprobe-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_capture_stream,
        args=(process.stderr, stderr_state, overflow),
        name="codeprobe-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    output_limit_exceeded = False
    deadline = started + timeout_seconds
    try:
        while process.poll() is None:
            if overflow.is_set():
                output_limit_exceeded = True
                _terminate_tree(process, job)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_tree(process, job)
                break
            time.sleep(0.02)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_tree(process, job)
            process.wait(timeout=5)
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        readers_finished = not stdout_thread.is_alive() and not stderr_thread.is_alive()
        job.close()

    if not readers_finished:
        raise ProcessControlError("process output readers did not terminate cleanly")
    if stdout_state.exceeded or stderr_state.exceeded:
        output_limit_exceeded = True
    duration = max(0.0, time.monotonic() - started)
    return ProcessResult(
        args=argv,
        returncode=int(process.returncode if process.returncode is not None else -1),
        stdout=stdout_state.value(),
        stderr=stderr_state.value(),
        duration_seconds=duration,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
    )


__all__ = [
    "DEFAULT_STDERR_LIMIT",
    "DEFAULT_STDOUT_LIMIT",
    "DEFAULT_TIMEOUT_SECONDS",
    "ProcessControlError",
    "ProcessResult",
    "run_bounded_process",
]
