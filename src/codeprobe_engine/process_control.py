"""Bounded process execution for CodeProbe maintenance tools.

The browser application never launches native processes.  This module is the
single process boundary for repository-controlled Python tools: it rejects
shell execution, caps both output streams, enforces a wall-clock deadline and
cleans the owned execution boundary when the command finishes or fails.
On POSIX this boundary is the new process group, not detached sessions.
The broker is the exclusive owner of child reaping and of both output pipes.
"""

from __future__ import annotations

import math
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
_CLEANUP_TIMEOUT_SECONDS = 5.0
_POLL_INTERVAL_SECONDS = 0.02


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
    """Own a non-inheritable kill-on-close job and admit suspended children."""

    def __init__(self) -> None:
        self._handle = None
        self._assigned_process_handle = None
        self.error = None  # Compatibility diagnostic; API failures raise directly.
        if os.name != "nt":
            return
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._wintypes = wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class BASIC_LIMIT_INFORMATION(ctypes.Structure):
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

        class EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        class THREADENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
            ]

        self._accounting_type = BASIC_ACCOUNTING_INFORMATION
        self._thread_entry_type = THREADENTRY32
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        for name in ("Thread32First", "Thread32Next"):
            function = getattr(kernel32, name)
            function.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
            function.restype = wintypes.BOOL
        kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
        kernel32.GetProcessIdOfThread.restype = wintypes.DWORD
        kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        kernel32.ResumeThread.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.PeekNamedPipe.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.PeekNamedPipe.restype = wintypes.BOOL

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise self._error("CreateJobObjectW")
        self._handle = handle
        try:
            information = EXTENDED_LIMIT_INFORMATION()
            information.BasicLimitInformation.LimitFlags = 0x00002000
            if not kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(information), ctypes.sizeof(information),
            ):
                raise self._error("SetInformationJobObject")
        except BaseException:
            self.close()
            raise

    def _error(self, operation: str) -> OSError:
        return OSError(self._ctypes.get_last_error(), operation + " failed")

    def _close_handle(self, handle: object) -> None:
        if not self._kernel32.CloseHandle(handle):
            raise self._error("CloseHandle")

    def _require_live_process(self, process: subprocess.Popen[bytes]) -> None:
        result = self._kernel32.WaitForSingleObject(int(process._handle), 0)
        if result == 0xFFFFFFFF:
            raise self._error("WaitForSingleObject")
        if result != 0x00000102:
            raise ProcessControlError("suspended child is no longer live")

    @property
    def active(self) -> bool:
        """Whether this wrapper owns a job handle, not whether a child is live."""
        return self._handle is not None

    @property
    def assigned(self) -> bool:
        return self._handle is not None and self._assigned_process_handle is not None

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        if self._handle is None:
            raise ProcessControlError("Windows job is unavailable")
        self._require_live_process(process)
        if not self._kernel32.AssignProcessToJobObject(
            self._handle, int(process._handle),
        ):
            raise self._error("AssignProcessToJobObject")
        self._assigned_process_handle = int(process._handle)

    def resume(self, process: subprocess.Popen[bytes], deadline: float) -> None:
        """Resume exactly one owned initial thread after job assignment."""
        if not self.assigned or self._assigned_process_handle != int(process._handle):
            raise ProcessControlError("cannot resume a child not assigned to this job")
        self._require_live_process(process)
        ctypes = self._ctypes
        kernel32 = self._kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise self._error("CreateToolhelp32Snapshot")
        candidate = None
        try:
            entry = self._thread_entry_type()
            entry.dwSize = ctypes.sizeof(entry)
            present = kernel32.Thread32First(snapshot, ctypes.byref(entry))
            scanned = 0
            while present:
                scanned += 1
                if scanned > 100_000 or time.monotonic() >= deadline:
                    raise ProcessControlError("suspended-thread enumeration exceeded its budget")
                required_size = self._thread_entry_type.th32OwnerProcessID.offset + 4
                if entry.dwSize < required_size:
                    raise ProcessControlError("thread snapshot omitted ownership fields")
                if entry.th32OwnerProcessID == process.pid:
                    if candidate is not None:
                        raise ProcessControlError("suspended child has multiple initial threads")
                    candidate = int(entry.th32ThreadID)
                entry.dwSize = ctypes.sizeof(entry)
                present = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
            error = ctypes.get_last_error()
            if error != 18:  # ERROR_NO_MORE_FILES
                raise OSError(error, "thread enumeration failed")
        finally:
            self._close_handle(snapshot)
        if candidate is None:
            raise ProcessControlError("suspended child's initial thread was not found")
        self._require_live_process(process)
        # THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION; no inheritance.
        thread = kernel32.OpenThread(0x0002 | 0x0800, False, candidate)
        if not thread:
            raise self._error("OpenThread")
        try:
            owner = kernel32.GetProcessIdOfThread(thread)
            if owner == 0:
                raise self._error("GetProcessIdOfThread")
            if owner != process.pid:
                raise ProcessControlError("suspended-thread ownership changed")
            self._require_live_process(process)
            if time.monotonic() >= deadline:
                raise ProcessControlError("child deadline expired before resume")
            previous_count = kernel32.ResumeThread(thread)
            if previous_count == 0xFFFFFFFF:
                raise self._error("ResumeThread")
            if previous_count != 1:
                raise ProcessControlError("unexpected initial thread suspend count")
        finally:
            self._close_handle(thread)

    def active_process_count(self) -> int:
        if self._handle is None:
            raise ProcessControlError("cannot query a closed Windows job")
        information = self._accounting_type()
        if not self._kernel32.QueryInformationJobObject(
            self._handle, 1, self._ctypes.byref(information),
            self._ctypes.sizeof(information), None,
        ):
            raise self._error("QueryInformationJobObject")
        return int(information.ActiveProcesses)

    def pipe_available(self, descriptor: int) -> int | None:
        """Return bytes ready, zero for open/empty, or None for broken-pipe EOF.

        This broker must be the sole I/O owner. It calls os.read() for no more
        than the available amount. No competing buffered reads are permitted.
        PeekNamedPipe on a synchronous handle is not a universal nonblocking
        guarantee for arbitrary multithreaded embeddings (Microsoft caveat).
        """
        import msvcrt

        available = self._wintypes.DWORD()
        handle = msvcrt.get_osfhandle(descriptor)
        if not self._kernel32.PeekNamedPipe(
            handle, None, 0, None, self._ctypes.byref(available), None,
        ):
            error = self._ctypes.get_last_error()
            if error == 109:  # ERROR_BROKEN_PIPE; anonymous pipe writers closed.
                return None
            raise OSError(error, "PeekNamedPipe failed")
        return int(available.value)

    def terminate(self) -> None:
        if self._handle is not None:
            if not self._kernel32.TerminateJobObject(self._handle, 1):
                raise self._error("TerminateJobObject")

    def close(self) -> None:
        if self._handle is not None:
            handle = self._handle
            self._close_handle(handle)
            self._handle = None
            self._assigned_process_handle = None


def _positive_limit(name: str, value: int | float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    try:
        rendered = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite positive number") from exc
    if not math.isfinite(rendered) or rendered <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return rendered


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


def _require_windows_containment(
    process: subprocess.Popen[bytes],
    job: _WindowsJob,
) -> None:
    if os.name != "nt" or job.active and job.assigned:
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


def _require_posix_ownership() -> None:
    if os.name == "nt":
        return
    required = ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "set_blocking")
    if any(not hasattr(os, name) for name in required):
        raise ProcessControlError(
            "safe process-group ownership requires waitid/WNOWAIT and nonblocking pipes; "
            "on macOS use Python 3.13 or later"
        )
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ProcessControlError(
            "process-group ownership requires default SIGCHLD handling and exclusive child reaping"
        )


def _posix_child_exited(process: subprocess.Popen[bytes]) -> bool:
    """Observe the child without releasing its PID or process-group identity."""
    if process.returncode is not None:
        raise ProcessControlError("owned child was reaped before process-group cleanup")
    try:
        observed = os.waitid(
            os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as exc:
        raise ProcessControlError("owned child identity was lost before cleanup") from exc
    if observed is not None and observed.si_pid != process.pid:
        raise ProcessControlError("child observation did not match the owned identity")
    return observed is not None


def _signal_owned_group(process: subprocess.Popen[bytes], signum: int) -> None:
    # A waitable child anchors this PID until the last group signal. In
    # particular, Popen.poll/terminate/kill must not be used on this POSIX path.
    _posix_child_exited(process)
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


class _OutputPipe:
    """One bounded pipe, read only by the broker's controlling thread."""

    def __init__(self, stream: object, state: _CaptureState, job: _WindowsJob) -> None:
        self.stream = stream
        self.state = state
        self.job = job
        self.descriptor = stream.fileno()  # type: ignore[attr-defined]
        self.finished = False
        if os.name != "nt":
            os.set_blocking(self.descriptor, False)

    def read_available(self) -> bool:
        if self.finished:
            return False
        amount = _READ_CHUNK if self.state.exceeded else min(
            _READ_CHUNK, max(1, self.state.limit - self.state.stored + 1),
        )
        if os.name == "nt":
            available = self.job.pipe_available(self.descriptor)
            if available is None:
                self.finished = True
                return False
            if not available:
                return False
            amount = min(amount, available)
        try:
            chunk = os.read(self.descriptor, amount)
        except BlockingIOError:
            return False
        if not chunk:
            self.finished = True
            return False
        self.state.accept(chunk)
        return True


def _pump_outputs(pipes: list[_OutputPipe]) -> bool:
    received = False
    for pipe in pipes:
        received = pipe.read_available() or received
    return received


def _terminate_tree(
    process: subprocess.Popen[bytes],
    job: _WindowsJob,
    *,
    graceful: bool = True,
    cleanup_deadline: float | None = None,
) -> None:
    """Stop the owned group/job before reaping the leader."""
    if os.name == "nt":
        try:
            if job.active:
                job.terminate()
        finally:
            if not job.assigned:
                # Even a failed empty-job termination must not skip killing
                # the still-suspended child that failed job admission.
                process.kill()
        return
    if not graceful:
        _signal_owned_group(process, signal.SIGKILL)
        return
    try:
        _signal_owned_group(process, signal.SIGTERM)
        remaining = _TERMINATION_GRACE_SECONDS
        if cleanup_deadline is not None:
            remaining = min(remaining, max(0.0, cleanup_deadline - time.monotonic()))
        # Event.wait is a timer here, not a capture thread. A cancellation
        # injected into the monitor's sleep does not interrupt cleanup again.
        threading.Event().wait(remaining)
    finally:
        _signal_owned_group(process, signal.SIGKILL)


def _finish_process(
    process: subprocess.Popen[bytes],
    job: _WindowsJob,
    pipes: list[_OutputPipe],
    *,
    graceful: bool,
) -> None:
    """Make every post-launch exit release owned resources within one budget."""
    deadline = time.monotonic() + _CLEANUP_TIMEOUT_SECONDS
    failure: BaseException | None = None
    try:
        try:
            _terminate_tree(process, job, graceful=graceful, cleanup_deadline=deadline)
        except BaseException as exc:
            failure = exc
            # On Windows, closing our job is the kill-on-close fallback. It
            # cannot restore a failed containment observation to a success.
            if os.name == "nt":
                try:
                    job.close()
                except BaseException:
                    pass
        try:
            # The last POSIX group signal has already happened. Only now may
            # wait() release the leader's PID and obtain its real return code.
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except BaseException as exc:
            if failure is None:
                failure = exc
        try:
            while True:
                received = _pump_outputs(pipes)
                job_empty = os.name != "nt" or not job.active or job.active_process_count() == 0
                if all(pipe.finished for pipe in pipes) and job_empty:
                    break
                if time.monotonic() >= deadline:
                    raise ProcessControlError(
                        "owned process cleanup or output pipes did not finish within the cleanup budget"
                    )
                if not received:
                    threading.Event().wait(min(_POLL_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))
        except BaseException as exc:
            if failure is None:
                failure = exc
    finally:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
        try:
            job.close()
        except BaseException as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        raise ProcessControlError("owned process cleanup did not complete safely") from failure


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
    """Run a controlled command with bounded output and an execution deadline.

    The deadline remains active until the leader has exited and both output
    pipes reach EOF. Cleanup has a separate five-second budget, including at
    most one second of POSIX TERM grace. POSIX descendants that leave the new
    process group are outside this boundary. Detached pipe writers cause a
    bounded cleanup error; they are not silently described as contained.

    Returned bytes are exact stream prefixes. Inspect both limit flags before
    treating the return code as meaningful. The host must not reap this child
    or change SIGCHLD handling while the broker owns it.
    """
    argv = _normalise_command(command)
    timeout_seconds = _positive_limit("timeout", timeout)
    stdout_ceiling = _positive_byte_limit("stdout_limit", stdout_limit)
    stderr_ceiling = _positive_byte_limit("stderr_limit", stderr_limit)
    working_directory = Path(cwd)
    if not working_directory.is_dir():
        raise ProcessControlError(f"working directory is not a directory: {working_directory}")
    child_environment = _normalise_environment(
        environment, replace_environment=replace_environment,
    )
    _require_posix_ownership()
    stdout_state = _CaptureState(stdout_ceiling, [])
    stderr_state = _CaptureState(stderr_ceiling, [])
    pipes: list[_OutputPipe] = []
    # The Windows job exists before process creation, so failure to create the
    # job cannot leave a running child. CREATE_SUSPENDED closes the admission race.
    job = _WindowsJob()
    process = None
    timed_out = False
    output_limit_exceeded = False
    started = time.monotonic()
    deadline = started + timeout_seconds
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | 0x00000004
    try:
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
                start_new_session=os.name != "nt",
                creationflags=creationflags,
                bufsize=0,
            )
        except OSError as exc:
            raise ProcessControlError(f"could not launch {argv[0]!r}: {exc}") from exc
        pipes.append(_OutputPipe(process.stdout, stdout_state, job))
        pipes.append(_OutputPipe(process.stderr, stderr_state, job))
        if os.name == "nt":
            job.assign(process)
            _require_windows_containment(process, job)
            job.resume(process, deadline)
        while True:
            received = _pump_outputs(pipes)
            output_limit_exceeded = stdout_state.exceeded or stderr_state.exceeded
            if output_limit_exceeded:
                break
            leader_exited = process.poll() is not None if os.name == "nt" else _posix_child_exited(process)
            if leader_exited and all(pipe.finished for pipe in pipes):
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if not received:
                time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))
    except BaseException as primary:
        if process is not None:
            try:
                _finish_process(process, job, pipes, graceful=True)
            except BaseException as cleanup_error:
                raise primary from cleanup_error
        else:
            try:
                job.close()
            except BaseException as cleanup_error:
                raise primary from cleanup_error
        raise
    _finish_process(
        process, job, pipes,
        graceful=timed_out or output_limit_exceeded,
    )
    output_limit_exceeded = output_limit_exceeded or stdout_state.exceeded or stderr_state.exceeded
    return ProcessResult(
        args=argv,
        returncode=int(process.returncode if process.returncode is not None else -1),
        stdout=stdout_state.value(),
        stderr=stderr_state.value(),
        duration_seconds=max(0.0, time.monotonic() - started),
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
