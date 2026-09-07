from __future__ import annotations

import ctypes
import errno
import json
import os
import signal
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codeprobe_engine import process_control  # noqa: E402
from codeprobe_engine.process_control import (  # noqa: E402
    ProcessControlError,
    run_bounded_process,
)


# These programmes are test-owned fixtures, never submitted source. Every
# running process exits after thirty seconds even if broker and test both fail.
# Files provide readiness and cooperative cleanup without signalling a reused PID.
_FIXTURE_SOURCE = r'''
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
options = json.loads(sys.argv[2])
role = sys.argv[3]
expires = time.monotonic() + 30

def identity():
    result = {"pid": os.getpid(), "platform": sys.platform}
    if sys.platform.startswith("linux"):
        proc_pid = int(os.readlink("/proc/self"))
        stat = Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()
        status = Path("/proc/self/status").read_text().splitlines()
        ns = next(line for line in status if line.startswith("NSpid:"))
        result.update(proc_pid=proc_pid, start=stat[19],
                      nspid=[int(p) for p in ns.split()[1:]],
                      namespace=os.readlink("/proc/self/ns/pid"))
    elif os.name == "nt":
        from ctypes import wintypes
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.GetCurrentProcess.restype = wintypes.HANDLE
        api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        api.GetProcessTimes.restype = wintypes.BOOL
        values = [wintypes.FILETIME() for _ in range(4)]
        if not api.GetProcessTimes(api.GetCurrentProcess(), *map(ctypes.byref, values)):
            raise ctypes.WinError(ctypes.get_last_error())
        result["created"] = values[0].dwLowDateTime | (values[0].dwHighDateTime << 32)
    elif sys.platform == "darwin":
        class Info(ctypes.Structure):
            _fields_ = [("prefix", ctypes.c_uint32 * 12),
                        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
                        ("suffix", ctypes.c_uint32 * 5), ("nice", ctypes.c_int32),
                        ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]
        api = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        api.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                    ctypes.c_void_p, ctypes.c_int]
        api.proc_pidinfo.restype = ctypes.c_int
        info = Info()
        if ctypes.sizeof(info) != 136 or api.proc_pidinfo(os.getpid(), 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info):
            raise OSError(ctypes.get_errno(), "proc_pidinfo failed")
        if info.prefix[3] != os.getpid() or info.start_sec <= 0:
            raise RuntimeError("Darwin identity ABI was not verified")
        result.update(start_sec=info.start_sec, start_usec=info.start_usec)
    else:
        raise RuntimeError("This platform has no qualified process-identity oracle")
    return result

def publish():
    target = root / (role + ".json")
    pending = target.with_suffix(".pending")
    pending.write_text(json.dumps(identity()), encoding="utf-8")
    os.replace(pending, target)

def wait_for(name):
    while time.monotonic() < expires and not (root / "stop").exists():
        if (root / name).exists():
            return True
        time.sleep(0.01)
    return False

def idle():
    while time.monotonic() < expires and not (root / "stop").exists():
        time.sleep(0.02)

if options.get("ignore_term") and role == "leaf" and os.name != "nt":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
publish()
if role == "leader" and options.get("tree"):
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", __file__, str(root), sys.argv[2], "leaf"],
        stdin=subprocess.DEVNULL,
        start_new_session=bool(options.get("detached")),
    )
    if not wait_for("leaf.json"):
        sys.exit(2)
if role == "leader":
    (root / "ready").touch()
if not wait_for("release"):
    sys.exit(3)
if options.get("close_pipes") or (options.get("detached") and not options.get("retain_pipes")):
    os.close(1)
    os.close(2)
if role == "leader" and options.get("leader_exit"):
    sys.exit(0)
if role == "leader" and options.get("stream"):
    os.write(options["stream"], bytes.fromhex(options["output_hex"]))
idle()
'''


def _linux_state(record: dict[str, object]) -> tuple[bool, str]:
    """Read the recorded procfs identity, without polling/reaping any Popen."""
    directory = Path("/proc") / str(record["proc_pid"])
    try:
        fields = (directory / "stat").read_text().rsplit(") ", 1)[1].split()
        status = (directory / "status").read_text().splitlines()
        ns = next(line for line in status if line.startswith("NSpid:"))
        actual = (fields[19], [int(p) for p in ns.split()[1:]],
                  os.readlink(directory / "ns/pid"))
    except FileNotFoundError:
        return False, "absent"
    expected = (record["start"], record["nspid"], record["namespace"])
    return actual == expected, fields[0]


class _DarwinInfo(ctypes.Structure):
    # struct proc_bsdinfo: the fixed-size BSD process identity record.
    _fields_ = [
        ("prefix", ctypes.c_uint32 * 12),
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        ("suffix", ctypes.c_uint32 * 5), ("nice", ctypes.c_int32),
        ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64),
    ]


class _ObservedProcess:
    """A process first proved live, then observed by its kernel identity."""

    def __init__(self, record: dict[str, object], *, allow_terminate: bool = False) -> None:
        self.record = record
        self.handle = None
        self.verified = False
        if os.name == "nt":
            from ctypes import wintypes
            self.api = ctypes.WinDLL("kernel32", use_last_error=True)
            self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self.api.OpenProcess.restype = wintypes.HANDLE
            self.api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            self.api.GetProcessTimes.restype = wintypes.BOOL
            self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            self.api.WaitForSingleObject.restype = wintypes.DWORD
            self.api.CloseHandle.argtypes = [wintypes.HANDLE]
            self.api.CloseHandle.restype = wintypes.BOOL
            self.api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            self.api.TerminateProcess.restype = wintypes.BOOL
            # Only the suspended assignment-failure fixture needs terminate
            # access: it cannot observe a cooperative stop file before resume.
            access = 0x1000 | 0x100000 | (1 if allow_terminate else 0)
            self.handle = self.api.OpenProcess(access, False, int(record["pid"]))
            if not self.handle:
                raise ctypes.WinError(ctypes.get_last_error())
            values = [wintypes.FILETIME() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *map(ctypes.byref, values)):
                self.close()
                raise ctypes.WinError(ctypes.get_last_error())
            actual = values[0].dwLowDateTime | (values[0].dwHighDateTime << 32)
            if actual != record["created"]:
                self.close()
                raise AssertionError("Windows creation identity does not match")
        elif sys.platform == "darwin":
            self.api = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.api.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                             ctypes.c_void_p, ctypes.c_int]
            self.api.proc_pidinfo.restype = ctypes.c_int
        try:
            if not self.alive():
                raise AssertionError("Fixture identity was not verified while alive")
        except BaseException:
            self.close()
            raise
        self.verified = True

    def alive(self) -> bool:
        if sys.platform.startswith("linux"):
            if (int(self.record["nspid"][-1]) != self.record["pid"] or
                    int(self.record["nspid"][0]) != self.record["proc_pid"]):
                raise AssertionError("Caller and procfs IDs do not match the recorded namespace mapping")
            matches, state = _linux_state(self.record)
            if not self.verified and not matches:
                raise AssertionError("Recorded PID/procfs/NSpid/start-time identity does not match")
            return matches and state not in {"Z", "X"}
        if os.name == "nt":
            status = self.api.WaitForSingleObject(self.handle, 0)
            if status == 0:
                return False
            if status == 0x102:
                return True
            raise OSError("WaitForSingleObject failed: " + str(status))
        if sys.platform == "darwin":
            info = _DarwinInfo()
            if ctypes.sizeof(info) != 136:
                raise AssertionError("Darwin process-identity ABI is unavailable")
            ctypes.set_errno(0)
            size = self.api.proc_pidinfo(int(self.record["pid"]), 3, 0,
                                         ctypes.byref(info), ctypes.sizeof(info))
            if size == 0 and ctypes.get_errno() == 3:  # ESRCH
                if not self.verified:
                    raise AssertionError("Darwin process was not observed alive")
                return False
            if size != ctypes.sizeof(info):
                raise OSError(ctypes.get_errno(), "proc_pidinfo identity unavailable")
            matches = (info.prefix[3] == self.record["pid"] and
                       info.start_sec == self.record["start_sec"] and
                       info.start_usec == self.record["start_usec"])
            if not self.verified and not matches:
                raise AssertionError("Darwin start-time identity does not match")
            return matches and info.prefix[1] != 5  # SZOMB
        raise unittest.SkipTest("No qualified process-identity oracle for this platform")

    def close(self) -> None:
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def terminate_suspended_fixture(self) -> None:
        if os.name != "nt" or not self.verified:
            raise AssertionError("Suspended fixture cleanup requires a verified Windows handle")
        if self.alive():
            if not self.api.TerminateProcess(self.handle, 97):
                raise ctypes.WinError(ctypes.get_last_error())
            if self.api.WaitForSingleObject(self.handle, 5000) != 0:
                raise AssertionError("Verified suspended fixture did not terminate")


class _OwnedFixture:
    """External observer and finite fallback cleanup for one broker invocation."""

    def __init__(self, **options: object) -> None:
        self.options = options
        self.temporary = tempfile.TemporaryDirectory(prefix="codeprobe-process-test-")
        self.root = Path(self.temporary.name)
        self.script = self.root / "fixture.py"
        self.script.write_text(_FIXTURE_SOURCE, encoding="utf-8")
        self.observers: list[_ObservedProcess] = []
        self.armed = threading.Event()
        self.done = threading.Event()
        self.outcome: list[object] = []
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "_OwnedFixture":
        return self

    def run(self, *, timeout: float = 3, **kwargs: object):
        def execute() -> None:
            try:
                self.outcome.append(run_bounded_process(
                    [sys.executable, "-I", "-S", "-B", str(self.script),
                     str(self.root), json.dumps(self.options), "leader"],
                    cwd=ROOT, timeout=timeout, **kwargs,
                ))
            except BaseException as exc:
                self.outcome.append(exc)
            finally:
                self.done.set()
        self.thread = threading.Thread(target=execute, name="broker-test-call", daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 5
        while not (self.root / "ready").exists():
            if self.done.is_set():
                self._result()
                raise AssertionError("Broker returned before fixture readiness")
            if time.monotonic() >= deadline:
                raise AssertionError("Fixture did not complete its bounded readiness handshake")
            time.sleep(0.01)
        roles = ["leader", "leaf"] if self.options.get("tree") else ["leader"]
        for role in roles:
            record = json.loads((self.root / (role + ".json")).read_text(encoding="utf-8"))
            self.observers.append(_ObservedProcess(record))
        (self.root / "release").touch()
        self.armed.set()
        if not self.done.wait(timeout + 6):
            raise AssertionError("Broker exceeded deadline plus bounded cleanup allowance")
        return self._result()

    def _result(self):
        result = self.outcome[0]
        if isinstance(result, BaseException):
            raise result
        return result

    def assert_stopped(self) -> None:
        deadline = time.monotonic() + 2
        while any(observer.alive() for observer in self.observers):
            if time.monotonic() >= deadline:
                self.print_identities()
                raise AssertionError("An independently identified fixture process remains live")
            time.sleep(0.01)
        self.print_identities()

    def print_identities(self) -> None:
        print("PROCESS_FIXTURE_IDENTITY=" + json.dumps({
            "platform": sys.platform,
            "detached_characterisation": bool(self.options.get("detached")),
            "processes": [{"identity": observer.record,
                           "observed_live_before_release": observer.verified,
                           "live_now": observer.alive()}
                          for observer in self.observers],
        }, sort_keys=True))

    def __exit__(self, kind, error, traceback) -> None:
        (self.root / "stop").touch()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            live = any(observer.alive() for observer in self.observers)
            if not live and (self.thread is None or self.done.is_set()):
                break
            time.sleep(0.01)
        else:
            message = "Independent fixture cleanup did not finish; preserve external supervisor evidence"
            if error is None:
                raise AssertionError(message)
            if hasattr(error, "add_note"):
                error.add_note(message)
            else:
                print("FIXTURE_CLEANUP_ERROR=" + message, file=sys.stderr)
        for observer in self.observers:
            observer.close()
        self.temporary.cleanup()


@unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin" or os.name == "nt",
                     "Requires a qualified native process-identity oracle")
class ProcessControlTests(unittest.TestCase):
    def test_success_and_nonzero_capture_exact_bytes(self) -> None:
        for returncode in (0, 7):
            with self.subTest(returncode=returncode):
                result = run_bounded_process(
                    [sys.executable, "-I", "-S", "-B", "-c",
                     "import os; os.write(1, b'out\\x00\\xff\\r\\n'); "
                     "os.write(2, b'err\\xfe\\n'); raise SystemExit(" + str(returncode) + ")"],
                    cwd=ROOT, timeout=10, stdout_limit=1024, stderr_limit=1024,
                )
                self.assertEqual(result.returncode, returncode)
                self.assertFalse(result.timed_out)
                self.assertFalse(result.output_limit_exceeded)
                self.assertEqual(result.stdout, b"out\x00\xff\r\n")
                self.assertEqual(result.stderr, b"err\xfe\n")
                self.assertEqual(result.stdout_text, "out\x00\\xff\r\n")
                self.assertEqual(result.stderr_text, "err\\xfe\n")

    def test_shell_string_is_rejected_without_launch(self) -> None:
        with mock.patch.object(process_control.subprocess, "Popen",
                               side_effect=AssertionError("invalid input reached Popen")) as launch:
            with self.assertRaisesRegex(TypeError, "shell string"):
                run_bounded_process("echo unsafe", cwd=ROOT)  # type: ignore[arg-type]
        launch.assert_not_called()

    def test_invalid_deadlines_and_byte_limits_never_launch(self) -> None:
        cases = [("timeout", value) for value in (float("nan"), float("inf"),
                 -float("inf"), 0, -1, True, 10 ** 400)]
        cases += [(name, value) for name in ("stdout_limit", "stderr_limit")
                  for value in (0, -1, 1.5, True)]
        for keyword, value in cases:
            with self.subTest(keyword=keyword, value=value):
                with mock.patch.object(process_control.subprocess, "Popen",
                                       side_effect=AssertionError("invalid input reached Popen")) as launch:
                    with self.assertRaises(ValueError):
                        run_bounded_process([sys.executable, "-I", "-S", "-B", "-c", "pass"],
                                            cwd=ROOT, **{keyword: value})
                launch.assert_not_called()

    def test_short_and_exact_cap_outputs_are_not_overflows(self) -> None:
        for count in (1, 16):
            with self.subTest(count=count):
                result = run_bounded_process(
                    [sys.executable, "-I", "-S", "-B", "-c",
                     "import os; os.write(1, b'a'*" + str(count) + "); "
                     "os.write(2, b'b'*" + str(count) + ")"],
                    cwd=ROOT, timeout=10, stdout_limit=16, stderr_limit=16,
                )
                self.assertEqual((result.stdout, result.stderr), (b"a" * count, b"b" * count))
                self.assertEqual(result.returncode, 0)
                self.assertFalse(result.output_limit_exceeded)
                self.assertFalse(result.timed_out)

    def test_cap_plus_one_on_each_stream_is_detected_before_deadline(self) -> None:
        for stream in (1, 2):
            with self.subTest(stream=stream), _OwnedFixture(stream=stream, output_hex=(b"x" * 17).hex()) as fixture:
                started = time.monotonic()
                result = fixture.run(timeout=6, stdout_limit=16, stderr_limit=16)
                elapsed = time.monotonic() - started
                self.assertTrue(result.output_limit_exceeded)
                self.assertFalse(result.timed_out)
                self.assertLess(elapsed, 4, "Overflow waited towards the later six-second deadline")
                expected = (b"x" * 16, b"") if stream == 1 else (b"", b"x" * 16)
                self.assertEqual((result.stdout, result.stderr), expected)
                fixture.assert_stopped()

    def test_replace_and_extend_environment(self) -> None:
        for replace in (False, True):
            with self.subTest(replace=replace), mock.patch.dict(os.environ, {"CODEPROBE_AMBIENT_SECRET": "present"}):
                result = run_bounded_process(
                    [sys.executable, "-I", "-S", "-B", "-c",
                     "import os; print(os.environ.get('CODEPROBE_AMBIENT_SECRET', 'absent')); "
                     "print(os.environ['CODEPROBE_EXPLICIT'])"],
                    cwd=ROOT, environment={"CODEPROBE_EXPLICIT": "retained"},
                    replace_environment=replace, timeout=10,
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout_text.splitlines(),
                                 ["absent" if replace else "present", "retained"])

    def test_timeout_terminates_ordinary_child_and_descendant(self) -> None:
        with _OwnedFixture(tree=True) as fixture:
            result = fixture.run()
            self.assertTrue(result.timed_out)
            self.assertFalse(result.output_limit_exceeded)
            fixture.assert_stopped()

    @unittest.skipUnless(os.name == "posix", "POSIX signal disposition")
    def test_term_ignoring_descendant_is_killed_after_leader_termination(self) -> None:
        with _OwnedFixture(tree=True, ignore_term=True, close_pipes=True) as fixture:
            result = fixture.run()
            self.assertTrue(result.timed_out)
            fixture.assert_stopped()

    def test_deadline_survives_normal_leader_exit_with_inherited_pipes(self) -> None:
        with _OwnedFixture(tree=True, leader_exit=True, ignore_term=True) as fixture:
            result = fixture.run()
            self.assertTrue(result.timed_out, "Leader exit must not cancel the open-pipe deadline")
            self.assertFalse(result.output_limit_exceeded)
            fixture.assert_stopped()

    def test_oracle_observes_live_then_completed_identity(self) -> None:
        with _OwnedFixture() as fixture:
            result = fixture.run()
            self.assertTrue(result.timed_out)
            self.assertEqual(len(fixture.observers), 1)
            record = fixture.observers[0].record
            fixture.assert_stopped()
            if sys.platform.startswith("linux"):
                layout = "same-namespace" if record["pid"] == record["proc_pid"] else "outer-mounted"
                print("PROCESS_IDENTITY_LAYOUT=" + layout)
            else:
                print("PROCESS_IDENTITY_PLATFORM=" + sys.platform)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux procfs identity oracle")
    def test_procfs_oracle_rejects_unverified_missing_and_wrong_start_identities(self) -> None:
        # The fixture thread is paused at the release handshake while this
        # injection inspects an independently published live identity.
        with _OwnedFixture() as fixture:
            original = _ObservedProcess.__init__
            checked = []
            def inspect(observer, record):
                original(observer, record)
                if checked:
                    return
                checked.append(True)
                wrong_start = dict(record, start=str(int(record["start"]) + 1))
                with self.assertRaises(AssertionError):
                    candidate = object.__new__(_ObservedProcess)
                    original(candidate, wrong_start)
                missing = dict(record, proc_pid=2147483647, pid=2147483647,
                               nspid=[2147483647])
                with self.assertRaises(AssertionError):
                    candidate = object.__new__(_ObservedProcess)
                    original(candidate, missing)
            with mock.patch.object(_ObservedProcess, "__init__", inspect):
                fixture.run()
            self.assertEqual(checked, [True])
            fixture.assert_stopped()

    def test_cancellation_preserves_original_exception_after_cleanup(self) -> None:
        for leader_exit in (False, True):
            with self.subTest(leader_exit=leader_exit), _OwnedFixture(tree=True, leader_exit=leader_exit) as fixture:
                cancellation = KeyboardInterrupt("owned cancellation fixture")
                fired = []
                class Clock:
                    monotonic = staticmethod(time.monotonic)
                    @staticmethod
                    def sleep(seconds):
                        if fixture.armed.is_set() and not fired:
                            if not leader_exit or not fixture.observers[0].alive():
                                fired.append(True)
                                raise cancellation
                        time.sleep(seconds)
                with mock.patch.object(process_control, "time", Clock):
                    started = time.monotonic()
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        fixture.run(timeout=6)
                self.assertLess(time.monotonic() - started, 5,
                                "Cancellation waited towards the fixture's natural exit")
                self.assertIs(caught.exception, cancellation)
                self.assertEqual(fired, [True])
                fixture.assert_stopped()

    @unittest.skipUnless(os.name == "posix", "POSIX nonblocking pipe setup")
    def test_partial_pipe_setup_failure_preserves_error_and_cleans_child(self) -> None:
        original = os.set_blocking
        for successful_setups in (0, 1):
            with self.subTest(successful_setups=successful_setups), _OwnedFixture() as fixture:
                failure = RuntimeError("owned pipe-setup failure")
                calls = []
                def fail_setup(fd, blocking):
                    if len(calls) == successful_setups:
                        if not fixture.armed.wait(5):
                            raise AssertionError("No independently observed child before setup injection")
                        calls.append("failed")
                        raise failure
                    calls.append("configured")
                    return original(fd, blocking)
                with mock.patch.object(process_control.os, "set_blocking", fail_setup):
                    with self.assertRaises(RuntimeError) as caught:
                        fixture.run(timeout=6)
                self.assertIs(caught.exception, failure)
                self.assertIn("failed", calls)
                fixture.assert_stopped()

    @unittest.skipUnless(os.name == "posix", "POSIX pipe read fault")
    def test_pipe_read_failure_is_not_reported_as_success(self) -> None:
        with _OwnedFixture(stream=1, output_hex="61") as fixture:
            original = os.read
            failure = OSError("owned pipe-read failure")
            fired = []
            def fail_read(fd, size):
                if fixture.armed.is_set() and not fired:
                    fired.append(True)
                    raise failure
                return original(fd, size)
            with mock.patch.object(process_control.os, "read", fail_read):
                with self.assertRaises((OSError, ProcessControlError)) as caught:
                    fixture.run(timeout=6)
            self.assertTrue(caught.exception is failure or caught.exception.__cause__ is failure)
            self.assertEqual(fired, [True])
            fixture.assert_stopped()

    def test_windows_containment_failure_kills_the_child_and_fails_closed(self) -> None:
        # A contract mock; only the actual Windows fixtures qualify Job behaviour.
        process = mock.Mock()
        job = mock.Mock(active=False, error=OSError("job unavailable"))
        with mock.patch.object(process_control.os, "name", "nt"):
            with self.assertRaisesRegex(ProcessControlError, "Windows Job Object"):
                process_control._require_windows_containment(process, job)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

    @unittest.skipUnless(os.name == "nt", "Actual Windows suspended-process and Job assignment boundary")
    def test_windows_assignment_failure_terminates_verified_suspended_process(self) -> None:
        from ctypes import wintypes
        observed: list[_ObservedProcess] = []
        failure = OSError("injected Job assignment failure")
        with tempfile.TemporaryDirectory(prefix="codeprobe-suspended-test-") as tmp:
            marker = Path(tmp) / "resumed"
            def fail_assignment(job, process):
                api = ctypes.WinDLL("kernel32", use_last_error=True)
                api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
                api.GetProcessTimes.restype = wintypes.BOOL
                values = [wintypes.FILETIME() for _ in range(4)]
                if not api.GetProcessTimes(int(process._handle), *map(ctypes.byref, values)):
                    raise ctypes.WinError(ctypes.get_last_error())
                record = {"pid": process.pid, "platform": sys.platform,
                          "created": values[0].dwLowDateTime | (values[0].dwHighDateTime << 32)}
                observed.append(_ObservedProcess(record, allow_terminate=True))
                raise failure
            try:
                with mock.patch.object(process_control._WindowsJob, "assign", fail_assignment):
                    with self.assertRaises(OSError) as caught:
                        run_bounded_process(
                            [sys.executable, "-I", "-S", "-B", "-c",
                             "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()"],
                            cwd=ROOT, timeout=6,
                        )
                self.assertIs(caught.exception, failure)
                self.assertEqual(len(observed), 1)
                self.assertFalse(observed[0].alive())
                self.assertFalse(marker.exists(), "The unassigned child executed before failure")
                print("WINDOWS_SUSPENDED_IDENTITY=" + json.dumps({
                    "identity": observed[0].record, "verified_live_before_failure": True,
                    "live_after_failure": observed[0].alive(), "resumed_marker": marker.exists(),
                    "failure_kind": "injected assignment error on a real suspended process",
                }, sort_keys=True))
            finally:
                for observer in observed:
                    try:
                        observer.terminate_suspended_fixture()
                    finally:
                        observer.close()

    @unittest.skipUnless(os.name == "posix", "POSIX detached-session scope characterisation")
    def test_detached_session_is_an_explicit_group_scope_characterisation(self) -> None:
        with _OwnedFixture(tree=True, detached=True) as fixture:
            result = fixture.run()
            self.assertTrue(result.timed_out)
            self.assertFalse(fixture.observers[0].alive())
            self.assertTrue(fixture.observers[1].alive(),
                            "Detached fixture changed; review the scope characterisation")
            fixture.print_identities()
            print("CHARACTERISATION_ONLY: detached session survives outside POSIX group containment; "
                  "A01-F003 universal containment remains OPEN")
            (fixture.root / "stop").touch()
            fixture.assert_stopped()

    def test_cancellation_chains_cleanup_failure_after_owned_child_stops(self) -> None:
        with _OwnedFixture(tree=True) as fixture:
            cancellation = KeyboardInterrupt("owned cancellation with cleanup failure")
            close_failure = OSError("injected failure after the owned job was closed")
            cancelled = []
            closed = []
            original_close = process_control._WindowsJob.close

            class Clock:
                monotonic = staticmethod(time.monotonic)

                @staticmethod
                def sleep(seconds):
                    if fixture.armed.is_set() and not cancelled:
                        cancelled.append(True)
                        raise cancellation
                    time.sleep(seconds)

            def fail_after_close(job):
                original_close(job)
                closed.append(True)
                raise close_failure

            with mock.patch.object(process_control, "time", Clock), \
                    mock.patch.object(process_control._WindowsJob, "close", fail_after_close):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    fixture.run(timeout=6)
            self.assertIs(caught.exception, cancellation)
            self.assertIsInstance(caught.exception.__cause__, ProcessControlError)
            self.assertIs(caught.exception.__cause__.__cause__, close_failure)
            self.assertEqual(cancelled, [True])
            self.assertEqual(closed, [True])
            fixture.assert_stopped()

    @unittest.skipUnless(os.name == "posix", "Actual POSIX detached pipe-writer scope")
    def test_detached_pipe_writer_fails_within_cleanup_budget(self) -> None:
        # The ordinary writer is the positive control for the same handshake
        # and inherited pipes. Neither case waits for the fixture's 30s expiry.
        for detached in (False, True):
            with self.subTest(detached=detached), _OwnedFixture(
                tree=True, leader_exit=True, detached=detached, retain_pipes=True,
            ) as fixture:
                started = time.monotonic()
                if detached:
                    with self.assertRaises(ProcessControlError) as caught:
                        fixture.run(timeout=2)
                    self.assertIsInstance(caught.exception.__cause__, ProcessControlError)
                    self.assertIn("cleanup budget", str(caught.exception.__cause__))
                    self.assertFalse(fixture.observers[0].alive())
                    self.assertTrue(fixture.observers[1].alive(),
                                    "Detached writer must still own its pipe at the failed deadline")
                    fixture.print_identities()
                    (fixture.root / "stop").touch()
                else:
                    result = fixture.run(timeout=2)
                    self.assertTrue(result.timed_out)
                    self.assertFalse(result.output_limit_exceeded)
                    self.assertEqual((result.stdout, result.stderr), (b"", b""))
                self.assertLess(time.monotonic() - started, 9,
                                "Cleanup exceeded the 2s execution + 5s cleanup budget and margin")
                fixture.assert_stopped()


class _LibprocFixture:
    """Finite public-ABI responses; this double never loads a native library."""

    anchor = 4101
    member = 4102

    def __init__(self, *, snapshots=None, list_sizes=None, records=None,
                 info_sizes=None, after_info=None) -> None:
        self.snapshots = snapshots or [[self.anchor, self.member], [self.anchor, self.member]]
        self.list_sizes = list_sizes or []
        self.records = records or {}
        self.info_sizes = info_sizes or {}
        self.after_info = after_info
        self.list_index = 0
        self.info_counts = {}
        self.proc_listpids = mock.Mock(side_effect=self._listpids)
        self.proc_pidinfo = mock.Mock(side_effect=self._pidinfo)

    def _listpids(self, kind, group, buffer, capacity):
        if kind != 2 or group != self.anchor:
            raise AssertionError("Fixture expects a process-group query")
        index = self.list_index
        self.list_index += 1
        pids = self.snapshots[min(index, len(self.snapshots) - 1)]
        data = struct.pack("=" + "i" * len(pids), *pids)
        if data:
            ctypes.memmove(buffer, data, min(len(data), capacity))
        result = self.list_sizes[index] if index < len(self.list_sizes) else len(data)
        if result == "full":
            return capacity
        if result == "oversized":
            return capacity + ctypes.sizeof(ctypes.c_int)
        return result

    def _pidinfo(self, pid, flavour, include_zombies, buffer, capacity):
        if flavour != 13 or include_zombies != 1 or capacity != 64:
            raise AssertionError("Fixture requires the public short-BSD zombie query contract")
        # Explicit public proc_bsdshortinfo layout, independent of the helper's
        # ctypes structure: four identity/state words, comm and eight words.
        record = {"pid": pid, "ppid": self.anchor, "pgid": self.anchor, "state": 5}
        changes = self.records.get(pid, {})
        index = self.info_counts.get(pid, 0)
        self.info_counts[pid] = index + 1
        if isinstance(changes, list):
            changes = changes[min(index, len(changes) - 1)]
        record.update(changes)
        data = struct.pack("=IIII16s8I", record["pid"], record["ppid"],
                           record["pgid"], record["state"], b"owned-fixture",
                           *([0] * 8))
        ctypes.memmove(buffer, data, min(len(data), capacity))
        if self.after_info is not None:
            self.after_info()
        return self.info_sizes.get(pid, len(data))


def _owned_posix_interface():
    """Model only observation/signalling syscalls; never consult a host PID."""
    process = SimpleNamespace(pid=_LibprocFixture.anchor, returncode=None)
    interface = SimpleNamespace(
        P_PID=1, WEXITED=4, WNOHANG=1, WNOWAIT=0x01000000,
        waitid=mock.Mock(return_value=SimpleNamespace(si_pid=process.pid)),
        killpg=mock.Mock(),
    )
    return process, interface


class ProcessOwnershipContractTests(unittest.TestCase):
    """Guard evidence on protocol doubles, distinct from real platform tests."""

    def _zombie_proof(self, library, *, process=None, interface=None, deadline=None):
        if process is None:
            process, interface = _owned_posix_interface()
        if deadline is None:
            deadline = time.monotonic() + 10
        with mock.patch.object(process_control, "os", interface), \
                mock.patch.object(ctypes, "CDLL", return_value=library):
            return process_control._darwin_group_is_zombie_only(process, deadline=deadline)

    def test_zombie_only_proof_accepts_complete_group_and_collected_member(self) -> None:
        for second in ([4101, 4102], [4101]):
            with self.subTest(second_snapshot=second):
                library = _LibprocFixture(snapshots=[[4101, 4102], second])
                self.assertTrue(self._zombie_proof(library))
                self.assertGreater(library.proc_pidinfo.call_count, 0)

    def test_zombie_proof_rejects_live_or_mismatched_member_records(self) -> None:
        for change in ({"state": 2}, {"state": 0}, {"pid": 9999}, {"pgid": 9999}):
            with self.subTest(change=change):
                library = _LibprocFixture(records={4102: change})
                self.assertFalse(self._zombie_proof(library))

    def test_zombie_proof_rejects_incomplete_or_failed_group_inventory(self) -> None:
        for size in (0, -1, 1, 5, "full", "oversized"):
            with self.subTest(returned_byte_count=size):
                library = _LibprocFixture(list_sizes=[size])
                self.assertFalse(self._zombie_proof(library))

    def test_zombie_proof_rejects_invalid_inventory_members(self) -> None:
        for first in ([4102], [4101, 4101], [4101, 0], [4101, -1]):
            with self.subTest(first_snapshot=first):
                self.assertFalse(self._zombie_proof(_LibprocFixture(snapshots=[first])))

    def test_zombie_proof_rejects_partial_or_failed_member_queries(self) -> None:
        for size in (-1, 0, 32, 63, 65):
            with self.subTest(returned_byte_count=size):
                library = _LibprocFixture(info_sizes={4102: size})
                self.assertFalse(self._zombie_proof(library))

    def test_zombie_proof_rejects_changed_membership_and_lost_anchor(self) -> None:
        for second in ([4101, 4102, 4103], [4102], [4101, 4101]):
            with self.subTest(second_snapshot=second):
                library = _LibprocFixture(snapshots=[[4101, 4102], second])
                self.assertFalse(self._zombie_proof(library))
        with self.subTest(same_pids="member is live at the final query"):
            library = _LibprocFixture(records={4102: [{"state": 5}, {"state": 2}]})
            self.assertFalse(self._zombie_proof(library))

    def test_zombie_proof_rejects_unavailable_api_and_library(self) -> None:
        process, interface = _owned_posix_interface()
        with mock.patch.object(process_control, "os", interface), \
                mock.patch.object(ctypes, "CDLL", side_effect=OSError("fixture library unavailable")):
            self.assertFalse(process_control._darwin_group_is_zombie_only(
                process, deadline=time.monotonic() + 10))
        self.assertFalse(self._zombie_proof(SimpleNamespace()))
        library = _LibprocFixture()
        library.proc_pidinfo.side_effect = OSError("fixture query denied")
        self.assertFalse(self._zombie_proof(library))

    def test_zombie_proof_rejects_live_leader_and_expired_budget(self) -> None:
        process, interface = _owned_posix_interface()
        interface.waitid.return_value = None
        library = _LibprocFixture()
        self.assertFalse(self._zombie_proof(library, process=process, interface=interface))
        library.proc_listpids.assert_not_called()
        process, interface = _owned_posix_interface()
        library = _LibprocFixture()
        self.assertFalse(self._zombie_proof(library, process=process, interface=interface,
                                           deadline=time.monotonic() - 1))
        library.proc_listpids.assert_not_called()

    def test_zombie_proof_stops_when_its_budget_expires_during_inspection(self) -> None:
        expired = []
        library = _LibprocFixture(after_info=lambda: expired.append(True))
        clock = SimpleNamespace(monotonic=lambda: 20 if expired else 1)
        with mock.patch.object(process_control, "time", clock):
            self.assertFalse(self._zombie_proof(library, deadline=10))
        self.assertTrue(expired)

    def test_zombie_proof_does_not_hide_lost_ownership_during_inspection(self) -> None:
        lost = []
        process, interface = _owned_posix_interface()
        interface.waitid.side_effect = lambda *args: SimpleNamespace(
            si_pid=9999 if lost else process.pid)
        library = _LibprocFixture(after_info=lambda: lost.append(True))
        with self.assertRaises(ProcessControlError):
            self._zombie_proof(library, process=process, interface=interface)
        interface.killpg.assert_not_called()

    def test_darwin_signal_denial_requires_complete_zombie_proof(self) -> None:
        for case, states in (("zombies", {"state": 5}), ("live", {"state": 2}),
                             ("became_live", [{"state": 5}, {"state": 2}])):
            with self.subTest(member_state=case):
                process, interface = _owned_posix_interface()
                denial = PermissionError(errno.EPERM, "fixture group denial")
                interface.killpg.side_effect = denial
                library = _LibprocFixture(records={4102: states})
                with mock.patch.object(process_control, "os", interface), \
                        mock.patch.object(process_control, "sys", SimpleNamespace(platform="darwin")), \
                        mock.patch.object(ctypes, "CDLL", return_value=library):
                    if case == "zombies":
                        process_control._signal_owned_group(process, signal.SIGTERM)
                    else:
                        with self.assertRaises(PermissionError) as caught:
                            process_control._signal_owned_group(process, signal.SIGTERM)
                        self.assertIs(caught.exception, denial)
                interface.killpg.assert_called_once_with(process.pid, signal.SIGTERM)

    def test_other_platform_and_non_eperm_denials_are_preserved(self) -> None:
        for platform, code in (("linux", errno.EPERM), ("darwin", errno.EACCES)):
            with self.subTest(platform=platform, errno=code):
                process, interface = _owned_posix_interface()
                denial = PermissionError(code, "fixture denial requiring propagation")
                interface.killpg.side_effect = denial
                with mock.patch.object(process_control, "os", interface), \
                        mock.patch.object(process_control, "sys", SimpleNamespace(platform=platform)), \
                        mock.patch.object(process_control, "_darwin_group_is_zombie_only") as proof:
                    with self.assertRaises(PermissionError) as caught:
                        process_control._signal_owned_group(process, signal.SIGTERM)
                self.assertIs(caught.exception, denial)
                proof.assert_not_called()

    def test_invalid_posix_ownership_never_signals_a_group(self) -> None:
        for case in ("previously_reaped", "wrong_pid", "no_child"):
            with self.subTest(case=case):
                process, interface = _owned_posix_interface()
                if case == "previously_reaped":
                    process.returncode = 0
                elif case == "wrong_pid":
                    interface.waitid.return_value = SimpleNamespace(si_pid=9999)
                else:
                    interface.waitid.side_effect = ChildProcessError(errno.ECHILD, "fixture child gone")
                with mock.patch.object(process_control, "os", interface):
                    with self.assertRaises(ProcessControlError):
                        process_control._signal_owned_group(process, signal.SIGTERM)
                interface.killpg.assert_not_called()
                if case == "previously_reaped":
                    interface.waitid.assert_not_called()

    def test_valid_live_and_exited_anchor_observations_keep_nowait_ownership(self) -> None:
        for exited in (False, True):
            with self.subTest(exited=exited):
                process, interface = _owned_posix_interface()
                interface.waitid.return_value = SimpleNamespace(si_pid=process.pid) if exited else None
                with mock.patch.object(process_control, "os", interface):
                    self.assertEqual(process_control._posix_child_exited(process), exited)
                    process_control._signal_owned_group(process, signal.SIGTERM)
                for call in interface.waitid.call_args_list:
                    self.assertEqual(call.args[:2], (interface.P_PID, process.pid))
                    self.assertTrue(call.args[2] & interface.WNOWAIT,
                                    "Identity observation must not reap the anchor")
                interface.killpg.assert_called_once_with(process.pid, signal.SIGTERM)


class _CleanupDouble:
    """Finite lifecycle responses with no host PID, descriptor or job handle."""

    stages = ("terminate", "wait", "drain", "stdout_close", "stderr_close", "job_close")

    def __init__(self, failures=None) -> None:
        self.failures = failures or {}
        self.events = []

        def operation(stage, result=None):
            def call(*args, **kwargs):
                self.events.append(stage)
                if len(self.events) > 20:
                    raise AssertionError("Cleanup double exceeded its finite operation budget")
                if stage in self.failures:
                    raise self.failures[stage]
                return result
            return mock.Mock(side_effect=call)

        self.process = SimpleNamespace(
            stdout=SimpleNamespace(close=operation("stdout_close")),
            stderr=SimpleNamespace(close=operation("stderr_close")),
            wait=operation("wait", 0), kill=operation("kill"),
        )
        self.job = SimpleNamespace(
            active=False, assigned=False, close=operation("job_close"),
            terminate=operation("terminate"), active_process_count=operation("job_count", 0),
        )
        self.pipes = [SimpleNamespace(finished=True), SimpleNamespace(finished=True)]
        self.terminate = operation("terminate")
        self.drain = operation("drain", False)
        self.clock = SimpleNamespace(monotonic=mock.Mock(side_effect=[10.0, 10.0]))


class ProcessCleanupContractTests(unittest.TestCase):
    """Error precedence and release attempts; doubles do not prove native cleanup."""

    def _finish(self, fixture):
        with mock.patch.object(process_control, "os", SimpleNamespace(name="posix")), \
                mock.patch.object(process_control, "time", fixture.clock), \
                mock.patch.object(process_control, "_terminate_tree", fixture.terminate), \
                mock.patch.object(process_control, "_pump_outputs", fixture.drain):
            return process_control._finish_process(
                fixture.process, fixture.job, fixture.pipes, graceful=False)

    def test_cleanup_preserves_first_failure_and_attempts_remaining_release(self) -> None:
        for index, first in enumerate(_CleanupDouble.stages):
            with self.subTest(first_failure=first):
                failures = {stage: OSError("owned " + stage + " failure")
                            for stage in _CleanupDouble.stages[index:]}
                fixture = _CleanupDouble(failures)
                with self.assertRaises(ProcessControlError) as caught:
                    self._finish(fixture)
                self.assertIs(caught.exception.__cause__, failures[first])
                self.assertEqual(fixture.events, list(_CleanupDouble.stages))
                fixture.terminate.assert_called_once_with(
                    fixture.process, fixture.job, graceful=False, cleanup_deadline=15.0)
                fixture.process.wait.assert_called_once_with(timeout=5.0)
                fixture.drain.assert_called_once_with(fixture.pipes)

    def test_complete_cleanup_returns_without_error_and_closes_each_resource(self) -> None:
        fixture = _CleanupDouble()
        self.assertIsNone(self._finish(fixture))
        self.assertEqual(fixture.events, list(_CleanupDouble.stages))
        fixture.process.wait.assert_called_once_with(timeout=5.0)
        fixture.process.stdout.close.assert_called_once_with()
        fixture.process.stderr.close.assert_called_once_with()
        fixture.job.close.assert_called_once_with()
        fixture.process.kill.assert_not_called()

    def test_windows_termination_failure_still_kills_unassigned_child_and_closes_job(self) -> None:
        failure = OSError("owned job termination failure")
        fixture = _CleanupDouble({"terminate": failure,
                                  "job_close": OSError("owned fallback close failure")})
        fixture.job.active = True
        with mock.patch.object(process_control, "os", SimpleNamespace(name="nt")), \
                mock.patch.object(process_control, "time", fixture.clock), \
                mock.patch.object(process_control, "_pump_outputs", fixture.drain):
            with self.assertRaises(ProcessControlError) as caught:
                process_control._finish_process(
                    fixture.process, fixture.job, fixture.pipes, graceful=True)
        self.assertIs(caught.exception.__cause__, failure)
        self.assertEqual(fixture.events, [
            "terminate", "kill", "job_close", "wait", "drain", "job_count",
            "stdout_close", "stderr_close", "job_close",
        ])
        fixture.process.kill.assert_called_once_with()
        fixture.process.wait.assert_called_once_with(timeout=5.0)
        self.assertEqual(fixture.job.close.call_count, 2)

    def test_launch_cancellation_closes_job_and_preserves_cleanup_cause(self) -> None:
        for fail_close in (False, True):
            with self.subTest(cleanup_failure=fail_close):
                cancellation = KeyboardInterrupt("owned launch cancellation before a child exists")
                close_failure = OSError("owned job close failure")
                job = SimpleNamespace(close=mock.Mock(
                    side_effect=close_failure if fail_close else None))
                with mock.patch.object(process_control, "_WindowsJob", return_value=job), \
                        mock.patch.object(process_control, "_require_posix_ownership"), \
                        mock.patch.object(process_control.subprocess, "Popen",
                                          side_effect=cancellation) as launch, \
                        mock.patch.object(process_control, "_finish_process") as finish:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        run_bounded_process(["owned-fixture-never-launched"], cwd=ROOT, timeout=2)
                self.assertIs(caught.exception, cancellation)
                self.assertIs(caught.exception.__cause__, close_failure if fail_close else None)
                launch.assert_called_once()
                job.close.assert_called_once_with()
                finish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
