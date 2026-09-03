from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codeprobe_engine import process_control  # noqa: E402
from codeprobe_engine.process_control import (  # noqa: E402
    ProcessControlError,
    run_bounded_process,
)


class ProcessControlTests(unittest.TestCase):
    def test_success_captures_both_streams(self) -> None:
        result = run_bounded_process(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                "import sys; print('out'); print('err', file=sys.stderr)",
            ],
            cwd=ROOT,
            timeout=10,
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_limit_exceeded)
        self.assertEqual(result.stdout_text.strip(), "out")
        self.assertEqual(result.stderr_text.strip(), "err")

    def test_shell_string_is_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "shell string"):
            run_bounded_process("echo unsafe", cwd=ROOT)  # type: ignore[arg-type]

    def test_output_limit_terminates_noisy_child_and_keeps_prefix(self) -> None:
        result = run_bounded_process(
            [sys.executable, "-I", "-S", "-B", "-c", "print('x' * 200000)"],
            cwd=ROOT,
            timeout=10,
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertTrue(result.output_limit_exceeded)
        self.assertFalse(result.timed_out)
        self.assertEqual(len(result.stdout), 1024)
        self.assertTrue(result.stdout.startswith(b"x" * 100))

    def test_timeout_returns_a_bounded_failure(self) -> None:
        started = time.monotonic()
        result = run_bounded_process(
            [sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(30)"],
            cwd=ROOT,
            timeout=0.25,
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 5)

    def test_replace_environment_does_not_leak_ambient_values(self) -> None:
        with mock.patch.dict(os.environ, {"CODEPROBE_AMBIENT_SECRET": "present"}):
            result = run_bounded_process(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import os; "
                        "print(os.environ.get('CODEPROBE_AMBIENT_SECRET', 'absent')); "
                        "print(os.environ['CODEPROBE_EXPLICIT'])"
                    ),
                ],
                cwd=ROOT,
                environment={"CODEPROBE_EXPLICIT": "retained"},
                replace_environment=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout_text.splitlines(), ["absent", "retained"])

    def test_windows_containment_failure_kills_the_child_and_fails_closed(self) -> None:
        process = mock.Mock()
        process.kill = mock.Mock()
        process.wait = mock.Mock()
        job = mock.Mock(active=False, error=OSError("job unavailable"))
        with mock.patch.object(process_control.os, "name", "nt"):
            with self.assertRaisesRegex(ProcessControlError, "Windows Job Object"):
                process_control._require_windows_containment(process, job)
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=5)

    def test_invalid_limits_fail_before_launch(self) -> None:
        for keyword, value in (
            ("timeout", 0),
            ("stdout_limit", 0),
            ("stderr_limit", -1),
        ):
            with self.subTest(keyword=keyword):
                with self.assertRaises(ValueError):
                    run_bounded_process(
                        [sys.executable, "-c", "pass"],
                        cwd=ROOT,
                        **{keyword: value},
                    )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux /proc assertion")
    def test_timeout_terminates_descendant_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pid_path = Path(tmp) / "child.pid"
            source = (
                "import pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', "
                "'import time; time.sleep(30)'])\n"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid), encoding='ascii')\n"
                "time.sleep(30)\n"
            )
            result = run_bounded_process(
                [sys.executable, "-I", "-S", "-B", "-c", source],
                cwd=ROOT,
                timeout=0.5,
            )
            self.assertTrue(result.timed_out)
            child_pid = int(pid_path.read_text(encoding="ascii"))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                status = Path(f"/proc/{child_pid}/stat")
                if not status.exists():
                    break
                fields = status.read_text(encoding="ascii", errors="replace").split()
                if len(fields) > 2 and fields[2] == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail(f"descendant process {child_pid} survived the process-group timeout")


if __name__ == "__main__":
    unittest.main()
