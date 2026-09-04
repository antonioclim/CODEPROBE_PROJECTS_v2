from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
TOOLS = ROOT / "tools"


class AnalysisDeadlineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.watchdog = (APP / "analysis-watchdog.js").read_text(encoding="utf-8")
        cls.loader = (APP / "pyodide-loader.js").read_text(encoding="utf-8")
        cls.main_html = (APP / "index.html").read_text(encoding="utf-8")
        cls.project_html = (APP / "project.html").read_text(encoding="utf-8")
        cls.server = (
            ROOT / "src" / "codeprobe_engine" / "server.py"
        ).read_text(encoding="utf-8")
        cls.functional = (
            TOOLS / "check_browser_functional.js"
        ).read_text(encoding="utf-8")
        cls.runtime_config = json.loads(
            (APP / "runtime-config.json").read_text(encoding="utf-8")
        )

    def test_worker_sets_shared_interrupt_signal(self) -> None:
        for fragment in (
            "new SharedArrayBuffer",
            "new Worker",
            "Atomics.store(view, 0, 2)",
            "runtime.setInterruptBuffer",
            "AnalysisDeadlineError",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.watchdog)

    def test_deadline_wraps_sync_and_async_python_calls(self) -> None:
        self.assertIn("runtime.runPython = function", self.watchdog)
        self.assertIn("runtime.runPythonAsync = async function", self.watchdog)
        self.assertIn("Analysis exceeded the", self.watchdog)
        self.assertIn("Nested CodeProbe analyses are not permitted", self.watchdog)

    def test_production_runtime_fails_closed_without_interrupt_support(self) -> None:
        self.assertIn("require_interrupt_buffer", self.loader)
        self.assertIn("CodeProbeAnalysisWatchdog.attach", self.loader)
        self.assertIn("Analysis deadline containment is unavailable", self.watchdog)
        analysis = self.runtime_config["analysis"]
        self.assertTrue(analysis["require_interrupt_buffer"])
        self.assertGreaterEqual(analysis["deadline_ms"], 100)
        self.assertLessEqual(analysis["deadline_ms"], 60_000)

    def test_watchdog_is_loaded_before_runtime_loader(self) -> None:
        for name, html in (
            ("main", self.main_html),
            ("project", self.project_html),
        ):
            with self.subTest(page=name):
                watchdog_index = html.index("analysis-watchdog.js")
                loader_index = html.index("pyodide-loader.js")
                self.assertLess(watchdog_index, loader_index)
                self.assertRegex(
                    html,
                    r"analysis-watchdog\.js[^>]*integrity=\"sha256-[A-Za-z0-9+/=]+\"",
                )

    def test_server_allowlist_and_isolation_headers_support_deadline(self) -> None:
        self.assertIn("analysis-watchdog.js", self.server)
        self.assertIn("Cross-Origin-Embedder-Policy", self.server)
        self.assertIn("require-corp", self.server)
        self.assertIn("Cross-Origin-Opener-Policy", self.server)
        self.assertIn("same-origin", self.server)

    def test_real_browser_gate_contains_non_terminating_python_fixture(self) -> None:
        for fragment in (
            "testAnalysisDeadline",
            "while True:",
            "AnalysisDeadlineError",
            "deadline",
            "20_000",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.functional)


if __name__ == "__main__":
    unittest.main()
