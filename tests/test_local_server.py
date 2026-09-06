from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from codeprobe_engine.server import (  # noqa: E402
    CONTENT_SECURITY_POLICY,
    ServerPolicyError,
    canonical_request_path,
    create_server,
    public_resource,
    validate_bind_address,
)


class LocalServerPolicyTests(unittest.TestCase):
    def test_bind_address_requires_explicit_network_authorisation(self) -> None:
        self.assertEqual(validate_bind_address("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_bind_address("::1"), "::1")
        self.assertEqual(validate_bind_address("localhost"), "localhost")
        with self.assertRaisesRegex(ServerPolicyError, "--allow-network"):
            validate_bind_address("0.0.0.0")
        self.assertEqual(
            validate_bind_address("0.0.0.0", allow_network=True),
            "0.0.0.0",
        )
        with self.assertRaisesRegex(ServerPolicyError, "literal IP"):
            validate_bind_address("example.invalid")

    def test_server_factory_enforces_network_authorisation(self) -> None:
        with self.assertRaisesRegex(ServerPolicyError, "--allow-network"):
            create_server(ROOT, "0.0.0.0", 0)
        server = create_server(ROOT, "0.0.0.0", 0, allow_network=True)
        server.server_close()

    def test_request_paths_are_canonical_and_allowlisted(self) -> None:
        self.assertEqual(canonical_request_path("/"), "app/index.html")
        self.assertEqual(canonical_request_path("/app"), "app/index.html")
        self.assertEqual(canonical_request_path("/app/project.html?x=1"), "app/project.html")
        for target in (
            "//app/index.html",
            "/app//index.html",
            "/app/../README.md",
            "/app/%2e%2e/README.md",
            "/app/%5c..%5cREADME.md",
            "https://example.invalid/app/index.html",
        ):
            with self.subTest(target=target):
                with self.assertRaises(ServerPolicyError):
                    canonical_request_path(target)
        with self.assertRaises(FileNotFoundError):
            public_resource(ROOT, "/README.md")
        with self.assertRaises(FileNotFoundError):
            public_resource(ROOT, "/docs/04-browser-security.md")
        self.assertTrue(public_resource(ROOT, "/app/index.html").content)
        self.assertTrue(public_resource(ROOT, "/src/codeprobe_runtime.py").content)

    def test_public_resource_rejects_a_symlinked_leaf(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links are unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            external = Path(tmp) / "external.html"
            (root / "app").mkdir(parents=True)
            external.write_text("external", encoding="utf-8")
            try:
                (root / "app" / "index.html").symlink_to(external)
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")
            with self.assertRaisesRegex(ServerPolicyError, "symbolic links"):
                public_resource(root, "/app/index.html")


class LocalServerHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = create_server(ROOT, "127.0.0.1", 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path: str, *, method: str = "GET"):
        return urllib.request.urlopen(
            urllib.request.Request(self.base + path, method=method),
            timeout=5,
        )

    def test_allowed_page_has_restrictive_headers(self) -> None:
        with self.request("/app/index.html") as response:
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertIn(b"CodeProbe", body)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(response.headers["Content-Security-Policy"], CONTENT_SECURITY_POLICY)
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_root_redirects_logically_without_http_redirect(self) -> None:
        with self.request("/") as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"CodeProbe", response.read())

    def test_head_has_no_body(self) -> None:
        with self.request("/app/project.html", method="HEAD") as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"")
            self.assertGreater(int(response.headers["Content-Length"]), 0)

    def test_repository_files_and_directory_indexes_are_not_served(self) -> None:
        for path in ("/README.md", "/docs/", "/release/release-manifest.json", "/tests/"):
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    self.request(path)
                self.assertIn(caught.exception.code, {400, 404})

    def test_write_methods_are_rejected(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request("/app/index.html", method="POST")
        self.assertEqual(caught.exception.code, 405)
        self.assertEqual(caught.exception.headers["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
