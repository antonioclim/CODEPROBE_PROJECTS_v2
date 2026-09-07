from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
import unittest.mock
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
from codeprobe_engine import release, server as server_module  # noqa: E402


class BoundedPublicResourceTests(unittest.TestCase):
    def test_zero_and_exact_ceiling_preserve_bytes_and_mime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "app" / "index.html"
            path.parent.mkdir()
            for content in (b"", b"x" * 32):
                with self.subTest(size=len(content)):
                    path.write_bytes(content)
                    with unittest.mock.patch.object(server_module, "MAX_PUBLIC_FILE_BYTES", 32):
                        resource = public_resource(root, "/app/index.html")
                    self.assertEqual(resource.path, "app/index.html")
                    self.assertEqual(resource.content, content)
                    self.assertEqual(resource.content_type, "text/html; charset=utf-8")
                    self.assertEqual(path.read_bytes(), content)

    def test_initial_oversize_is_rejected_without_body_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "app" / "index.html"
            path.parent.mkdir()
            path.write_bytes(b"x" * 33)
            with unittest.mock.patch.object(server_module, "MAX_PUBLIC_FILE_BYTES", 32):
                with unittest.mock.patch.object(release.os, "read") as body_read:
                    with self.assertRaisesRegex(ServerPolicyError, "size ceiling"):
                        public_resource(root, "/app/index.html")
            body_read.assert_not_called()
            self.assertEqual(path.read_bytes(), b"x" * 33)

    def test_growth_before_reader_open_is_rejected_without_body_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "app" / "index.html"
            path.parent.mkdir()
            path.write_bytes(b"x" * 32)

            def grow_before_read(candidate, **kwargs):
                with path.open("ab") as handle:
                    handle.write(b"y" * 32)
                return release.read_regular_file(candidate, **kwargs)

            with unittest.mock.patch.object(server_module, "MAX_PUBLIC_FILE_BYTES", 32):
                with unittest.mock.patch.object(server_module, "read_regular_file", side_effect=grow_before_read):
                    with unittest.mock.patch.object(release.os, "read") as body_read:
                        with self.assertRaisesRegex(ServerPolicyError, "read safely"):
                            public_resource(root, "/app/index.html")
            body_read.assert_not_called()
            self.assertEqual(path.read_bytes(), b"x" * 32 + b"y" * 32)

    def test_growth_during_read_consumes_at_most_one_extra_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "app" / "index.html"
            path.parent.mkdir()
            path.write_bytes(b"x" * 32)
            real_read = os.read
            observed = []

            def grow_before_body(descriptor, requested):
                if not observed:
                    with path.open("ab") as handle:
                        handle.write(b"y" * 32)
                content = real_read(descriptor, requested)
                observed.append((descriptor, requested, len(content)))
                return content

            with unittest.mock.patch.object(server_module, "MAX_PUBLIC_FILE_BYTES", 32):
                with unittest.mock.patch.object(release.os, "read", side_effect=grow_before_body):
                    with self.assertRaisesRegex(ServerPolicyError, "read safely"):
                        public_resource(root, "/app/index.html")
            self.assertEqual(sum(size for _fd, _request, size in observed), 33)
            self.assertEqual([requested for _fd, requested, _size in observed], [33])
            for descriptor, _requested, _size in observed:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual(path.read_bytes(), b"x" * 32 + b"y" * 32)

    def test_bounded_resource_still_rejects_symlinked_ancestry(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = parent / "root"
            root.mkdir()
            external = parent / "external"
            external.mkdir()
            path = external / "index.html"
            path.write_bytes(b"owned external fixture")
            try:
                (root / "app").symlink_to(external, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symbolic links are unavailable: {exc}")
            with unittest.mock.patch.object(release.os, "read") as body_read:
                with self.assertRaisesRegex(ServerPolicyError, "symbolic links"):
                    public_resource(root, "/app/index.html")
            body_read.assert_not_called()
            self.assertEqual(path.read_bytes(), b"owned external fixture")


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
