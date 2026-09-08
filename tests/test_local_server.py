from __future__ import annotations

import contextlib
import errno
import http.client
import importlib.util
import io
import json
import os
import socket
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
        with unittest.mock.patch.object(
            server_module.ThreadingHTTPServer, "__init__", return_value=None,
        ) as constructor:
            with self.assertRaisesRegex(ServerPolicyError, "--allow-network"):
                create_server(ROOT, "0.0.0.0", 0)
            constructor.assert_not_called()
            create_server(ROOT, "0.0.0.0", 0, allow_network=True)
            self.assertEqual(constructor.call_args.args[0], ("0.0.0.0", 0))

    def test_factory_selects_ipv4_ipv6_and_localhost_before_socket_creation(self) -> None:
        for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6), ("localhost", socket.AF_INET)):
            with self.subTest(host=host):
                with unittest.mock.patch.object(
                    server_module.ThreadingHTTPServer, "__init__", return_value=None,
                ) as constructor:
                    server = create_server(ROOT, host, 0)
                self.assertEqual(server.address_family, family)
                self.assertEqual(constructor.call_args.args[0], (host, 0))

    def test_invalid_addresses_and_ports_never_reach_constructor(self) -> None:
        with unittest.mock.patch.object(
            server_module.ThreadingHTTPServer, "__init__", return_value=None,
        ) as constructor:
            for host in ("example.invalid", "", "0.0.0.0", "::"):
                with self.subTest(host=host), self.assertRaises(ServerPolicyError):
                    create_server(ROOT, host, 0)
            for port in (-1, 65536, True, "8123", 1.5):
                with self.subTest(port=port), self.assertRaises(ServerPolicyError):
                    create_server(ROOT, "127.0.0.1", port)
            constructor.assert_not_called()

    def test_raw_target_is_rejected_before_normalising_url_parser(self) -> None:
        targets = (
            "", " /app/index.html", "\x00/app/index.html", "/app/in\ndex.html",
            "/app/index.html?x=\t", "/app/index.html?x=\x7f",
        )
        with unittest.mock.patch.object(server_module, "urlsplit") as parser:
            for target in targets:
                with self.subTest(target=target), self.assertRaises(ServerPolicyError):
                    canonical_request_path(target)
            parser.assert_not_called()

    def test_malformed_authorities_are_controlled_policy_errors(self) -> None:
        for target in (
            "http://[invalid]/app/index.html", "http://[::1/app/index.html",
            "http://example.invalid/app/index.html",
        ):
            with self.subTest(target=target), self.assertRaises(ServerPolicyError):
                canonical_request_path(target)

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


class LocalServerMemoryTests(unittest.TestCase):
    def exchange(self, request: bytes):
        incoming, outgoing, logs = io.BytesIO(request), io.BytesIO(), io.StringIO()

        class MemoryHandler(server_module.handler_for_root(ROOT)):
            def setup(self):
                self.rfile, self.wfile = incoming, outgoing

            def finish(self):
                self.wfile.flush()

        with contextlib.redirect_stdout(logs):
            MemoryHandler(None, ("127.0.0.1", 1), None)
        return outgoing.getvalue(), logs.getvalue()

    def response(self, method="GET", target="/app/index.html"):
        request = f"{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        raw, logs = self.exchange(request.encode("latin-1"))
        head, body = raw.split(b"\r\n\r\n", 1)
        status, header_bytes = head.split(b"\r\n", 1)
        headers = http.client.parse_headers(io.BytesIO(header_bytes + b"\r\n\r\n"))
        return int(status.split()[1]), headers, body, logs

    def assert_common_headers(self, headers):
        expected = {
            "Cache-Control": "no-store",
            "Content-Security-Policy": CONTENT_SECURITY_POLICY,
            "Cross-Origin-Opener-Policy": "same-origin",
            "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        }
        for name, value in expected.items():
            self.assertEqual(headers.get_all(name), [value], name)

    def test_entry_aliases_and_queries_preserve_exact_get_and_head_bytes(self):
        expected = (ROOT / "app/index.html").read_bytes()
        for target in ("/", "/app", "/app/", "/app/index.html?ignored=1"):
            for method in ("GET", "HEAD"):
                with self.subTest(target=target, method=method):
                    status, headers, body, _ = self.response(method, target)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, expected if method == "GET" else b"")
                    self.assertEqual(headers["Content-Length"], str(len(expected)))
                    self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
                    self.assertIsNone(headers["Allow"])
                    self.assert_common_headers(headers)

    def test_malformed_and_encoded_targets_return_controlled_400(self):
        targets = (
            "http://[invalid]/app/index.html", "http://[::1/app/index.html", "//app/index.html",
            "/app/\x00index.html", "/app/index.html?x=\x1b", "/app/%2e%2e/README.md",
            "/app/%5cindex.html", "/app/%00index.html", "/app/%ffindex.html",
        )
        for target in targets:
            with self.subTest(target=target):
                status, headers, body, _ = self.response(target=target)
                self.assertEqual(status, 400)
                self.assertEqual(headers["Content-Length"], str(len(body)))
                self.assertEqual(headers["Content-Type"], "text/plain; charset=utf-8")
                self.assert_common_headers(headers)

    def test_all_known_rejected_methods_include_allow_once(self):
        for method in ("CONNECT", "DELETE", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"):
            with self.subTest(method=method):
                status, headers, body, _ = self.response(method)
                self.assertEqual(status, 405)
                self.assertEqual(headers.get_all("Allow"), ["GET, HEAD"])
                self.assertEqual(headers["Content-Length"], str(len(body)))
                self.assert_common_headers(headers)

    def test_unknown_method_remains_501_with_common_headers(self):
        status, headers, body, _ = self.response("BREW")
        self.assertEqual(status, 501)
        self.assertIsNone(headers["Allow"])
        self.assertEqual(headers["Content-Length"], str(len(body)))
        self.assertIn("text/html", headers["Content-Type"])
        self.assert_common_headers(headers)

    def test_head_policy_and_missing_resource_errors_have_no_body(self):
        for target, expected_status in (("http://[invalid]/app/index.html", 400), ("/README.md", 404)):
            with self.subTest(target=target):
                status, headers, body, _ = self.response("HEAD", target)
                self.assertEqual(status, expected_status)
                self.assertEqual(body, b"")
                self.assertGreater(int(headers["Content-Length"]), 0)
                self.assert_common_headers(headers)

    def test_http09_remains_headerless(self):
        raw, _ = self.exchange(b"GET /app/index.html\r\n\r\n")
        self.assertEqual(raw, (ROOT / "app/index.html").read_bytes())

    def test_request_logs_escape_controls_and_keep_context(self):
        _, _, _, ordinary = self.response()
        _, _, _, refused = self.response(target="/app/index.html?x=\x1b")
        self.assertIn('"GET /app/index.html HTTP/1.1" 200', ordinary)
        self.assertIn('"GET /app/index.html?x=\\x1b HTTP/1.1" 400', refused)
        self.assertEqual(refused.count("\n"), 1)
        self.assertTrue(all(character.isprintable() or character == "\n" for character in refused))

    def test_direct_log_escapes_client_address_and_unicode_nonprinting_text(self):
        handler = object.__new__(server_module.CodeProbeRequestHandler)
        handler.client_address = ("owned\naddress", 1)
        logs = io.StringIO()
        with contextlib.redirect_stdout(logs):
            handler.log_message("%s 400", "request\r\n\x1b\x7f\x85\u202e\\done")
        text = logs.getvalue()
        self.assertEqual(text.count("\n"), 1)
        self.assertTrue(all(character.isprintable() or character == "\n" for character in text))
        for escaped in ("\\n", "\\r", "\\x1b", "\\x7f", "\\x85", "\\u202e", "\\\\done"):
            self.assertIn(escaped, text)
        self.assertIn("400", text)


def load_server_cli():
    spec = importlib.util.spec_from_file_location("codeprobe_server_cli_test", ROOT / "tools/run_local_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stop_owned_server(server, thread):
    shutdown = threading.Thread(target=server.shutdown, daemon=True)
    shutdown.start()
    shutdown.join(timeout=5)
    server.server_close()
    thread.join(timeout=5)
    if shutdown.is_alive() or thread.is_alive():
        raise AssertionError("owned server shutdown or serving thread did not stop")
    if server.socket.fileno() != -1:
        raise AssertionError("owned server socket was not closed")


class LocalServerCliTests(unittest.TestCase):
    def test_default_launch_binds_zero_once_and_prints_both_actual_urls(self):
        cli = load_server_cli()
        server = unittest.mock.Mock(server_address=("127.0.0.1", 45678))
        server.serve_forever.side_effect = KeyboardInterrupt
        output = io.StringIO()
        with (
            unittest.mock.patch.object(cli, "create_server", return_value=server) as create,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["--no-browser"]), 0)
        create.assert_called_once_with(ROOT, "127.0.0.1", 0, allow_network=False)
        self.assertIn("Open: http://127.0.0.1:45678/app/index.html", output.getvalue())
        self.assertIn("Project: http://127.0.0.1:45678/app/project.html", output.getvalue())
        server.server_close.assert_called_once_with()

    def test_explicit_consent_reaches_factory_without_public_bind(self):
        cli = load_server_cli()
        server = unittest.mock.Mock(server_address=("0.0.0.0", 8123))
        server.serve_forever.side_effect = KeyboardInterrupt
        with (
            unittest.mock.patch.object(cli, "create_server", return_value=server) as create,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(cli.main(["--host", "0.0.0.0", "--port", "8123", "--allow-network", "--no-browser"]), 0)
        create.assert_called_once_with(ROOT, "0.0.0.0", 8123, allow_network=True)

    def test_nonloopback_without_consent_never_reaches_factory(self):
        cli = load_server_cli()
        errors = io.StringIO()
        with unittest.mock.patch.object(cli, "create_server") as create, contextlib.redirect_stderr(errors):
            self.assertEqual(cli.main(["--host", "0.0.0.0", "--no-browser"]), 2)
        create.assert_not_called()
        self.assertIn("--allow-network", errors.getvalue())

    def test_ipv6_urls_are_bracketed_and_browser_uses_actual_port(self):
        cli = load_server_cli()
        server = unittest.mock.Mock(server_address=("::1", 45679, 0, 0))
        server.serve_forever.side_effect = KeyboardInterrupt
        output = io.StringIO()
        with (
            unittest.mock.patch.object(cli, "create_server", return_value=server) as create,
            unittest.mock.patch.object(cli.webbrowser, "open") as browser,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["--host", "::1"]), 0)
        create.assert_called_once_with(ROOT, "::1", 0, allow_network=False)
        browser.assert_called_once_with("http://[::1]:45679/app/index.html")
        self.assertIn("Project: http://[::1]:45679/app/project.html", output.getvalue())

    def test_constructor_failure_is_controlled_and_opens_no_browser(self):
        cli = load_server_cli()
        errors = io.StringIO()
        with (
            unittest.mock.patch.object(cli, "create_server", side_effect=OSError("owned occupied port")),
            unittest.mock.patch.object(cli.webbrowser, "open") as browser,
            contextlib.redirect_stderr(errors),
        ):
            self.assertEqual(cli.main(["--port", "8123"]), 2)
        browser.assert_not_called()
        self.assertIn("Cannot start the local server: owned occupied port", errors.getvalue())


class LocalServerHttpTests(unittest.TestCase):
    host = "127.0.0.1"

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.server = create_server(ROOT, cls.host, 0)
        except OSError as exc:
            unavailable = {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL, errno.ENETUNREACH}
            if cls.host == "::1" and exc.errno in unavailable:
                raise unittest.SkipTest(f"IPv6 loopback is unavailable: {exc}") from exc
            raise
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        try:
            cls.thread.start()
        except BaseException:
            cls.server.server_close()
            raise
        host = f"[{cls.host}]" if ":" in cls.host else cls.host
        cls.base = f"http://{host}:{cls.server.server_address[1]}"
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @classmethod
    def tearDownClass(cls) -> None:
        family = int(cls.server.socket.family)
        port = int(cls.server.server_address[1])
        stop_owned_server(cls.server, cls.thread)
        print("CODEPROBE_SERVER_TRANSPORT " + json.dumps({
            "host": cls.host, "family": family, "port": port,
            "thread_alive": cls.thread.is_alive(), "socket_fileno": cls.server.socket.fileno(),
        }, sort_keys=True))

    def request(self, path: str, *, method: str = "GET"):
        return self.opener.open(
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
                caught.exception.close()

    def test_write_methods_are_rejected(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request("/app/index.html", method="POST")
        self.assertEqual(caught.exception.code, 405)
        self.assertEqual(caught.exception.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(caught.exception.headers.get_all("Allow"), ["GET, HEAD"])
        caught.exception.close()

    def test_actual_family_and_ephemeral_port_serve_exact_public_bytes(self):
        expected_family = socket.AF_INET6 if self.host == "::1" else socket.AF_INET
        self.assertEqual(self.server.socket.family, expected_family)
        self.assertGreater(self.server.server_address[1], 0)
        for path in (
            "app/index.html", "app/project.html", "app/codeprobe.css", "app/analysis-worker.js",
            "app/runtime-config.json", "src/codeprobe_runtime.py",
        ):
            expected = (ROOT / path).read_bytes()
            for method in ("GET", "HEAD"):
                with self.subTest(path=path, method=method), self.request("/" + path, method=method) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["Content-Length"], str(len(expected)))
                    self.assertEqual(response.read(), expected if method == "GET" else b"")

    def test_real_http_rejections_have_exact_status_length_and_headers(self):
        cases = [
            (method, "/app/index.html", 405)
            for method in ("CONNECT", "DELETE", "OPTIONS", "PATCH", "POST", "PUT", "TRACE")
        ]
        cases += [("BREW", "/app/index.html", 501), ("GET", "/README.md", 404)]
        cases += [("GET", path, 400) for path in (
            "http://[invalid]/app/index.html", "//app/index.html", "/app/\x00index.html",
            "/app/index.html?x=\x1b", "/app/%2e%2e/README.md", "/app/%5cindex.html",
        )]
        cases += [("HEAD", "http://[invalid]/app/index.html", 400), ("HEAD", "/README.md", 404)]
        for method, target, expected in cases:
            with self.subTest(method=method, target=target):
                with socket.create_connection((self.host, self.server.server_address[1]), timeout=3) as connection:
                    request = f"{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    connection.sendall(request.encode("ascii"))
                    response = http.client.HTTPResponse(connection, method=method)
                    try:
                        response.begin()
                        body = response.fp.read(65537) if method == "HEAD" else response.read(65537)
                        self.assertLessEqual(len(body), 65536)
                        self.assertEqual(response.status, expected)
                        self.assertEqual(response.headers.get_all("Cache-Control"), ["no-store"])
                        self.assertEqual(
                            response.headers.get_all("Content-Security-Policy"), [CONTENT_SECURITY_POLICY],
                        )
                        self.assertEqual(response.headers.get_all("X-Content-Type-Options"), ["nosniff"])
                        self.assertEqual(response.headers.get_all("Allow"), ["GET, HEAD"] if expected == 405 else None)
                        if method == "HEAD":
                            self.assertEqual(body, b"")
                        else:
                            self.assertEqual(len(body), int(response.headers["Content-Length"]))
                    finally:
                        response.close()

    def test_an_occupied_fixed_port_returns_a_controlled_cli_error(self):
        cli = load_server_cli()
        errors = io.StringIO()

        def require_occupied_port(*args, **kwargs):
            unexpected = create_server(*args, **kwargs)
            unexpected.server_close()
            self.fail("the occupied listening port unexpectedly allowed a second server")

        with (
            unittest.mock.patch.object(cli, "create_server", side_effect=require_occupied_port),
            unittest.mock.patch.object(cli.webbrowser, "open") as browser,
            contextlib.redirect_stderr(errors),
        ):
            result = cli.main(["--host", self.host, "--port", str(self.server.server_address[1]), "--no-browser"])
        self.assertEqual(result, 2)
        self.assertIn("Cannot start the local server:", errors.getvalue())
        browser.assert_not_called()

    def test_cli_printed_urls_reach_both_pages_on_its_actual_bound_port(self):
        cli = load_server_cli()
        output = io.StringIO()

        def create_and_exercise(root, host, port, *, allow_network):
            self.assertEqual(port, 0)
            self.assertFalse(allow_network)
            owned = create_server(root, host, port, allow_network=allow_network)
            original_serve = owned.serve_forever

            def serve_and_fetch():
                thread = threading.Thread(target=original_serve, kwargs={"poll_interval": 0.05}, daemon=True)
                thread.start()
                try:
                    lines = output.getvalue().splitlines()
                    for label, path in (("Open: ", "app/index.html"), ("Project: ", "app/project.html")):
                        urls = [line[len(label):] for line in lines if line.startswith(label)]
                        self.assertEqual(len(urls), 1)
                        display_host = f"[{host}]" if ":" in host else host
                        self.assertEqual(urls[0], f"http://{display_host}:{owned.server_address[1]}/{path}")
                        with self.opener.open(urls[0], timeout=3) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.read(), (ROOT / path).read_bytes())
                finally:
                    stop_owned_server(owned, thread)
                raise KeyboardInterrupt

            owned.serve_forever = serve_and_fetch
            return owned

        with (
            unittest.mock.patch.object(cli, "create_server", side_effect=create_and_exercise),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["--host", self.host, "--no-browser"]), 0)

    def test_real_http_log_escapes_control_and_preserves_request_status(self):
        logs = io.StringIO()
        with contextlib.redirect_stdout(logs):
            with socket.create_connection((self.host, self.server.server_address[1]), timeout=3) as connection:
                connection.sendall(
                    b"GET /app/index.html?x=\x1b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                response = http.client.HTTPResponse(connection)
                try:
                    response.begin()
                    self.assertEqual(response.status, 400)
                    self.assertLessEqual(len(response.read(65537)), 65536)
                finally:
                    response.close()
        self.assertIn('"GET /app/index.html?x=\\x1b HTTP/1.1" 400', logs.getvalue())
        self.assertEqual(logs.getvalue().count("\n"), 1)
        self.assertTrue(all(character.isprintable() or character == "\n" for character in logs.getvalue()))


class LocalServerIPv6HttpTests(LocalServerHttpTests):
    host = "::1"


if __name__ == "__main__":
    unittest.main()
