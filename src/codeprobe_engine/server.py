"""Constrained static HTTP serving for CodeProbe's browser application."""

from __future__ import annotations

import ipaddress
import mimetypes
import posixpath
import stat
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import unquote_to_bytes, urlsplit

from .release import ReleaseSetError, read_regular_file


DEFAULT_HOST = "127.0.0.1"
DEFAULT_ENTRY_PATH = "/app/index.html"
MAX_PUBLIC_FILE_BYTES = 32 * 1024 * 1024
PUBLIC_EXACT_PATHS = frozenset({
    "app/index.html",
    "app/project.html",
    "app/codeprobe.css",
    "app/project.css",
    "app/pyodide-loader.js",
    "app/analysis-worker.js",
    "app/codeprobe-ui.js",
    "app/project-ui.js",
    "app/runtime-config.json",
    "app/resource-integrity.json",
    "app/pyodide-provenance.json",
    "src/codeprobe_runtime.py",
})
PUBLIC_PREFIXES = ("app/vendor/pyodide/",)
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net blob: 'wasm-unsafe-eval'; "
    "connect-src 'self' https://cdn.jsdelivr.net; "
    "worker-src 'self' blob:; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


class ServerPolicyError(ValueError):
    """Raised when a request or bind address violates the local-server policy."""


@dataclass(frozen=True)
class PublicResource:
    """One authorised response body."""

    path: str
    content_type: str
    content: bytes


def validate_bind_address(host: str, *, allow_network: bool = False) -> str:
    """Validate a bind address and require explicit approval outside loopback."""

    rendered = str(host).strip()
    if not rendered or any(ord(character) < 32 for character in rendered):
        raise ServerPolicyError("bind address must be a non-empty printable value")
    try:
        address = ipaddress.ip_address(rendered)
    except ValueError:
        if rendered.lower() != "localhost":
            raise ServerPolicyError(
                "bind address must be a literal IP address or localhost"
            )
        is_loopback = True
    else:
        is_loopback = address.is_loopback
    if not is_loopback and not allow_network:
        raise ServerPolicyError(
            "non-loopback binding requires --allow-network; this exposes the local page to the network"
        )
    return rendered


def canonical_request_path(target: str) -> str:
    """Return a canonical relative POSIX path for one HTTP request target."""

    parsed = urlsplit(str(target))
    if parsed.scheme or parsed.netloc:
        raise ServerPolicyError("absolute request targets are not accepted")
    try:
        raw = unquote_to_bytes(parsed.path or "/")
        decoded = raw.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ServerPolicyError("request path is not valid UTF-8") from exc
    if any(ord(character) < 32 or ord(character) == 127 for character in decoded):
        raise ServerPolicyError("request path contains a control character")
    if "\\" in decoded or "\x00" in decoded:
        raise ServerPolicyError("request path contains a forbidden separator")
    if not decoded.startswith("/") or decoded.startswith("//"):
        raise ServerPolicyError("request path is not canonical")
    if decoded in {"/", "/app", "/app/"}:
        decoded = DEFAULT_ENTRY_PATH
    components = decoded[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ServerPolicyError("request path contains an empty or dot component")
    canonical = PurePosixPath(*components).as_posix()
    normalised = posixpath.normpath(decoded).lstrip("/")
    if canonical != normalised:
        raise ServerPolicyError("request path is not canonical")
    return canonical


def is_public_path(relative_path: str) -> bool:
    return relative_path in PUBLIC_EXACT_PATHS or any(
        relative_path.startswith(prefix) and relative_path != prefix.rstrip("/")
        for prefix in PUBLIC_PREFIXES
    )


def _assert_unlinked_components(root: Path, relative_path: str) -> Path:
    candidate = root
    parts = PurePosixPath(relative_path).parts
    for index, part in enumerate(parts):
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise FileNotFoundError(relative_path) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ServerPolicyError("public resources may not traverse symbolic links")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise FileNotFoundError(relative_path)
    return candidate


def public_resource(root: Path, request_target: str) -> PublicResource:
    """Read one allowlisted regular file through the release-safe reader."""

    relative = canonical_request_path(request_target)
    if not is_public_path(relative):
        raise FileNotFoundError(relative)
    root_path = Path(root).resolve(strict=True)
    candidate = _assert_unlinked_components(root_path, relative)
    try:
        metadata = candidate.stat()
    except OSError as exc:
        raise FileNotFoundError(relative) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise FileNotFoundError(relative)
    if metadata.st_size > MAX_PUBLIC_FILE_BYTES:
        raise ServerPolicyError("public resource exceeds the local-server size ceiling")
    try:
        content = read_regular_file(candidate, root=root_path)
    except (OSError, ReleaseSetError) as exc:
        raise ServerPolicyError("public resource could not be read safely") from exc
    if len(content) > MAX_PUBLIC_FILE_BYTES:
        raise ServerPolicyError("public resource exceeds the local-server size ceiling")
    content_type, _ = mimetypes.guess_type(relative)
    overrides = {
        ".js": "text/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".py": "text/x-python; charset=utf-8",
        ".wasm": "application/wasm",
    }
    suffix = Path(relative).suffix.lower()
    rendered_type = overrides.get(suffix, content_type or "application/octet-stream")
    if rendered_type.startswith("text/") and "charset=" not in rendered_type:
        rendered_type += "; charset=utf-8"
    return PublicResource(relative, rendered_type, content)


class CodeProbeRequestHandler(BaseHTTPRequestHandler):
    """Serve only the browser application's declared public resources."""

    server_version = "CodeProbeLocal/1"
    sys_version = ""
    root: Path

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        print(f"{self.client_address[0]} - {format % args}")

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _send_plain_error(self, status: HTTPStatus, message: str) -> None:
        body = (message.rstrip(".") + ".\n").encode("utf-8")
        self.send_response(status.value, status.phrase)
        self._security_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve(self, *, send_body: bool) -> None:
        try:
            resource = public_resource(self.root, self.path)
        except FileNotFoundError:
            self._send_plain_error(HTTPStatus.NOT_FOUND, "Resource not found")
            return
        except ServerPolicyError:
            self._send_plain_error(HTTPStatus.BAD_REQUEST, "Invalid request")
            return
        self.send_response(HTTPStatus.OK.value)
        self._security_headers()
        self.send_header("Content-Type", resource.content_type)
        self.send_header("Content-Length", str(len(resource.content)))
        self.end_headers()
        if send_body:
            self.wfile.write(resource.content)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(send_body=False)

    def _method_not_allowed(self) -> None:
        self._send_plain_error(HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")

    do_CONNECT = _method_not_allowed  # type: ignore[assignment]
    do_DELETE = _method_not_allowed  # type: ignore[assignment]
    do_OPTIONS = _method_not_allowed  # type: ignore[assignment]
    do_PATCH = _method_not_allowed  # type: ignore[assignment]
    do_POST = _method_not_allowed  # type: ignore[assignment]
    do_PUT = _method_not_allowed  # type: ignore[assignment]
    do_TRACE = _method_not_allowed  # type: ignore[assignment]


def handler_for_root(root: Path) -> type[CodeProbeRequestHandler]:
    """Create a request-handler class bound to one immutable package root."""

    root_path = Path(root).resolve(strict=True)

    class BoundCodeProbeRequestHandler(CodeProbeRequestHandler):
        root = root_path

    return BoundCodeProbeRequestHandler


def create_server(
    root: Path,
    host: str,
    port: int,
    *,
    allow_network: bool = False,
) -> ThreadingHTTPServer:
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ServerPolicyError("port must be an integer between 0 and 65535")
    bind_address = validate_bind_address(host, allow_network=allow_network)
    server = ThreadingHTTPServer((bind_address, port), handler_for_root(root))
    server.daemon_threads = True
    server.allow_reuse_address = True
    return server


__all__ = [
    "CodeProbeRequestHandler",
    "CONTENT_SECURITY_POLICY",
    "DEFAULT_ENTRY_PATH",
    "DEFAULT_HOST",
    "MAX_PUBLIC_FILE_BYTES",
    "PUBLIC_EXACT_PATHS",
    "PUBLIC_PREFIXES",
    "PublicResource",
    "ServerPolicyError",
    "canonical_request_path",
    "create_server",
    "handler_for_root",
    "is_public_path",
    "public_resource",
    "validate_bind_address",
]
