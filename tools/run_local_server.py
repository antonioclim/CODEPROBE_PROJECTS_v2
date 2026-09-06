#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Serve CodeProbe's declared browser surface on a local HTTP endpoint."""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site):
    raise SystemExit(
        "this command requires isolated, site-free Python; rerun it with -I -S -B"
    )

import argparse
import socket
import webbrowser
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.append(str(SRC))

from codeprobe_engine.server import (  # noqa: E402
    DEFAULT_ENTRY_PATH,
    DEFAULT_HOST,
    ServerPolicyError,
    create_server,
    validate_bind_address,
)


def find_free_port(host: str = DEFAULT_HOST) -> int:
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Serve only CodeProbe's browser application and authorised runtime files."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="Port to use. Default: choose a free port.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Explicitly permit a non-loopback bind address. This exposes the page to the network.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        host = validate_bind_address(args.host, allow_network=args.allow_network)
        port = args.port or find_free_port(host)
        server = create_server(ROOT, host, port)
    except (OSError, ServerPolicyError, ValueError) as exc:
        print(f"Cannot start the local server: {exc}", file=sys.stderr)
        return 2

    actual_port = int(server.server_address[1])
    display_host = f"[{host}]" if ":" in host else host
    url = f"http://{display_host}:{actual_port}{DEFAULT_ENTRY_PATH}"
    print(f"Serving the declared CodeProbe browser surface from: {ROOT}")
    print(f"Open: {url}")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
