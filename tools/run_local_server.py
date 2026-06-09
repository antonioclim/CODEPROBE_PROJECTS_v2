#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small localhost server for CodeProbe's static browser interface."""

from __future__ import annotations

import argparse
import functools
import socket
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional


DEFAULT_HOST = "127.0.0.1"


class QuietStaticHandler(SimpleHTTPRequestHandler):
    """Static-file handler with concise terminal logging."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003 - inherited name
        print(f"{self.address_string()} - {format % args}")


def find_free_port(host: str = DEFAULT_HOST) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve CodeProbe locally from the package root and open app/index.html.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="Port to use. Default: choose a free port.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    port = args.port or find_free_port(args.host)
    url = f"http://{args.host}:{port}/app/index.html"
    handler = functools.partial(QuietStaticHandler, directory=str(root))
    server = ThreadingHTTPServer((args.host, port), handler)

    print(f"Serving CodeProbe package root from: {root}")
    print(f"Open: {url}")
    if args.host != DEFAULT_HOST:
        print("Warning: binding outside 127.0.0.1 can expose the page on your network.")
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


if __name__ == "__main__":
    main()
