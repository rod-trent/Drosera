"""``drosera dashboard``: the HTML report, live, on localhost.

This is an analyst tool, not part of the honeypot, and the two must never
share a port. The honeypot faces hostile traffic by design; the dashboard shows
exactly what that traffic has been doing and how it was scored. So:

* it binds 127.0.0.1 by default and warns loudly if told otherwise,
* it has no write paths -- GET only, read-only access to the events file,
* it re-renders only when the events file changes, so a large file is not
  re-parsed on every refresh,
* it sends the same Content-Security-Policy as the static report, plus
  ``nosniff`` and ``no-referrer``.

For a shared, authenticated, long-retention dashboard, ship events to
Sentinel and use the workbook in ``integrations/sentinel`` instead.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ..telemetry.export import collect
from ..telemetry.html import CSP, render_html

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class _Cache:
    """Re-read the events file only when its size or mtime moves."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._key: tuple[int, int] | None = None
        self._rows: list[dict[str, Any]] = []
        self._canaries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def get(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        p = Path(self.path)
        try:
            st = p.stat()
            key = (st.st_mtime_ns, st.st_size)
        except OSError:
            return [], []
        with self._lock:
            if key != self._key:
                self._rows, self._canaries = collect(self.path)
                self._key = key
            return self._rows, self._canaries


def make_handler(cache: _Cache, refresh: int, title: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "drosera-dashboard"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                rows, canaries = cache.get()
                page = render_html(rows, canaries, title=title, source=cache.path, refresh=refresh)
                self._send(200, "text/html; charset=utf-8", page.encode())
            elif path == "/api/sessions.json":
                rows, _ = cache.get()
                self._send(200, "application/json", json.dumps(rows, default=str).encode())
            elif path == "/api/canaries.json":
                _, canaries = cache.get()
                self._send(200, "application/json", json.dumps(canaries, default=str).encode())
            elif path == "/healthz":
                self._send(200, "text/plain", b"ok\n")
            else:
                self._send(404, "text/plain", b"not found\n")

        def _refuse(self) -> None:
            self._send(405, "text/plain", b"read-only\n")

        do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = _refuse  # noqa: N815

        def _send(self, status: int, ctype: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            pass

    return Handler


def make_server(
    events: str, host: str = "127.0.0.1", port: int = 8765, refresh: int = 30,
    title: str = "Drosera dashboard",
) -> ThreadingHTTPServer:
    handler = make_handler(_Cache(events), refresh, title)
    return ThreadingHTTPServer((host, port), handler)


def run(events: str, host: str = "127.0.0.1", port: int = 8765, refresh: int = 30) -> None:
    if host not in LOOPBACK:
        print(
            f"drosera: WARNING: dashboard bound to {host}. It has no authentication and shows "
            "everything the honeypot has captured. Put it behind an authenticating proxy, "
            "and never on the honeypot's own public interface.",
            file=sys.stderr,
        )
    server = make_server(events, host, port, refresh)
    shown = f"[{host}]" if ":" in host else host
    print(f"drosera: dashboard for {events} on http://{shown}:{port}/ (Ctrl-C to stop)")
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
