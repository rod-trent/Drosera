"""Run the playground locally, without Vercel.

    python web/dev.py          # then open http://127.0.0.1:3000

Serves index.html and routes /api/assess to the same dispatch() the serverless
function uses, so what you see locally is what deploys.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "api"))
sys.path.insert(0, str(HERE.parent / "src"))

import assess  # noqa: E402


class Dev(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/assess":
            payload = {
                "drosera": assess.__version__,
                "scenarios": {k: v["label"] for k, v in assess.SCENARIOS.items()},
            }
            self._send(200, json.dumps(payload).encode(), "application/json")
            return
        page = (HERE / "index.html").read_bytes()
        self._send(200, page, "text/html; charset=utf-8")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b"{}"
        status, payload = assess.dispatch(
            body, dict(self.headers.items()), self.path, self.client_address[0]
        )
        self._send(status, json.dumps(payload).encode(), "application/json")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    print(f"playground: http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Dev).serve_forever()
