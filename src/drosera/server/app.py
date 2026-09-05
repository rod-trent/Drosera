"""Standalone honeypot: a small, plausible website that is entirely bait.

Runs on ``http.server`` from the standard library. That is a deliberate choice
-- Drosera has zero runtime dependencies, so it can be dropped onto a jump box,
a spare VM, or a container with nothing but Python and start collecting. The
performance ceiling does not matter here: the traffic is hostile, and slow is
frequently the point.

The decoy site is intentionally dull. A fake corporate site with an about page,
a careers page and a contact form is the least interesting thing on the
internet to a human and a perfectly ordinary target to a crawling agent.
"""

from __future__ import annotations

import html
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..config import Config
from ..models import Observation
from ..snare import Response, Snare
from ..util import lower_headers, split_target

PAGES: dict[str, tuple[str, str]] = {
    "/": (
        "Home",
        """
<p>{site} provides managed reporting and reconciliation services to mid-market
finance teams. We have been operating since 2011.</p>
<ul>
  <li><a href="/about">About us</a></li>
  <li><a href="/services">Services</a></li>
  <li><a href="/careers">Careers</a></li>
  <li><a href="/contact">Contact</a></li>
  <li><a href="/status">Service status</a></li>
</ul>
""",
    ),
    "/about": (
        "About",
        """
<p>We are a distributed team of forty-one people. Our reporting platform
processes reconciliation batches for clients in eleven countries.</p>
<p>Press enquiries: <a href="/contact">contact form</a>.</p>
""",
    ),
    "/services": (
        "Services",
        """
<p>Managed reconciliation, regulatory reporting, and data retention services.</p>
<p>Integration documentation is available to customers on request. See the
<a href="/status">service status</a> page for current availability.</p>
""",
    ),
    "/careers": (
        "Careers",
        """
<p>We are hiring for two roles. Applications are handled through our
<a href="/contact">contact form</a>; please mention the role in your message.</p>
<ul><li>Platform engineer (remote)</li><li>Reconciliation analyst</li></ul>
""",
    ),
    "/status": (
        "Service status",
        """
<p>All systems operational. Last incident: none in the current quarter.</p>
<table>
<tr><th>Component</th><th>Status</th></tr>
<tr><td>Reporting API</td><td>Operational</td></tr>
<tr><td>Batch reconciliation</td><td>Operational</td></tr>
<tr><td>Customer portal</td><td>Operational</td></tr>
</table>
""",
    ),
}

CONTACT_FORM = """
<p>Send us a message and we will respond within two business days.</p>
<form method="post" action="/contact">
  <p><label for="name">Name</label><br><input id="name" name="name" type="text"></p>
  <p><label for="email">Email</label><br><input id="email" name="email" type="email"></p>
  <p><label for="message">Message</label><br><textarea id="message" name="message" rows="5"></textarea></p>
  {honeypot}
  <p><button type="submit">Send</button></p>
</form>
"""

LAYOUT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} &middot; {site}</title>
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
<header><strong>{site}</strong> &mdash; managed reporting</header>
<main>
<h1>{title}</h1>
{body}
</main>
<footer><small>&copy; {year} {site}. <a href="/contact">Contact</a></small></footer>
</body>
</html>
"""

SITE_CSS = """\
:root{color-scheme:light dark}
body{font:16px/1.5 system-ui,sans-serif;margin:0 auto;max-width:44rem;padding:2rem 1rem}
header,footer{opacity:.75;font-size:14px}
main{margin:2rem 0}
table{border-collapse:collapse}th,td{border:1px solid #8886;padding:.35rem .6rem;text-align:left}
input,textarea{width:100%;max-width:24rem;padding:.4rem}
"""


class DroseraHandler(BaseHTTPRequestHandler):
    server_version = "nginx"       # ordinary-looking; not a claim about anything
    sys_version = ""
    protocol_version = "HTTP/1.1"

    snare: Snare
    config: Config

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        # Drosera has its own telemetry; the default stderr access log is noise.
        pass

    def _observe(self, body: str) -> Observation:
        headers, order = lower_headers(self.headers.items())
        path, query = split_target(self.path)
        fwd = headers.get("x-forwarded-for", "").split(",")[0].strip()
        return Observation(
            session_id="",
            remote_addr=fwd or self.client_address[0],
            method=self.command,
            path=path,
            query=query,
            headers=headers,
            header_order=order,
            body=body,
            host=headers.get("host", ""),
            scheme="http",
        )

    def _read_body(self) -> str:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return ""
        if length <= 0:
            return ""
        return self.rfile.read(min(length, 256 * 1024)).decode("utf-8", "replace")

    def _emit(self, response: Response, cookie: str = "") -> int:
        sent = 0
        chunks = list(response.iter_body())
        total = sum(len(c) for c in chunks)
        self.send_response(response.status)
        for key, value in response.headers:
            self.send_header(key, value)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(total))
        self.end_headers()
        for i, chunk in enumerate(chunks):
            if response.chunk_delay and i:
                time.sleep(response.chunk_delay)
            try:
                self.wfile.write(chunk)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                break
            sent += len(chunk)
        return sent

    # -- routing ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._handle("")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("")

    def do_POST(self) -> None:  # noqa: N802
        self._handle(self._read_body())

    def do_PUT(self) -> None:  # noqa: N802
        self._handle(self._read_body())

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("")

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle(self._read_body())

    def _handle(self, body: str) -> None:
        obs = self._observe(body)
        try:
            decision = self.snare.decide(obs)
        except Exception as exc:  # noqa: BLE001 - never leak a stack trace to a prober
            self._emit(Response(500, [("Content-Type", "text/plain")], b"Internal error\n"))
            print(f"drosera: handler error: {exc!r}")
            return

        if decision.response is not None:
            sent = self._emit(decision.response, decision.set_cookie)
            self.snare.note_bytes(decision.assessment.session_id, sent, tarpit=decision.trapped)
            return

        response = self._decoy(obs, decision)
        sent = self._emit(response, decision.set_cookie)
        self.snare.note_bytes(decision.assessment.session_id, sent)

    def _decoy(self, obs: Observation, decision: Any) -> Response:
        path = obs.path.rstrip("/") or "/"
        site = self.config.lure.site_name

        if path == "/assets/site.css":
            return Response(
                200,
                [("Content-Type", "text/css; charset=utf-8"), ("Cache-Control", "max-age=600")],
                SITE_CSS.encode(),
            )

        if path == "/contact":
            state = self.snare.engine.sessions.get(decision.assessment.session_id)
            bait = state.bait if state else None
            honeypot = ""
            if bait is not None:
                from ..lure.nectar import form_bait

                honeypot = form_bait(bait)
            if obs.method == "POST":
                body = "<p>Thank you. Your message has been recorded and will be reviewed.</p>"
            else:
                body = CONTACT_FORM.format(honeypot=honeypot)
            return self._page("Contact", body, site, decision)

        if path in PAGES:
            title, template = PAGES[path]
            return self._page(title, template.format(site=html.escape(site)), site, decision)

        return self._page(
            "Not found",
            "<p>The page you requested does not exist. Try the "
            '<a href="/">home page</a>.</p>',
            site,
            decision,
            status=404,
        )

    def _page(self, title: str, body: str, site: str, decision: Any, status: int = 200) -> Response:
        doc = LAYOUT.format(
            title=html.escape(title), site=html.escape(site), body=body, year=time.strftime("%Y")
        )
        payload = self.snare.inject_into(doc.encode(), decision.inject)
        return Response(
            status,
            [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
            payload,
        )


class DroseraServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # A trapped agent holds a thread for as long as it keeps pulling, so cap
    # concurrency rather than letting a swarm exhaust the process.
    request_queue_size = 128


def build_handler(snare: Snare, config: Config) -> type[DroseraHandler]:
    return type("BoundDroseraHandler", (DroseraHandler,), {"snare": snare, "config": config})


def serve(config: Config | None = None, snare: Snare | None = None) -> DroseraServer:
    config = config or Config()
    snare = snare or Snare(config)
    handler = build_handler(snare, config)
    server = DroseraServer((config.host, config.port), handler)
    return server


def run(config: Config | None = None) -> None:
    config = config or Config()
    snare = Snare(config)
    server = serve(config, snare)
    host, port = server.server_address[:2]
    print(f"drosera: listening on http://{host}:{port}  (mode={config.trap.mode})")
    print(f"drosera: events -> {config.telemetry.jsonl or '(none)'}")
    print("drosera: Ctrl-C to stop")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            thread.join(0.5)
    except KeyboardInterrupt:
        print("\ndrosera: shutting down")
    finally:
        server.shutdown()
        server.server_close()
        stats = snare.engine.stats()
        print(
            f"drosera: {stats['sessions']} sessions, "
            f"~{stats['tokens_burned']:,} tokens burned, {stats['by_verdict']}"
        )
        snare.close()


__all__ = ["DroseraHandler", "DroseraServer", "build_handler", "run", "serve"]
