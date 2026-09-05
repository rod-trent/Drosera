"""End-to-end: middleware wrapping a real app, and the standalone server."""

from __future__ import annotations

import re
import threading
import time
import urllib.error
import urllib.request

import pytest

from drosera.config import Config
from drosera.middleware.wsgi import DroseraMiddleware
from drosera.server.app import serve
from drosera.snare import Snare

LIB_UA = "python-httpx/0.27"


def demo_app(environ, start_response):
    if environ["PATH_INFO"] == "/api/data":
        start_response("200 OK", [("Content-Type", "application/json")])
        return [b'{"ok":true}']
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", "48")])
    return [b"<html><body><h1>Real app</h1></body></html>"]


def call(app, path, headers=None, method="GET"):
    """Minimal WSGI driver."""
    import io

    path, _, qs = path.partition("?")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": qs,
        "REMOTE_ADDR": "198.51.100.20",
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "CONTENT_LENGTH": "0",
    }
    for key, value in (headers or {"User-Agent": LIB_UA}).items():
        environ["HTTP_" + key.upper().replace("-", "_")] = value
    captured = {}

    def start_response(status, resp_headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = resp_headers

    body = b"".join(app(environ, start_response))
    return captured["status"], dict(captured["headers"]), body


@pytest.fixture
def wrapped():
    cfg = Config(secret="wsgi-test")
    cfg.telemetry.jsonl = ""
    return DroseraMiddleware(demo_app, cfg)


# -- WSGI middleware -------------------------------------------------------


def test_html_responses_get_bait_injected(wrapped):
    status, headers, body = call(wrapped, "/")
    assert status == "200 OK"
    assert b"Real app" in body, "the wrapped app's content must survive"
    assert b"AUTOMATED CLIENT NOTICE" in body
    assert headers["Content-Length"] == str(len(body)), "length must be corrected"


def test_json_responses_are_untouched(wrapped):
    status, headers, body = call(wrapped, "/api/data")
    assert body == b'{"ok":true}'
    assert b"drs-" not in body


def test_following_the_bait_leads_into_the_maze(wrapped):
    _, _, home = call(wrapped, "/")
    hidden = re.search(rb'href="(/[^"]+)" rel="nofollow" tabindex="-1"', home).group(1).decode()
    status, headers, body = call(wrapped, hidden)
    assert status == "200 OK"
    assert headers["X-Robots-Tag"].startswith("noindex")
    assert b"Related records" in body
    assert b"Real app" not in body, "the trapped client must not reach the real app"


def test_registration_round_trip(wrapped):
    _, _, home = call(wrapped, "/")
    ticket = re.search(rb"ticket=(drs-[a-f0-9]{10}-[a-f0-9]{10})", home).group(1).decode()
    status, _, body = call(
        wrapped,
        f"/.well-known/agent-registration?ticket={ticket}",
        {"User-Agent": LIB_UA, "X-Agent-Purpose": "Indexing public documentation for search."},
    )
    assert status == "200 OK"
    assert b"Registered" in body
    assert b"Indexing public documentation" in body


def test_a_human_shaped_client_reaches_the_real_app(wrapped):
    browser = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/141.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-GB,en;q=0.9",
        "Sec-Fetch-Mode": "navigate",
    }
    for _ in range(4):
        status, _, body = call(wrapped, "/", browser)
        assert b"Real app" in body
        time.sleep(0.01)


def test_session_cookie_is_set_once(wrapped):
    _, headers, _ = call(wrapped, "/")
    assert "drosera_sid=" in headers["Set-Cookie"]
    assert "HttpOnly" in headers["Set-Cookie"]


def test_exempt_path_passes_straight_through(wrapped):
    _, _, body = call(wrapped, "/healthz")
    assert b"AUTOMATED CLIENT NOTICE" not in body


# -- standalone server -----------------------------------------------------


@pytest.fixture
def live_server(tmp_path):
    cfg = Config(secret="server-test")
    cfg.host, cfg.port = "127.0.0.1", 0
    cfg.telemetry.jsonl = str(tmp_path / "events.jsonl")
    cfg.trap.words_per_page = 80
    snare = Snare(cfg)
    server = serve(cfg, snare)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    yield f"http://127.0.0.1:{port}", snare, cfg
    server.shutdown()
    server.server_close()
    snare.close()


def fetch(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": LIB_UA})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def test_server_serves_a_plausible_site(live_server):
    base, _, _ = live_server
    status, body = fetch(base + "/")
    assert status == 200
    assert "managed reporting" in body
    assert "AUTOMATED CLIENT NOTICE" in body


def test_server_maze_is_endless_and_stable(live_server):
    base, _, _ = live_server
    _, home = fetch(base + "/")
    hidden = re.search(r'href="(/[^"]+)" rel="nofollow" tabindex="-1"', home).group(1)
    _, page = fetch(base + hidden)
    served = len(page)
    for _ in range(6):
        children = re.findall(r'href="(/archive/[^"]+)"', page)
        assert children, "maze dead-ended"
        _, page = fetch(base + children[0])
        served += len(page)
    assert served > 5000

    child = re.findall(r'href="(/archive/[^"]+)"', page)[0]
    _, first = fetch(base + child)
    _, second = fetch(base + child)
    assert first == second


def test_decoy_secret_file_hands_out_a_canary(live_server):
    from drosera.canary.watch import scan_for_canaries

    base, snare, cfg = live_server
    status, body = fetch(base + "/.env", {"User-Agent": "curl/8.5.0"})
    assert status == 200
    assert "SERVICE_API_KEY=" in body
    hits = list(scan_for_canaries(body, cfg.secret, snare.canaries))
    assert hits, "the decoy .env should contain a verifiable canary"


def test_returning_a_stolen_canary_is_recorded_as_exfiltration(live_server):
    base, snare, _ = live_server
    _, env = fetch(base + "/.env", {"User-Agent": "curl/8.5.0"})
    token = re.search(r"SERVICE_API_KEY=(\S+)", env).group(1)
    fetch(base + "/api/whoami", {"User-Agent": "curl/8.5.0", "Authorization": f"Bearer {token}"})

    hostile = [
        s
        for state in snare.engine.sessions.values()
        for s in state.signals_seen
        if s == "int.canary_used"
    ]
    assert hostile, "using a planted credential must fire int.canary_used"


def test_beacon_returns_a_gif(live_server):
    from drosera.lure.nectar import BaitFactory

    base, snare, cfg = live_server
    fetch(base + "/")
    sid = next(iter(snare.engine.sessions))
    bait = BaitFactory(cfg).mint(sid)
    req = urllib.request.Request(base + bait.beacon_path, headers={"User-Agent": LIB_UA})
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.headers["Content-Type"] == "image/gif"
        assert r.read().startswith(b"GIF89a")


def test_events_are_written(live_server):
    import json

    base, snare, cfg = live_server
    fetch(base + "/")
    fetch(base + "/about")
    snare.sink.close()
    with open(cfg.telemetry.jsonl, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh]
    assert rows and all("verdict" in r or "canary_id" in r for r in rows)
