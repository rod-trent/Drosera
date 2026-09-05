"""Vercel serverless function: score a request trace with the real engine.

This deliberately imports ``drosera`` and runs the actual detector rather than
reimplementing the scoring in JavaScript. A second implementation in the
browser would drift from the library within a release or two, and a demo that
misreports your own detection is worse than no demo.

It fits serverless because the parts of Drosera that matter here are already
stateless by construction: bait is HMAC-derived rather than stored, ticket
validation is a signature check with no lookup, and the maze is seeded from its
own URL. The session store is the only stateful piece, and one trace is scored
inside a single invocation, so a fresh Engine per request is correct as well as
convenient -- it also means one visitor can never see another's state.

What this endpoint does NOT do is run a tarpit. Serving an endless maze from a
per-second billing model would invert the economics the trap depends on. See
docs/ethics.md and the deployment guide.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler

from drosera import __version__
from drosera.config import Config
from drosera.detect.engine import Engine
from drosera.detect.rules import SIGNALS
from drosera.lure.nectar import BaitFactory
from drosera.models import Observation
from drosera.util import lower_headers, split_target

MAX_BODY = 64 * 1024
MAX_STEPS = 40
MAX_HEADERS = 40
MAX_VALUE = 2048

# Fixed so the demo is reproducible and shareable; a real deployment must use a
# secret nobody else knows, which is what `drosera doctor` checks for.
DEMO_SECRET = "drosera-public-playground"

BROWSER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}
CRAWLER = {
    "User-Agent": "Mozilla/5.0 (compatible; ExampleCrawler/2.1; +http://example.net/bot)",
    "Accept": "*/*",
    "Accept-Encoding": "gzip",
}
SCANNER = {"User-Agent": "python-requests/2.32.3", "Accept": "*/*"}
AGENT = {
    "User-Agent": "Mozilla/5.0 (compatible; ResearchAgent/1.0; python-httpx/0.27)",
    "Accept": "*/*",
}


def _steps_human(bait):
    return [
        ("GET", "/", BROWSER, 0.0),
        ("GET", "/assets/site.css", BROWSER, 0.3),
        ("GET", bait.beacon_path, BROWSER, 0.5),
        ("GET", "/about", BROWSER, 9.4),
        ("GET", "/assets/site.css", BROWSER, 9.6),
        ("GET", bait.beacon_path, BROWSER, 9.8),
        ("GET", "/contact", BROWSER, 26.1),
    ]


def _steps_crawler(bait):
    paths = ["/robots.txt", "/", "/about", "/services", "/careers", "/status", "/sitemap.xml"]
    return [("GET", p, CRAWLER, i * 1.05) for i, p in enumerate(paths)]


def _steps_scanner(bait):
    paths = [
        "/.env",
        "/.git/config",
        "/admin",
        "/wp-login.php",
        "/api/v1/users?id=1%20OR%201=1",
        "/../../etc/passwd",
        "/actuator/env",
        "/.aws/credentials",
    ]
    return [("GET", p, SCANNER, i * 0.11) for i, p in enumerate(paths)]


def _steps_agent(bait):
    registering = dict(AGENT)
    registering["X-Agent-Purpose"] = (
        "Collecting public pricing pages to build a market comparison report."
    )
    return [
        ("GET", "/", AGENT, 0.0),
        ("GET", "/llms.txt", AGENT, 1.4),
        ("GET", f"/.well-known/agent-registration?ticket={bait.ticket}", registering, 2.6),
        ("GET", bait.hidden_path, AGENT, 3.9),
        ("GET", "/archive/index/a1/folio-2201", AGENT, 5.2),
    ]


SCENARIOS = {
    "human": {
        "label": "A person in a browser",
        "note": "Loads a page, its stylesheet fires, JavaScript runs the beacon, then pauses to read.",
        "steps": _steps_human,
        "headers": BROWSER,
    },
    "crawler": {
        "label": "An ordinary crawler",
        "note": "Reads robots.txt, walks the sitemap at a steady rate, fetches no assets.",
        "steps": _steps_crawler,
        "headers": CRAWLER,
    },
    "scanner": {
        "label": "A hostile scanner",
        "note": "Hunts for secrets and admin panels, probes for injection. Fast and mechanical.",
        "steps": _steps_scanner,
        "headers": SCANNER,
    },
    "agent": {
        "label": "An LLM agent",
        "note": "Reads the notice, understands it, registers with the ticket and states its purpose.",
        "steps": _steps_agent,
        "headers": AGENT,
    },
}


def _config() -> Config:
    cfg = Config(secret=DEMO_SECRET)
    cfg.telemetry.jsonl = ""      # nothing is written; nothing is retained
    cfg.telemetry.sqlite = ""
    cfg.telemetry.webhook = ""
    return cfg


def _engine(cfg: Config) -> tuple[Engine, BaitFactory]:
    factory = BaitFactory(cfg)
    engine = Engine(cfg, bait_factory=factory.mint, ticket_validator=factory.verify_any)
    engine.robots_disallowed = {"/internal/", "/staff/", "/ops/", "/legacy/"}
    return engine, factory


def _observation(method, target, headers, ts, addr="203.0.113.42"):
    low, order = lower_headers(list(headers.items()))
    path, query = split_target(target)
    return Observation(
        session_id="",
        remote_addr=addr,
        method=method,
        path=path,
        query=query,
        headers=low,
        header_order=order,
        ts=ts,
    )


def _collect(collected: dict, assessment) -> None:
    """Accumulate every signal seen across a trace.

    Reporting only the last request's signals would be misleading: the decisive
    moment -- the ticket coming back -- is usually several requests earlier, and
    the point of the demo is to show exactly when the verdict was earned.
    """
    for sig in assessment.signals:
        if sig.id in collected:
            continue
        definition = SIGNALS.get(sig.id)
        collected[sig.id] = {
            "id": sig.id,
            "category": sig.category.value,
            "agency": round(sig.agency, 2),
            "hostility": round(sig.hostility, 2),
            "detail": sig.detail,
            "description": definition.description if definition else "",
            "proves_llm": sig.category.value == "comprehension" or sig.id == "id.declared_agent",
        }


def _describe(assessment, collected: dict) -> dict:
    fired = sorted(collected.values(), key=lambda s: (-s["agency"], s["id"]))
    return {
        "verdict": assessment.verdict.value,
        "automation": round(assessment.automation, 1),
        "agency": round(assessment.agency, 1),
        "hostility": round(assessment.hostility, 1),
        "action": assessment.action.value,
        "requests": assessment.hits,
        "signals": fired,
    }


def run_scenario(key: str) -> dict:
    spec = SCENARIOS[key]
    cfg = _config()
    engine, factory = _engine(cfg)
    base = time.time()

    # Mint the same bait the engine will mint for this client, so the scripted
    # trace can reference the ticket and hidden path it would really have seen.
    probe = _observation("GET", "/", spec["headers"], base)
    bait = factory.mint(engine.session_key(probe))

    timeline = []
    collected: dict = {}
    assessment = None
    for method, target, headers, offset in spec["steps"](bait):
        assessment = engine.observe(_observation(method, target, headers, base + offset))
        _collect(collected, assessment)
        timeline.append(
            {
                "method": method,
                "target": target,
                "at": round(offset, 2),
                "verdict": assessment.verdict.value,
                "agency": round(assessment.agency, 1),
                "automation": round(assessment.automation, 1),
                "new_signals": [s.id for s in assessment.signals],
            }
        )

    result = _describe(assessment, collected)
    result.update({"scenario": key, "label": spec["label"], "note": spec["note"], "timeline": timeline})
    return result


def score_live_request(headers: dict, path: str, addr: str) -> dict:
    """Score the visitor's own request. One observation, no history."""
    cfg = _config()
    engine, _ = _engine(cfg)
    low, order = lower_headers(list(headers.items())[:MAX_HEADERS])
    route, query = split_target(path or "/")
    obs = Observation(
        session_id="",
        remote_addr=addr,
        method="GET",
        path=route,
        query=query,
        headers=low,
        header_order=order,
        ts=time.time(),
    )
    assessment = engine.observe(obs)
    collected: dict = {}
    _collect(collected, assessment)
    result = _describe(assessment, collected)
    result["note"] = (
        "Scored from one background fetch() rather than a page navigation, so two "
        "things are expected here: behavioural signals that need request history "
        "cannot fire, and a browser's fetch() legitimately sends Accept: */*, which "
        "is why a real person may pick up a weak identity signal. Neither can move "
        "the LLM axis, which is the point."
    )
    return result


def score_custom(payload: dict) -> dict:
    """Score a user-supplied trace. Everything here is untrusted input."""
    raw_headers = payload.get("headers") or {}
    if not isinstance(raw_headers, dict):
        raise ValueError("headers must be an object")
    headers = {
        str(k)[:128]: str(v)[:MAX_VALUE]
        for k, v in list(raw_headers.items())[:MAX_HEADERS]
    }
    steps = payload.get("requests") or [{"path": "/"}]
    if not isinstance(steps, list):
        raise ValueError("requests must be a list")
    steps = steps[:MAX_STEPS]

    cfg = _config()
    engine, factory = _engine(cfg)
    base = time.time()
    interval = float(payload.get("interval", 1.0))
    interval = min(max(interval, 0.0), 3600.0)

    assessment = None
    timeline = []
    collected: dict = {}
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        target = str(step.get("path", "/"))[:MAX_VALUE]
        method = str(step.get("method", "GET"))[:12].upper()
        step_headers = dict(headers)
        extra = step.get("headers")
        if isinstance(extra, dict):
            for k, v in list(extra.items())[:MAX_HEADERS]:
                step_headers[str(k)[:128]] = str(v)[:MAX_VALUE]
        assessment = engine.observe(
            _observation(method, target, step_headers, base + i * interval)
        )
        _collect(collected, assessment)
        timeline.append(
            {
                "method": method,
                "target": target,
                "at": round(i * interval, 2),
                "verdict": assessment.verdict.value,
                "agency": round(assessment.agency, 1),
                "automation": round(assessment.automation, 1),
                "new_signals": [s.id for s in assessment.signals],
            }
        )

    if assessment is None:
        raise ValueError("no valid requests supplied")
    result = _describe(assessment, collected)
    result["timeline"] = timeline
    result["scenario"] = "custom"
    result["label"] = "Custom trace"
    return result


def dispatch(body: bytes, request_headers: dict, request_path: str, addr: str) -> tuple[int, dict]:
    """Route one API call. Returns (status, payload)."""
    try:
        payload = json.loads(body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 400, {"error": "body must be JSON"}
    if not isinstance(payload, dict):
        return 400, {"error": "body must be a JSON object"}

    mode = payload.get("mode", "scenario")
    try:
        if mode == "scenario":
            key = payload.get("scenario", "agent")
            if key not in SCENARIOS:
                return 400, {"error": f"unknown scenario {key!r}"}
            return 200, run_scenario(key)
        if mode == "live":
            return 200, score_live_request(request_headers, request_path, addr)
        if mode == "custom":
            return 200, score_custom(payload)
    except ValueError as exc:
        return 400, {"error": str(exc)}
    return 400, {"error": f"unknown mode {mode!r}"}


class handler(BaseHTTPRequestHandler):  # noqa: N801 - Vercel requires this name
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._send(
            200,
            {
                "drosera": __version__,
                "scenarios": {k: v["label"] for k, v in SCENARIOS.items()},
                "signal_count": len(SIGNALS),
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self._send(413, {"error": "request too large"})
            return
        body = self.rfile.read(length) if length > 0 else b"{}"
        addr = (self.headers.get("x-forwarded-for") or "203.0.113.42").split(",")[0].strip()
        status, payload = dispatch(body, dict(self.headers.items()), self.path, addr)
        payload.setdefault("drosera_version", __version__)
        self._send(status, payload)

    def log_message(self, *args) -> None:
        pass
