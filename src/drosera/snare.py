"""The snare: one transport-agnostic decision function.

Everything above this file (ASGI middleware, WSGI middleware, the standalone
server) does nothing but translate its own request objects into an
``Observation``, call :meth:`Snare.decide`, and act on the result. That keeps
exactly one copy of the interesting logic and makes the behaviour identical
whichever way Drosera is deployed.

The contract:

* ``decide`` never blocks and never sleeps. Slow delivery is expressed as a
  chunk iterator plus a delay, so each transport can honour it in whatever way
  suits its concurrency model.
* If ``Decision.response`` is set, serve it and do not call the wrapped app.
* If it is ``None``, call the app, and if the result is HTML, insert
  ``Decision.inject`` before ``</body>``.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .canary import mint as canary_mint
from .canary import watch as canary_watch
from .config import Config
from .detect.engine import SESSION_COOKIE, Engine
from .lure import nectar
from .models import Action, Assessment, Bait, Observation
from .telemetry import sink as sinks
from .trap import derail
from .trap.tarpit import Labyrinth

# 1x1 transparent GIF -- the presence beacon's actual payload.
BEACON_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

# Decoy secret files served over HTTP. Requesting any of these is already a
# hostility signal; serving a canary turns a probe into a traceable event.
DECOY_ROUTES = {
    "/.env": "dotenv",
    "/.env.production": "dotenv",
    "/.aws/credentials": "aws",
    "/credentials.json": "credentials_json",
    "/.npmrc": "npmrc",
    "/appsettings.Production.json": "appsettings",
    "/config/kubeconfig": "kubeconfig",
}


@dataclass
class Response:
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    chunks: Iterator[bytes] | None = None
    chunk_delay: float = 0.0

    def iter_body(self) -> Iterator[bytes]:
        if self.chunks is not None:
            yield from self.chunks
        else:
            yield self.body


@dataclass
class Decision:
    assessment: Assessment
    response: Response | None = None
    inject: str = ""
    set_cookie: str = ""
    trapped: bool = False


class Snare:
    """Wires the engine, the lure, the trap and telemetry into one object."""

    def __init__(self, config: Config | None = None, sink: Any | None = None) -> None:
        self.config = config or Config()
        self.bait_factory = nectar.BaitFactory(self.config)
        self.engine = Engine(
            self.config,
            bait_factory=self.bait_factory.mint,
            ticket_validator=self.bait_factory.verify_any,
        )
        self.engine.robots_disallowed = nectar.disallowed_paths()
        self.labyrinth = Labyrinth(self.config)
        self.sink = sink if sink is not None else sinks.build(self.config)
        self.canaries = canary_watch.index(canary_mint.load_registry(canary_mint.REGISTRY_DEFAULT))

    # -- entry point ------------------------------------------------------

    def decide(self, obs: Observation) -> Decision:
        if self.config.is_exempt(obs.path):
            # Health checks must stay boring and fast, and must never be logged
            # as suspicious just because a probe has no User-Agent.
            return Decision(assessment=self._null_assessment(obs))

        # Resolve the session key before scanning so a canary hit can be
        # queued against the session that is about to be assessed. Scanning
        # first and correlating afterwards loses the association entirely.
        if not obs.session_id:
            obs.session_id = self.engine.session_key(obs)
        self._scan_body_for_canaries(obs)

        assessment = self.engine.observe(obs)
        state = self.engine.sessions.get(assessment.session_id)
        bait = state.bait if state else None

        self.sink.emit(assessment.to_dict())

        response, trapped = self._route(obs, bait, assessment)

        if response is None:
            response, trapped = self._enforce(obs, assessment)

        inject = ""
        if response is None and bait is not None and self.config.lure.enabled and self.config.lure.inject_html:
            inject = nectar.html_bait(bait, self.config)

        if response is not None:
            self.engine.note_response(assessment.session_id, self._size(response), tarpit=trapped)

        cookie = ""
        if not obs.headers.get("cookie", "").count(SESSION_COOKIE):
            cookie = (
                f"{SESSION_COOKIE}={assessment.session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
            )

        return Decision(assessment=assessment, response=response, inject=inject, set_cookie=cookie, trapped=trapped)

    # -- lure routes ------------------------------------------------------

    def _route(
        self, obs: Observation, bait: Bait | None, assessment: Assessment
    ) -> tuple[Response | None, bool]:
        """Handle lure and trap routes. Returns (response, is_tarpit)."""
        path = obs.path.rstrip("/") or "/"
        lure = self.config.lure

        if bait is not None:
            if path == bait.beacon_path.rstrip("/"):
                return Response(
                    200,
                    [("Content-Type", "image/gif"), ("Cache-Control", "no-store")],
                    BEACON_GIF,
                ), False
            if path == bait.instruction_path.rstrip("/"):
                ticket = obs.qs("ticket") or ""
                purpose = obs.headers.get(bait.purpose_header.lower(), "") or obs.qs("purpose") or ""
                ok = bool(ticket) and ticket == bait.ticket
                body = nectar.registration_response(bait, purpose, ok)
                return Response(
                    200 if ok else 400,
                    [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")],
                    body.encode(),
                ), False
            if lure.enabled and path in (bait.hidden_path.rstrip("/"), bait.comment_path.rstrip("/")):
                # Bait links lead into the maze. Following one is already
                # recorded; from here on the client pays for every page.
                return self._tarpit_response(self.labyrinth.entry_path(assessment.session_id)), True

        if lure.enabled and lure.robots and path == "/robots.txt":
            return Response(
                200,
                [("Content-Type", "text/plain; charset=utf-8")],
                nectar.robots_txt(self.config).encode(),
            ), False

        if lure.enabled and lure.llms_txt and bait is not None and path == "/llms.txt":
            return Response(
                200,
                [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")],
                nectar.llms_txt(bait, self.config).encode(),
            ), False

        if lure.enabled and bait is not None and path == nectar.POLICY_PATH.rstrip("/"):
            return Response(
                200,
                [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")],
                nectar.policy_page(bait, self.config).encode(),
            ), False

        if lure.enabled and lure.secret_files and obs.path in DECOY_ROUTES:
            return self._decoy_secret(DECOY_ROUTES[obs.path]), False

        if self.config.trap.enabled and self.labyrinth.owns(obs.path):
            return self._tarpit_response(obs.path), True

        return None, False

    def _decoy_secret(self, kind: str) -> Response:
        """Serve a fresh canary. Minted per request so each theft is distinguishable."""
        canary, content = canary_mint.render(kind, self.config.secret, self.config.lure.contact.split("@")[-1])
        self.canaries[canary.id] = canary
        return Response(
            200,
            [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")],
            content.encode(),
        )

    # -- enforcement ------------------------------------------------------

    def _enforce(self, obs: Observation, assessment: Assessment) -> tuple[Response | None, bool]:
        action = assessment.action
        if action in (Action.ALLOW, Action.OBSERVE, Action.TAG):
            return None, False
        if action == Action.BLOCK:
            return Response(
                403,
                [("Content-Type", "text/plain; charset=utf-8")],
                b"Forbidden.\n",
            ), False
        if action == Action.DERAIL:
            kind = derail.DEFAULT
            return Response(
                derail.status_for(kind), derail.headers(), derail.derail_html(kind).encode()
            ), False
        # TARPIT and DIVERT both feed the maze; DIVERT simply enters at a
        # per-session root so separate agents do not share a cached path.
        if self.engine.budget_exceeded(assessment.session_id):
            # Budget spent: stop paying to serve this client and close the branch.
            return Response(
                derail.status_for("retired"), derail.headers(), derail.derail_html("retired").encode()
            ), False
        entry = (
            obs.path
            if self.labyrinth.owns(obs.path)
            else self.labyrinth.entry_path(assessment.session_id)
        )
        return self._tarpit_response(entry), True

    def _tarpit_response(self, path: str) -> Response:
        body = self.labyrinth.render(path)
        return Response(
            200,
            self.labyrinth.headers(),
            body.encode(),
            chunks=self.labyrinth.chunks(body) if self.config.trap.drip_bytes else None,
            chunk_delay=self.labyrinth.drip_delay,
        )

    # -- helpers ----------------------------------------------------------

    def _scan_body_for_canaries(self, obs: Observation) -> None:
        """A planted credential appearing in a request is proof of exfiltration."""
        haystack = obs.body[:16384]
        auth = obs.headers.get("authorization", "")
        if auth:
            haystack += "\n" + auth
        if not haystack:
            return
        for hit in canary_watch.scan_for_canaries(haystack, self.config.secret, self.canaries):
            self.engine.report_canary(hit.canary_id, f"{obs.method} {obs.path}", correlate=obs.session_id)
            self.sink.emit(hit.to_dict())

    @staticmethod
    def _size(response: Response) -> int:
        return len(response.body) if response.chunks is None else 0

    def _null_assessment(self, obs: Observation) -> Assessment:
        from .models import Verdict

        return Assessment(
            session_id="exempt",
            verdict=Verdict.UNKNOWN,
            agency=0.0,
            hostility=0.0,
            action=Action.ALLOW,
            path=obs.path,
            method=obs.method,
        )

    def inject_into(self, html: bytes, snippet: str) -> bytes:
        """Insert bait before ``</body>``, or append if the document has no body tag."""
        if not snippet:
            return html
        payload = snippet.encode()
        lower = html.lower()
        idx = lower.rfind(b"</body>")
        if idx == -1:
            return html + payload
        return html[:idx] + payload + html[idx:]

    def note_bytes(self, session_id: str, nbytes: int, tarpit: bool = False) -> None:
        self.engine.note_response(session_id, nbytes, tarpit=tarpit)

    def close(self) -> None:
        self.sink.close()
