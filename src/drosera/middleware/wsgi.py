"""WSGI middleware -- Flask, Django, Pyramid, Bottle, anything PEP 3333.

::

    from drosera.middleware.wsgi import DroseraMiddleware
    app = DroseraMiddleware(app)

WSGI has no way to express "send this slowly without holding a worker", so the
drip delay is honoured by sleeping in the handler thread. On a threaded server
that is exactly the intended trade -- one held thread per trapped agent. On a
single-worker server, leave ``drip_delay`` at 0 or you will stall the process.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Any

from ..config import Config
from ..models import Observation
from ..snare import Snare
from ..util import lower_headers, split_target


class DroseraMiddleware:
    def __init__(
        self,
        app: Callable[..., Iterable[bytes]],
        config: Config | None = None,
        snare: Snare | None = None,
        max_body: int = 64 * 1024,
    ) -> None:
        self.app = app
        self.snare = snare or Snare(config or Config())
        self.max_body = max_body

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        body = self._read_body(environ)
        obs = self._observation(environ, body)
        decision = self.snare.decide(obs)

        if decision.response is not None:
            r = decision.response
            headers = list(r.headers)
            if decision.set_cookie:
                headers.append(("Set-Cookie", decision.set_cookie))
            start_response(f"{r.status} {_reason(r.status)}", headers)
            return self._drip(r)

        return self._proxy(environ, start_response, decision)

    # -- request ----------------------------------------------------------

    def _read_body(self, environ: dict[str, Any]) -> str:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return ""
        if length <= 0:
            return ""
        stream = environ.get("wsgi.input")
        if stream is None:
            return ""
        take = min(length, self.max_body)
        data = stream.read(take)
        rest = stream.read(length - take) if length > take else b""
        # Hand the app back a complete, re-readable body.
        import io

        environ["wsgi.input"] = io.BytesIO(data + rest)
        return data.decode("utf-8", "replace")

    def _observation(self, environ: dict[str, Any], body: str) -> Observation:
        raw: list[tuple[str, str]] = []
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                raw.append((key[5:].replace("_", "-"), str(value)))
            elif key in ("CONTENT_TYPE", "CONTENT_LENGTH") and value:
                raw.append((key.replace("_", "-"), str(value)))
        headers, order = lower_headers(raw)
        target = environ.get("PATH_INFO", "/")
        if qs := environ.get("QUERY_STRING", ""):
            target += "?" + qs
        path, query = split_target(target)
        return Observation(
            session_id="",
            remote_addr=headers.get("x-forwarded-for", "").split(",")[0].strip()
            or environ.get("REMOTE_ADDR", ""),
            method=environ.get("REQUEST_METHOD", "GET"),
            path=path,
            query=query,
            headers=headers,
            header_order=order,
            body=body,
            host=headers.get("host", ""),
            scheme=environ.get("wsgi.url_scheme", "http"),
        )

    # -- response ---------------------------------------------------------

    def _drip(self, response) -> Iterable[bytes]:
        for i, chunk in enumerate(response.iter_body()):
            if response.chunk_delay and i:
                time.sleep(response.chunk_delay)
            yield chunk

    def _proxy(self, environ, start_response, decision) -> Iterable[bytes]:
        captured: dict[str, Any] = {}

        def capture(status: str, headers: list[tuple[str, str]], exc_info=None):
            captured["status"] = status
            captured["headers"] = headers
            captured["exc_info"] = exc_info
            return lambda data: None  # write() callable; unused by modern apps

        result = self.app(environ, capture)
        headers = list(captured.get("headers", []))
        status = captured.get("status", "200 OK")
        content_type = next((v for k, v in headers if k.lower() == "content-type"), "")
        is_html = "text/html" in content_type.lower() and bool(decision.inject)

        if decision.set_cookie:
            headers.append(("Set-Cookie", decision.set_cookie))

        if not is_html:
            start_response(status, headers, captured.get("exc_info"))
            return result

        body = self.snare.inject_into(b"".join(result), decision.inject)
        if hasattr(result, "close"):
            result.close()
        headers = [(k, v) for k, v in headers if k.lower() != "content-length"]
        headers.append(("Content-Length", str(len(body))))
        start_response(status, headers, captured.get("exc_info"))
        self.snare.note_bytes(decision.assessment.session_id, len(body))
        return [body]


_REASONS = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    410: "Gone",
    429: "Too Many Requests",
}


def _reason(status: int) -> str:
    return _REASONS.get(status, "OK")
