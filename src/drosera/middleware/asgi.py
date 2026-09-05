"""ASGI middleware -- FastAPI, Starlette, Litestar, Django ASGI, Quart.

Wrap your app and you are done::

    from drosera.middleware.asgi import DroseraMiddleware
    app = DroseraMiddleware(app)

Two behaviours worth knowing about:

* Response bodies are only buffered when the response is HTML *and* there is
  bait to inject. Anything else streams straight through untouched, so JSON
  APIs and file downloads keep their streaming semantics.
* The body of an incoming request is read only up to ``max_body`` bytes and is
  replayed to the wrapped app, so upstream handlers still see a complete
  request. Large uploads skip inspection entirely rather than being buffered.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..config import Config
from ..models import Observation
from ..snare import Snare
from ..util import lower_headers, split_target

Scope = dict[str, Any]


class DroseraMiddleware:
    """ASGI3 middleware."""

    def __init__(
        self,
        app: Any,
        config: Config | None = None,
        snare: Snare | None = None,
        max_body: int = 64 * 1024,
    ) -> None:
        self.app = app
        self.snare = snare or Snare(config or Config())
        self.max_body = max_body

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        body, receive = await self._peek_body(receive)
        obs = self._observation(scope, body)
        decision = await asyncio.to_thread(self.snare.decide, obs)

        if decision.response is not None:
            await self._send_response(send, decision)
            return

        await self._proxy(scope, receive, send, decision)

    # -- request side -----------------------------------------------------

    async def _peek_body(self, receive: Any) -> tuple[str, Any]:
        """Read a bounded prefix of the body and rebuild a replayable receive()."""
        chunks: list[bytes] = []
        total = 0
        messages: list[dict[str, Any]] = []
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            chunk = message.get("body", b"")
            if total < self.max_body:
                chunks.append(chunk[: self.max_body - total])
                total += len(chunk)
            if not message.get("more_body", False):
                break

        queue = list(messages)

        async def replay() -> dict[str, Any]:
            if queue:
                return queue.pop(0)
            return await receive()

        return b"".join(chunks).decode("utf-8", "replace"), replay

    def _observation(self, scope: Scope, body: str) -> Observation:
        raw_headers = [
            (k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers", [])
        ]
        headers, order = lower_headers(raw_headers)
        query_string = scope.get("query_string", b"").decode("latin-1")
        path, query = split_target(scope.get("path", "/") + ("?" + query_string if query_string else ""))
        client = scope.get("client") or ("", 0)
        return Observation(
            session_id="",
            remote_addr=headers.get("x-forwarded-for", "").split(",")[0].strip() or (client[0] or ""),
            method=scope.get("method", "GET"),
            path=path,
            query=query,
            headers=headers,
            header_order=order,
            body=body,
            host=headers.get("host", ""),
            scheme=scope.get("scheme", "http"),
        )

    # -- response side ----------------------------------------------------

    async def _send_response(self, send: Any, decision: Any) -> None:
        r = decision.response
        headers = [(k.encode(), v.encode()) for k, v in r.headers]
        if decision.set_cookie:
            headers.append((b"set-cookie", decision.set_cookie.encode()))
        await send({"type": "http.response.start", "status": r.status, "headers": headers})
        chunks = list(r.iter_body())
        for i, chunk in enumerate(chunks):
            if r.chunk_delay and i:
                await asyncio.sleep(r.chunk_delay)
            await send({"type": "http.response.body", "body": chunk, "more_body": i < len(chunks) - 1})
        if not chunks:
            await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _proxy(self, scope: Scope, receive: Any, send: Any, decision: Any) -> None:
        """Pass through to the app, injecting bait into HTML responses."""
        state: dict[str, Any] = {"html": False, "start": None, "buffer": bytearray()}

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                content_type = b""
                for k, v in headers:
                    if k.lower() == b"content-type":
                        content_type = v.lower()
                state["html"] = b"text/html" in content_type and bool(decision.inject)
                if decision.set_cookie:
                    headers.append((b"set-cookie", decision.set_cookie.encode()))
                if state["html"]:
                    # Length changes once bait is inserted; drop it and let the
                    # server frame the response.
                    headers = [(k, v) for k, v in headers if k.lower() != b"content-length"]
                    state["start"] = {**message, "headers": headers}
                    return
                await send({**message, "headers": headers})
                return

            if message["type"] == "http.response.body" and state["html"]:
                state["buffer"].extend(message.get("body", b""))
                if message.get("more_body", False):
                    return
                body = self.snare.inject_into(bytes(state["buffer"]), decision.inject)
                start = state["start"] or {"type": "http.response.start", "status": 200, "headers": []}
                headers = [*start.get("headers", []), (b"content-length", str(len(body)).encode())]
                await send({**start, "headers": headers})
                await send({"type": "http.response.body", "body": body, "more_body": False})
                self.snare.note_bytes(decision.assessment.session_id, len(body))
                return

            await send(message)

        await self.app(scope, receive, send_wrapper)
