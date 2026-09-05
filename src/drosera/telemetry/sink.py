"""Where events go.

Sinks are intentionally dumb and never raise into the request path. A honeypot
that 500s because its log disk filled up is a honeypot that just told the
attacker exactly where the tripwire is, so every failure here degrades to a
warning on stderr and nothing else.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from ..models import Assessment
from ..util import stable_hash


class Sink(Protocol):
    def emit(self, event: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


def _warn(msg: str) -> None:
    print(f"drosera: telemetry: {msg}", file=sys.stderr)


class StderrSink:
    """Human-readable one-liners. Useful in the foreground, noisy in production."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def emit(self, event: dict[str, Any]) -> None:
        if self.verbose:
            print(json.dumps(event, sort_keys=True), file=sys.stderr)
        else:
            sig = ",".join(s["id"] for s in event.get("signals", [])) or "-"
            print(
                f"[{event.get('verdict','?'):<14}] "
                f"a={event.get('agency',0):>5} h={event.get('hostility',0):>5} "
                f"{event.get('method','')} {event.get('path','')} <- {event.get('remote_addr','')} [{sig}]",
                file=sys.stderr,
            )

    def close(self) -> None:
        pass


class JsonlSink:
    """Append-only JSON Lines. The default, and the format every other tool reads."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _warn(f"cannot create {self.path.parent}: {exc}")

    def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), sort_keys=False)
        try:
            with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            _warn(f"write to {self.path} failed: {exc}")

    def close(self) -> None:
        pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    session_id   TEXT,
    fingerprint  TEXT,
    remote_addr  TEXT,
    method       TEXT,
    path         TEXT,
    user_agent   TEXT,
    verdict      TEXT,
    agency       REAL,
    hostility    REAL,
    action       TEXT,
    hits         INTEGER,
    tokens_burned INTEGER,
    signals      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""


class SqliteSink:
    """Queryable history. One connection, guarded by a lock; WAL for concurrent reads."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def emit(self, event: dict[str, Any]) -> None:
        row = (
            event.get("ts", time.time()),
            event.get("session_id"),
            event.get("fingerprint"),
            event.get("remote_addr"),
            event.get("method"),
            event.get("path"),
            event.get("user_agent"),
            event.get("verdict"),
            event.get("agency"),
            event.get("hostility"),
            event.get("action"),
            event.get("hits"),
            event.get("tokens_burned"),
            json.dumps(event.get("signals", [])),
        )
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO events (ts,session_id,fingerprint,remote_addr,method,path,"
                    "user_agent,verdict,agency,hostility,action,hits,tokens_burned,signals) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    row,
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            _warn(f"sqlite insert failed: {exc}")

    def close(self) -> None:
        with self._lock, contextlib.suppress(sqlite3.Error):
            self._conn.close()


class WebhookSink:
    """POST events to a URL from a background thread.

    Buffered and lossy on purpose: if the receiver is slow or down, events are
    dropped rather than allowed to back up into request handling.
    """

    def __init__(self, url: str, timeout: float = 4.0, capacity: int = 1000) -> None:
        self.url = url
        self.timeout = timeout
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=capacity)
        self._dropped = 0
        self._thread = threading.Thread(target=self._pump, name="drosera-webhook", daemon=True)
        self._thread.start()

    def emit(self, event: dict[str, Any]) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:
                _warn(f"webhook queue full, dropped {self._dropped} events")

    def _pump(self) -> None:
        while True:
            event = self._q.get()
            if event is None:
                return
            body = json.dumps(event).encode()
            req = urllib.request.Request(
                self.url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "drosera/0.1"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=self.timeout).close()
            except (urllib.error.URLError, OSError, ValueError) as exc:
                _warn(f"webhook POST failed: {exc}")

    def close(self) -> None:
        with contextlib.suppress(queue.Full):
            self._q.put_nowait(None)


class MultiSink:
    """Fan out to several sinks; one failing never stops the others."""

    def __init__(self, sinks: list[Sink], redact_ip: bool = False, salt: str = "") -> None:
        self.sinks = sinks
        self.redact_ip = redact_ip
        self.salt = salt

    def emit(self, event: dict[str, Any]) -> None:
        if self.redact_ip and event.get("remote_addr"):
            event = dict(event)
            event["remote_addr"] = "sha256:" + stable_hash(self.salt, event["remote_addr"])
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception as exc:  # noqa: BLE001 - telemetry must never break serving
                _warn(f"{type(sink).__name__} raised {exc!r}")

    def emit_assessment(self, assessment: Assessment) -> None:
        self.emit(assessment.to_dict())

    def close(self) -> None:
        for sink in self.sinks:
            with contextlib.suppress(Exception):
                sink.close()


def build(config) -> MultiSink:
    """Assemble the sink stack from a ``Config``."""
    tele = config.telemetry
    sinks: list[Sink] = []
    if tele.jsonl:
        sinks.append(JsonlSink(tele.jsonl))
    if tele.sqlite:
        sinks.append(SqliteSink(tele.sqlite))
    if tele.webhook:
        sinks.append(WebhookSink(tele.webhook))
    if tele.stderr:
        sinks.append(StderrSink())
    return MultiSink(sinks, redact_ip=tele.redact_ip, salt=config.secret)
