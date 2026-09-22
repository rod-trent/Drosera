"""Where events go.

Sinks are intentionally dumb and never raise into the request path. A honeypot
that 500s because its log disk filled up is a honeypot that just told the
attacker exactly where the tripwire is, so every failure here degrades to a
warning on stderr and nothing else.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import queue
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from importlib.metadata import entry_points
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
        elif event.get("event") == "canary":
            print(
                f"[canary        ] {event.get('channel', '?')} {event.get('kind', '')} "
                f"{event.get('path', '')} ({event.get('detail', '')})",
                file=sys.stderr,
            )
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
    automation   REAL,
    hostility    REAL,
    action       TEXT,
    hits         INTEGER,
    tokens_burned INTEGER,
    signals      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE TABLE IF NOT EXISTS canary_hits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL    NOT NULL,
    canary_id    TEXT,
    kind         TEXT,
    channel      TEXT,
    detail       TEXT,
    path         TEXT
);
"""

# Columns added after 0.1.0. A database written by an older release is
# migrated in place when it is opened, so upgrading never needs a manual step.
_MIGRATIONS = {"automation": "ALTER TABLE events ADD COLUMN automation REAL"}


class SqliteSink:
    """Queryable history. One connection, guarded by a lock; WAL for concurrent reads."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            have = {r[1] for r in self._conn.execute("PRAGMA table_info(events)")}
            for column, ddl in _MIGRATIONS.items():
                if column not in have:
                    self._conn.execute(ddl)
            self._conn.commit()

    def emit(self, event: dict[str, Any]) -> None:
        if event.get("event") == "canary":
            self._emit_canary(event)
            return
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
            event.get("automation"),
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
                    "user_agent,verdict,agency,automation,hostility,action,hits,tokens_burned,signals) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    row,
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            _warn(f"sqlite insert failed: {exc}")

    def _emit_canary(self, event: dict[str, Any]) -> None:
        row = (
            event.get("ts", time.time()),
            event.get("canary_id"),
            event.get("kind"),
            event.get("channel"),
            event.get("detail"),
            event.get("path"),
        )
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO canary_hits (ts,canary_id,kind,channel,detail,path) "
                    "VALUES (?,?,?,?,?,?)",
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
                headers={"Content-Type": "application/json", "User-Agent": user_agent()},
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


def user_agent() -> str:
    from .. import __version__

    return f"drosera/{__version__}"


# -- plug-in sinks ---------------------------------------------------------
#
# Anything beyond the four built-in sinks is a plug-in: a factory that takes
# the options table from ``[sinks.<name>]`` in drosera.toml plus the whole
# Config, and returns an object with ``emit`` and ``close``. A third-party
# package registers one under the ``drosera.sinks`` entry-point group:
#
#     [project.entry-points."drosera.sinks"]
#     splunk = "drosera_splunk:make_sink"
#
# The shipped integrations use exactly this interface, so they double as the
# reference implementation.

SinkFactory = Callable[[dict[str, Any], Any], Sink]
ENTRY_POINT_GROUP = "drosera.sinks"
BUILTIN_PLUGINS = {
    "azure_monitor": "drosera.telemetry.azure:make_sink",
}


def available_plugins() -> list[str]:
    return sorted({*BUILTIN_PLUGINS, *(ep.name for ep in entry_points(group=ENTRY_POINT_GROUP))})


def resolve_plugin(name: str) -> SinkFactory:
    """Find the factory for a ``[sinks.<name>]`` table, or raise ValueError."""
    target = BUILTIN_PLUGINS.get(name)
    if target:
        module, _, attr = target.partition(":")
        return getattr(importlib.import_module(module), attr)
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name == name:
            return ep.load()
    raise ValueError(
        f"no sink plug-in named {name!r} (available: {', '.join(available_plugins())})"
    )


def build_plugins(config, only: str | None = None) -> list[Sink]:
    """Instantiate every enabled ``[sinks.*]`` table.

    Misconfiguration raises here, at startup, on purpose: a sink that quietly
    fails to start is a SIEM that quietly stops receiving evidence. Once a sink
    is running, the usual rule applies and nothing it does can break serving.
    """
    out: list[Sink] = []
    for name, options in (config.sinks or {}).items():
        if only and name != only:
            continue
        if not isinstance(options, dict):
            raise ValueError(f"[sinks.{name}] must be a table")
        if options.get("enabled", True) is False:
            continue
        out.append(resolve_plugin(name)(options, config))
    if only and not out:
        raise ValueError(f"no enabled [sinks.{only}] table in the configuration")
    return out


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
    sinks.extend(build_plugins(config))
    return MultiSink(sinks, redact_ip=tele.redact_ip, salt=config.secret)
