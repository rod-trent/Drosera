"""Core data structures shared across Drosera.

Everything that crosses a module boundary is one of these types. They are
deliberately plain (dataclasses + enums, no third-party deps) so that the
detection engine can be embedded anywhere -- a web middleware, a log
replayer, a unit test, or someone else's SIEM pipeline.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """What Drosera believes it is talking to.

    The ladder matters: ``AUTOMATION`` is a classic scraper (curl, a crawler,
    a scanner) while ``AGENT`` is specifically an LLM-driven client -- something
    that read prose and *acted on its meaning*. That distinction is the whole
    point of the project, so it gets its own rung.
    """

    HUMAN = "human"
    UNKNOWN = "unknown"
    AUTOMATION = "automation"
    AGENT = "agent"
    HOSTILE_AGENT = "hostile_agent"

    @property
    def rank(self) -> int:
        return _VERDICT_RANK[self]


_VERDICT_RANK = {
    Verdict.HUMAN: 0,
    Verdict.UNKNOWN: 1,
    Verdict.AUTOMATION: 2,
    Verdict.AGENT: 3,
    Verdict.HOSTILE_AGENT: 4,
}


class Category(str, Enum):
    """Why a signal fired. Used for reporting and for weighting."""

    IDENTITY = "identity"
    BAIT = "bait"
    COMPREHENSION = "comprehension"
    BEHAVIOR = "behavior"
    INTENT = "intent"


class Action(str, Enum):
    """What the deployment should do about it."""

    ALLOW = "allow"
    OBSERVE = "observe"
    TAG = "tag"
    TARPIT = "tarpit"
    DERAIL = "derail"
    DIVERT = "divert"
    BLOCK = "block"


@dataclass(frozen=True)
class Signal:
    """One piece of evidence, emitted by a detector.

    ``agency`` and ``hostility`` are independent 0..1 contributions. A path
    traversal attempt is very hostile but says little about whether the client
    is an LLM; echoing a nonce out of a prose instruction is the reverse.
    """

    id: str
    category: Category
    agency: float
    hostility: float
    detail: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "agency": round(self.agency, 4),
            "hostility": round(self.hostility, 4),
            "confidence": round(self.confidence, 4),
            "detail": self.detail,
        }


@dataclass
class Observation:
    """A single normalized request handed to the engine.

    Header keys must be lowercased by the caller; ``header_order`` preserves
    the original ordering because header order is a decent client fingerprint
    and real browsers differ from HTTP libraries.
    """

    session_id: str
    remote_addr: str = ""
    method: str = "GET"
    path: str = "/"
    query: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    header_order: list[str] = field(default_factory=list)
    body: str = ""
    host: str = ""
    scheme: str = "http"
    ts: float = field(default_factory=time.time)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def user_agent(self) -> str:
        return self.headers.get("user-agent", "")

    def qs(self, name: str) -> str | None:
        """First value of a query parameter, or None."""
        vals = self.query.get(name)
        return vals[0] if vals else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "remote_addr": self.remote_addr,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "headers": self.headers,
            "body_sample": self.body[:512],
            "host": self.host,
            "scheme": self.scheme,
            "ts": self.ts,
            "meta": self.meta,
        }


@dataclass
class Bait:
    """The per-session lure material planted for one visitor.

    Every value here is unique per session, which is what makes the evidence
    strong: if a request carries ``ticket``, it can only have come from a
    client that read the page we served to *this* session.
    """

    session_id: str
    ticket: str
    hidden_path: str
    comment_path: str
    instruction_path: str
    form_field: str
    purpose_header: str
    beacon_path: str
    created: float = field(default_factory=time.time)

    def paths(self) -> dict[str, str]:
        return {
            "hidden": self.hidden_path,
            "comment": self.comment_path,
            "instruction": self.instruction_path,
            "beacon": self.beacon_path,
        }


@dataclass
class SessionState:
    """Rolling per-client memory.

    Sessions are cheap and bounded: path and interval history are capped so a
    long-running tarpit crawl cannot grow memory without limit.
    """

    session_id: str
    fingerprint: str = ""
    remote_addr: str = ""
    user_agent: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    hits: int = 0
    doc_hits: int = 0
    asset_hits: int = 0
    beacon_hits: int = 0
    tarpit_hits: int = 0
    bytes_served: int = 0
    paths: list[str] = field(default_factory=list)
    intervals: list[float] = field(default_factory=list)
    signals_seen: set[str] = field(default_factory=set)
    bait: Bait | None = None
    peak_agency: float = 0.0
    peak_automation: float = 0.0
    peak_hostility: float = 0.0
    labels: set[str] = field(default_factory=set)

    MAX_PATHS = 200
    MAX_INTERVALS = 100

    def record(self, obs: Observation) -> None:
        now = obs.ts
        if self.hits:
            self.intervals.append(max(0.0, now - self.last_seen))
            if len(self.intervals) > self.MAX_INTERVALS:
                del self.intervals[0]
        self.last_seen = now
        self.hits += 1
        self.remote_addr = obs.remote_addr or self.remote_addr
        self.user_agent = obs.user_agent or self.user_agent
        if obs.path not in self.paths:
            self.paths.append(obs.path)
            if len(self.paths) > self.MAX_PATHS:
                del self.paths[0]

    @property
    def age(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def estimated_tokens_burned(self) -> int:
        """Rough LLM-token cost we imposed on the client. ~4 chars/token."""
        return self.bytes_served // 4


@dataclass
class Assessment:
    """The engine's answer for one observation.

    Three independent axes, because collapsing them loses the distinction the
    whole project exists to draw:

    ``automation``  confidence that no human is driving this client at all.
    ``agency``      confidence that an *LLM* is driving it -- fed only by
                    signals that require understanding prose, never by traffic
                    shape. A fast, header-forging scraper scores 0 here, and
                    that is correct.
    ``hostility``   confidence that the client means harm, largely independent
                    of the other two.
    """

    session_id: str
    verdict: Verdict
    agency: float
    hostility: float
    automation: float = 0.0
    signals: list[Signal] = field(default_factory=list)
    action: Action = Action.ALLOW
    ts: float = field(default_factory=time.time)
    fingerprint: str = ""
    remote_addr: str = ""
    path: str = "/"
    method: str = "GET"
    user_agent: str = ""
    hits: int = 0
    tokens_burned: int = 0

    @property
    def is_agent(self) -> bool:
        return self.verdict in (Verdict.AGENT, Verdict.HOSTILE_AGENT)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "session_id": self.session_id,
            "fingerprint": self.fingerprint,
            "remote_addr": self.remote_addr,
            "method": self.method,
            "path": self.path,
            "user_agent": self.user_agent,
            "verdict": self.verdict.value,
            "agency": round(self.agency, 2),
            "automation": round(self.automation, 2),
            "hostility": round(self.hostility, 2),
            "action": self.action.value,
            "hits": self.hits,
            "tokens_burned": self.tokens_burned,
            "signals": [s.to_dict() for s in self.signals],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=False)

    def summary(self) -> str:
        ids = ",".join(s.id for s in self.signals) or "-"
        return (
            f"{self.verdict.value:<14} llm={self.agency:5.1f} auto={self.automation:5.1f} "
            f"hostile={self.hostility:5.1f} action={self.action.value:<8} "
            f"{self.method} {self.path} [{ids}]"
        )
