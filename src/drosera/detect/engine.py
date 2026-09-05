"""The scoring engine: observations in, verdicts out.

Design notes worth keeping in mind when changing this file:

* Sessions are keyed by fingerprint, not cookies. Agents drop cookies between
  steps constantly, so cookie-only tracking loses the very clients we care about.
* Evidence is combined with noisy-OR on *three separate axes*. The LLM-agency
  axis is fed only by comprehension signals and explicit self-identification --
  never by traffic shape. This is the correction for the obvious failure mode:
  a fast, header-forging scraper trips half a dozen behavioural signals, and
  noisy-OR will happily compound those into a high number. That number means
  "definitely a robot", which is not the same claim as "an LLM is driving",
  and Drosera would be lying if it reported one as the other.
* The engine never blocks or delays anything. It returns a recommended
  ``Action``; enforcing it is the transport layer's job. That separation keeps
  the engine usable for offline log replay.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from ..config import Config
from ..models import (
    Action,
    Assessment,
    Bait,
    Category,
    Observation,
    SessionState,
    Signal,
    Verdict,
)
from ..util import fingerprint as fp_of
from ..util import noisy_or
from . import signals as detectors
from .rules import get

SESSION_COOKIE = "drosera_sid"


class Engine:
    """Stateful detector. Safe for single-threaded and GIL-serialized use;
    wrap ``observe`` in a lock if you drive it from a thread pool."""

    def __init__(self, config: Config | None = None, bait_factory=None, ticket_validator=None) -> None:
        self.config = config or Config()
        self.ticket_validator = ticket_validator
        self.sessions: OrderedDict[str, SessionState] = OrderedDict()
        self.robots_disallowed: set[str] = set()
        self._bait_factory = bait_factory
        self._canary_pending: dict[str, list[Signal]] = {}

    # -- session handling ------------------------------------------------

    def session_key(self, obs: Observation) -> str:
        """Prefer our own cookie, fall back to a header fingerprint."""
        cookie = obs.headers.get("cookie", "")
        if SESSION_COOKIE in cookie:
            for part in cookie.split(";"):
                name, _, value = part.strip().partition("=")
                if name == SESSION_COOKIE and value:
                    return value.strip()[:64]
        return fp_of(obs.headers, obs.header_order, obs.remote_addr)

    def session(self, obs: Observation) -> SessionState:
        key = obs.session_id or self.session_key(obs)
        obs.session_id = key
        state = self.sessions.get(key)
        now = obs.ts
        if state is not None and now - state.last_seen > self.config.session_ttl:
            del self.sessions[key]
            state = None
        if state is None:
            state = SessionState(
                session_id=key,
                fingerprint=fp_of(obs.headers, obs.header_order, obs.remote_addr),
                remote_addr=obs.remote_addr,
                user_agent=obs.user_agent,
                first_seen=now,
                last_seen=now,
            )
            self.sessions[key] = state
            self._evict()
        else:
            self.sessions.move_to_end(key)
        return state

    def _evict(self) -> None:
        cap = self.config.max_sessions
        cutoff = time.time() - self.config.session_ttl
        while self.sessions:
            key, state = next(iter(self.sessions.items()))
            if len(self.sessions) > cap or state.last_seen < cutoff:
                del self.sessions[key]
            else:
                break

    def bait_for(self, state: SessionState) -> Bait | None:
        """Mint (once) and return the lure material for a session."""
        if state.bait is None and self._bait_factory is not None:
            state.bait = self._bait_factory(state.session_id)
        return state.bait

    # -- main entry point -------------------------------------------------

    def observe(self, obs: Observation) -> Assessment:
        state = self.session(obs)
        state.record(obs)

        bait = self.bait_for(state)
        found: list[Signal] = []

        found.extend(detectors.identity_signals(obs))
        found.extend(detectors.bait_signals(obs, bait, self.ticket_validator))
        found.extend(detectors.static_bait_signals(obs, self.robots_disallowed))
        found.extend(detectors.intent_signals(obs))

        # Beacon hits are positive evidence of a real rendering engine, so they
        # are counted before behavioural scoring runs.
        if bait and obs.path.rstrip("/") == bait.beacon_path.rstrip("/"):
            state.beacon_hits += 1
        elif detectors.is_asset(obs.path):
            state.asset_hits += 1
        elif obs.method.upper() in ("GET", "HEAD"):
            state.doc_hits += 1

        found.extend(detectors.behavior_signals(state))

        # Out-of-band canary hits attach to the next observation for the session.
        for key in (state.session_id, state.fingerprint, state.remote_addr):
            if key and key in self._canary_pending:
                found.extend(self._canary_pending.pop(key))

        # Persistence: once a session proves comprehension, it stays proven.
        # Otherwise an agent could look like a human simply by going quiet.
        state.signals_seen.update(s.id for s in found)

        automation = 100.0 * noisy_or(s.agency for s in found)
        agency = 100.0 * noisy_or(s.agency for s in found if _proves_llm(s))
        hostility = 100.0 * noisy_or(s.hostility for s in found)
        state.peak_automation = max(state.peak_automation, automation)
        state.peak_agency = max(state.peak_agency, agency)
        state.peak_hostility = max(state.peak_hostility, hostility)

        verdict = self._verdict(state, found)
        action = self._action(verdict, state.peak_hostility)

        return Assessment(
            session_id=state.session_id,
            verdict=verdict,
            agency=state.peak_agency,
            automation=state.peak_automation,
            hostility=state.peak_hostility,
            signals=found,
            action=action,
            ts=obs.ts,
            fingerprint=state.fingerprint,
            remote_addr=obs.remote_addr,
            path=obs.path,
            method=obs.method,
            user_agent=state.user_agent,
            hits=state.hits,
            tokens_burned=state.estimated_tokens_burned(),
        )

    def _verdict(self, state: SessionState, found: list[Signal]) -> Verdict:
        t = self.config.thresholds
        hostility = state.peak_hostility

        # AGENT requires evidence of comprehension or self-identification.
        # Traffic shape alone tops out at AUTOMATION no matter how extreme it
        # gets, because traffic shape cannot distinguish a language model from
        # a shell script and pretending otherwise would poison every downstream
        # decision made from these verdicts.
        if state.peak_agency >= t.agent:
            return Verdict.HOSTILE_AGENT if hostility >= t.hostile else Verdict.AGENT
        if state.peak_automation >= t.automation:
            return Verdict.AUTOMATION
        # A fired beacon means something executed our JavaScript and requested
        # subresources. That is the only affirmative evidence of a human we get.
        if state.beacon_hits > 0 and state.asset_hits > 0:
            return Verdict.HUMAN
        return Verdict.UNKNOWN

    def _action(self, verdict: Verdict, hostility: float) -> Action:
        action = self.config.action_for(verdict)
        # Hostility escalates a passive response even when agency is low: a
        # plain scanner hunting for .env still should not get a quiet 404.
        if hostility >= self.config.thresholds.hostile and action in (Action.ALLOW, Action.OBSERVE):
            action = Action.TARPIT if self.config.trap.enabled else Action.OBSERVE
        if action in (Action.TARPIT, Action.DERAIL, Action.DIVERT) and not self.config.trap.enabled:
            return Action.OBSERVE
        return action

    # -- side channels ----------------------------------------------------

    def report_canary(self, token_id: str, where: str, correlate: str = "") -> Signal:
        """Record that a planted credential was used.

        Canaries fire wherever the stolen credential is *used*, which is a
        different place and time from the request that stole it. The signal is
        queued against a correlation key (session id, fingerprint or IP) and
        attaches to that client's next observation; it is also returned so the
        caller can log it immediately.
        """
        sig = next(detectors.canary_signal(token_id, where))
        if correlate:
            self._canary_pending.setdefault(correlate, []).append(sig)
        return sig

    def note_response(self, session_id: str, nbytes: int, tarpit: bool = False) -> None:
        """Feed response size back in so token-burn accounting stays honest."""
        state = self.sessions.get(session_id)
        if state is None:
            return
        state.bytes_served += max(0, nbytes)
        if tarpit:
            state.tarpit_hits += 1

    def budget_exceeded(self, session_id: str) -> bool:
        budget = self.config.trap.session_byte_budget
        if budget <= 0:
            return False
        state = self.sessions.get(session_id)
        return bool(state and state.bytes_served >= budget)

    # -- introspection ----------------------------------------------------

    def stats(self) -> dict:
        by_verdict: dict[str, int] = {}
        burned = 0
        for state in self.sessions.values():
            v = self._verdict(state, []).value
            by_verdict[v] = by_verdict.get(v, 0) + 1
            burned += state.estimated_tokens_burned()
        return {
            "sessions": len(self.sessions),
            "by_verdict": by_verdict,
            "tokens_burned": burned,
        }


# Only these establish that a *language model* is in the loop: signals that
# require understanding prose, plus a client that says so itself.
def _proves_llm(signal: Signal) -> bool:
    return signal.category is Category.COMPREHENSION or signal.id == "id.declared_agent"


def assess_once(obs: Observation, config: Config | None = None) -> Assessment:
    """Convenience for stateless callers (tests, log replay of a single line)."""
    return Engine(config).observe(obs)


__all__ = ["Engine", "assess_once", "SESSION_COOKIE", "get"]
