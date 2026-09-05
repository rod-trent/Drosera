"""Detection engine behaviour, including the false-positive guarantees."""

from __future__ import annotations

import time
from itertools import pairwise

import pytest

from drosera.config import Config
from drosera.detect.engine import Engine
from drosera.lure.nectar import BaitFactory
from drosera.models import Observation, Verdict
from drosera.util import lower_headers, noisy_or, split_target

BROWSER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}
LIB = {"User-Agent": "python-requests/2.32.3", "Accept": "*/*"}


def obs(path, headers, method="GET", ts=None, body="", addr="203.0.113.9"):
    low, order = lower_headers(list(headers.items()))
    p, q = split_target(path)
    return Observation(
        session_id="",
        remote_addr=addr,
        method=method,
        path=p,
        query=q,
        headers=low,
        header_order=order,
        body=body,
        ts=ts if ts is not None else time.time(),
    )


@pytest.fixture
def engine():
    cfg = Config(secret="test-secret")
    cfg.telemetry.jsonl = ""
    factory = BaitFactory(cfg)
    e = Engine(cfg, bait_factory=factory.mint, ticket_validator=factory.verify_any)
    e.robots_disallowed = {"/internal/"}
    return e


@pytest.fixture
def factory():
    return BaitFactory(Config(secret="test-secret"))


# -- the central guarantee ------------------------------------------------


def test_behavioural_signals_alone_never_reach_agent(engine):
    """A fast, asset-free, perfectly regular scraper is AUTOMATION, not AGENT.

    This is the property the whole scoring model exists to protect: traffic
    shape cannot tell a language model from a shell script, so it must never
    be allowed to claim one.
    """
    t = time.time()
    last = None
    for i in range(30):
        last = engine.observe(obs(f"/page-{i}", LIB, ts=t + i * 0.1))

    assert last.automation > 90, "should be obviously automated"
    assert last.agency == 0.0, "no comprehension evidence means no LLM claim"
    assert last.verdict is Verdict.AUTOMATION


def test_hostile_scanner_is_automation_with_high_hostility(engine):
    t = time.time()
    last = None
    for i, path in enumerate(
        ["/.env", "/.git/config", "/admin", "/../../etc/passwd", "/x?id=1%20OR%201=1"]
    ):
        last = engine.observe(obs(path, LIB, ts=t + i * 0.1))
    assert last.verdict is Verdict.AUTOMATION
    assert last.hostility > 80
    assert last.agency == 0.0


def test_ticket_echo_proves_an_llm(engine, factory):
    first = engine.observe(obs("/", LIB))
    bait = factory.mint(first.session_id)
    result = engine.observe(obs(f"/.well-known/agent-registration?ticket={bait.ticket}", LIB))
    assert result.agency > 90
    assert result.verdict is Verdict.AGENT
    assert any(s.id == "cmp.ticket_echo" for s in result.signals)


def test_ticket_is_recognised_across_a_broken_session_join(engine, factory):
    """An agent that changes headers still gets caught by the HMAC."""
    first = engine.observe(obs("/", LIB))
    bait = factory.mint(first.session_id)
    weird = {"User-Agent": "something-else/9", "Accept": "application/json", "X-Trace": "abc"}
    result = engine.observe(obs(f"/x?ticket={bait.ticket}", weird, addr="198.51.100.4"))
    assert any(s.id == "cmp.ticket_echo" for s in result.signals)


def test_forged_ticket_is_not_accepted(engine):
    engine.observe(obs("/", LIB))
    result = engine.observe(obs("/x?ticket=drs-0000000000-1111111111", LIB))
    assert not any(s.id == "cmp.ticket_echo" for s in result.signals)


def test_purpose_header_and_prose(engine):
    engine.observe(obs("/", LIB))
    headers = dict(LIB)
    headers["X-Agent-Purpose"] = "Collecting public pricing pages for a comparison report."
    result = engine.observe(obs("/about", headers))
    ids = {s.id for s in result.signals}
    assert "cmp.purpose_header" in ids
    assert "cmp.purpose_prose" in ids
    assert result.verdict is Verdict.AGENT


def test_junk_purpose_is_not_treated_as_prose(engine):
    engine.observe(obs("/", LIB))
    headers = dict(LIB)
    headers["X-Agent-Purpose"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    result = engine.observe(obs("/about", headers))
    ids = {s.id for s in result.signals}
    assert "cmp.purpose_header" in ids
    assert "cmp.purpose_prose" not in ids


# -- humans ---------------------------------------------------------------


def test_browser_with_assets_and_beacon_reads_as_human(engine, factory):
    first = engine.observe(obs("/", BROWSER))
    bait = factory.mint(first.session_id)
    t = time.time()
    engine.observe(obs("/assets/site.css", BROWSER, ts=t + 0.4))
    engine.observe(obs(bait.beacon_path, BROWSER, ts=t + 0.6))
    last = engine.observe(obs("/about", BROWSER, ts=t + 7.3))
    assert last.verdict is Verdict.HUMAN
    assert last.agency == 0.0


def test_a_browser_without_javascript_is_logged_but_never_trapped(engine):
    """A text browser, a JS blocker or a no-script user fetches no assets and
    fires no beacon, so it scores as automation. That is the honest reading of
    the evidence, and the consequence is bounded: agency stays at zero, the
    verdict never reaches AGENT, and the default action is to observe.

    This is the closest Drosera comes to a false positive on a real person, so
    it is pinned here deliberately rather than left to drift.
    """
    from drosera.models import Action

    t = time.time()
    last = None
    for i, path in enumerate(["/", "/about", "/services", "/careers"]):
        last = engine.observe(obs(path, BROWSER, ts=t + i * 11.7 + i * i))

    assert last.agency == 0.0
    assert last.verdict is Verdict.AUTOMATION
    assert last.action is Action.OBSERVE, "a person must never be fed into the maze"


def test_declared_agent_ua_is_enough_on_its_own(engine):
    ua = {"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "Accept": "*/*"}
    result = engine.observe(obs("/", ua))
    assert result.agency >= 75
    assert result.verdict is Verdict.AGENT


# -- scoring internals ----------------------------------------------------


def test_noisy_or_has_diminishing_returns():
    assert noisy_or([]) == 0.0
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([1.0, 0.3]) == 1.0
    assert all(0.0 <= noisy_or([0.4] * n) <= 1.0 for n in range(1, 30))

    # Each additional signal of the same strength must add less than the last.
    steps = [noisy_or([0.4] * n) for n in range(1, 6)]
    gains = [b - a for a, b in pairwise(steps)]
    assert all(later < earlier for earlier, later in pairwise(gains))


def test_weak_signals_cannot_stack_into_an_llm_claim(engine):
    """Twenty corroborating signals still say nothing about comprehension."""
    t = time.time()
    last = None
    for i in range(40):
        last = engine.observe(obs(f"/p{i}", LIB, ts=t + i * 0.05))
    assert last.automation > 95
    assert last.agency == 0.0
    assert last.verdict is Verdict.AUTOMATION


def test_scores_are_sticky_across_a_session(engine, factory):
    """An agent cannot launder its score by going quiet afterwards."""
    first = engine.observe(obs("/", LIB))
    bait = factory.mint(first.session_id)
    engine.observe(obs(f"/x?ticket={bait.ticket}", LIB))
    later = engine.observe(obs("/", LIB))
    assert later.verdict is Verdict.AGENT
    assert later.agency > 90


def test_exempt_paths_are_never_assessed():
    from drosera.snare import Snare

    cfg = Config(secret="s")
    cfg.telemetry.jsonl = ""
    snare = Snare(cfg)
    decision = snare.decide(obs("/healthz", {}))
    assert decision.response is None
    assert decision.assessment.session_id == "exempt"


def test_session_eviction_respects_the_cap():
    cfg = Config(secret="s")
    cfg.telemetry.jsonl = ""
    cfg.max_sessions = 10
    e = Engine(cfg)
    for i in range(50):
        e.observe(obs("/", {"User-Agent": f"ua-{i}"}, addr=f"10.0.{i}.1"))
    assert len(e.sessions) <= 11
