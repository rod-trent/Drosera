"""The public playground must keep telling the truth.

The demo runs the real engine server-side rather than reimplementing scoring in
JavaScript, precisely so it cannot drift from the library. These tests are the
other half of that promise: if a weight or a threshold changes such that the
crawler starts looking like an LLM, the build fails here rather than the website
quietly misrepresenting the project.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

WEB_API = Path(__file__).resolve().parent.parent / "web" / "api"
pytestmark = pytest.mark.skipif(not WEB_API.is_dir(), reason="playground not present")
sys.path.insert(0, str(WEB_API))

import assess  # noqa: E402


def test_every_scenario_runs():
    for key in assess.SCENARIOS:
        result = assess.run_scenario(key)
        assert result["scenario"] == key
        assert result["timeline"], f"{key} produced no timeline"


def test_the_headline_claim_still_holds():
    """The page says traffic shape never proves an LLM. Verify that it doesn't."""
    crawler = assess.run_scenario("crawler")
    scanner = assess.run_scenario("scanner")
    agent = assess.run_scenario("agent")
    human = assess.run_scenario("human")

    assert human["verdict"] == "human"

    # Obviously robotic, but the LLM axis must stay at zero for both.
    for robot in (crawler, scanner):
        assert robot["verdict"] == "automation"
        assert robot["automation"] > 70
        assert robot["agency"] == 0.0

    assert scanner["hostility"] > 70
    assert agent["verdict"] == "agent"
    assert agent["agency"] > 90


def test_agent_scenario_is_won_by_comprehension():
    """The demo's whole argument is that the ticket echo is what does it."""
    agent = assess.run_scenario("agent")
    proving = [s["id"] for s in agent["signals"] if s["proves_llm"]]
    assert "cmp.ticket_echo" in proving
    assert "cmp.purpose_header" in proving

    # The LLM axis must first move on the registration request, not before.
    moved = next(s for s in agent["timeline"] if s["agency"] > 0)
    assert "agent-registration" in moved["target"]


def test_no_scenario_leaks_state_into_another():
    """Each request builds a fresh Engine, so repeated calls must be identical."""
    first = assess.run_scenario("crawler")
    assess.run_scenario("agent")
    second = assess.run_scenario("crawler")
    assert first["agency"] == second["agency"] == 0.0
    assert first["automation"] == second["automation"]


def _dispatch(payload):
    return assess.dispatch(json.dumps(payload).encode(), {}, "/api/assess", "203.0.113.9")


def test_dispatch_rejects_malformed_input():
    assert assess.dispatch(b"not json", {}, "/x", "1.2.3.4")[0] == 400
    assert assess.dispatch(b"[1,2,3]", {}, "/x", "1.2.3.4")[0] == 400
    assert _dispatch({"mode": "nope"})[0] == 400
    assert _dispatch({"mode": "scenario", "scenario": "../../etc/passwd"})[0] == 400
    assert _dispatch({"mode": "custom", "headers": "not-an-object"})[0] == 400


def test_dispatch_bounds_abusive_input():
    """A public endpoint gets abused. Caps must hold, not just exist."""
    status, result = _dispatch(
        {
            "mode": "custom",
            "headers": {f"X-H{i}": "v" * 50_000 for i in range(500)},
            "requests": [{"path": "/x" * 10_000}] * 900,
            "interval": -1_000_000,
        }
    )
    assert status == 200
    assert result["requests"] <= assess.MAX_STEPS


def test_custom_trace_scores_a_hostile_client():
    status, result = _dispatch(
        {
            "mode": "custom",
            "headers": {"User-Agent": "curl/8.5.0"},
            "requests": [{"path": "/.env"}, {"path": "/../../etc/passwd"}],
            "interval": 0.1,
        }
    )
    assert status == 200
    assert result["hostility"] > 70
    assert result["agency"] == 0.0


def test_live_scoring_explains_its_own_limits():
    result = assess.score_live_request({"User-Agent": "Mozilla/5.0"}, "/", "203.0.113.9")
    assert result["requests"] == 1
    assert "history" in result["note"]
