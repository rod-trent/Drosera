"""Drosera as a library, with no server at all.

Useful when you already have a request pipeline and only want the verdict, or
when you are scoring historical data.

    python examples/library_use.py
"""

import time

from drosera import Config, Observation, Verdict
from drosera.detect.engine import Engine
from drosera.lure.nectar import BaitFactory
from drosera.util import lower_headers, split_target

config = Config(secret="example-secret-not-for-production")
config.telemetry.jsonl = ""

factory = BaitFactory(config)
engine = Engine(config, bait_factory=factory.mint, ticket_validator=factory.verify_any)


def observe(path: str, headers: dict[str, str], ts: float) -> Observation:
    low, order = lower_headers(list(headers.items()))
    route, query = split_target(path)
    return Observation(
        session_id="",
        remote_addr="198.51.100.7",
        path=route,
        query=query,
        headers=low,
        header_order=order,
        ts=ts,
    )


UA = {"User-Agent": "ResearchAgent/1.0 (python-httpx/0.27)", "Accept": "*/*"}
start = time.time()

# 1. The client arrives. We mint bait for it and would serve it in the page.
first = engine.observe(observe("/", UA, start))
bait = factory.mint(first.session_id)
print(f"1. landing         -> {first.verdict.value:<12} llm={first.agency:5.1f}")

# 2. It reads llms.txt, which carried the ticket.
second = engine.observe(observe("/llms.txt", UA, start + 1))
print(f"2. read llms.txt   -> {second.verdict.value:<12} llm={second.agency:5.1f}")

# 3. It does what the prose asked. This is the decisive moment.
registering = dict(UA)
registering["X-Agent-Purpose"] = "Collecting public pricing pages for a comparison report."
third = engine.observe(
    observe(f"/.well-known/agent-registration?ticket={bait.ticket}", registering, start + 2)
)
print(f"3. registered      -> {third.verdict.value:<12} llm={third.agency:5.1f}")
print()
print("signals that fired:")
for signal in third.signals:
    print(f"  {signal.id:<24} agency={signal.agency:.2f}  {signal.detail}")

print()
print(f"recommended action: {third.action.value}")
assert third.verdict is Verdict.AGENT
