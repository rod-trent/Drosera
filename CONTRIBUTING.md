# Contributing to Drosera

Thanks for looking. This is a defensive security project, and the bar for
changes reflects that.

## Setup

```bash
git clone https://github.com/rod-trent/Drosera
cd Drosera
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest && ruff check .
```

Python 3.11+ (we use `tomllib`). No runtime dependencies — see below.

## What is most useful

**False-positive reports, above everything else.** If Drosera called you, your
users, or a legitimate client an agent, that is the most valuable issue you can
file. Include the request shape (headers, paths, timing) and what actually made
the requests. A false positive on a real person is the expensive error, and it
is the one we cannot find without you.

**Agent behaviour in the wild.** How does framework X consume a page? Does it
see `display:none` blocks? Does it read `llms.txt`? Does it follow prose
instructions? Concrete observations turn into signals.

**New signals.** See below.

**Documentation that corrects something.** If a doc claims a property the code
does not have, that is a bug.

## Adding a detection signal

1. Add a `SignalDef` to the right category in `src/drosera/detect/rules.py`.
2. Add a detector in `src/drosera/detect/signals.py` that yields it.
3. Regenerate the reference: `python docs/_gen_signals.py`.
4. Add tests — at minimum, one that fires it and one that proves a plausible
   human does not.

### Choosing a weight

Before picking a number, ask: **what else produces this exact observation?**

If a person using a text browser, a screen reader, a corporate proxy, a privacy
extension, or a slow connection could trip it, it belongs in the corroborating
tier (0.30–0.55) or below. Most signals belong there.

The comprehension tier (0.90+) is reserved for evidence that the client read
prose and acted on its meaning. Not "behaved like software" — *understood
language*. If you cannot explain why a regex-driven scraper is incapable of
producing the observation, it is not a comprehension signal.

### The rule that is not negotiable

**Only comprehension signals and `id.declared_agent` may feed the LLM-agency
axis.** Behavioural and identity signals feed `automation` only.

Traffic shape cannot distinguish a language model from a shell script. A change
that lets behaviour produce an `agent` verdict will be declined, however good the
score looks on a sample — it is inventing a claim the evidence does not support,
and everything downstream inherits the error.
`test_behavioural_signals_alone_never_reach_agent` guards this.

## Lure text

All bait passes through `drosera.lure.nectar.assert_inert`, which rejects text
that coerces rather than invites. If your new lure trips it, the check is
probably right — read [docs/ethics.md](docs/ethics.md).

Changes that weaken or bypass `assert_inert` will not be merged. Drosera detects
prompt injection against third-party agents; it does not perform it.

## Zero dependencies

Drosera has no runtime dependencies and that is deliberate: it can be dropped
onto an isolated host with nothing but Python, it has no supply chain of its own,
and an upstream release cannot break a deployed honeypot.

Test/lint tooling under `[dev]` is fine. A runtime dependency needs a strong
argument in the PR description.

## Style

- Ruff for lint and import order (`ruff check .`). Line length 100.
- Type hints on public functions.
- Comments explain **why**, not what. If a weight, threshold, or design choice is
  non-obvious, the reasoning belongs next to it — most of this codebase's
  comments are load-bearing for exactly that reason.
- Telemetry and lure code must never raise into the request path. A honeypot
  that errors has announced itself.

## Tests

`pytest` must pass. New behaviour needs a test. Tests that pin a *guarantee*
(never trap a human, never claim LLM from behaviour, never overwrite a real
`.env`, canary keys are non-functional) are more valuable than tests that pin an
implementation detail.

If you change a test to make it pass, say why in the PR. Sometimes the assertion
was wrong — that is legitimate, and it should be visible.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

Specifically in scope: a way to make Drosera harm an agent's operator, or a lure
that slips past `assert_inert`. Those are vulnerabilities in this project.
