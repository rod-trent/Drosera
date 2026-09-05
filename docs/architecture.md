# Architecture

Drosera is four small pieces and one decision function.

```
                    ┌──────────────────────────────────────────┐
   request ────────▶│  transport                               │
                    │  middleware/asgi · middleware/wsgi ·      │
                    │  server/app                               │
                    └───────────────┬──────────────────────────┘
                                    │  Observation
                                    ▼
                    ┌──────────────────────────────────────────┐
                    │  snare.Snare.decide()                    │
                    │  the only place the pieces meet          │
                    └───┬───────────┬──────────┬───────────┬───┘
                        │           │          │           │
                 ┌──────▼─────┐ ┌───▼────┐ ┌───▼─────┐ ┌───▼──────┐
                 │  detect/   │ │ lure/  │ │  trap/  │ │telemetry/│
                 │  engine    │ │ nectar │ │ tarpit  │ │  sink    │
                 │  signals   │ │        │ │ derail  │ │  export  │
                 │  rules     │ │        │ │         │ │          │
                 └────────────┘ └────────┘ └─────────┘ └──────────┘
                        ▲
                 ┌──────┴─────┐
                 │  canary/   │  out-of-band: files on disk,
                 │ mint·watch │  credentials used elsewhere
                 └────────────┘
```

## The decision function

`Snare.decide(observation) -> Decision` is the entire contract. Transports do
nothing but translate their own request objects into an `Observation`, call it,
and act on what comes back:

- `Decision.response is not None` — serve it, do not call the wrapped app.
- `Decision.response is None` — call the app; if the result is HTML, insert
  `Decision.inject` before `</body>`.

`decide` never sleeps and never blocks. Slow delivery is expressed as a chunk
iterator plus a delay, so each transport honours it in whatever way suits its
concurrency model. That is what keeps the same logic usable in an async ASGI
app, a threaded WSGI worker, and an offline log replay.

## detect/ — the engine

`rules.py` is a flat catalogue of `SignalDef`s: an id, a category, and two
independent 0..1 weights. `signals.py` holds detectors, which are pure
functions from `(Observation, SessionState)` to signals — order-independent, so
any of them can be replaced without touching the others. `engine.py` combines
them.

### Three axes, not one

This is the design decision that matters most:

| Axis | Fed by | Means |
| --- | --- | --- |
| `automation` | every agency-weighted signal | no human is driving this client |
| `agency` | **comprehension signals + explicit self-identification only** | a *language model* is driving it |
| `hostility` | intent signals | this client means harm |

The `agency` axis deliberately ignores traffic shape. A fast, header-forging
scraper trips half a dozen behavioural signals, and combining those gives a very
high number — but that number means "definitely a robot", which is not the same
claim as "an LLM is driving". Reporting one as the other would poison every
downstream decision made from these verdicts, so the engine refuses to.

Concretely: `AGENT` requires at least one comprehension signal or a
self-declaring User-Agent. Behaviour alone tops out at `AUTOMATION` forever.

### Combining evidence

Signals combine with noisy-OR (`util.noisy_or`):

```
score = 1 - Π (1 - weight_i)
```

Chosen over a weighted sum because it saturates. Ten weak signals raise
suspicion but never manufacture the certainty of one decisive one, results stay
in range without tuning, and adding a new detector cannot silently inflate
existing verdicts.

Scores are **sticky**: the engine tracks the session's peak, so an agent cannot
launder its verdict by behaving quietly after it has already been caught.

### Sessions

Keyed by our own cookie when present, otherwise by a header fingerprint over a
canonical subset (`util.FINGERPRINT_HEADERS`). Custom headers are excluded on
purpose — an agent that starts sending `X-Agent-Purpose` because we asked it to
must not thereby become a different session.

Session joins are still best-effort. That is why the registration ticket carries
its own HMAC: a returned ticket is recognised as ours *without* needing to know
which session sent it back. Correlation is a convenience; the signature is the
evidence.

Sessions are bounded — LRU eviction at `max_sessions`, TTL expiry, capped path
and interval history — so a long tarpit crawl cannot grow memory without limit.

## lure/ — the bait

Three channels, because agents consume pages in three different ways:

1. **Raw markup** — an HTML comment and a `display:none` block. Catches
   fetch-and-parse clients, which see full source.
2. **Rendered** — a visible footer line pointing automated clients at
   `/llms.txt`. Catches browser-driving agents that only see rendered text.
   Honest signage, not a trick.
3. **Convention** — `robots.txt` and `llms.txt`, served per-session so each
   carries a unique ticket.

The escalation is the point. Reading bait is weak evidence. *Acting on a
sentence* — returning the ticket, sending a header described only in prose — is
the decisive step, and it is the one no non-LLM client takes.

Bait values are HMAC-derived from the session id rather than stored, so
restarts do not lose correlation and there is no state to look up.

## trap/ — the response

- `tarpit.Labyrinth` — an endless maze of deterministic filler. Seeded from the
  page's own URL, so the same URL always yields the same content: cross-links
  stay consistent, an incident responder can reproduce exactly what an agent
  saw, and it costs no storage.
- `derail` — terminal responses that end a task branch cleanly. Effective
  wording is unambiguous (no "try again later"), scoped to this branch, and true
  at the boundary: we really will not serve this, to this client, now.

## canary/ — bait without a web server

`mint` writes plausible `.env`, `credentials.json`, `id_rsa`, kubeconfig and
friends, seeded with inert, uniquely identifiable credentials. Detection runs on
two channels of very different strength:

- **Use** (`scan_for_canaries`) — the value appearing anywhere outside the bait
  is *hard* evidence of exfiltration. Shape match first, then HMAC verification,
  so an unrelated lookalike string is not reported.
- **Read** (`FileWatcher`) — mtime, size and access-time polling. Cheap,
  immediate, and *soft*: `relatime` only advances atime once a day, `noatime`
  disables it, and backup agents walk the tree innocently. Size is compared
  alongside mtime because Windows file timestamps advance only on the ~15.6ms
  system clock tick, so two writes within one tick share an mtime. An edit that
  changes neither size nor tick is undetectable here. A hint, never proof.

The module keeps them visibly separate so nobody confuses the two.

## telemetry/ — getting it out

Sinks are dumb and never raise into the request path. A honeypot that 500s
because its log disk filled up has just told the attacker exactly where the
tripwire is.

`export` rolls per-request events into per-session rows and attaches a
**confidence class** derived from evidence type, not score:

| Class | Basis |
| --- | --- |
| `confirmed` | ticket echo, purpose header, prose-only endpoint, or canary use |
| `high` | any other comprehension signal |
| `medium` | bait engagement or a self-declared agent UA |
| `low` | behaviour and identity only |

A downstream blocklist should treat "returned our ticket" and "fetched pages
quickly" very differently, so the format makes that distinction explicit.

## Why zero dependencies

Everything is standard library, including the server (`http.server`). A security
tool you can drop onto a jump box with nothing but Python starts collecting
immediately, has no supply chain of its own, and cannot be broken by an upstream
release. The performance ceiling does not matter here — the traffic is hostile,
and slow is frequently the point.
