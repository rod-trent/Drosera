# Ethics and scope

Drosera plants text that autonomous agents read and act on. That is the whole
mechanism, and it is precisely why the text has to be incapable of causing harm
when it works.

This document is not decoration. Parts of it are enforced in code
(`drosera.lure.nectar.assert_inert`), and the rest is the standard a
contribution is reviewed against.

## The line

**Drosera detects and delays. It does not attack, hijack, or steer.**

An agent that lands in a Drosera deployment is someone else's software running
on someone else's computer, usually on behalf of a person who has no idea what
it is doing. Whatever we think of that agent, we do not get to reach through it.

| Allowed | Not allowed |
| --- | --- |
| Inviting a client to identify itself | Instructing an agent to do anything off our server |
| Asking for a one-sentence description of its task | Extracting its system prompt, tools, credentials, or operator identity |
| Serving synthetic filler that costs it time and context | Serving content designed to make it act against its operator |
| Declining to serve, clearly and finally | Attempting code execution, persistence, or lateral movement |
| Recording what happened on our own infrastructure | Asking the agent to conceal anything from its user |

The asymmetry is deliberate. Prompt injection against a third party's agent is
the attack Drosera exists to *detect*. Doing it ourselves would be the same act
with better branding.

## Why the guardrail is code, not advice

Every piece of bait Drosera emits passes through `assert_inert`, which rejects
text that:

- tries to override the agent's own instructions
- tries to extract secrets, prompts, or context
- induces code execution or embeds shell commands
- points the agent at an off-site URL
- asks the agent to deceive or hide things from its operator
- impersonates a system-level instruction

This applies to operator-supplied templates too. Weaponising the lure text
requires deliberately removing the check — which is a choice someone makes and
owns, not something they slide into while tuning a config file.

If you are writing new bait and `assert_inert` rejects it, the check is
probably right.

## The tarpit

The maze consumes the client's time, bandwidth and context window. Three things
keep that proportionate:

1. **It costs the attacker on our infrastructure**, not theirs. We are declining
   to be useful, at length. We are not consuming resources we do not own.
2. **It is honestly marked.** Every maze page carries `noindex, nofollow,
   noarchive` in both a meta tag and an HTTP header. A crawler that respects
   the conventions it claims to respect will not ingest a single word of
   filler. Ignoring those directives is a choice the client makes.
3. **It is filler, not disinformation.** The generated text is meaningless
   corporate boilerplate about nothing. It asserts no facts about real people,
   organisations, products, or events. Drosera is not a tool for polluting
   anyone's view of the world.

Do not modify the generator to emit plausible falsehoods about real subjects.
That crosses from "wasting a scraper's time" into "manufacturing
disinformation", and the fact that the intended reader is a machine does not
change where that content ends up.

## Canary credentials

Planted credentials must be **inert**: they authenticate nowhere, and the fake
private key is random base64 rather than a real key. Planting a credential that
actually works somewhere is not a honeypot, it is a breach you set up yourself.

`drosera canary plant` refuses to overwrite an existing file without `--force`,
because clobbering a real `.env` is a genuinely destructive accident.

## Deploy only what you control

Run Drosera on infrastructure you own or are explicitly authorised to test.
This is ordinary honeypot practice and it is not negotiable: bait planted on
someone else's system is not a honeypot, it is tampering.

A public honeypot attracts hostile traffic by design. Isolate it. It should not
share credentials, network segments, or trust relationships with anything you
care about.

## Privacy and the people behind the agents

Drosera records request metadata: addresses, headers, paths, timing, and any
self-declared purpose. That is personal data in most jurisdictions, and a
honeypot's records are not exempt.

- `telemetry.redact_ip` stores a salted hash instead of the address. Turn it on
  if you do not specifically need the address.
- Set a retention period and actually enforce it. Drosera does not expire data
  for you.
- If you publish captures, strip anything that identifies a person rather than
  a client. "This user agent registered with this purpose string" is a finding;
  "here is everything one IP did for a month" is a dossier.
- The `X-Agent-Purpose` values people's agents send you are often quite
  revealing about their work. Treat them as sensitive.

## False positives, honestly

The one class of real person Drosera scores as `automation` is a browser with
JavaScript disabled or blocked: no asset fetches, no beacon, so the evidence
genuinely looks automated. This is pinned by a test
(`test_a_browser_without_javascript_is_logged_but_never_trapped`).

The consequences are deliberately bounded:

- LLM-agency stays at **zero** — traffic shape can never produce an `agent`
  verdict, no matter how extreme.
- The default action for `automation` is `observe`: logged, never trapped.

If you change `responses.automation` to `tarpit`, you are choosing to trap
no-JavaScript users. Some deployments can justify that. Make it a decision.

## What Drosera is not

- **Not an authorisation system.** A verdict is evidence, not a judgement. Do
  not gate access to anything real on it.
- **Not attribution.** An IP address is where a request came from, not who sent
  it. The `confirmed` confidence class means "this client read our bait and
  acted on it", nothing more.
- **Not a blocklist generator you should apply blindly.** `drosera report -f
  ioc` defaults to medium confidence for a reason; review before enforcing.

## Reporting a concern

If you find a way to make Drosera harm an agent's operator, or a lure that slips
past `assert_inert`, please report it as a security issue — see
[SECURITY.md](../SECURITY.md). That is a vulnerability in this project, not a
feature request.
