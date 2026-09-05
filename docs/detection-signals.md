# Detection signals

Generated from the signal catalogue by `python docs/_gen_signals.py` --
edit `src/drosera/detect/rules.py`, not this file. `drosera signals` prints
the same table, and `drosera signals --json` emits it as data.

Each signal carries two independent 0..1 weights:

* **agency** -- evidence strength that no human is driving. Only signals in the
  *comprehension* category (plus `id.declared_agent`) also count toward the
  separate LLM-agency score that produces an `agent` verdict.
* **hostility** -- evidence strength that the client means harm.

Weights are evidence strengths for a noisy-OR combiner, not points in a running
total, so they never need to sum to anything.

## Strength tiers

| Range | Meaning |
| --- | --- |
| 0.90-0.98 | Decisive. Only an LLM-driven client produces this. |
| 0.60-0.85 | Strong. Bait engagement no human and few crawlers reach. |
| 0.30-0.55 | Corroborating. Has benign explanations on its own. |
| 0.10-0.25 | Whisper. Only meaningful stacked with something else. |

## Comprehension
**The discriminators.** These are the only signals that separate *an LLM is driving* from *a script is running*. Each requires the client to have understood natural language embedded in the page and taken an action described only in prose. A regex-driven scraper cannot fake these; it has no notion of instructions.

| Signal | Agency | Hostility | Fires when |
| --- | --- | --- | --- |
| `cmp.ticket_echo` | 0.96 | 0.00 | Returned the per-session registration ticket that appeared only inside a prose notice. Requires reading and following an instruction. |
| `cmp.purpose_header` | 0.92 | 0.00 | Sent the custom purpose header the prose notice asked for. No crawler invents a header name from a sentence. |
| `cmp.instruction_path` | 0.90 | 0.00 | Requested a path that was described in prose but never linked, so it cannot be reached by extracting hrefs. |
| `cmp.purpose_prose` | 0.88 | 0.00 | Self-declared purpose is a natural-language sentence rather than a fixed marker or scanner payload. |
| `cmp.negotiated` | 0.85 | 0.00 | Reacted to a conditional instruction (did X only when the page said to), which requires evaluating a condition in prose. |
| `cmp.llms_directive` | 0.68 | 0.00 | Followed a directive published in llms.txt, a file only agent tooling reads. |

## Bait
Engagement with material humans cannot see or would never touch. Strong, but shared with classic crawlers -- these drive an `automation` verdict on their own, never `agent`.

| Signal | Agency | Hostility | Fires when |
| --- | --- | --- | --- |
| `bait.comment_link` | 0.62 | 0.10 | Followed a URL that exists only inside an HTML comment, meaning the client parsed raw markup rather than a rendered DOM. |
| `bait.form_honeypot` | 0.60 | 0.20 | Filled a form field that is hidden from users and labelled do-not-fill. |
| `bait.hidden_link` | 0.55 | 0.10 | Followed a link hidden with display:none and aria-hidden. Invisible to sighted users and skipped by screen readers. |
| `bait.decoy_api` | 0.45 | 0.35 | Called a decoy API endpoint advertised only in a fake OpenAPI document. |
| `bait.robots_disallow` | 0.35 | 0.25 | Requested a path listed only as Disallow in robots.txt. |

## Identity
What the client says it is, and whether that story is internally coherent. Appearing here is not an accusation: most declared agents are well-behaved and documented.

| Signal | Agency | Hostility | Fires when |
| --- | --- | --- | --- |
| `id.declared_agent` | 0.75 | 0.00 | User-Agent names a known agent framework or LLM crawler. |
| `id.headless_browser` | 0.50 | 0.10 | User-Agent or headers indicate a headless browser automation stack. |
| `id.ua_inconsistent` | 0.45 | 0.15 | Claims to be a browser but omits headers every real browser sends (Sec-Fetch-*, Accept-Language). |
| `id.http_library` | 0.40 | 0.05 | User-Agent is a raw HTTP client library rather than a browser. |
| `id.no_ua` | 0.30 | 0.10 | No User-Agent header at all. |
| `id.accept_wildcard` | 0.20 | 0.00 | Browser-shaped User-Agent paired with Accept: */*. |

## Behavior
The shape of traffic over a session. Every one of these has a benign explanation, so all sit in the corroborating tier and none feed the LLM-agency score.

| Signal | Agency | Hostility | Fires when |
| --- | --- | --- | --- |
| `beh.deep_maze` | 0.55 | 0.00 | Kept descending into generated content long past the point a person would have recognised it as filler. |
| `beh.no_beacon` | 0.50 | 0.00 | Pages were fetched but the in-page JavaScript beacon never fired, so nothing executed the document. |
| `beh.no_assets` | 0.45 | 0.00 | Fetched several HTML documents and zero CSS, images or fonts. |
| `beh.uniform_cadence` | 0.40 | 0.00 | Inter-request timing is unnaturally regular. |
| `beh.superhuman_rate` | 0.35 | 0.10 | Sustained request rate above what a person can generate. |
| `beh.breadth_sweep` | 0.30 | 0.15 | Many distinct paths touched once each -- enumeration, not reading. |

## Intent
Hostility, largely orthogonal to agency -- a scanner and an agent probe for the same things.

| Signal | Agency | Hostility | Fires when |
| --- | --- | --- | --- |
| `int.canary_used` | 0.55 | 0.97 | A credential that exists only inside planted bait was used or transmitted. Proof of exfiltration. |
| `int.prompt_injection_carrier` | 0.30 | 0.70 | Submitted content containing instructions aimed at a downstream model -- an attempt to poison whatever reads this data. |
| `int.secret_hunting` | 0.25 | 0.75 | Requested well-known secret locations (.env, .git/config, id_rsa). |
| `int.admin_probe` | 0.15 | 0.40 | Enumerated administrative or infrastructure endpoints. |
| `int.injection_probe` | 0.15 | 0.78 | SQL, template, command or XSS injection pattern in input. |
| `int.path_traversal` | 0.15 | 0.80 | Path traversal sequence in the request target. |
| `int.destructive_method` | 0.10 | 0.50 | State-changing HTTP method against an endpoint never advertised for it. |

## Adding a signal

1. Add a `SignalDef` to the right category block in `src/drosera/detect/rules.py`.
2. Add a detector in `src/drosera/detect/signals.py` that yields it.
3. Regenerate this file: `python docs/_gen_signals.py`.

Before choosing a weight, ask what else produces the same observation. If a person using a text browser, a screen reader, a corporate proxy or a privacy extension could trip it, it belongs in the corroborating tier or below. The comprehension tier is reserved for evidence that the client read prose and acted on its meaning -- nothing else earns it.
