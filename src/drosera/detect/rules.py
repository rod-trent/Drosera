"""Signal catalogue: the weights that define what Drosera believes.

Each entry is a ``SignalDef`` with two independent 0..1 weights:

* ``agency``    -- how much this raises "an LLM is driving this client"
* ``hostility`` -- how much this raises "this client means harm"

Weights are evidence strengths for a noisy-OR combiner (see ``util.noisy_or``),
not points in a running total, so they never need to sum to anything.

The tiering that matters:

  0.90-0.98  Decisive. Only an LLM-driven client produces this. Reserved for
             *comprehension* -- the client read prose and acted on its meaning.
  0.60-0.85  Strong. Bait engagement that no human and few crawlers reach.
  0.30-0.55  Corroborating. Consistent with automation, common in false
             positives on its own.
  0.10-0.25  Whisper. Only meaningful stacked with something else.

Nothing below 0.6 can produce an AGENT verdict alone -- that is a design
constraint, not an accident. A user with a screen reader, a text browser, a
privacy extension, or an odd proxy trips low-tier signals constantly.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Category, Signal


@dataclass(frozen=True)
class SignalDef:
    id: str
    category: Category
    agency: float
    hostility: float
    description: str

    def fire(self, detail: str = "", confidence: float = 1.0) -> Signal:
        return Signal(
            id=self.id,
            category=self.category,
            agency=self.agency * confidence,
            hostility=self.hostility * confidence,
            detail=detail,
            confidence=confidence,
        )


def _d(
    id: str, cat: Category, agency: float, hostility: float, desc: str
) -> tuple[str, SignalDef]:
    return id, SignalDef(id, cat, agency, hostility, desc)


# --------------------------------------------------------------------------
# Comprehension -- the discriminators.
#
# These are the only signals that separate "an LLM is driving" from "a script
# is running". They all require the client to have *understood* natural
# language embedded in the page and taken an action described only in prose.
# A regex-driven scraper cannot fake these; it has no notion of instructions.
# --------------------------------------------------------------------------
_COMPREHENSION = dict(
    (
        _d(
            "cmp.ticket_echo",
            Category.COMPREHENSION,
            0.96,
            0.0,
            "Returned the per-session registration ticket that appeared only inside a "
            "prose notice. Requires reading and following an instruction.",
        ),
        _d(
            "cmp.purpose_header",
            Category.COMPREHENSION,
            0.92,
            0.0,
            "Sent the custom purpose header the prose notice asked for. No crawler "
            "invents a header name from a sentence.",
        ),
        _d(
            "cmp.purpose_prose",
            Category.COMPREHENSION,
            0.88,
            0.0,
            "Self-declared purpose is a natural-language sentence rather than a "
            "fixed marker or scanner payload.",
        ),
        _d(
            "cmp.instruction_path",
            Category.COMPREHENSION,
            0.90,
            0.0,
            "Requested a path that was described in prose but never linked, so it "
            "cannot be reached by extracting hrefs.",
        ),
        _d(
            "cmp.llms_directive",
            Category.COMPREHENSION,
            0.68,
            0.0,
            "Followed a directive published in llms.txt, a file only agent tooling "
            "reads.",
        ),
        _d(
            "cmp.negotiated",
            Category.COMPREHENSION,
            0.85,
            0.0,
            "Reacted to a conditional instruction (did X only when the page said to), "
            "which requires evaluating a condition in prose.",
        ),
    )
)

# --------------------------------------------------------------------------
# Bait -- engagement with material humans cannot see or would never touch.
# Strong, but shared with classic crawlers, so it drives AUTOMATION on its own
# and AGENT only in combination with comprehension.
# --------------------------------------------------------------------------
_BAIT = dict(
    (
        _d(
            "bait.hidden_link",
            Category.BAIT,
            0.55,
            0.1,
            "Followed a link hidden with display:none and aria-hidden. Invisible to "
            "sighted users and skipped by screen readers.",
        ),
        _d(
            "bait.comment_link",
            Category.BAIT,
            0.62,
            0.1,
            "Followed a URL that exists only inside an HTML comment, meaning the "
            "client parsed raw markup rather than a rendered DOM.",
        ),
        _d(
            "bait.robots_disallow",
            Category.BAIT,
            0.35,
            0.25,
            "Requested a path listed only as Disallow in robots.txt.",
        ),
        _d(
            "bait.form_honeypot",
            Category.BAIT,
            0.60,
            0.2,
            "Filled a form field that is hidden from users and labelled do-not-fill.",
        ),
        _d(
            "bait.decoy_api",
            Category.BAIT,
            0.45,
            0.35,
            "Called a decoy API endpoint advertised only in a fake OpenAPI document.",
        ),
    )
)

# --------------------------------------------------------------------------
# Identity -- what the client says it is, and whether that story is coherent.
# --------------------------------------------------------------------------
_IDENTITY = dict(
    (
        _d(
            "id.declared_agent",
            Category.IDENTITY,
            0.75,
            0.0,
            "User-Agent names a known agent framework or LLM crawler.",
        ),
        _d(
            "id.http_library",
            Category.IDENTITY,
            0.40,
            0.05,
            "User-Agent is a raw HTTP client library rather than a browser.",
        ),
        _d(
            "id.headless_browser",
            Category.IDENTITY,
            0.50,
            0.1,
            "User-Agent or headers indicate a headless browser automation stack.",
        ),
        _d(
            "id.ua_inconsistent",
            Category.IDENTITY,
            0.45,
            0.15,
            "Claims to be a browser but omits headers every real browser sends "
            "(Sec-Fetch-*, Accept-Language).",
        ),
        _d(
            "id.accept_wildcard",
            Category.IDENTITY,
            0.20,
            0.0,
            "Browser-shaped User-Agent paired with Accept: */*.",
        ),
        _d(
            "id.no_ua",
            Category.IDENTITY,
            0.30,
            0.1,
            "No User-Agent header at all.",
        ),
    )
)

# --------------------------------------------------------------------------
# Behaviour -- shape of traffic over a session.
# All corroborating tier: every one of these has a benign explanation.
# --------------------------------------------------------------------------
_BEHAVIOR = dict(
    (
        _d(
            "beh.no_assets",
            Category.BEHAVIOR,
            0.45,
            0.0,
            "Fetched several HTML documents and zero CSS, images or fonts.",
        ),
        _d(
            "beh.no_beacon",
            Category.BEHAVIOR,
            0.50,
            0.0,
            "Pages were fetched but the in-page JavaScript beacon never fired, so "
            "nothing executed the document.",
        ),
        _d(
            "beh.uniform_cadence",
            Category.BEHAVIOR,
            0.40,
            0.0,
            "Inter-request timing is unnaturally regular.",
        ),
        _d(
            "beh.superhuman_rate",
            Category.BEHAVIOR,
            0.35,
            0.1,
            "Sustained request rate above what a person can generate.",
        ),
        _d(
            "beh.breadth_sweep",
            Category.BEHAVIOR,
            0.30,
            0.15,
            "Many distinct paths touched once each -- enumeration, not reading.",
        ),
        _d(
            "beh.deep_maze",
            Category.BEHAVIOR,
            0.55,
            0.0,
            "Kept descending into generated content long past the point a person "
            "would have recognised it as filler.",
        ),
    )
)

# --------------------------------------------------------------------------
# Intent -- hostility. Mostly orthogonal to agency: a scanner and an agent
# probe for the same things.
# --------------------------------------------------------------------------
_INTENT = dict(
    (
        _d(
            "int.canary_used",
            Category.INTENT,
            0.55,
            0.97,
            "A credential that exists only inside planted bait was used or "
            "transmitted. Proof of exfiltration.",
        ),
        _d(
            "int.secret_hunting",
            Category.INTENT,
            0.25,
            0.75,
            "Requested well-known secret locations (.env, .git/config, id_rsa).",
        ),
        _d(
            "int.path_traversal",
            Category.INTENT,
            0.15,
            0.80,
            "Path traversal sequence in the request target.",
        ),
        _d(
            "int.injection_probe",
            Category.INTENT,
            0.15,
            0.78,
            "SQL, template, command or XSS injection pattern in input.",
        ),
        _d(
            "int.admin_probe",
            Category.INTENT,
            0.15,
            0.40,
            "Enumerated administrative or infrastructure endpoints.",
        ),
        _d(
            "int.destructive_method",
            Category.INTENT,
            0.10,
            0.50,
            "State-changing HTTP method against an endpoint never advertised for it.",
        ),
        _d(
            "int.prompt_injection_carrier",
            Category.INTENT,
            0.30,
            0.70,
            "Submitted content containing instructions aimed at a downstream model "
            "-- an attempt to poison whatever reads this data.",
        ),
    )
)

SIGNALS: dict[str, SignalDef] = {**_COMPREHENSION, **_BAIT, **_IDENTITY, **_BEHAVIOR, **_INTENT}


def get(signal_id: str) -> SignalDef:
    try:
        return SIGNALS[signal_id]
    except KeyError:  # pragma: no cover - programmer error
        raise KeyError(f"unknown signal id {signal_id!r}") from None


def catalogue() -> list[SignalDef]:
    """All definitions, sorted for stable documentation output."""
    return sorted(SIGNALS.values(), key=lambda s: (s.category.value, -s.agency, s.id))
