"""Detectors. Each function inspects one observation (plus session history)
and yields zero or more ``Signal`` instances.

Detectors are pure and independent -- order does not matter, and any of them
can be disabled or replaced without touching the others. The engine simply
runs them all and hands the results to the combiner.
"""

from __future__ import annotations

import re
import statistics
from collections.abc import Iterator

from ..models import Bait, Observation, SessionState
from ..util import looks_like_prose
from .rules import get

# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

# Clients that announce themselves as agents or LLM-operated fetchers. Being on
# this list is not an accusation -- most are well-behaved and documented. It is
# an agency signal, not a hostility one.
AGENT_UA = re.compile(
    r"(?i)\b("
    r"gptbot|chatgpt-user|oai-searchbot|claudebot|claude-user|claude-searchbot|anthropic-ai"
    r"|perplexitybot|perplexity-user|google-extended|gemini|bard|applebot-extended"
    r"|ccbot|bytespider|amazonbot|meta-externalagent|youbot|cohere-ai|diffbot"
    r"|langchain|llamaindex|autogpt|agentgpt|babyagi|crewai|autogen|semantic-kernel"
    r"|browser-use|browserbase|stagehand|agent-e|webvoyager|openhands|opendevin"
    r"|smolagents|browserless|scrapegraph|firecrawl|jina-ai|jinabot"
    r")\b"
)

HTTP_LIB_UA = re.compile(
    r"(?i)\b("
    r"python-requests|python-httpx|httpx|aiohttp|urllib3|python-urllib|scrapy|libwww-perl"
    r"|go-http-client|okhttp|java|apache-httpclient|axios|node-fetch|undici|got"
    r"|curl|wget|powershell|restsharp|guzzle|reqwest|hyper"
    r")\b"
)

HEADLESS_UA = re.compile(r"(?i)\b(headlesschrome|phantomjs|electron|playwright|puppeteer|selenium)\b")

BROWSERISH_UA = re.compile(r"(?i)\bmozilla/5\.0\b")


def identity_signals(obs: Observation) -> Iterator:
    ua = obs.user_agent
    h = obs.headers

    if not ua.strip():
        yield get("id.no_ua").fire("no User-Agent header")
        return

    if m := AGENT_UA.search(ua):
        yield get("id.declared_agent").fire(f"UA declares {m.group(1)!r}")
    if m := HEADLESS_UA.search(ua):
        yield get("id.headless_browser").fire(f"UA indicates {m.group(1)!r}")
    if m := HTTP_LIB_UA.search(ua):
        yield get("id.http_library").fire(f"UA is HTTP client {m.group(1)!r}")

    # A client claiming to be a modern browser should carry the fetch metadata
    # and language preferences every modern browser sends. Missing both is a
    # forged UA, not a quirky one.
    if BROWSERISH_UA.search(ua) and not HTTP_LIB_UA.search(ua):
        has_sec_fetch = any(k.startswith("sec-fetch-") for k in h)
        has_lang = "accept-language" in h
        if not has_sec_fetch and not has_lang:
            yield get("id.ua_inconsistent").fire("browser UA without Sec-Fetch-* or Accept-Language")
        elif not has_sec_fetch:
            yield get("id.ua_inconsistent").fire(
                "browser UA without Sec-Fetch-* headers", confidence=0.6
            )
        if h.get("accept", "").strip() == "*/*":
            yield get("id.accept_wildcard").fire("browser UA with Accept: */*")


# --------------------------------------------------------------------------
# Bait engagement + comprehension
# --------------------------------------------------------------------------


def bait_signals(
    obs: Observation, bait: Bait | None, validate_ticket=None
) -> Iterator:
    """Signals that depend on the per-session lure we planted.

    ``validate_ticket`` recognises any ticket this deployment minted, not just
    this session's. Session joins are best-effort; the HMAC is not.
    """
    if bait is None:
        return

    path = obs.path.rstrip("/") or "/"

    if path == bait.hidden_path.rstrip("/"):
        yield get("bait.hidden_link").fire(f"followed hidden link {bait.hidden_path}")
    if path == bait.comment_path.rstrip("/"):
        yield get("bait.comment_link").fire(f"followed comment-only URL {bait.comment_path}")
    if path == bait.instruction_path.rstrip("/"):
        # The registration endpoint is described in prose and never linked.
        yield get("cmp.instruction_path").fire(
            f"requested prose-only endpoint {bait.instruction_path}"
        )

    # The ticket is unique to this session and appears exactly once, inside a
    # sentence telling the reader to send it back. Seeing it return is the
    # single strongest thing Drosera can observe.
    ticket_seen = _find_ticket(obs, bait.ticket, validate_ticket)
    if ticket_seen:
        yield get("cmp.ticket_echo").fire(f"returned registration ticket via {ticket_seen}")

    # The same notice asks for a header naming the client's task.
    purpose = obs.headers.get(bait.purpose_header.lower())
    if purpose:
        yield get("cmp.purpose_header").fire(f"sent {bait.purpose_header}: {purpose[:120]!r}")
        if looks_like_prose(purpose):
            yield get("cmp.purpose_prose").fire("purpose header reads as natural language")

    # Hidden form field, for anything that POSTs.
    if bait.form_field and _field_present(obs, bait.form_field):
        yield get("bait.form_honeypot").fire(f"filled hidden field {bait.form_field!r}")

    purpose_param = obs.qs("purpose") or obs.qs("task")
    if purpose_param and looks_like_prose(purpose_param):
        yield get("cmp.purpose_prose").fire(f"declared purpose {purpose_param[:120]!r}")


_TICKET_SHAPE = re.compile(r"\bdrs-[a-f0-9]{10}-[a-f0-9]{10}\b")


def _match(value: str, ticket: str, validate) -> bool:
    if ticket and ticket in value:
        return True
    if validate is None:
        return False
    return any(validate(m.group(0)) for m in _TICKET_SHAPE.finditer(value))


def _find_ticket(obs: Observation, ticket: str, validate=None) -> str | None:
    for key, values in obs.query.items():
        if any(_match(v, ticket, validate) for v in values):
            return f"query param {key!r}"
    for key, value in obs.headers.items():
        if key == "cookie":
            continue
        if _match(value, ticket, validate):
            return f"header {key!r}"
    if _match(obs.body[:8192], ticket, validate):
        return "request body"
    if _match(obs.path, ticket, validate):
        return "path"
    return None


def _field_present(obs: Observation, field: str) -> bool:
    if field in obs.query and any(v.strip() for v in obs.query[field]):
        return True
    if not obs.body:
        return False
    # Works for both urlencoded and JSON bodies without parsing either strictly.
    return bool(re.search(rf'(?:^|[&{{,"]){re.escape(field)}["\']?\s*[=:]\s*["\']?[^&,\s"\']+', obs.body))


STATIC_BAIT_PATHS = {
    "/.well-known/agent-policy": "cmp.llms_directive",
    "/agent-policy": "cmp.llms_directive",
}


def static_bait_signals(obs: Observation, robots_disallowed: set[str]) -> Iterator:
    """Bait that is the same for every visitor (robots.txt, llms.txt)."""
    path = obs.path
    if sig := STATIC_BAIT_PATHS.get(path.rstrip("/") or "/"):
        yield get(sig).fire(f"followed llms.txt directive to {path}")
    for disallowed in robots_disallowed:
        if path == disallowed or path.startswith(disallowed.rstrip("*")):
            yield get("bait.robots_disallow").fire(f"requested robots.txt Disallow entry {disallowed}")
            break


# --------------------------------------------------------------------------
# Behaviour
# --------------------------------------------------------------------------

ASSET_EXT = re.compile(
    r"\.(css|js|mjs|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|map|mp4|webm)$", re.I
)


def is_asset(path: str) -> bool:
    return bool(ASSET_EXT.search(path))


def behavior_signals(state: SessionState) -> Iterator:
    # Documents fetched, nothing that renders them requested.
    if state.doc_hits >= 3 and state.asset_hits == 0:
        conf = min(1.0, state.doc_hits / 6)
        yield get("beh.no_assets").fire(
            f"{state.doc_hits} documents, 0 assets", confidence=round(conf, 2)
        )

    # The page ships a tiny JS beacon. A real browser fires it; a fetch-and-parse
    # client never executes it. Requires the page to have actually been served.
    if state.doc_hits >= 2 and state.beacon_hits == 0:
        conf = min(1.0, state.doc_hits / 4)
        yield get("beh.no_beacon").fire(
            f"{state.doc_hits} documents, beacon never fired", confidence=round(conf, 2)
        )

    intervals = [i for i in state.intervals if i > 0]
    if len(intervals) >= 5:
        mean = statistics.fmean(intervals)
        if mean > 0:
            cv = statistics.pstdev(intervals) / mean
            # Humans are bursty; coefficient of variation well under 0.25 means
            # a loop with a sleep in it.
            if cv < 0.25:
                yield get("beh.uniform_cadence").fire(
                    f"cv={cv:.3f} over {len(intervals)} intervals",
                    confidence=round(min(1.0, (0.25 - cv) / 0.25 + 0.4), 2),
                )
        rate = 1.0 / mean if mean > 0 else 0.0
        if rate > 4.0:
            yield get("beh.superhuman_rate").fire(f"{rate:.1f} req/s sustained")

    if len(state.paths) >= 15 and state.age > 0 and len(state.paths) / max(state.hits, 1) > 0.85:
        yield get("beh.breadth_sweep").fire(f"{len(state.paths)} distinct paths in {state.hits} hits")

    if state.tarpit_hits >= 8:
        conf = min(1.0, state.tarpit_hits / 25)
        yield get("beh.deep_maze").fire(
            f"{state.tarpit_hits} generated pages consumed "
            f"(~{state.estimated_tokens_burned():,} tokens)",
            confidence=round(conf, 2),
        )


# --------------------------------------------------------------------------
# Intent
# --------------------------------------------------------------------------

SECRET_PATHS = re.compile(
    r"(?i)(^|/)(\.env(\.|$)|\.git/|\.svn/|\.aws/|\.ssh/|id_rsa|id_ed25519|\.npmrc|\.pypirc"
    r"|credentials(\.json)?$|secrets?(\.ya?ml|\.json)?$|wp-config\.php|web\.config"
    r"|appsettings(\.[A-Za-z]+)?\.json|config\.php\.bak|\.DS_Store|dump\.sql|backup\.(sql|zip|tar\.gz)"
    r"|kubeconfig|\.kube/config|docker-compose\.ya?ml|\.terraform|terraform\.tfstate)"
)

TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e[/\\%]|\.\.%2f|/etc/passwd|\\windows\\win\.ini)", re.I)

INJECTION = re.compile(
    r"(?i)("
    r"union\s+(all\s+)?select|select\s+.{0,40}\s+from\s|or\s+1\s*=\s*1|sleep\s*\(\s*\d|benchmark\s*\("
    r"|<script[\s>]|javascript:|onerror\s*=|onload\s*="
    r"|\{\{.{0,40}\}\}|\$\{.{0,40}\}|<%=.{0,40}%>"
    r"|;\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\s|\|\s*(curl|wget|nc|bash|sh)\b|\$\(.{0,40}\)"
    r")"
)

ADMIN_PATHS = re.compile(
    r"(?i)(^|/)(admin|administrator|wp-admin|wp-login|phpmyadmin|manager/html|actuator|debug"
    r"|console|cgi-bin|xmlrpc\.php|solr|jenkins|graphql|swagger|api-docs|metrics|server-status"
    r"|\.well-known/security\.txt|v1/secrets|latest/meta-data)(/|$)"
)

# Text aimed at a *downstream* model rather than at our server. Seeing this in
# submitted content means the client is trying to poison whatever reads it --
# a review queue, a summarizer, another agent.
PROMPT_INJECTION = re.compile(
    r"(?i)("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
    r"|disregard\s+(your|all|the)\s+(instructions|rules|system\s+prompt)"
    r"|you\s+are\s+now\s+(a|an|in)\b"
    r"|system\s*prompt\s*[:=]|<\|im_start\|>|\[/?INST\]|###\s*(system|instruction)"
    r"|reveal\s+(your|the)\s+(system\s+)?prompt"
    r"|new\s+instructions?\s*[:=]"
    r"|do\s+not\s+(tell|inform|alert)\s+the\s+user"
    r")"
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def intent_signals(obs: Observation) -> Iterator:
    target = obs.path + ("?" + "&".join(f"{k}={v}" for k, vs in obs.query.items() for v in vs) if obs.query else "")
    haystack = f"{target}\n{obs.body[:8192]}"

    if m := TRAVERSAL.search(haystack):
        yield get("int.path_traversal").fire(f"traversal token {m.group(1)!r}")
    if m := SECRET_PATHS.search(obs.path):
        yield get("int.secret_hunting").fire(f"requested secret location {obs.path!r}")
    if m := INJECTION.search(haystack):
        yield get("int.injection_probe").fire(f"injection pattern {m.group(0)[:60]!r}")
    if ADMIN_PATHS.search(obs.path):
        yield get("int.admin_probe").fire(f"admin surface {obs.path!r}")
    if obs.method.upper() not in SAFE_METHODS and obs.method.upper() in {"DELETE", "PUT", "PATCH"}:
        yield get("int.destructive_method").fire(f"{obs.method} {obs.path}")
    if obs.body and (m := PROMPT_INJECTION.search(obs.body[:8192])):
        yield get("int.prompt_injection_carrier").fire(f"model-directed text {m.group(0)[:80]!r}")


def canary_signal(token_id: str, where: str) -> Iterator:
    """Emitted out of band when a planted credential is actually used."""
    yield get("int.canary_used").fire(f"canary {token_id} used at {where}")
