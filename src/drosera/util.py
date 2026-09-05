"""Small shared helpers: tokens, fingerprints, deterministic randomness."""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import re
import secrets
import string
from urllib.parse import parse_qs, urlsplit

_ALPHABET = string.ascii_lowercase + string.digits


def token(n: int = 16) -> str:
    """URL-safe opaque token. Used for tickets, canary ids, maze seeds."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def sign(secret: str, payload: str, length: int = 12) -> str:
    """Short HMAC tag so we can verify a token is ours without a database."""
    mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256)
    return mac.hexdigest()[:length]


def verify(secret: str, payload: str, tag: str, length: int = 12) -> bool:
    return hmac.compare_digest(sign(secret, payload, length), tag)


def stable_hash(*parts: str, length: int = 16) -> str:
    h = hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()
    return h[:length]


# Only well-known headers contribute to the fingerprint. Custom headers are
# excluded on purpose: an agent that starts sending `X-Agent-Purpose` because we
# asked it to must not thereby become a different session, which would destroy
# exactly the correlation we were trying to build.
FINGERPRINT_HEADERS = (
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "connection",
    "upgrade-insecure-requests",
    "sec-fetch-mode",
    "sec-fetch-dest",
)


def fingerprint(headers: dict[str, str], header_order: list[str], remote_addr: str) -> str:
    """Cookie-independent client identity.

    Agents routinely drop cookies between steps, so session continuity has to
    survive without them. Header *order* is included because HTTP client
    libraries emit a stable, library-specific ordering that differs sharply
    from real browsers -- but only over the canonical subset above.
    """
    ua = headers.get("user-agent", "")
    accept = headers.get("accept", "")
    lang = headers.get("accept-language", "")
    enc = headers.get("accept-encoding", "")
    order = ",".join(h for h in header_order if h in FINGERPRINT_HEADERS)
    net = remote_addr.rsplit(".", 1)[0] if "." in remote_addr else remote_addr
    return stable_hash(ua, accept, lang, enc, order, net)


def seeded_rng(*parts: str) -> random.Random:
    """Deterministic RNG. The same maze URL always yields the same page."""
    seed = int(hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16], 16)
    return random.Random(seed)


def split_target(target: str) -> tuple[str, dict[str, list[str]]]:
    """Split a raw request target into (path, query dict)."""
    parts = urlsplit(target)
    return parts.path or "/", parse_qs(parts.query, keep_blank_values=True)


def lower_headers(pairs) -> tuple[dict[str, str], list[str]]:
    """Normalize header pairs to a lowercase dict plus the original ordering."""
    out: dict[str, str] = {}
    order: list[str] = []
    for k, v in pairs:
        lk = k.lower()
        order.append(lk)
        if lk in out:
            out[lk] = f"{out[lk]}, {v}"
        else:
            out[lk] = v
    return out, order


def env_secret(name: str = "DROSERA_SECRET") -> str:
    """Signing secret from the environment, generated if unset.

    A generated secret is per-process, which means canary tokens minted in one
    run will not verify in the next. That is fine for a quick demo and wrong
    for a deployment, so `drosera doctor` warns about it.
    """
    val = os.environ.get(name)
    if val:
        return val
    return secrets.token_hex(32)


_NL_WORD = re.compile(r"[A-Za-z]{2,}")


def looks_like_prose(text: str, min_words: int = 3) -> bool:
    """Cheap check that a free-text field holds a natural-language sentence.

    Used on self-declared 'purpose' values: a scanner that blindly fills every
    field emits junk or a fixed marker, whereas an LLM writes a sentence.
    """
    if not text or len(text) > 2000:
        return False
    words = _NL_WORD.findall(text)
    if len(words) < min_words:
        return False
    # Reject values that are one long token or obvious scanner payloads.
    longest = max((len(w) for w in words), default=0)
    return longest <= 30 and len(set(w.lower() for w in words)) >= min_words - 1


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def noisy_or(values) -> float:
    """Combine independent 0..1 evidence into a single 0..1 belief.

    Chosen over a plain sum because it saturates: ten weak signals can raise
    suspicion but never manufacture the certainty of one decisive one, and no
    weight tuning is needed to keep the result in range.
    """
    inv = 1.0
    for v in values:
        inv *= 1.0 - clamp(v)
    return 1.0 - inv
