"""The tarpit: an endless, deterministic maze of plausible filler.

Why deterministic? Because a maze whose pages change on every fetch is
obviously synthetic, cheap to detect, and impossible to reason about after the
fact. Seeding every page from its own URL means the same URL always yields the
same content, cross-links stay consistent, and an incident responder can
reproduce exactly what an agent saw. It also costs no storage.

What this does and does not do:

* It consumes the *client's* time and context budget on *our* server. Every
  page is a few kilobytes of prose an LLM has to read and decide about.
* It does not attack the client, run anything on it, or attempt to influence
  what the agent does anywhere else. It is a wall of nothing, not a payload.
* It carries ``noindex, nofollow`` in both a meta tag and an HTTP header, so
  any crawler that honours the conventions it claims to honour will not ingest
  filler. A client that ignores those directives has chosen to keep digging.
"""

from __future__ import annotations

import html
from dataclasses import dataclass

from ..config import Config
from ..util import seeded_rng, stable_hash

_NOUNS = (
    "allocation policy provisioning workflow migration schedule retention window "
    "throughput baseline reconciliation ledger dependency graph service tier "
    "escalation path capacity model change record incident summary audit trail "
    "vendor assessment procurement note staffing plan quarterly rollup index "
    "checkpoint archive segment revision draft appendix addendum errata"
).split()

_ADJS = (
    "interim provisional consolidated deprecated superseded quarterly regional "
    "internal preliminary revised legacy standing supplementary aggregated "
    "distributed nominal residual pending archived"
).split()

_VERBS = (
    "supersedes references consolidates deprecates summarises replaces extends "
    "reconciles annotates supplements withdraws amends"
).split()

_SENTENCES = (
    "The {adj} {noun} {verb} the {adj} {noun} recorded in section {n}.{m}.",
    "Section {n} of this {noun} was carried forward from the {adj} {noun} without amendment.",
    "See the {adj} {noun} for the corresponding {noun}; figures are reported to the nearest unit.",
    "This entry {verb} record {n}-{m} and remains open pending review of the {adj} {noun}.",
    "No material change was recorded against the {adj} {noun} during period {n}.",
    "Cross-references to the {noun} were normalised during the {adj} {noun} migration.",
    "Where the {noun} and the {adj} {noun} disagree, the later revision governs.",
    "Retention for this {noun} follows the {adj} schedule described in appendix {m}.",
)

_SEGMENTS = (
    "vol", "part", "rev", "set", "batch", "series", "folio", "bundle", "item", "index",
)


@dataclass
class Page:
    path: str
    title: str
    body_html: str
    links: list[str]
    depth: int


class Labyrinth:
    """Generates the maze. Pure function of (config.secret, path)."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()

    # -- addressing -------------------------------------------------------

    @property
    def root(self) -> str:
        return "/" + self.config.trap.root.strip("/")

    def owns(self, path: str) -> bool:
        root = self.root
        return path == root or path.startswith(root + "/")

    def entry_path(self, hint: str = "") -> str:
        seed = stable_hash(self.config.secret, "entry", hint, length=8)
        return f"{self.root}/index/{seed}"

    def depth_of(self, path: str) -> int:
        rel = path[len(self.root) :].strip("/")
        return len([p for p in rel.split("/") if p])

    # -- generation -------------------------------------------------------

    def page(self, path: str) -> Page:
        cfg = self.config.trap
        rng = seeded_rng(self.config.secret, "maze", path)
        depth = self.depth_of(path)

        title = (
            f"{rng.choice(_ADJS).title()} {rng.choice(_NOUNS).title()} "
            f"{rng.randrange(1000, 9999)}"
        )

        paragraphs: list[str] = []
        words_left = max(60, cfg.words_per_page)
        while words_left > 0:
            sentences = []
            for _ in range(rng.randrange(3, 7)):
                s = rng.choice(_SENTENCES).format(
                    adj=rng.choice(_ADJS),
                    noun=rng.choice(_NOUNS),
                    verb=rng.choice(_VERBS),
                    n=rng.randrange(1, 40),
                    m=rng.randrange(1, 20),
                )
                sentences.append(s)
                words_left -= len(s.split())
            paragraphs.append(" ".join(sentences))

        links: list[str] = []
        if cfg.max_depth <= 0 or depth < cfg.max_depth:
            for _ in range(max(1, cfg.links_per_page)):
                seg = rng.choice(_SEGMENTS)
                num = rng.randrange(100, 99999)
                child = f"{path.rstrip('/')}/{seg}-{num}"
                links.append(child)

        body = []
        for para in paragraphs:
            body.append(f"<p>{html.escape(para)}</p>")
        if links:
            body.append("<h2>Related records</h2><ul>")
            for child in links:
                label = child.rsplit("/", 1)[-1].replace("-", " ")
                body.append(f'<li><a href="{html.escape(child)}">{html.escape(label)}</a></li>')
            body.append("</ul>")

        return Page(path=path, title=title, body_html="\n".join(body), links=links, depth=depth)

    def render(self, path: str) -> str:
        page = self.page(path)
        crumb = html.escape(f"depth {page.depth}")
        return (
            "<!doctype html>\n<html lang=en>\n<head>\n<meta charset=utf-8>\n"
            '<meta name="robots" content="noindex,nofollow,noarchive">\n'
            f"<title>{html.escape(page.title)}</title>\n</head>\n<body>\n"
            f"<h1>{html.escape(page.title)}</h1>\n"
            f"<p><small>Record {crumb}</small></p>\n"
            f"{page.body_html}\n"
            "</body>\n</html>\n"
        )

    def headers(self) -> list[tuple[str, str]]:
        return [
            ("Content-Type", "text/html; charset=utf-8"),
            ("X-Robots-Tag", "noindex, nofollow, noarchive"),
            ("Cache-Control", "no-store"),
        ]

    # -- delivery ---------------------------------------------------------

    def chunks(self, body: str):
        """Yield the body, optionally dripped out in small slow chunks.

        Slow delivery is the classic tarpit lever: it holds an agent's
        connection and wall-clock budget open without consuming ours beyond a
        socket. Off by default because it also holds a worker thread.
        """
        cfg = self.config.trap
        data = body.encode("utf-8")
        if cfg.drip_bytes <= 0:
            yield data
            return
        for i in range(0, len(data), cfg.drip_bytes):
            yield data[i : i + cfg.drip_bytes]

    @property
    def drip_delay(self) -> float:
        return max(0.0, self.config.trap.drip_delay)
