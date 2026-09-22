"""A self-contained HTML report: ``drosera report -f html`` and ``drosera dashboard``.

One file, no network. Styles, charts (inline SVG) and the small table filter
are all embedded, so the page can be mailed, attached to an incident, archived
next to the events it summarises, or opened on an air-gapped analyst box.

**Everything on this page is attacker-controlled until proven otherwise.**
User agents, paths, even IP fields arrive from the clients being reported on,
and a honeypot report is exactly where someone would plant markup to see if it
renders. Every interpolated value goes through ``_e`` (``html.escape``), and a
Content-Security-Policy forbids any script except the one inline block, pinned
by hash. If a new field is added here, it goes through ``_e`` too; the test
suite feeds the renderer a ``<script>`` user agent to hold that line.
"""

from __future__ import annotations

import base64
import hashlib
import html
import math
import time
from collections import Counter
from typing import Any

# Non-human verdicts, in ladder order, with fixed colour slots. Colour follows
# the verdict, never its rank in a chart, and every mark also carries a text
# label so colour is never the only channel.
SERIES = [
    ("automation", "Automation", "--s-auto"),
    ("agent", "LLM agent", "--s-agent"),
    ("hostile_agent", "Hostile agent", "--s-hostile"),
]
VERDICTS = ["hostile_agent", "agent", "automation", "unknown", "human"]
CONFIDENCE_ORDER = {"confirmed": 3, "high": 2, "medium": 1, "low": 0}
RANK = {"human": 0, "unknown": 1, "automation": 2, "agent": 3, "hostile_agent": 4}

MAX_TABLE_ROWS = 500


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _ts(ts: float, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return time.strftime(fmt, time.gmtime(float(ts or 0))) if ts else "-"


def _n(value: float) -> str:
    return f"{int(value):,}"


# -- charts ----------------------------------------------------------------------


def _nice_max(value: float) -> float:
    if value <= 0:
        return 1
    exp = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        if value <= step * exp:
            return step * exp
    return 10 * exp


def _bucket_seconds(span: float) -> tuple[int, str]:
    for size, label in ((3600, "hour"), (6 * 3600, "6 hours"), (86400, "day"), (7 * 86400, "week")):
        if span / size <= 72:
            return size, label
    return 30 * 86400, "30 days"


def timeline_svg(rows: list[dict[str, Any]]) -> str:
    """Stacked columns: new non-human sessions per time bucket, by verdict."""
    points = [r for r in rows if r["verdict"] in RANK and RANK[r["verdict"]] >= 2 and r["first_seen"]]
    if not points:
        return '<p class="empty">No non-human sessions in this window.</p>'
    start = min(r["first_seen"] for r in points)
    end = max(r["first_seen"] for r in points)
    size, unit = _bucket_seconds(max(end - start, 1))
    origin = start - (start % size)
    nbuckets = int((end - origin) // size) + 1
    counts: list[Counter] = [Counter() for _ in range(nbuckets)]
    for r in points:
        counts[int((r["first_seen"] - origin) // size)][r["verdict"]] += 1

    width, height = 720, 240
    left, right, top, bottom = 44, 8, 12, 28
    plot_w, plot_h = width - left - right, height - top - bottom
    peak = _nice_max(max(sum(c.values()) for c in counts))
    slot = plot_w / nbuckets
    bar_w = max(2.0, min(28.0, slot - 2))

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" class="chart" '
        f'aria-label="New non-human sessions per {unit}, stacked by verdict">'
    ]
    # Whole-number gridlines: 5 -> 0..5 in ones, 20 -> fives, never 1.67.
    steps = next((n for n in (4, 5, 3, 2) if (peak / n).is_integer()), 1)
    for i in range(steps + 1):
        v = peak * i / steps
        y = top + plot_h - plot_h * i / steps
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>')
        parts.append(f'<text x="{left - 6}" y="{y + 4:.1f}" class="tick" text-anchor="end">{_n(v)}</text>')

    for i, bucket in enumerate(counts):
        x = left + i * slot + (slot - bar_w) / 2
        y = top + plot_h
        label = _ts(origin + i * size, "%Y-%m-%d %H:%M") + " UTC"
        detail = ", ".join(f"{name}: {bucket[key]}" for key, name, _ in SERIES if bucket[key])
        for key, name, var in SERIES:
            n = bucket[key]
            if not n:
                continue
            h = plot_h * n / peak
            # 2px surface gap between stacked segments; rounding only at the top.
            y -= h
            parts.append(
                f'<rect x="{x:.1f}" y="{y + 1:.1f}" width="{bar_w:.1f}" height="{max(h - 2, 1):.1f}" '
                f'rx="1.5" fill="var({var})"><title>{_e(label)} - {_e(name)}: {n}'
                f' ({_e(detail)})</title></rect>'
            )
    for i in sorted({0, nbuckets // 2, nbuckets - 1}):
        x = left + i * slot + slot / 2
        fmt = "%m-%d %H:%M" if size < 86400 else "%Y-%m-%d"
        anchor = "start" if i == 0 else ("end" if i == nbuckets - 1 and nbuckets > 1 else "middle")
        parts.append(
            f'<text x="{x:.1f}" y="{height - 8}" class="tick" text-anchor="{anchor}">'
            f"{_e(_ts(origin + i * size, fmt))}</text>"
        )
    parts.append(f'<line x1="{left}" x2="{width - right}" y1="{top + plot_h}" y2="{top + plot_h}" class="axis"/>')
    parts.append("</svg>")
    legend = "".join(
        f'<span class="key"><i style="background:var({var})"></i>{_e(name)}</span>' for _, name, var in SERIES
    )
    return f'<div class="legend">{legend}<span class="unit">per {unit}, UTC</span></div>' + "".join(parts)


def bars(items: list[tuple[str, int]], total: int | None = None, mono: bool = False) -> str:
    """Horizontal ranked bars. HTML rather than SVG so long labels wrap."""
    if not items:
        return '<p class="empty">Nothing to show.</p>'
    peak = max(n for _, n in items) or 1
    out = ['<ul class="bars">']
    for label, n in items:
        pct = 100 * n / peak
        share = f' <span class="muted">{100 * n / total:.0f}%</span>' if total else ""
        cls = "lbl mono" if mono else "lbl"
        out.append(
            f'<li><span class="{cls}" title="{_e(label)}">{_e(label)}</span>'
            f'<span class="track"><span class="fill" style="width:{pct:.1f}%"></span></span>'
            f'<span class="val">{_n(n)}{share}</span></li>'
        )
    out.append("</ul>")
    return "".join(out)


# -- page ------------------------------------------------------------------------

SCRIPT = """
(function () {
  var box = document.getElementById('q');
  var rows = Array.prototype.slice.call(document.querySelectorAll('#sessions tbody tr'));
  var count = document.getElementById('shown');
  function apply() {
    var q = box.value.trim().toLowerCase(), n = 0;
    rows.forEach(function (tr) {
      var hit = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
      tr.hidden = !hit; if (hit) n++;
    });
    count.textContent = n;
    try { history.replaceState(null, '', q ? '#q=' + encodeURIComponent(q) : '#'); } catch (e) {}
  }
  if (box) {
    var m = /^#q=(.*)$/.exec(location.hash);
    if (m) { try { box.value = decodeURIComponent(m[1]); } catch (e) {} }
    box.addEventListener('input', apply);
    apply();
  }
})();
"""

_SCRIPT_HASH = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    f"script-src 'sha256-{_SCRIPT_HASH}'; base-uri 'none'; form-action 'none'"
)

STYLE = """
:root {
  color-scheme: light;
  --bg: #f7f7f5; --surface: #fcfcfb; --line: #e4e3df; --grid: #ecebe7;
  --ink: #0b0b0b; --ink-2: #52514e; --ink-3: #7a7974;
  --accent: #6d4aff; --bar: #2a78d6;
  --s-auto: #1baf7a; --s-agent: #2a78d6; --s-hostile: #eb6834;
  --c-confirmed: #d03b3b; --c-high: #ec835a;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --bg: #121211; --surface: #1a1a19; --line: #2e2e2c; --grid: #262624;
    --ink: #ffffff; --ink-2: #c3c2b7; --ink-3: #8f8e86;
    --accent: #9d85ff; --bar: #3987e5;
    --s-auto: #199e70; --s-agent: #3987e5; --s-hostile: #d95926;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #121211; --surface: #1a1a19; --line: #2e2e2c; --grid: #262624;
  --ink: #ffffff; --ink-2: #c3c2b7; --ink-3: #8f8e86;
  --accent: #9d85ff; --bar: #3987e5;
  --s-auto: #199e70; --s-agent: #3987e5; --s-hostile: #d95926;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1180px; margin: 0 auto; padding: 24px 16px 48px; overflow-x: hidden; }
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; margin-bottom: 20px; }
h1 { font-size: 22px; margin: 0; letter-spacing: -0.01em; }
h1 span { color: var(--accent); }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--ink-2);
  margin: 0 0 12px; font-weight: 600; }
.meta { color: var(--ink-3); font-size: 13px; overflow-wrap: anywhere; min-width: 0; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px; min-width: 0; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 12px; }
.kpi .v { font-size: 28px; font-weight: 650; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.kpi .k { color: var(--ink-2); font-size: 13px; }
.kpi .s { color: var(--ink-3); font-size: 12px; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; margin-bottom: 12px; }
.wide { margin-bottom: 12px; }
.chart { width: 100%; height: auto; max-height: 280px; display: block; }
.chart .grid { stroke: var(--grid); stroke-width: 1; }
.chart .axis { stroke: var(--line); stroke-width: 1; }
.chart .tick { fill: var(--ink-3); font-size: 11px; font-variant-numeric: tabular-nums; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 14px; margin-bottom: 8px; font-size: 12px; color: var(--ink-2); }
.legend .key { display: inline-flex; align-items: center; gap: 6px; }
.legend i { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.legend .unit { color: var(--ink-3); margin-left: auto; }
.bars { list-style: none; margin: 0; padding: 0; }
.bars li { display: grid; grid-template-columns: minmax(0, 11fr) minmax(60px, 9fr) auto; gap: 10px; align-items: center; padding: 3px 0; }
.bars .lbl { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bars .track { height: 8px; background: var(--grid); border-radius: 4px; overflow: hidden; }
.bars .fill { display: block; height: 100%; background: var(--bar); border-radius: 0 4px 4px 0; }
.bars .val { font-variant-numeric: tabular-nums; text-align: right; min-width: 3.5em; }
.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; }
.muted { color: var(--ink-3); }
.empty { color: var(--ink-3); margin: 8px 0; }
.tools { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin-bottom: 10px; }
.tools input { flex: 1 1 240px; max-width: 420px; padding: 7px 10px; border-radius: 7px;
  border: 1px solid var(--line); background: var(--bg); color: var(--ink); font: inherit; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-2); font-weight: 600; white-space: nowrap; position: sticky; top: 0; background: var(--surface); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.ua { max-width: 280px; overflow-wrap: anywhere; }
td.sig { max-width: 320px; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 12px; font-weight: 600;
  border: 1px solid var(--line); white-space: nowrap; }
.badge.confirmed { border-color: var(--c-confirmed); color: var(--c-confirmed); }
.badge.high { border-color: var(--c-high); color: var(--c-high); }
.badge.medium, .badge.low { color: var(--ink-2); }
.verdict { white-space: nowrap; }
.verdict i { width: 8px; height: 8px; border-radius: 2px; display: inline-block; margin-right: 6px; }
footer { color: var(--ink-3); font-size: 12px; margin-top: 24px; }
footer a { color: inherit; }
"""


def _verdict_cell(verdict: str) -> str:
    var = {k: v for k, _, v in SERIES}.get(verdict)
    dot = f'<i style="background:var({var})"></i>' if var else '<i style="background:var(--grid)"></i>'
    return f'<span class="verdict">{dot}{_e(verdict)}</span>'


def render_html(
    rows: list[dict[str, Any]],
    canaries: list[dict[str, Any]],
    title: str = "Drosera report",
    source: str = "",
    refresh: int = 0,
    generated: float | None = None,
) -> str:
    generated = generated or time.time()
    by_verdict = Counter(r["verdict"] for r in rows)
    by_conf = Counter(r["confidence"] for r in rows)
    nonhuman = [r for r in rows if RANK.get(r["verdict"], 1) >= 2]
    agents = by_verdict["agent"] + by_verdict["hostile_agent"]
    tokens = sum(r["tokens_burned"] for r in rows)
    confirmed_canaries = sum(1 for c in canaries if c.get("channel") == "value_seen")

    signals: Counter = Counter()
    uas: Counter = Counter()
    for r in nonhuman:
        signals.update(r["signals"])
        uas[r["user_agent"] or "(none)"] += 1

    if rows:
        window = f"{_ts(min(r['first_seen'] for r in rows))} to {_ts(max(r['last_seen'] for r in rows))} UTC"
    else:
        window = "no sessions"

    def kpi(value: str, label: str, sub: str = "") -> str:
        s = f'<div class="s">{_e(sub)}</div>' if sub else ""
        return f'<div class="card kpi"><div class="v">{_e(value)}</div><div class="k">{_e(label)}</div>{s}</div>'

    kpis = "".join([
        kpi(_n(len(rows)), "Sessions", f"{_n(len(nonhuman))} non-human"),
        kpi(_n(agents), "LLM agent sessions", f"{_n(by_verdict['hostile_agent'])} hostile"),
        kpi(_n(by_conf["confirmed"]), "Confirmed", "returned a ticket or used a canary"),
        kpi(_n(tokens), "Tokens burned", "estimated, in traps"),
        kpi(_n(len(canaries)), "Canary hits", f"{_n(confirmed_canaries)} credential use"),
    ])

    verdict_items = [(v, by_verdict[v]) for v in VERDICTS if by_verdict.get(v)]
    conf_items = [(c, by_conf[c]) for c in ("confirmed", "high", "medium", "low") if by_conf.get(c)]

    ordered = sorted(
        nonhuman,
        key=lambda r: (-CONFIDENCE_ORDER.get(r["confidence"], 0), -RANK.get(r["verdict"], 1),
                       -r["agency"], -r["requests"]),
    )
    shown = ordered[:MAX_TABLE_ROWS]
    body_rows = []
    for r in shown:
        sigs = " ".join(r["signals"])
        body_rows.append(
            "<tr>"
            f'<td><span class="badge {_e(r["confidence"])}">{_e(r["confidence"])}</span></td>'
            f"<td>{_verdict_cell(r['verdict'])}</td>"
            f'<td class="mono">{_e(r["remote_addr"])}</td>'
            f'<td class="ua">{_e(r["user_agent"] or "-")}</td>'
            f'<td class="num">{_n(r["requests"])}</td>'
            f'<td class="num">{r["agency"]:.0f}</td>'
            f'<td class="num">{r["hostility"]:.0f}</td>'
            f'<td class="num">{_n(r["tokens_burned"])}</td>'
            f'<td class="num">{_e(_ts(r["first_seen"]))}</td>'
            f'<td class="mono sig">{_e(sigs)}</td>'
            "</tr>"
        )
    more = (
        f'<p class="muted">Showing the {MAX_TABLE_ROWS} highest-confidence of {_n(len(ordered))} '
        "sessions. Use <code>drosera report -f csv</code> for all of them.</p>"
        if len(ordered) > MAX_TABLE_ROWS else ""
    )
    sessions_table = (
        '<div class="tools"><input id="q" type="search" placeholder="Filter by address, agent, signal..." '
        f'aria-label="Filter sessions"><span class="muted"><span id="shown">{len(shown)}</span> shown</span></div>'
        '<div class="scroll"><table id="sessions"><thead><tr>'
        '<th>Confidence</th><th>Verdict</th><th>Address</th><th>User agent</th>'
        '<th class="num">Req</th><th class="num">LLM</th><th class="num">Hostile</th>'
        '<th class="num">Tokens</th><th class="num">First seen (UTC)</th><th>Signals</th>'
        f"</tr></thead><tbody>{''.join(body_rows)}</tbody></table></div>{more}"
        if shown else '<p class="empty">No non-human sessions.</p>'
    )

    canary_rows = "".join(
        "<tr>"
        f'<td class="num">{_e(_ts(c.get("ts") or 0, "%Y-%m-%d %H:%M:%S"))}</td>'
        f'<td><span class="badge {"confirmed" if c.get("channel") == "value_seen" else "low"}">'
        f'{_e(c.get("channel", ""))}</span></td>'
        f'<td>{_e(c.get("kind", ""))}</td><td class="mono">{_e(c.get("path", ""))}</td>'
        f'<td>{_e(c.get("detail", ""))}</td>'
        "</tr>"
        for c in sorted(canaries, key=lambda c: -float(c.get("ts") or 0))[:200]
    )
    canary_section = (
        '<section class="card wide"><h2>Canary hits</h2><div class="scroll"><table><thead><tr>'
        '<th class="num">Time (UTC)</th><th>Channel</th><th>Kind</th><th>Path</th><th>Detail</th>'
        f"</tr></thead><tbody>{canary_rows}</tbody></table></div>"
        '<p class="muted"><b>value_seen</b> is proof a planted credential was used. '
        "<b>file_read</b> and <b>file_modified</b> are hints only; backups and indexers touch files too.</p>"
        "</section>"
        if canaries else ""
    )

    refresh_tag = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
    source_note = f" &middot; source <span class=\"mono\">{_e(source)}</span>" if source else ""
    top_signals = signals.most_common(15)
    top_uas = uas.most_common(10)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="robots" content="noindex, nofollow">
{refresh_tag}
<title>{_e(title)}</title>
<style>{STYLE}</style>
</head>
<body>
<main>
<header>
  <h1><span>&#10033;</span> {_e(title)}</h1>
  <div class="meta">{_e(window)}{source_note} &middot; generated {_e(_ts(generated))} UTC</div>
</header>

<section class="kpis">{kpis}</section>

<section class="card wide">
  <h2>New non-human sessions over time</h2>
  {timeline_svg(rows)}
</section>

<div class="grid2">
  <section class="card"><h2>Sessions by verdict</h2>{bars(verdict_items, total=len(rows))}</section>
  <section class="card"><h2>Evidence confidence</h2>{bars(conf_items, total=len(rows))}
    <p class="muted">Confidence is the <i>kind</i> of evidence, not the score: <b>confirmed</b> returned
    this site's signed ticket or used a planted credential; <b>low</b> is traffic shape alone.</p></section>
</div>

<div class="grid2">
  <section class="card"><h2>Top signals (non-human sessions)</h2>{bars(top_signals, mono=True)}</section>
  <section class="card"><h2>Top user agents (non-human sessions)</h2>{bars(top_uas)}</section>
</div>

{canary_section}

<section class="card wide">
  <h2>Sessions</h2>
  {sessions_table}
</section>

<footer>
  Drosera detects and delays; it does not attack. A verdict is not a judgement &mdash;
  an address is not a person. Confirm before acting on anything real.
</footer>
</main>
<script>{SCRIPT}</script>
</body>
</html>
"""
