"""Turn captured events into something another tool can act on.

Formats:

``summary``  human-readable rollup for a terminal
``csv``      one row per session, for a spreadsheet or a notebook
``ioc``      indicators (addresses, fingerprints, user agents) as JSON
``stix``     STIX 2.1 bundle of observed-data + indicator objects

The IOC and STIX outputs deliberately carry a confidence field derived from the
*evidence class*, not just the score. An address seen only via corroborating
behavioural signals is not the same claim as one that returned a session ticket,
and downstream blocklists should be able to tell those apart.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import time
import uuid
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

COMPREHENSION_PREFIX = "cmp."
DECISIVE = {"cmp.ticket_echo", "cmp.purpose_header", "cmp.instruction_path", "int.canary_used"}


def read_jsonl(path: str) -> Iterator[dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        return
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read_sqlite(path: str) -> Iterator[dict[str, Any]]:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        for row in conn.execute("SELECT * FROM events ORDER BY ts"):
            event = dict(row)
            try:
                event["signals"] = json.loads(event.get("signals") or "[]")
            except json.JSONDecodeError:
                event["signals"] = []
            yield event
    finally:
        conn.close()


def read(path: str) -> Iterator[dict[str, Any]]:
    return read_sqlite(path) if path.endswith((".db", ".sqlite", ".sqlite3")) else read_jsonl(path)


class SessionRollup:
    """Collapse per-request events into one row per session."""

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}

    def add(self, event: dict[str, Any]) -> None:
        sid = event.get("session_id") or event.get("fingerprint") or "?"
        row = self.rows.get(sid)
        if row is None:
            row = self.rows[sid] = {
                "session_id": sid,
                "fingerprint": event.get("fingerprint", ""),
                "remote_addr": event.get("remote_addr", ""),
                "user_agent": event.get("user_agent", ""),
                "first_seen": event.get("ts", 0.0),
                "last_seen": event.get("ts", 0.0),
                "requests": 0,
                "verdict": event.get("verdict", "unknown"),
                "agency": 0.0,
                "automation": 0.0,
                "hostility": 0.0,
                "tokens_burned": 0,
                "signals": set(),
                "paths": set(),
            }
        row["requests"] += 1
        row["last_seen"] = max(row["last_seen"], event.get("ts", 0.0))
        row["first_seen"] = min(row["first_seen"], event.get("ts", 0.0))
        row["agency"] = max(row["agency"], float(event.get("agency") or 0))
        row["automation"] = max(row["automation"], float(event.get("automation") or 0))
        row["hostility"] = max(row["hostility"], float(event.get("hostility") or 0))
        row["tokens_burned"] = max(row["tokens_burned"], int(event.get("tokens_burned") or 0))
        if _rank(event.get("verdict", "")) > _rank(row["verdict"]):
            row["verdict"] = event.get("verdict", "unknown")
        for sig in event.get("signals", []):
            sid_ = sig.get("id") if isinstance(sig, dict) else str(sig)
            if sid_:
                row["signals"].add(sid_)
        if p := event.get("path"):
            row["paths"].add(p)

    def finish(self) -> list[dict[str, Any]]:
        out = []
        for row in self.rows.values():
            r = dict(row)
            r["signals"] = sorted(row["signals"])
            r["distinct_paths"] = len(row["paths"])
            r["duration"] = round(row["last_seen"] - row["first_seen"], 1)
            r["confidence"] = confidence_of(r["signals"])
            r.pop("paths", None)
            out.append(r)
        out.sort(key=lambda r: (-_rank(r["verdict"]), -r["agency"]))
        return out


_RANKS = {"human": 0, "unknown": 1, "automation": 2, "agent": 3, "hostile_agent": 4}


def _rank(v: str) -> int:
    return _RANKS.get(v, 1)


def confidence_of(signal_ids: list[str]) -> str:
    """Evidence class, not score. Drives how a downstream blocklist should treat a row."""
    if any(s in DECISIVE for s in signal_ids):
        return "confirmed"
    if any(s.startswith(COMPREHENSION_PREFIX) for s in signal_ids):
        return "high"
    if any(s.startswith(("bait.", "id.declared")) for s in signal_ids):
        return "medium"
    return "low"


# -- renderers -----------------------------------------------------------


def to_summary(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No events.\n"
    by_verdict: dict[str, int] = defaultdict(int)
    by_signal: dict[str, int] = defaultdict(int)
    burned = 0
    for r in rows:
        by_verdict[r["verdict"]] += 1
        burned += r["tokens_burned"]
        for s in r["signals"]:
            by_signal[s] += 1

    out = io.StringIO()
    out.write(f"Sessions observed: {len(rows)}\n")
    out.write(f"Estimated tokens burned in traps: {burned:,}\n\n")
    out.write("By verdict\n")
    for v in ("hostile_agent", "agent", "automation", "unknown", "human"):
        if by_verdict.get(v):
            out.write(f"  {v:<14} {by_verdict[v]:>6}\n")
    out.write("\nTop signals\n")
    for sig, count in sorted(by_signal.items(), key=lambda kv: -kv[1])[:15]:
        out.write(f"  {sig:<30} {count:>6}\n")

    notable = [r for r in rows if r["confidence"] in ("confirmed", "high")][:15]
    if notable:
        out.write("\nHighest-confidence sessions\n")
        for r in notable:
            ua = (r["user_agent"] or "-")[:48]
            out.write(
                f"  {r['confidence']:<9} {r['verdict']:<14} {r['remote_addr']:<16} "
                f"{r['requests']:>4} req  {r['tokens_burned']:>8,} tok  {ua}\n"
            )
    return out.getvalue()


CSV_FIELDS = [
    "session_id", "fingerprint", "remote_addr", "user_agent", "verdict", "confidence",
    "agency", "automation", "hostility", "requests", "distinct_paths", "duration", "tokens_burned",
    "first_seen", "last_seen", "signals",
]


def to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        r = dict(r)
        r["signals"] = " ".join(r["signals"])
        w.writerow(r)
    return buf.getvalue()


def to_ioc(rows: list[dict[str, Any]], min_confidence: str = "medium") -> str:
    order = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
    floor = order.get(min_confidence, 1)
    addrs: dict[str, dict[str, Any]] = {}
    agents: dict[str, dict[str, Any]] = {}
    prints: dict[str, dict[str, Any]] = {}
    for r in rows:
        if order[r["confidence"]] < floor:
            continue
        for bucket, key in ((addrs, "remote_addr"), (agents, "user_agent"), (prints, "fingerprint")):
            value = r.get(key)
            if not value:
                continue
            entry = bucket.setdefault(
                value,
                {"value": value, "confidence": r["confidence"], "verdict": r["verdict"], "sessions": 0, "signals": set()},
            )
            entry["sessions"] += 1
            entry["signals"].update(r["signals"])
            if order[r["confidence"]] > order[entry["confidence"]]:
                entry["confidence"] = r["confidence"]
            if _rank(r["verdict"]) > _rank(entry["verdict"]):
                entry["verdict"] = r["verdict"]

    def norm(bucket: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for e in bucket.values():
            e = dict(e)
            e["signals"] = sorted(e["signals"])
            out.append(e)
        return sorted(out, key=lambda e: -e["sessions"])

    return json.dumps(
        {
            "generated": time.time(),
            "generator": "drosera",
            "min_confidence": min_confidence,
            "ip_addresses": norm(addrs),
            "user_agents": norm(agents),
            "fingerprints": norm(prints),
        },
        indent=2,
    )


def to_stix(rows: list[dict[str, Any]], min_confidence: str = "high") -> str:
    """STIX 2.1 bundle. Enough to import; not a full ontology mapping."""
    order = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
    floor = order.get(min_confidence, 2)
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'drosera')}",
            "created": now,
            "modified": now,
            "name": "Drosera",
            "identity_class": "system",
            "description": "Autonomous-agent honeypot",
        }
    ]
    confidence_map = {"low": 15, "medium": 50, "high": 80, "confirmed": 95}
    for r in rows:
        if order[r["confidence"]] < floor or not r.get("remote_addr"):
            continue
        pattern = f"[ipv4-addr:value = '{r['remote_addr']}']"
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, 'drosera:' + r['session_id'])}",
                "created": now,
                "modified": now,
                "name": f"Drosera {r['verdict']} ({r['confidence']})",
                "description": "Signals: " + ", ".join(r["signals"]),
                "indicator_types": ["malicious-activity" if r["verdict"] == "hostile_agent" else "anomalous-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "confidence": confidence_map[r["confidence"]],
                "labels": [r["verdict"], *r["signals"]],
            }
        )
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=2)


def render(rows: list[dict[str, Any]], fmt: str, min_confidence: str = "medium") -> str:
    if fmt == "csv":
        return to_csv(rows)
    if fmt == "ioc":
        return to_ioc(rows, min_confidence)
    if fmt == "stix":
        return to_stix(rows, min_confidence)
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str)
    return to_summary(rows)


def rollup(path: str) -> list[dict[str, Any]]:
    agg = SessionRollup()
    for event in read(path):
        agg.add(event)
    return agg.finish()
