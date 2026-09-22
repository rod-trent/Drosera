"""Reporting, plug-in sinks, the Sentinel sink and the Sentinel content pack."""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import sqlite3
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from drosera import cli
from drosera.config import Config
from drosera.telemetry import azure, export, html, sink

ROOT = Path(__file__).resolve().parent.parent


def _event(sid="s1", verdict="agent", addr="203.0.113.9", ua="agent/1.0", ts=1_800_000_000.0,
           signals=("cmp.ticket_echo",), **kw):
    e = {
        "ts": ts, "session_id": sid, "fingerprint": "fp-" + sid, "remote_addr": addr,
        "method": "GET", "path": "/", "user_agent": ua, "verdict": verdict,
        "agency": 100.0 if verdict in ("agent", "hostile_agent") else 0.0,
        "automation": 92.5, "hostility": 0.0, "action": "tarpit", "hits": 1, "tokens_burned": 10,
        "signals": [{"id": s, "category": "x", "agency": 1, "hostility": 0, "confidence": 1, "detail": ""}
                    for s in signals],
    }
    e.update(kw)
    return e


CANARY = {"event": "canary", "ts": 1_800_000_100.0, "canary_id": "c1", "kind": "dotenv",
          "channel": "value_seen", "detail": "seen in a request", "path": "/srv/.env"}


# -- sqlite ------------------------------------------------------------------------


def test_sqlite_keeps_the_automation_score(tmp_path):
    db = tmp_path / "e.db"
    s = sink.SqliteSink(db)
    s.emit(_event(verdict="automation", signals=()))
    s.close()
    assert export.rollup(str(db))[0]["automation"] == 92.5


def test_sqlite_written_by_0_1_0_is_migrated_in_place(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(sink.SCHEMA.replace("    automation   REAL,\n", ""))
    conn.execute("INSERT INTO events (ts, session_id, verdict) VALUES (1, 'old', 'human')")
    conn.commit()
    conn.close()
    s = sink.SqliteSink(db)
    s.emit(_event(sid="new", verdict="automation", signals=()))
    s.close()
    rows = {r["session_id"]: r for r in export.rollup(str(db))}
    assert rows["old"]["verdict"] == "human"
    assert rows["new"]["automation"] == 92.5


def test_canary_events_round_trip_without_polluting_sessions(tmp_path):
    for name, cls in (("e.jsonl", sink.JsonlSink), ("e.db", sink.SqliteSink)):
        path = tmp_path / name
        s = cls(path)
        s.emit(_event())
        s.emit(dict(CANARY))
        s.close()
        rows, canaries = export.collect(str(path))
        assert [r["session_id"] for r in rows] == ["s1"], name
        assert canaries and canaries[0]["channel"] == "value_seen", name
        assert "Canary hits (1)" in export.to_summary(rows, canaries)


# -- plug-ins -----------------------------------------------------------------------


def test_builtin_plugin_resolves_and_unknown_fails_loudly():
    assert sink.resolve_plugin("azure_monitor") is azure.make_sink
    with pytest.raises(ValueError, match="no sink plug-in named 'nope'"):
        sink.resolve_plugin("nope")


def test_entry_point_plugins_are_discovered(monkeypatch):
    made = []

    class EP:
        name = "memory"

        def load(self):
            def factory(options, config):
                made.append(options)
                return sink.StderrSink()
            return factory

    monkeypatch.setattr(sink, "entry_points", lambda group: [EP()] if group == sink.ENTRY_POINT_GROUP else [])
    cfg = Config.from_dict({"sinks": {"memory": {"x": 1}, "off": {"enabled": False}}})
    built = sink.build_plugins(cfg)
    assert made == [{"x": 1}] and len(built) == 1
    assert "memory" in sink.available_plugins()


def test_sink_secrets_are_masked_in_config_dumps():
    cfg = Config.from_dict({"sinks": {"azure_monitor": {"client_secret": "hunter2", "endpoint": "https://x"}}})
    dumped = cfg.to_dict()["sinks"]["azure_monitor"]
    assert dumped == {"client_secret": "***", "endpoint": "https://x"}


def test_env_alone_switches_the_sentinel_sink_on(monkeypatch):
    monkeypatch.setenv("DROSERA_AZURE_ENDPOINT", "https://dce.example")
    cfg = Config.load("does-not-exist.toml")
    assert "azure_monitor" in cfg.sinks


# -- the Azure Monitor sink ---------------------------------------------------------------


class FakeAzure:
    """Token endpoint plus Logs Ingestion endpoint, on one local port."""

    def __init__(self, fail_first_with: int = 0):
        self.batches: list[list[dict]] = []
        self.headers: list[dict] = []
        self.tokens_issued = 0
        self.fail_first_with = fail_first_with
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if "/oauth2/v2.0/token" in self.path:
                    outer.tokens_issued += 1
                    payload = json.dumps({"access_token": f"tok{outer.tokens_issued}", "expires_in": 3600})
                    return self._reply(200, payload.encode())
                if outer.fail_first_with:
                    code, outer.fail_first_with = outer.fail_first_with, 0
                    return self._reply(code, b"{}")
                outer.headers.append(dict(self.headers))
                outer.batches.append(json.loads(gzip.decompress(body)))
                self._reply(204, b"")

            def _reply(self, code, body):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def rows(self):
        return [r for b in self.batches for r in b]


@pytest.fixture
def fake_azure():
    f = FakeAzure()
    yield f
    f.close()


def _azure_sink(url, **kw):
    cred = azure.ClientSecretCredential("tenant", "client", "secret", authority=url)
    return azure.AzureMonitorSink(endpoint=url, rule_id="dcr-abc", credential=cred, sensor="hp1",
                                  flush_interval=0.1, **kw)


def test_sentinel_sink_ships_gzipped_rows_with_a_bearer_token(fake_azure):
    s = _azure_sink(fake_azure.url)
    s.emit(_event(verdict="agent"))
    s.emit(_event(sid="h", verdict="human", signals=()))  # below min_verdict: stays home
    s.emit(dict(CANARY))  # canaries always ship
    s.close()
    rows = fake_azure.rows
    assert [r["EventType"] for r in rows] == ["request", "canary"]
    req = rows[0]
    assert req["SrcIpAddr"] == "203.0.113.9" and req["Confidence"] == "confirmed"
    assert req["SignalIds"] == ["cmp.ticket_echo"] and req["Sensor"] == "hp1"
    assert req["TimeGenerated"].endswith("Z")
    assert rows[1]["Confidence"] == "confirmed" and rows[1]["CanaryKind"] == "dotenv"
    h = fake_azure.headers[0]
    assert h["Authorization"] == "Bearer tok1" and h["Content-Encoding"] == "gzip"
    assert s.sent == 2 and s.dropped == 0


def test_sentinel_rows_only_use_declared_columns():
    declared = {name for name, _ in azure.COLUMNS}
    for event in (_event(), dict(CANARY)):
        assert set(azure.to_row(event, "s")) <= declared


def test_sentinel_sink_refreshes_its_token_on_401():
    f = FakeAzure(fail_first_with=401)
    try:
        s = _azure_sink(f.url)
        s.emit(_event())
        s.close()
        assert len(f.rows) == 1 and f.tokens_issued == 2
    finally:
        f.close()


def test_sentinel_sink_drops_rather_than_blocks_when_azure_is_down():
    s = _azure_sink("http://127.0.0.1:9")  # nothing listens on the discard port
    s.emit(_event())
    s.close()
    assert s.sent == 0 and s.dropped == 1


def test_sentinel_sink_misconfiguration_fails_at_startup():
    with pytest.raises(ValueError, match="endpoint"):
        azure.make_sink({"tenant_id": "t", "client_id": "c", "client_secret": "s"}, Config())
    with pytest.raises(ValueError, match="auth must be"):
        azure.make_sink({"auth": "password", "endpoint": "x", "rule_id": "y"}, Config())


def test_oversized_batches_are_split_under_the_api_limit():
    row = {"x": "a" * 200_000}
    chunks = list(azure._chunks([row] * 10))
    assert len(chunks) > 1
    assert all(len(json.dumps(c)) < azure.MAX_BATCH_BYTES for c in chunks)


# -- Defender export ------------------------------------------------------------------------


def test_mde_csv_emits_only_public_confirmed_addresses():
    rows = export.SessionRollup()
    rows.add(_event(sid="a", addr="203.0.113.9"))            # TEST-NET: not global
    rows.add(_event(sid="b", addr="8.8.8.8"))                 # public, confirmed
    rows.add(_event(sid="c", addr="10.0.0.5"))                # private
    rows.add(_event(sid="d", addr="sha256:abcd"))             # redacted
    rows.add(_event(sid="e", addr="1.1.1.1", verdict="automation", signals=("beh.no_beacon",)))
    out = export.render(rows.finish(), "mde")
    parsed = list(csv.DictReader(io.StringIO(out)))
    assert list(parsed[0]) == export.MDE_FIELDS
    assert [r["IndicatorValue"] for r in parsed] == ["8.8.8.8"]
    assert parsed[0]["Action"] == "Audit" and parsed[0]["IndicatorType"] == "IpAddress"


def test_mde_rejects_an_unknown_action():
    with pytest.raises(ValueError):
        export.to_mde([], action="Nuke")


# -- HTML report and dashboard ------------------------------------------------------------------


def test_html_report_escapes_attacker_controlled_fields():
    agg = export.SessionRollup()
    agg.add(_event(ua='<script>alert(1)</script>', path='/"><img src=x onerror=alert(2)>'))
    page = html.render_html(agg.finish(), [dict(CANARY, path="<b>x</b>")])
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    assert "<b>x</b>" not in page
    assert page.count("<script>") == 1  # ours, and only ours


def test_html_csp_pins_the_inline_script_by_hash():
    import base64
    import hashlib

    page = html.render_html([], [])
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in page
    assert "No non-human sessions" in page


def test_report_cli_writes_html(tmp_path):
    events = tmp_path / "e.jsonl"
    s = sink.JsonlSink(events)
    s.emit(_event())
    out = tmp_path / "r.html"
    assert cli.main(["report", str(events), "-f", "html", "-o", str(out)]) == 0
    assert "LLM agent sessions" in out.read_text(encoding="utf-8")


def test_dashboard_serves_read_only(tmp_path):
    from drosera.server.dashboard import make_server

    events = tmp_path / "e.jsonl"
    sink.JsonlSink(events).emit(_event())
    server = make_server(str(events), port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/") as r:
            assert "Content-Security-Policy" in r.headers and r.headers["X-Content-Type-Options"] == "nosniff"
            assert b"Drosera dashboard" in r.read()
        with urllib.request.urlopen(base + "/api/sessions.json") as r:
            assert json.loads(r.read())[0]["session_id"] == "s1"
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(urllib.request.Request(base + "/", data=b"x", method="POST"))
        assert exc.value.code == 405
    finally:
        server.shutdown()
        server.server_close()


# -- CLI: ship and canary --emit ------------------------------------------------------------------


def test_ship_backfills_an_events_file_to_sentinel(tmp_path, fake_azure):
    events = tmp_path / "e.jsonl"
    s = sink.JsonlSink(events)
    for i in range(3):
        s.emit(_event(sid=f"s{i}"))
    s.emit(dict(CANARY))
    toml = tmp_path / "drosera.toml"
    toml.write_text(
        "[sinks.azure_monitor]\n"
        f'endpoint = "{fake_azure.url}"\nrule_id = "dcr-x"\nauthority = "{fake_azure.url}"\n'
        'tenant_id = "t"\nclient_id = "c"\nclient_secret = "s"\nflush_interval = 0.1\n',
        encoding="utf-8",
    )
    assert cli.main(["-c", str(toml), "ship", str(events)]) == 0
    assert len(fake_azure.rows) == 4
    assert events.read_text(encoding="utf-8").count("\n") == 4  # the source was not appended to


def test_canary_scan_emit_reaches_the_events_file(tmp_path, monkeypatch):
    from drosera.canary import mint

    monkeypatch.setenv("DROSERA_SECRET", "s3cret")
    reg = tmp_path / "reg.json"
    mint.plant(tmp_path / "bait", ["dotenv"], "s3cret", "example.net", registry=reg)
    leaked = tmp_path / "leak.txt"
    leaked.write_text((tmp_path / "bait" / ".env").read_text(encoding="utf-8"), encoding="utf-8")
    events = tmp_path / "e.jsonl"
    toml = tmp_path / "drosera.toml"
    toml.write_text(f'[telemetry]\njsonl = "{events.as_posix()}"\n', encoding="utf-8")
    assert cli.main(["-c", str(toml), "canary", "scan", str(leaked), "--registry", str(reg), "--emit"]) == 2
    _, canaries = export.collect(str(events))
    assert canaries and canaries[0]["channel"] == "value_seen"


# -- Sentinel content pack --------------------------------------------------------------------------


def test_sentinel_templates_are_in_sync_with_the_code():
    result = subprocess.run(
        [sys.executable, str(ROOT / "integrations" / "sentinel" / "_build.py"), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_dcr_stream_and_table_match_the_sink_columns():
    t = json.loads((ROOT / "integrations/sentinel/deploy/ingestion.json").read_text(encoding="utf-8"))
    by_type = {r["type"]: r for r in t["resources"]}
    table = by_type["Microsoft.OperationalInsights/workspaces/tables"]["properties"]["schema"]["columns"]
    dcr = by_type["Microsoft.Insights/dataCollectionRules"]["properties"]
    stream = dcr["streamDeclarations"][azure.DEFAULT_STREAM]["columns"]
    assert [c["name"] for c in table] == [c["name"] for c in stream] == [n for n, _ in azure.COLUMNS]
    assert dcr["dataFlows"][0]["outputStream"] == "Custom-DroseraEvents_CL"


def test_rule_queries_only_reference_known_drosera_columns():
    declared = {n for n, _ in azure.COLUMNS}
    # Columns of DroseraEvents_CL are PascalCase words that appear right after a pipe
    # operator keyword and are compared or projected; checking every capitalised token
    # that *looks* like one of ours catches renames on either side.
    lookalikes = re.compile(r"\b(Http[A-Z]\w+|Canary[A-Z]\w+|Src\w+|Signal\w*|Session\w*|Url\w+)\b")
    derived = {"Signal", "Signals", "SignalList", "Sessions", "SessionId1", "SrcIpAddr"}
    for path in (ROOT / "integrations/sentinel/kql").rglob("*.kql"):
        for name in lookalikes.findall(path.read_text(encoding="utf-8")):
            assert name in declared or name in derived, f"{path.name}: unknown column {name}"
