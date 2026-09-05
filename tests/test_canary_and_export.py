"""Canary credentials, telemetry sinks and export formats."""

from __future__ import annotations

import json

import pytest

from drosera.canary import mint, watch
from drosera.config import Config
from drosera.telemetry import export, sink

SECRET = "test-secret"


# -- canaries --------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(mint.TEMPLATES))
def test_every_kind_renders_and_round_trips(kind):
    canary, content = mint.render(kind, SECRET, "example.net")
    assert content.strip()
    assert "{" not in content or kind in ("credentials_json", "appsettings")
    hits = list(watch.scan_for_canaries(content, SECRET, {canary.id: canary}))
    assert hits, f"{kind} content does not contain a detectable token"
    assert hits[0].canary_id == canary.id


def test_tokens_do_not_verify_under_another_secret():
    _, content = mint.render("dotenv", SECRET, "example.net")
    assert not list(watch.scan_for_canaries(content, "a-different-secret"))


def test_unrelated_text_is_not_flagged():
    text = "drs0123456789abcdef0123 is not a real token, nor is AKIAAAAAAAAAAAAAAAAA"
    assert not list(watch.scan_for_canaries(text, SECRET))


def test_fake_private_key_is_not_a_usable_key():
    """Planting a decoy must never plant a working credential."""
    _, content = mint.render("ssh_key", SECRET, "example.net")
    assert "BEGIN OPENSSH PRIVATE KEY" in content
    # A real OpenSSH key body starts with the "openssh-key-v1" magic, base64
    # encoded as b3BlbnNzaC1rZXktdjEA. Ours must not.
    assert "b3BlbnNzaC1rZXktdjEA" not in content


def test_plant_refuses_to_clobber_an_existing_file(tmp_path):
    (tmp_path / ".env").write_text("REAL_SECRET=do-not-lose-me\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        mint.plant(tmp_path, ["dotenv"], SECRET, "example.net", registry=tmp_path / "reg.json")
    assert "do-not-lose-me" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_plant_and_registry_round_trip(tmp_path):
    reg = tmp_path / "reg.json"
    planted = mint.plant(tmp_path, ["dotenv", "npmrc"], SECRET, "example.net", label="repo", registry=reg)
    assert len(planted) == 2
    loaded = mint.load_registry(reg)
    assert {c.kind for c in loaded} == {"dotenv", "npmrc"}
    assert all(c.label == "repo" for c in loaded)
    assert (tmp_path / ".env").is_file()


def test_file_watcher_notices_modification(tmp_path):
    reg = tmp_path / "reg.json"
    mint.plant(tmp_path, ["dotenv"], SECRET, "example.net", registry=reg)
    watcher = watch.FileWatcher(reg)
    assert watcher.poll() == []
    target = tmp_path / ".env"
    target.write_text(target.read_text(encoding="utf-8") + "\n# touched\n", encoding="utf-8")
    hits = watcher.poll()
    assert len(hits) == 1 and hits[0].channel == "file_modified"
    assert watcher.poll() == [], "a hit should not repeat on the next poll"


# -- sinks -----------------------------------------------------------------


def test_jsonl_sink_appends(tmp_path):
    path = tmp_path / "events.jsonl"
    s = sink.JsonlSink(path)
    s.emit({"verdict": "agent", "ts": 1.0})
    s.emit({"verdict": "human", "ts": 2.0})
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(x)["verdict"] for x in lines] == ["agent", "human"]


def test_sqlite_sink_is_queryable(tmp_path):
    path = tmp_path / "events.db"
    s = sink.SqliteSink(path)
    s.emit({"ts": 1.0, "session_id": "a", "verdict": "agent", "signals": [{"id": "cmp.ticket_echo"}]})
    s.close()
    rows = list(export.read_sqlite(str(path)))
    assert rows[0]["verdict"] == "agent"
    assert rows[0]["signals"][0]["id"] == "cmp.ticket_echo"


def test_a_failing_sink_does_not_stop_the_others(tmp_path):
    class Exploding:
        def emit(self, event):
            raise RuntimeError("disk on fire")

        def close(self):
            pass

    path = tmp_path / "events.jsonl"
    multi = sink.MultiSink([Exploding(), sink.JsonlSink(path)])
    multi.emit({"verdict": "agent"})
    assert path.read_text(encoding="utf-8").strip()


def test_ip_redaction(tmp_path):
    path = tmp_path / "events.jsonl"
    multi = sink.MultiSink([sink.JsonlSink(path)], redact_ip=True, salt="pepper")
    multi.emit({"remote_addr": "198.51.100.4", "verdict": "agent"})
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["remote_addr"].startswith("sha256:")
    assert "198.51.100.4" not in path.read_text(encoding="utf-8")


# -- export ----------------------------------------------------------------


EVENTS = [
    {"ts": 1.0, "session_id": "s1", "remote_addr": "198.51.100.1", "verdict": "agent",
     "agency": 96.0, "automation": 99.0, "hostility": 5.0, "tokens_burned": 1000,
     "user_agent": "agent/1", "fingerprint": "fp1", "path": "/",
     "signals": [{"id": "cmp.ticket_echo"}]},
    {"ts": 2.0, "session_id": "s1", "remote_addr": "198.51.100.1", "verdict": "agent",
     "agency": 96.0, "automation": 99.0, "hostility": 5.0, "tokens_burned": 9000,
     "user_agent": "agent/1", "fingerprint": "fp1", "path": "/archive/x",
     "signals": [{"id": "beh.deep_maze"}]},
    {"ts": 3.0, "session_id": "s2", "remote_addr": "198.51.100.2", "verdict": "automation",
     "agency": 0.0, "automation": 80.0, "hostility": 70.0, "tokens_burned": 0,
     "user_agent": "curl/8", "fingerprint": "fp2", "path": "/.env",
     "signals": [{"id": "int.secret_hunting"}]},
]


def rows():
    agg = export.SessionRollup()
    for e in EVENTS:
        agg.add(e)
    return agg.finish()


def test_rollup_collapses_sessions_and_keeps_peaks():
    out = rows()
    assert len(out) == 2
    s1 = next(r for r in out if r["session_id"] == "s1")
    assert s1["requests"] == 2
    assert s1["tokens_burned"] == 9000
    assert s1["distinct_paths"] == 2
    assert s1["signals"] == ["beh.deep_maze", "cmp.ticket_echo"]


def test_confidence_reflects_evidence_class():
    assert export.confidence_of(["cmp.ticket_echo"]) == "confirmed"
    assert export.confidence_of(["int.canary_used"]) == "confirmed"
    assert export.confidence_of(["cmp.llms_directive"]) == "high"
    assert export.confidence_of(["bait.hidden_link"]) == "medium"
    assert export.confidence_of(["beh.no_assets", "id.http_library"]) == "low"


def test_ioc_export_filters_by_confidence():
    low = json.loads(export.to_ioc(rows(), "low"))
    confirmed = json.loads(export.to_ioc(rows(), "confirmed"))
    assert len(low["ip_addresses"]) == 2
    assert len(confirmed["ip_addresses"]) == 1
    assert confirmed["ip_addresses"][0]["value"] == "198.51.100.1"


def test_stix_bundle_is_well_formed():
    bundle = json.loads(export.to_stix(rows(), "high"))
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators and all("pattern" in i for i in indicators)
    assert indicators[0]["confidence"] == 95


def test_csv_has_a_header_and_a_row_per_session():
    text = export.to_csv(rows())
    lines = text.strip().splitlines()
    assert lines[0].startswith("session_id,")
    assert len(lines) == 3


def test_summary_mentions_burned_tokens():
    assert "tokens burned" in export.to_summary(rows()).lower()


def test_summary_handles_no_events():
    assert export.to_summary([]) == "No events.\n"


def test_config_round_trips_through_toml(tmp_path):
    path = tmp_path / "drosera.toml"
    path.write_text(Config().to_dict() and __import__("drosera.config", fromlist=["x"]).SAMPLE_TOML,
                    encoding="utf-8")
    cfg = Config.load(path)
    assert cfg.port == 8080
    assert cfg.thresholds.agent == 70.0
    assert cfg.trap.mode == "tarpit"
    assert cfg.responses["agent"] == "tarpit"
