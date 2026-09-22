# Reporting

Three ways to look at what Drosera caught, from quickest to most shared.

## Terminal and files

```bash
drosera report events.jsonl                           # summary
drosera report events.jsonl -f csv  -o sessions.csv   # one row per session
drosera report events.jsonl -f json                   # the same, as JSON
drosera report events.jsonl -f ioc  --min-confidence high
drosera report events.jsonl -f stix -o bundle.json
drosera report events.jsonl -f mde  -o indicators.csv # Defender for Endpoint import
```

Every format reads JSONL or SQLite, and every row carries a **confidence class**
based on the kind of evidence, not on the score. See
[architecture](architecture.md#telemetry--getting-it-out).

## HTML report

```bash
drosera report events.jsonl -f html -o report.html --title "Edge honeypot, week 38"
```

This is one self-contained file with no network requests. It can be mailed,
attached to an incident, archived beside the events it summarises, or opened on
an air-gapped analyst machine. It contains:

- headline counts: sessions, LLM-agent sessions, confirmed sessions, tokens
  burned, canary hits
- new non-human sessions over time, stacked by verdict
- sessions by verdict and by evidence confidence
- top signals and top user agents among non-human sessions
- canary hits, with proof (`value_seen`) kept visibly apart from hints
- a filterable session table, strongest evidence first

It follows your light or dark mode.

**Everything on the page came from the clients being reported on.** User agents
and paths are attacker-controlled, and a honeypot report is exactly where
someone would plant markup to see if it renders. Every value is HTML-escaped,
and a Content-Security-Policy allows only the page's own filter script, pinned
by hash. A test renders a `<script>` user agent to hold that line.

## Live dashboard

```bash
drosera dashboard events.jsonl
```

This serves the same page at `http://127.0.0.1:8765/` and refreshes it every 30
seconds (`--refresh 0` turns that off). It re-reads the events file only when the
file changes. It also serves `/api/sessions.json` and `/api/canaries.json` for
scripts.

The dashboard is an analyst tool, **not part of the honeypot**:

- It binds to localhost by default and warns if you bind it anywhere else. It
  has no authentication. To share it, put it behind an authenticating reverse
  proxy.
- Never run it on the honeypot's public interface. The honeypot invites hostile
  traffic; the dashboard shows how that traffic was scored.
- It is read-only: GET requests only, with read access to the events file.

To reach it on a remote honeypot, tunnel it rather than exposing it:

```bash
ssh -L 8765:127.0.0.1:8765 honeypot-host drosera dashboard /var/lib/drosera/events.jsonl
```

## Shared, long-retention reporting

For a team, use Sentinel. The [Sentinel pack](../integrations/sentinel/README.md)
ships a workbook with the same views, backed by months of retention, access
control, and incidents from the analytics rules.
