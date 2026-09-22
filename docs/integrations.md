# Integrations

Drosera's job ends at evidence: a verdict, the signals behind it, and a
confidence class that says what *kind* of evidence it is. Integrations move that
evidence to where people already work. None of them change what the honeypot
does, and none of them add a runtime dependency.

| Route | Use it for | How |
| --- | --- | --- |
| **Microsoft Sentinel** | SOC alerting, incidents, workbook, playbooks | `[sinks.azure_monitor]` plus [`integrations/sentinel`](../integrations/sentinel/README.md) |
| **Microsoft Defender XDR** | Correlating honeypot addresses with device, identity and web telemetry | Sentinel data in advanced hunting; [hunting queries](../integrations/sentinel/kql/hunting/) |
| **Defender for Endpoint indicators** | Alerting when any managed device contacts the same infrastructure | `drosera report -f mde`, or the `Drosera-MDE-Indicator` playbook |
| **Sentinel threat intelligence** | Sharing high-confidence indicators as STIX | `drosera report -f stix` plus the TI upload API |
| **Anything with an HTTP endpoint** | Logic Apps, Power Automate, Functions, SOAR | `[telemetry] webhook = "..."` |
| **Your own sink** | Splunk, Elastic, Kafka, a database | A plug-in (below) |

## Microsoft Sentinel

The built-in `azure_monitor` sink posts events to the Azure Monitor **Logs
Ingestion API**, which is the supported route for custom data into Sentinel. It
uses the standard library only: one OAuth token request and a gzipped HTTPS
POST per batch.

```toml
[sinks.azure_monitor]
endpoint = "https://drosera-dce-xxxx.eastus-1.ingest.monitor.azure.com"
rule_id  = "dcr-0123456789abcdef0123456789abcdef"
stream   = "Custom-DroseraEvents"
```

One ARM deployment creates everything on the Azure side. The
[Sentinel guide](../integrations/sentinel/README.md) covers it end to end,
including the identity, the analytics rules, the workbook and the playbooks.

## Microsoft Defender

Two different things are called "Defender integration". It helps to keep them apart.

**Correlation (usually what you want).** A honeypot address is interesting
mainly for what *else* it touched. Once Drosera's events are in the Sentinel
workspace, the [hunting queries](../integrations/sentinel/kql/hunting/) join
them against `DeviceNetworkEvents`, `SigninLogs` and web gateway logs. With
the workspace onboarded to the unified Defender portal, those same queries run
in Defender XDR advanced hunting and can be saved as custom detection rules.

**Indicators (use deliberately).** Defender for Endpoint custom IP indicators
act on connections *from your managed devices*:

```bash
drosera report events.jsonl -f mde -o indicators.csv
```

The CSV matches Defender's indicator import template (*Settings → Endpoints →
Indicators → Import*). Defaults are conservative: only `confirmed` sessions, only
publicly routable addresses, action `Audit`, and a 30-day expiry. `Audit` raises
a Defender alert if any device contacts the address. `Block` would stop your
devices reaching it. Neither stops the agent reaching *you*; that belongs on a
WAF or firewall. See `--mde-action`, `--expire-days` and `--min-confidence`.

## STIX and Sentinel threat intelligence

```bash
drosera report events.jsonl -f stix --min-confidence confirmed -o bundle.json
```

The bundle's `indicator` objects can be sent to Sentinel's threat-intelligence
upload API. There they become TI indicators that the built-in *TI map* analytics
rules match against all your other tables. Check Microsoft's documentation for
the current API version and the permissions it needs. Each indicator carries a
STIX `confidence` derived from the evidence class, so downstream consumers can
tell "returned our ticket" (95) from "looked automated" (15).

## Webhook

`[telemetry] webhook = "https://..."` POSTs each event as JSON from a background
thread. A Logic App or Power Automate HTTP trigger can take it from there. The
sink is lossy by design and sends one request per event, so prefer
`azure_monitor` for volume.

## Writing a plug-in sink

A plug-in is a factory that takes its `[sinks.<name>]` table and the whole
`Config`, and returns anything with `emit(event: dict)` and `close()`:

```python
# drosera_splunk/__init__.py
def make_sink(options, config):
    return SplunkHecSink(url=options["url"], token=os.environ["SPLUNK_HEC_TOKEN"])
```

```toml
# the plug-in's pyproject.toml
[project.entry-points."drosera.sinks"]
splunk = "drosera_splunk:make_sink"
```

```toml
# the operator's drosera.toml
[sinks.splunk]
url = "https://splunk.example.com:8088"
```

The rules the built-in sinks follow apply to plug-ins too:

- **Fail at construction, never at emit.** Raise from the factory for bad
  config, so `drosera serve` and `drosera doctor` report it at startup. Once
  running, `emit` must never raise or block the request path. Queue the event
  and ship it from a thread.
- **Prefer dropping to backing up.** When the destination is down, drop and
  warn. The JSONL sink is the durable record, and `drosera ship` backfills from
  it through every configured plug-in.
- **Expect two event shapes.** Request assessments have no `event` field.
  Canary hits have `"event": "canary"`.
- **Keep secrets out of the table.** Read them from the environment. Keys
  containing `secret`, `password`, `token` or `key` are masked when the config
  is printed, but they are still in the file.

`src/drosera/telemetry/azure.py` is the reference implementation.
