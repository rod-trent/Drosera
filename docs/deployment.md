# Deployment

Three ways to run Drosera, in increasing order of blast radius.

## 1. Replay first — no deployment at all

Before you serve anything, score the logs you already have:

```bash
drosera replay /var/log/nginx/access.log --quiet
```

This runs the detection engine offline. No traps, no bait, nothing served. It
tells you what is already crawling you and whether the traffic mix justifies
anything further. Combined and common log formats are supported, plus
`--format json` for one JSON object per line.

Note that a replay can never produce an `agent` verdict from access logs alone:
comprehension signals require bait that was never planted. What you get is the
`automation` and `hostility` picture, which is usually enough to decide.

## 2. Standalone honeypot

A separate host serving nothing but bait. This is the safest deployment: there
is no real application behind it, so there is nothing to get wrong.

```bash
export DROSERA_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
drosera init
drosera doctor
drosera serve --host 0.0.0.0 --port 8080
```

Put it on a hostname that looks ordinary and link it from nowhere. Anything that
arrives found it by scanning, by crawling, or by following bait.

**Isolate it.** It attracts hostile traffic on purpose. No shared credentials,
no shared network segment, no trust relationship with anything you care about.

### systemd

```ini
[Unit]
Description=Drosera honeypot
After=network.target

[Service]
Type=simple
User=drosera
WorkingDirectory=/var/lib/drosera
Environment=DROSERA_SECRET=<a stable random hex string>
ExecStart=/usr/local/bin/drosera serve --host 0.0.0.0 --port 8080
Restart=always
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/drosera

[Install]
WantedBy=multi-user.target
```

### Container

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir drosera
USER nobody
EXPOSE 8080
ENV DROSERA_JSONL=/data/events.jsonl
CMD ["drosera", "serve", "--host", "0.0.0.0", "--port", "8080"]
```

There are no runtime dependencies to install, so the image stays small and has
no supply chain of its own.

## 3. Middleware in front of a real app

The highest-value deployment and the one that needs care: bait is injected into
your real pages, and clients that bite get diverted into the maze instead of
your application.

```python
# ASGI -- FastAPI, Starlette, Litestar, Django ASGI, Quart
from drosera.middleware.asgi import DroseraMiddleware
app = DroseraMiddleware(app)

# WSGI -- Flask, Django, Pyramid, Bottle
from drosera.middleware.wsgi import DroseraMiddleware
app.wsgi_app = DroseraMiddleware(app.wsgi_app)
```

### Start in observe mode

Run for a week with traps off before you let it act on anything:

```toml
[trap]
enabled = false

[telemetry]
jsonl = "/var/log/drosera/events.jsonl"
```

Then review:

```bash
drosera report /var/log/drosera/events.jsonl
drosera report /var/log/drosera/events.jsonl -f csv -o sessions.csv
```

Look at every session that reached `agent`, and at anything with confidence
`confirmed`. If those all look like things you are happy to trap, turn traps on.

### What the middleware touches

- **HTML responses** get bait inserted before `</body>` and lose their
  `Content-Length` (recomputed after injection).
- **Everything else** streams through untouched — JSON APIs and downloads keep
  their streaming semantics.
- **Request bodies** are read up to `max_body` (64 KB default) and replayed to
  your app, so upstream handlers still see a complete request. Larger uploads
  skip inspection rather than being buffered.
- **These paths are claimed** by Drosera and will not reach your app:
  `/robots.txt`, `/llms.txt`, `/.well-known/agent-policy`,
  `/.well-known/agent-registration`, the per-session beacon and bait paths, the
  maze root (`trap.root`, default `/archive`), and the decoy secret files.

If you already serve your own `robots.txt`, set `lure.robots = false`. If any of
those paths collide with real routes, change `trap.root` or disable the relevant
lure.

### Exempt paths

Health checks must stay boring, fast, and unlogged:

```toml
exempt_paths = ["/healthz", "/readyz", "/metrics", "/_internal"]
```

Exempt requests skip assessment entirely.

## Tuning the response

```toml
[responses]
human         = "allow"
unknown       = "allow"
automation    = "observe"   # logged, never trapped -- see docs/ethics.md
agent         = "tarpit"
hostile_agent = "tarpit"
```

| Action | Effect |
| --- | --- |
| `allow` | pass through, nothing recorded beyond the event |
| `observe` | pass through, recorded |
| `tag` | pass through, session marked |
| `tarpit` | endless generated maze |
| `derail` | one clear terminal response that ends the task branch |
| `divert` | maze, entered at a per-session root |
| `block` | plain 403 |

Independently of this table, a session whose hostility crosses
`thresholds.hostile` is escalated out of `allow`/`observe` into the trap: a
scanner hunting for `.env` should not get a quiet 404 just because it never
proved it was an LLM.

### tarpit or derail?

`tarpit` costs you a socket for as long as the client keeps pulling, and buys
you evidence — depth reached, tokens burned, how long it persisted. `derail`
costs you one response and ends it.

Use `derail` when egress is expensive, when workers are scarce, or when you have
already collected what you need from a given client.

### Cost controls

```toml
[trap]
session_byte_budget = 5_000_000   # stop feeding after ~5 MB, then derail
words_per_page      = 420
links_per_page      = 6
max_depth           = 0           # 0 = unbounded
```

An unbounded maze with no budget means a determined crawler can make you serve
indefinitely. Set a budget if egress costs money.

Slow drip holds a connection open:

```toml
drip_bytes = 512
drip_delay = 0.4
```

WSGI has no way to express "send this slowly without holding a worker", so the
delay sleeps in the handler thread — one held thread per trapped client. On a
threaded server that is exactly the intended trade. On a single-worker server it
will stall the process; leave `drip_delay` at 0 there.

## Canary credentials

```bash
drosera canary plant /srv/app --kind dotenv --kind aws --label "prod web"
drosera canary list
drosera canary watch --interval 5
```

Plant them where an agent that has landed on a host would look. They are inert —
they authenticate nowhere — and `plant` refuses to overwrite an existing file
without `--force`, so it is safe to run against a live tree.

Detection has two channels of very different strength:

- **Use** is proof. `drosera canary scan <file>` searches any text for planted
  credentials, and the HTTP layer scans request bodies and `Authorization`
  headers automatically. A hit means the bait was read and the contents moved.
- **Read** (`canary watch --atime`) is a hint at best. Most Linux mounts use
  `relatime`, so atime advances once a day; `noatime` disables it; backups and
  file indexers touch files innocently. It is off by default for that reason.

## Getting data out

```bash
drosera report events.jsonl                              # terminal summary
drosera report events.jsonl -f csv -o sessions.csv
drosera report events.jsonl -f ioc --min-confidence high
drosera report events.jsonl -f stix -o bundle.json
```

Or stream live:

```toml
[telemetry]
webhook = "https://siem.internal.example/ingest"
sqlite  = "/var/lib/drosera/events.db"
```

The webhook sink is buffered and lossy on purpose: if the receiver is slow or
down, events are dropped rather than backing up into request handling.

## Operational checklist

- [ ] `DROSERA_SECRET` set to a stable random value (a per-process secret means
      tickets and canary tokens stop verifying across restarts)
- [ ] `drosera doctor` exits 0
- [ ] Telemetry sink configured and writable
- [ ] Retention period decided and enforced — Drosera does not expire data
- [ ] `telemetry.redact_ip` on unless you specifically need addresses
- [ ] Ran in observe mode long enough to review real traffic
- [ ] Honeypot host isolated from production credentials and networks
- [ ] Read [docs/ethics.md](ethics.md)
