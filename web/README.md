# The Drosera playground

A live demonstration of the detection engine, deployable to Vercel.

It runs the **real** `drosera` package server-side rather than reimplementing
scoring in JavaScript. A browser-side copy would drift from the library within a
release or two, and a demo that misreports the detection is worse than no demo.
`tests/test_playground.py` is the other half of that promise: if a weight ever
changes such that the crawler starts looking like an LLM, the build fails
instead of the website quietly misrepresenting the project.

## Run it locally

```bash
python web/dev.py          # http://127.0.0.1:3000
```

`dev.py` serves `index.html` and routes `/api/assess` through the same
`dispatch()` the serverless function uses, so local and deployed behaviour match.

## Deploy to Vercel

1. **New Project** → import `rod-trent/Drosera`.
2. Set **Root Directory** to `web`.
3. Framework preset: **Other**. No build command, no output directory —
   `index.html` is static and `api/assess.py` is picked up automatically.
4. Deploy.

`requirements.txt` currently installs the engine from the GitHub repo. Once
`drosera` is on PyPI, pin it instead so a deploy cannot drift with `main`:

```
drosera==0.1.0
```

## Why there is no tarpit here

The playground scores requests; it does not serve the maze.

The tarpit's premise is asymmetric cost — a held socket and a few kilobytes of
filler are nearly free for the defender and expensive in time and context for the
agent. Serverless inverts that exactly: every maze page an agent pulls is metered
compute *and* metered egress on the site owner's bill. An agent crawling ten
thousand pages would be running up your costs, not its own, and `drip_delay` —
deliberately holding a connection open — is the worst possible workload for
per-second billing.

The trap belongs on a cheap always-on box. See
[docs/deployment.md](../docs/deployment.md).

## What the endpoint does

`POST /api/assess`

| `mode` | Meaning |
| --- | --- |
| `scenario` | Replay a canned trace (`human`, `crawler`, `scanner`, `agent`). |
| `live` | Score the caller's own request headers. |
| `custom` | Score a supplied trace: `headers`, `requests[]`, `interval`. |

`GET /api/assess` returns the engine version and the available scenarios.

Input is untrusted and capped: 64 KB body, 40 requests, 40 headers, 2 KB per
value. A fresh `Engine` is built per request, so no visitor can observe another's
state and nothing accumulates between invocations.

Nothing is logged, stored or forwarded. All telemetry sinks are explicitly
disabled in `_config()`.
