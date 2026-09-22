# Changelog

All notable changes to Drosera are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-22

Evidence goes where the SOC works: Microsoft Sentinel, Defender correlation,
and reporting. Nothing in the detection engine, lures or traps changed.

### Added

- **Microsoft Sentinel sink** (`[sinks.azure_monitor]`): ships events to a
  custom table through the Azure Monitor Logs Ingestion API. Standard library
  only, with client-secret or managed-identity auth. It is batched, gzipped,
  lossy under pressure rather than blocking, and filtered by `min_verdict` so
  human traffic never leaves the host.
- **Sentinel content pack** under `integrations/sentinel`: an ARM deployment for
  the table, data collection endpoint and rule, and parser functions; five
  analytics rules; a workbook; hunting queries that join Drosera with Defender
  XDR, Entra ID sign-ins and web gateway logs; and two playbooks (incident
  enrichment, and Defender for Endpoint indicator submission). The templates
  are generated from the sink's column list and CI fails if they drift.
- **Plug-in sinks**: any `[sinks.<name>]` table resolves to a factory
  registered under the `drosera.sinks` entry-point group. The Sentinel sink is
  the reference implementation.
- **HTML report** (`drosera report -f html`): one self-contained page with
  headline counts, a verdict timeline, signal and user-agent breakdowns, canary
  hits and a filterable session table. Everything is escaped, and a
  hash-pinned CSP allows no script but the page's own.
- **`drosera dashboard`**: the same page served live on localhost, re-rendered
  when the events file changes, with JSON endpoints for scripts.
- **Defender for Endpoint export** (`drosera report -f mde`): an indicator
  import CSV covering public addresses only, `confirmed` evidence only, `Audit`
  and a 30-day expiry by default.
- **`drosera ship`**: backfill an events file through the configured plug-in
  sinks.
- `drosera canary watch --emit` and `canary scan --emit` send hits through the
  configured sinks as `"event": "canary"` records. Reports show them in their
  own section and keep them out of session rollups.
- `drosera doctor` checks plug-in sinks, and warns about secrets in the config
  file and about `redact_ip` combined with Sentinel.

### Fixed

- The SQLite sink never stored the `automation` score, so every report read
  from a `.db` file showed `automation` as 0. The column is added, and databases
  written by 0.1.0 are migrated in place when opened.
- `drosera canary watch` printed hits to stdout only; they could not reach any
  sink. See `--emit` below.

## [0.1.0] - 2026-09-05

First release.

### Added

- **Detection engine** with 30 signals across five categories, scored on three
  independent axes (`automation`, `agency`, `hostility`). An `agent` verdict
  requires comprehension evidence or explicit self-identification; traffic shape
  alone can never produce one.
- **Lure layer** with three bait channels: raw-markup (HTML comment plus hidden
  block), rendered (visible `/llms.txt` pointer), and convention (`robots.txt`,
  `llms.txt`, both served per-session with an HMAC-signed ticket).
- **`assert_inert` guardrail**, enforced on every piece of bait including
  operator-supplied templates, rejecting text that coerces an agent rather than
  inviting it.
- **Tarpit**: an endless, deterministic maze seeded from each page's own URL,
  marked `noindex, nofollow, noarchive`, with optional slow-drip delivery and a
  per-session byte budget.
- **Derail**: terminal responses that close an agent's task branch cleanly.
- **Canary credentials** for eight file kinds, inert and HMAC self-verifying,
  with use-detection (hard evidence) and access-time watching (soft hint) kept
  visibly separate.
- **ASGI and WSGI middleware**, plus a zero-dependency standalone honeypot
  server built on `http.server`.
- **Telemetry sinks**: JSONL, SQLite, webhook, stderr, with optional IP
  redaction. Sinks never raise into the request path.
- **Export formats**: terminal summary, CSV, JSON, IOC, and STIX 2.1 — each row
  carrying a confidence class derived from evidence type rather than score.
- **CLI**: `serve`, `demo`, `replay`, `report`, `signals`, `canary`, `init`,
  `doctor`.
- Zero runtime dependencies, enforced in CI.
- A public playground under `web/`: a Vercel-deployable page that scores four
  request traces with the real engine, and can score the visitor's own browser.
  Guarded by `tests/test_playground.py` so the demo cannot drift from the
  library it is demonstrating.

### Changed

- Packaging modernised for PyPI: PEP 639 SPDX licence expression with explicit
  licence files, a `MANIFEST.in` so the sdist carries tests and docs, and
  absolute documentation links in the README (relative ones 404 on PyPI).
- Release is automated via PyPI Trusted Publishing on a `v*` tag. No API token
  exists in the repository or its secrets.
- `Verdict`, `Category` and `Action` now subclass `enum.StrEnum` instead of
  `(str, Enum)`. Behaviour is unchanged for `.value`, comparison and JSON
  serialisation.
- Pinned `ruff>=0.16,<0.17` for development. An open-ended range meant a new
  linter release could fail CI on an unrelated commit.

### Fixed

- `FileWatcher` missed a canary modification that happened less than a
  millisecond after the previous poll. It compared float-seconds timestamps
  with a 0.001 tolerance, and on a fast filesystem the real gap is smaller than
  that. Comparisons now use integer nanosecond timestamps, which need no
  tolerance at all. It also compares file size, because Windows timestamps
  advance only on the ~15.6ms system clock tick and two writes inside one tick
  share an mtime. The watcher now baselines from a live stat when watching
  starts, and reports separately when a file was already modified before then.

[Unreleased]: https://github.com/rod-trent/Drosera/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rod-trent/Drosera/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rod-trent/Drosera/releases/tag/v0.1.0
