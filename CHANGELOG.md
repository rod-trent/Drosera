# Changelog

All notable changes to Drosera are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/rod-trent/Drosera/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rod-trent/Drosera/releases/tag/v0.1.0
