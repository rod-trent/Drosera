# Security policy

## Reporting a vulnerability

Please report privately via [GitHub Security
Advisories](https://github.com/rod-trent/Drosera/security/advisories/new) rather
than a public issue.

Include what you did, what happened, and what you expected. A proof of concept
helps. You will get an acknowledgement within a few days.

## In scope

Drosera is deliberately exposed to hostile traffic, so its own failure modes
matter more than usual:

- **Anything that makes Drosera harm an agent's operator.** A lure that slips
  past `assert_inert`, or any path by which Drosera influences an agent's
  behaviour beyond our own server, is a vulnerability. This is the primary
  concern.
- **Escape from the honeypot** — a request that reaches the host, executes code,
  reads files outside the served tree, or leaks the signing secret.
- **Bypassing the middleware** — a request shape that reaches a wrapped app when
  it should have been trapped, or that corrupts a response passing through.
- **Denial of service against the deployment** — unbounded memory growth,
  session-table exhaustion, or a request that makes a worker spin.
- **Telemetry injection** — crafted input that forges or corrupts events, breaks
  a downstream parser, or writes outside the sink.
- **Canary token forgery** — producing a token that verifies under a secret you
  do not have, or a planted credential that authenticates anywhere.
- **Ticket forgery** — producing a valid registration ticket without having read
  bait we served.

## Out of scope

- **An agent avoiding detection by ignoring the bait.** Comprehension signals
  require engagement; a client that touches nothing is undetectable by design,
  and this is documented.
- **Bait being discoverable.** Once deployed, `/llms.txt` and the notice are
  public. The per-deployment HMAC prevents forgery, not reconnaissance.
- **The tarpit consuming your own bandwidth.** That is the mechanism. Use
  `trap.session_byte_budget`.
- **Findings against a deployment you do not operate.** Please do not test other
  people's honeypots.

## Operational notes

- `DROSERA_SECRET` is the root of ticket and canary integrity. Treat it as a
  secret; rotating it invalidates outstanding tickets and canary tokens.
- Without it set, Drosera generates a per-process secret and `drosera doctor`
  reports a problem. Correlation will not survive a restart.
- Captured events contain personal data. See the privacy section of
  [docs/ethics.md](docs/ethics.md).

## Supported versions

Pre-1.0: fixes land on `main` and in the next release. Please report against a
recent `main`.
