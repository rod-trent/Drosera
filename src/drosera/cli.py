"""``drosera`` command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .config import SAMPLE_TOML, Config
from .models import Observation
from .util import lower_headers, split_target


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except (FileNotFoundError, FileExistsError, KeyError, ValueError) as exc:
        print(f"drosera: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="drosera",
        description="A carnivorous honeypot for autonomous AI agents.",
        epilog="Docs: https://github.com/rod-trent/Drosera",
    )
    p.add_argument("--version", action="version", version=f"drosera {__version__}")
    p.add_argument("-c", "--config", metavar="FILE", help="path to drosera.toml")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("serve", help="run the standalone honeypot site")
    s.add_argument("--host", help="bind address (default 127.0.0.1)")
    s.add_argument("--port", type=int, help="bind port (default 8080)")
    s.add_argument("--mode", choices=["tarpit", "derail", "divert", "observe"], help="trap mode")
    s.add_argument("--verbose", "-v", action="store_true", help="log every verdict to stderr")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("init", help="write a commented drosera.toml")
    s.add_argument("path", nargs="?", default="drosera.toml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("signals", help="list the signal catalogue and weights")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_signals)

    s = sub.add_parser("report", help="summarize captured events")
    s.add_argument("events", nargs="?", help="events file (.jsonl or .db)")
    s.add_argument(
        "-f", "--format", default="summary", choices=["summary", "csv", "json", "ioc", "stix"]
    )
    s.add_argument(
        "--min-confidence", default="medium", choices=["low", "medium", "high", "confirmed"]
    )
    s.add_argument("-o", "--out", help="write to a file instead of stdout")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("replay", help="score a request log without serving anything")
    s.add_argument("logfile", help="combined/common access log, or '-' for stdin")
    s.add_argument("--format", default="combined", choices=["combined", "common", "json"])
    s.add_argument("--quiet", action="store_true", help="only print non-human verdicts")
    s.set_defaults(func=cmd_replay)

    s = sub.add_parser("demo", help="run synthetic clients through the engine and show verdicts")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("doctor", help="check the deployment for common mistakes")
    s.set_defaults(func=cmd_doctor)

    c = sub.add_parser("canary", help="mint, plant and watch canary credentials")
    csub = c.add_subparsers(dest="canary_command")

    s = csub.add_parser("plant", help="write canary files into a directory")
    s.add_argument("dest", help="directory to plant into")
    s.add_argument("-k", "--kind", action="append", help="canary kind (repeatable); default: all")
    s.add_argument("--listener", default="", help="hostname the fake credentials point at")
    s.add_argument("--label", default="", help="free-text label recorded in the registry")
    s.add_argument("--registry", default=".drosera/canaries.json")
    s.add_argument("--force", action="store_true", help="overwrite existing files")
    s.set_defaults(func=cmd_canary_plant)

    s = csub.add_parser("list", help="show planted canaries")
    s.add_argument("--registry", default=".drosera/canaries.json")
    s.set_defaults(func=cmd_canary_list)

    s = csub.add_parser("watch", help="poll planted canaries for access")
    s.add_argument("--registry", default=".drosera/canaries.json")
    s.add_argument("--interval", type=float, default=5.0)
    s.add_argument("--atime", action="store_true", help="also report access-time changes (noisy)")
    s.set_defaults(func=cmd_canary_watch)

    s = csub.add_parser("scan", help="search a file or stdin for planted credentials")
    s.add_argument("target", help="file to scan, or '-' for stdin")
    s.add_argument("--registry", default=".drosera/canaries.json")
    s.set_defaults(func=cmd_canary_scan)

    s = csub.add_parser("kinds", help="list available canary kinds")
    s.set_defaults(func=cmd_canary_kinds)

    return p


def _config(args: argparse.Namespace) -> Config:
    return Config.load(getattr(args, "config", None))


# -- commands ------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    from .server.app import run

    config = _config(args)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.mode:
        config.trap.mode = args.mode
        if args.mode == "observe":
            config.trap.enabled = False
    if args.verbose:
        config.telemetry.stderr = True
    _warn_ephemeral_secret(config)
    run(config)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"drosera: {path} exists (use --force to overwrite)", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SAMPLE_TOML, encoding="utf-8", newline="\n")
    print(f"drosera: wrote {path}")
    print("drosera: set DROSERA_SECRET to a stable random value before deploying")
    return 0


def cmd_signals(args: argparse.Namespace) -> int:
    from .detect.rules import catalogue

    defs = catalogue()
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "id": d.id,
                        "category": d.category.value,
                        "agency": d.agency,
                        "hostility": d.hostility,
                        "description": d.description,
                    }
                    for d in defs
                ],
                indent=2,
            )
        )
        return 0
    current = ""
    for d in defs:
        if d.category.value != current:
            current = d.category.value
            print(f"\n{current.upper()}")
        print(f"  {d.id:<30} agency={d.agency:<5} hostility={d.hostility:<5}")
        print(f"      {d.description}")
    print()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .telemetry.export import render, rollup

    config = _config(args)
    path = args.events or config.telemetry.sqlite or config.telemetry.jsonl
    if not path or not Path(path).exists():
        print(f"drosera: no events file at {path!r}", file=sys.stderr)
        return 1
    rows = rollup(path)
    out = render(rows, args.format, args.min_confidence)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8", newline="\n")
        print(f"drosera: wrote {len(rows)} sessions to {args.out}")
    else:
        sys.stdout.write(out)
    return 0


LOG_RE = None


def cmd_replay(args: argparse.Namespace) -> int:
    """Score an existing access log. No server, no traps -- detection only.

    Useful for answering "has this already been happening?" against logs you
    already have, before deploying anything.
    """
    import re

    from .detect.engine import Engine

    global LOG_RE
    if LOG_RE is None:
        LOG_RE = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)[^"]*"'
            r' (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
        )

    config = _config(args)
    engine = Engine(config)
    stream = (
        sys.stdin
        if args.logfile == "-"
        else open(args.logfile, encoding="utf-8", errors="replace")  # noqa: SIM115 - closed in finally
    )
    counts: dict[str, int] = {}
    try:
        for line in stream:
            obs = _parse_log_line(line, args.format, LOG_RE)
            if obs is None:
                continue
            assessment = engine.observe(obs)
            counts[assessment.verdict.value] = counts.get(assessment.verdict.value, 0) + 1
            if args.quiet and assessment.verdict.value in ("human", "unknown"):
                continue
            print(assessment.summary())
    finally:
        if stream is not sys.stdin:
            stream.close()
    print("\n--- totals ---", file=sys.stderr)
    for verdict, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"{verdict:<14} {count:>8}", file=sys.stderr)
    return 0


def _parse_log_line(line: str, fmt: str, log_re) -> Observation | None:
    line = line.strip()
    if not line:
        return None
    if fmt == "json":
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return None
        headers, order = lower_headers(list(row.get("headers", {}).items()))
        path, query = split_target(row.get("path") or row.get("target") or "/")
        return Observation(
            session_id="",
            remote_addr=row.get("remote_addr", "") or row.get("ip", ""),
            method=row.get("method", "GET"),
            path=path,
            query=query,
            headers=headers,
            header_order=order,
            body=row.get("body", ""),
            ts=float(row.get("ts", time.time())),
        )
    m = log_re.match(line)
    if not m:
        return None
    ua = m.group("ua") or ""
    referer = m.group("referer") or ""
    raw = [("User-Agent", ua)]
    if referer and referer != "-":
        raw.append(("Referer", referer))
    headers, order = lower_headers(raw)
    path, query = split_target(m.group("target"))
    return Observation(
        session_id="",
        remote_addr=m.group("ip"),
        method=m.group("method"),
        path=path,
        query=query,
        headers=headers,
        header_order=order,
    )


def cmd_demo(args: argparse.Namespace) -> int:
    """Push three synthetic clients through the engine so the scoring is visible."""
    from .detect.engine import Engine
    from .lure.nectar import BaitFactory

    config = _config(args)
    config.telemetry.jsonl = ""
    factory = BaitFactory(config)

    scenarios = {
        "a person in a browser": _human_trace,
        "an ordinary crawler": _crawler_trace,
        "a hostile scanner": _scanner_trace,
        "an LLM agent that read the notice": _agent_trace,
    }

    for label, build in scenarios.items():
        engine = Engine(config, bait_factory=factory.mint)
        engine.robots_disallowed = {"/internal/", "/staff/"}
        print(f"\n=== {label} ===")
        last = None
        for obs in build(factory):
            last = engine.observe(obs)
        if last:
            print(f"  verdict   : {last.verdict.value}")
            print(f"  automation: {last.automation:.1f}   (no human at the keyboard)")
            print(f"  llm agency: {last.agency:.1f}   (a language model is driving)")
            print(f"  hostility : {last.hostility:.1f}")
            print(f"  action    : {last.action.value}")
            state = engine.sessions.get(last.session_id)
            seen = sorted(state.signals_seen) if state else []
            print(f"  signals   : {', '.join(seen) or '-'}")
    print()
    return 0


def _obs(path: str, headers: dict[str, str], method: str = "GET", ts: float = 0.0, body: str = "") -> Observation:
    pairs = list(headers.items())
    low, order = lower_headers(pairs)
    p, q = split_target(path)
    return Observation(
        session_id="",
        remote_addr="198.51.100.7",
        method=method,
        path=p,
        query=q,
        headers=low,
        header_order=order,
        body=body,
        ts=ts or time.time(),
    )


BROWSER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}


def _human_trace(factory):
    bait = None
    t = time.time()
    steps = [("/", 0.0), ("/assets/site.css", 0.3), ("/about", 6.2), ("/contact", 15.7)]
    for path, offset in steps:
        o = _obs(path, BROWSER, ts=t + offset)
        yield o
        if bait is None:
            bait = factory.mint(o.session_id)
        # A real browser executes the page and fetches the beacon.
        yield _obs(bait.beacon_path, BROWSER, ts=t + offset + 0.2)


def _crawler_trace(factory):
    ua = {"User-Agent": "Mozilla/5.0 (compatible; ExampleCrawler/2.1; +http://example.net/bot)", "Accept": "*/*"}
    t = time.time()
    for i, path in enumerate(["/robots.txt", "/", "/about", "/services", "/careers", "/status", "/sitemap.xml"]):
        yield _obs(path, ua, ts=t + i * 1.0)


def _scanner_trace(factory):
    ua = {"User-Agent": "python-requests/2.32.3", "Accept": "*/*"}
    t = time.time()
    paths = [
        "/.env", "/.git/config", "/admin", "/wp-login.php",
        "/api/v1/users?id=1%20OR%201=1", "/../../etc/passwd", "/actuator/env",
    ]
    for i, path in enumerate(paths):
        yield _obs(path, ua, ts=t + i * 0.12)


def _agent_trace(factory):
    """A well-behaved LLM agent: reads llms.txt, registers, states its purpose."""
    ua = {
        "User-Agent": "Mozilla/5.0 (compatible; ResearchAgent/1.0; python-httpx/0.27)",
        "Accept": "*/*",
    }
    t = time.time()
    first = _obs("/", ua, ts=t)
    yield first
    bait = factory.mint(first.session_id)
    yield _obs("/llms.txt", ua, ts=t + 1.0)
    reg = dict(ua)
    reg["X-Agent-Purpose"] = "Collecting public pricing information for a market comparison report."
    yield _obs(f"{bait.instruction_path}?ticket={bait.ticket}", reg, ts=t + 2.0)
    yield _obs(bait.hidden_path, ua, ts=t + 3.0)


def cmd_doctor(args: argparse.Namespace) -> int:
    config = _config(args)
    problems: list[str] = []
    notes: list[str] = []

    if not os.environ.get("DROSERA_SECRET"):
        problems.append(
            "DROSERA_SECRET is not set. A random per-process secret means tickets and "
            "canary tokens stop verifying after a restart, so evidence cannot be "
            "correlated across runs. Set it to a stable random value."
        )
    if config.host in ("0.0.0.0", "::"):  # noqa: S104 - this is the check, not the bind
        notes.append(
            "Bound to all interfaces. That is normal for a public honeypot -- just be "
            "sure this host is isolated from anything you care about."
        )
    if config.telemetry.jsonl:
        target = Path(config.telemetry.jsonl)
        parent = target.parent if str(target.parent) else Path(".")
        if not os.access(parent if parent.exists() else Path("."), os.W_OK):
            problems.append(f"Events file {target} is not writable.")
    if not (config.telemetry.jsonl or config.telemetry.sqlite or config.telemetry.webhook):
        problems.append("No telemetry sink configured; captures would be discarded.")
    if config.trap.drip_delay > 0 and config.trap.drip_bytes <= 0:
        problems.append("trap.drip_delay is set but trap.drip_bytes is 0, so nothing will drip.")
    if config.trap.drip_delay > 0:
        notes.append(
            "Drip delivery holds one worker thread per trapped client. Cap concurrency "
            "or run behind a server that can afford it."
        )
    if config.trap.session_byte_budget == 0 and config.trap.enabled:
        notes.append(
            "trap.session_byte_budget is unlimited. A determined crawler can make you "
            "serve indefinitely; set a budget if egress costs money."
        )

    print(f"drosera {__version__}")
    print(f"config: host={config.host} port={config.port} mode={config.trap.mode}")
    print(f"sinks : jsonl={config.telemetry.jsonl or '-'} sqlite={config.telemetry.sqlite or '-'} "
          f"webhook={'set' if config.telemetry.webhook else '-'}")
    for note in notes:
        print(f"\n  note    : {note}")
    for problem in problems:
        print(f"\n  PROBLEM : {problem}")
    print()
    return 1 if problems else 0


# -- canary commands -----------------------------------------------------


def cmd_canary_plant(args: argparse.Namespace) -> int:
    from .canary.mint import TEMPLATES, plant

    config = _config(args)
    kinds = args.kind or sorted(TEMPLATES)
    listener = args.listener or config.lure.contact.split("@")[-1]
    _warn_ephemeral_secret(config)
    planted = plant(
        args.dest,
        kinds,
        config.secret,
        listener,
        label=args.label,
        registry=args.registry,
        overwrite=args.force,
    )
    for c in planted:
        print(f"  {c.kind:<18} {c.path}")
    print(f"drosera: planted {len(planted)} canaries, registry {args.registry}")
    print("drosera: these credentials are inert -- they authenticate nowhere.")
    return 0


def cmd_canary_list(args: argparse.Namespace) -> int:
    from .canary.mint import load_registry

    canaries = load_registry(args.registry)
    if not canaries:
        print(f"drosera: no canaries in {args.registry}")
        return 0
    for c in canaries:
        age = time.strftime("%Y-%m-%d", time.localtime(c.created))
        print(f"  {c.id}  {c.kind:<18} {age}  {c.label or '-':<12} {c.path}")
    print(f"\n{len(canaries)} canaries")
    return 0


def cmd_canary_watch(args: argparse.Namespace) -> int:
    from .canary.watch import FileWatcher

    watcher = FileWatcher(args.registry, quiet_atime=not args.atime)
    if not watcher.canaries:
        print(f"drosera: no canaries in {args.registry}", file=sys.stderr)
        return 1
    print(f"drosera: watching {len(watcher.canaries)} canaries every {args.interval}s (Ctrl-C to stop)")
    if args.atime:
        print("drosera: access-time reporting is on; expect noise from backups and indexers")
    try:
        watcher.run(lambda hit: print(json.dumps(hit.to_dict())), interval=args.interval)
    except KeyboardInterrupt:
        print("\ndrosera: stopped")
    return 0


def cmd_canary_scan(args: argparse.Namespace) -> int:
    from .canary.mint import load_registry
    from .canary.watch import index, scan_for_canaries

    config = _config(args)
    text = sys.stdin.read() if args.target == "-" else Path(args.target).read_text(
        encoding="utf-8", errors="replace"
    )
    known = index(load_registry(args.registry))
    hits = list(scan_for_canaries(text, config.secret, known))
    for hit in hits:
        print(json.dumps(hit.to_dict()))
    if not hits:
        print("drosera: no canary credentials found", file=sys.stderr)
        return 0
    print(f"drosera: {len(hits)} canary credential(s) found -- treat as confirmed exfiltration",
          file=sys.stderr)
    return 2


def cmd_canary_kinds(args: argparse.Namespace) -> int:
    from .canary.mint import DEFAULT_FILENAMES, TEMPLATES

    for kind in sorted(TEMPLATES):
        print(f"  {kind:<18} -> {DEFAULT_FILENAMES[kind]}")
    return 0


def _warn_ephemeral_secret(config: Config) -> None:
    if not os.environ.get("DROSERA_SECRET"):
        print(
            "drosera: warning: DROSERA_SECRET unset, using a per-process secret. "
            "Tickets and canary tokens will not verify after a restart.",
            file=sys.stderr,
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
