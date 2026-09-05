"""Configuration loading.

TOML via stdlib ``tomllib`` (hence the 3.11 floor), with environment overrides
so containers can be configured without a file. Every field has a working
default -- ``Config()`` alone is a valid, useful deployment.
"""

from __future__ import annotations

import contextlib
import os
import tomllib
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .models import Action, Verdict
from .util import env_secret

DEFAULT_PATHS = ("drosera.toml", ".drosera/drosera.toml", "/etc/drosera/drosera.toml")


@dataclass
class ThresholdConfig:
    """Score cut-offs, on a 0..100 scale.

    Defaults are deliberately conservative on the human side: a false
    ``AGENT`` verdict on a real person is the expensive error, so the
    comprehension signals that carry the most weight are ones no human ever
    trips by accident.
    """

    automation: float = 45.0
    agent: float = 70.0
    hostile: float = 55.0  # hostility score at which an agent becomes HOSTILE_AGENT


@dataclass
class TrapConfig:
    enabled: bool = True
    mode: str = "tarpit"  # tarpit | derail | divert | observe
    root: str = "/archive"
    links_per_page: int = 6
    words_per_page: int = 420
    max_depth: int = 0  # 0 = unbounded
    drip_bytes: int = 0  # 0 = no drip; else chunk size for slow delivery
    drip_delay: float = 0.0  # seconds between chunks
    session_byte_budget: int = 0  # 0 = unlimited; else stop feeding after N bytes


@dataclass
class LureConfig:
    enabled: bool = True
    inject_html: bool = True
    robots: bool = True
    llms_txt: bool = True
    secret_files: bool = True  # serve fake .env, credentials.json, etc.
    contact: str = "security@example.com"
    site_name: str = "Example Corp"


@dataclass
class TelemetryConfig:
    jsonl: str = "drosera-events.jsonl"
    sqlite: str = ""
    webhook: str = ""
    stderr: bool = False
    redact_ip: bool = False  # store a salted hash of the IP instead of the IP


@dataclass
class Config:
    secret: str = field(default_factory=env_secret)
    host: str = "127.0.0.1"
    port: int = 8080
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    trap: TrapConfig = field(default_factory=TrapConfig)
    lure: LureConfig = field(default_factory=LureConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    session_ttl: float = 3600.0
    max_sessions: int = 20000
    # Paths the middleware must never trap or decorate (health checks, etc).
    exempt_paths: list[str] = field(default_factory=lambda: ["/healthz", "/readyz", "/metrics"])
    # Actions per verdict. Tuning this is the main deployment decision.
    responses: dict[str, str] = field(
        default_factory=lambda: {
            Verdict.HUMAN.value: Action.ALLOW.value,
            Verdict.UNKNOWN.value: Action.ALLOW.value,
            Verdict.AUTOMATION.value: Action.OBSERVE.value,
            Verdict.AGENT.value: Action.TARPIT.value,
            Verdict.HOSTILE_AGENT.value: Action.TARPIT.value,
        }
    )

    # ---- loading -------------------------------------------------------

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> Config:
        data: dict[str, Any] = {}
        candidates = [path] if path else DEFAULT_PATHS
        for cand in candidates:
            if not cand:
                continue
            p = Path(cand)
            if p.is_file():
                with p.open("rb") as fh:
                    data = tomllib.load(fh)
                break
        cfg = cls.from_dict(data)
        cfg.apply_env()
        return cfg

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        cfg = cls()
        nested = {
            "thresholds": ThresholdConfig,
            "trap": TrapConfig,
            "lure": LureConfig,
            "telemetry": TelemetryConfig,
        }
        for key, value in data.items():
            if key in nested and isinstance(value, dict):
                sub = nested[key]()
                valid = {f.name for f in fields(sub)}
                for k, v in value.items():
                    if k in valid:
                        setattr(sub, k, v)
                setattr(cfg, key, sub)
            elif hasattr(cfg, key) and key not in nested:
                setattr(cfg, key, value)
        return cfg

    def apply_env(self) -> None:
        """DROSERA_* environment variables win over the file."""
        env = os.environ
        if v := env.get("DROSERA_SECRET"):
            self.secret = v
        if v := env.get("DROSERA_HOST"):
            self.host = v
        if v := env.get("DROSERA_PORT"):
            with_int(self, "port", v)
        if v := env.get("DROSERA_MODE"):
            self.trap.mode = v
        if v := env.get("DROSERA_JSONL"):
            self.telemetry.jsonl = v
        if v := env.get("DROSERA_SQLITE"):
            self.telemetry.sqlite = v
        if v := env.get("DROSERA_WEBHOOK"):
            self.telemetry.webhook = v
        if v := env.get("DROSERA_SITE_NAME"):
            self.lure.site_name = v

    def action_for(self, verdict: Verdict) -> Action:
        raw = self.responses.get(verdict.value, Action.ALLOW.value)
        try:
            return Action(raw)
        except ValueError:
            return Action.OBSERVE

    def is_exempt(self, path: str) -> bool:
        return any(path == e or path.startswith(e.rstrip("/") + "/") for e in self.exempt_paths)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["secret"] = "***" if self.secret else ""
        return d


def with_int(obj: Any, attr: str, raw: str) -> None:
    """Set an int attribute, ignoring an unparseable value."""
    with contextlib.suppress(ValueError):
        setattr(obj, attr, int(raw))


SAMPLE_TOML = """\
# Drosera configuration. Every value shown is the default.
# https://github.com/rod-trent/Drosera

host = "127.0.0.1"
port = 8080
session_ttl = 3600.0
exempt_paths = ["/healthz", "/readyz", "/metrics"]

[thresholds]
automation = 45.0
agent      = 70.0
hostile    = 55.0

[lure]
enabled      = true
inject_html  = true
robots       = true
llms_txt     = true
secret_files = true
site_name    = "Example Corp"
contact      = "security@example.com"

[trap]
enabled              = true
mode                 = "tarpit"   # tarpit | derail | divert | observe
root                 = "/archive"
links_per_page       = 6
words_per_page       = 420
max_depth            = 0          # 0 = unbounded
drip_bytes           = 0          # >0 enables slow chunked delivery
drip_delay           = 0.0
session_byte_budget  = 0          # 0 = unlimited

[telemetry]
jsonl     = "drosera-events.jsonl"
sqlite    = ""
webhook   = ""
stderr    = false
redact_ip = false

[responses]
human         = "allow"
unknown       = "allow"
automation    = "observe"
agent         = "tarpit"
hostile_agent = "tarpit"
"""
