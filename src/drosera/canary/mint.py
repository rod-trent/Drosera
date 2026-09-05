"""Canary credentials: bait that works where there is no web server.

An agent that has landed on a host or been pointed at a repository goes looking
for secrets. ``.env``, ``credentials.json``, ``id_rsa``, a kubeconfig. Drosera
seeds those files with credentials that are real-looking, completely inert, and
uniquely identifiable.

Detection happens on two independent channels, because each has a blind spot:

* **Use** -- the credential names a host you control. When something tries to
  authenticate with it, you learn the credential leaked, from where, and to
  where. This is the high-fidelity channel: a hit is proof of exfiltration,
  not an inference.
* **Read** -- the file's access time changes. Cheap and immediate, but easily
  defeated by ``noatime``/``relatime`` mounts and by any backup or indexer
  that walks the tree. Treat it as a hint, never as proof.

Every token is self-verifying via HMAC, so a hit can be attributed to the
deployment that minted it without a shared database.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..util import sign, token, verify

REGISTRY_DEFAULT = ".drosera/canaries.json"
PREFIX = "drs"


@dataclass
class Canary:
    id: str
    kind: str
    value: str
    path: str = ""
    label: str = ""
    listener: str = ""
    created: float = field(default_factory=time.time)
    mtime: float = 0.0
    atime: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def mint_token(secret: str, kind: str) -> tuple[str, str]:
    """Return ``(canary_id, raw_token)``.

    The id is embedded in the token so a hit identifies which planted file
    leaked, and the HMAC tag proves the token is ours rather than a collision
    with a real credential someone actually uses.
    """
    cid = token(12)
    tag = sign(secret, f"{kind}:{cid}", 10)
    return cid, f"{PREFIX}{cid}{tag}"


def parse_token(secret: str, raw: str, kind: str = "") -> str | None:
    """Extract and verify a canary id from an observed credential value."""
    if not raw or not raw.startswith(PREFIX):
        return None
    rest = raw[len(PREFIX) :]
    if len(rest) < 22:
        return None
    cid, tag = rest[:12], rest[12:22]
    kinds = [kind] if kind else list(TEMPLATES)
    for k in kinds:
        if verify(secret, f"{k}:{cid}", tag, 10):
            return cid
    return None


def _aws_style(raw: str) -> tuple[str, str]:
    """AWS-shaped key pair carrying the token, so the file passes a glance."""
    digest = hashlib.sha256(raw.encode()).digest()
    key_id = "AKIA" + base64.b32encode(digest[:10]).decode().rstrip("=")[:16]
    secret_key = base64.b64encode(digest).decode()[:40]
    return key_id, secret_key


def _fake_pem(raw: str) -> str:
    """A PEM-shaped block that is deliberately not a usable key.

    It is random base64, not a serialised key: it cannot authenticate anywhere,
    so planting it creates no risk if it is stolen. The token is carried in the
    surrounding comment.
    """
    blob = hashlib.sha512((raw + "pem").encode()).digest() * 12
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"


# Each template renders a plausible file. ``{token}`` is the canary value and
# ``{listener}`` is the host that will observe its use.
TEMPLATES: dict[str, str] = {
    "dotenv": """\
# Environment configuration. Do not commit.
NODE_ENV=production
DATABASE_URL=postgresql://svc_reports:{token}@db-internal.{listener}:5432/reporting
REDIS_URL=redis://cache-internal.{listener}:6379/0
API_BASE_URL=https://api.{listener}
SERVICE_API_KEY={token}
JWT_SIGNING_KEY={token}
SMTP_HOST=smtp.{listener}
SMTP_USER=notifications@{listener}
SMTP_PASSWORD={token}
SENTRY_DSN=https://{token}@sentry.{listener}/4
""",
    "aws": """\
[default]
aws_access_key_id = {key_id}
aws_secret_access_key = {secret_key}
region = us-east-1

[reporting]
aws_access_key_id = {key_id}
aws_secret_access_key = {secret_key}
region = us-east-1
""",
    "credentials_json": """\
{{
  "type": "service_account",
  "project_id": "reporting-prod",
  "private_key_id": "{token}",
  "client_email": "reporting-svc@reporting-prod.iam.{listener}",
  "client_id": "{token}",
  "token_uri": "https://oauth2.{listener}/token",
  "api_key": "{token}"
}}
""",
    "ssh_key": """\
# deploy key for reporting-svc -- rotate quarterly (ref {token})
{pem}""",
    "kubeconfig": """\
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s-api.{listener}:6443
    insecure-skip-tls-verify: true
  name: prod
contexts:
- context:
    cluster: prod
    user: deploy
  name: prod
current-context: prod
users:
- name: deploy
  user:
    token: {token}
""",
    "npmrc": """\
//registry.{listener}/:_authToken={token}
@internal:registry=https://registry.{listener}/
always-auth=true
""",
    "appsettings": """\
{{
  "ConnectionStrings": {{
    "Default": "Server=sql-internal.{listener};Database=Reporting;User Id=svc_reports;Password={token};"
  }},
  "Auth": {{
    "ClientSecret": "{token}",
    "Authority": "https://login.{listener}/"
  }}
}}
""",
    "pgpass": "db-internal.{listener}:5432:reporting:svc_reports:{token}\n",
}

DEFAULT_FILENAMES = {
    "dotenv": ".env",
    "aws": ".aws/credentials",
    "credentials_json": "credentials.json",
    "ssh_key": ".ssh/id_rsa",
    "kubeconfig": ".kube/config",
    "npmrc": ".npmrc",
    "appsettings": "appsettings.Production.json",
    "pgpass": ".pgpass",
}


def render(kind: str, secret: str, listener: str) -> tuple[Canary, str]:
    if kind not in TEMPLATES:
        raise KeyError(f"unknown canary kind {kind!r}; known: {', '.join(sorted(TEMPLATES))}")
    cid, raw = mint_token(secret, kind)
    key_id, secret_key = _aws_style(raw)
    content = TEMPLATES[kind].format(
        token=raw,
        listener=listener,
        key_id=key_id,
        secret_key=secret_key,
        pem=_fake_pem(raw),
    )
    value = key_id if kind == "aws" else raw
    return Canary(id=cid, kind=kind, value=value, listener=listener), content


def plant(
    dest: str | os.PathLike[str],
    kinds: list[str],
    secret: str,
    listener: str,
    label: str = "",
    registry: str | os.PathLike[str] = REGISTRY_DEFAULT,
    overwrite: bool = False,
) -> list[Canary]:
    """Write canary files under ``dest`` and record them in the registry.

    Refuses to overwrite an existing file unless asked. Planting a decoy on top
    of a real ``.env`` would be a genuinely destructive accident, and the whole
    point of the tool is to be safe to run against a live host.
    """
    root = Path(dest)
    planted: list[Canary] = []
    for kind in kinds:
        canary, content = render(kind, secret, listener)
        target = root / DEFAULT_FILENAMES[kind]
        if target.exists() and not overwrite:
            raise FileExistsError(
                f"{target} already exists; refusing to overwrite. "
                "Pass overwrite=True (or --force) only if you are certain it is not a real file."
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        # Best effort; Windows and some mounts will decline.
        with contextlib.suppress(OSError):
            os.chmod(target, 0o600)
        st = target.stat()
        canary.path = str(target.resolve())
        canary.label = label
        canary.mtime = st.st_mtime
        canary.atime = st.st_atime
        planted.append(canary)
    save_registry(planted, registry, append=True)
    return planted


# -- registry ------------------------------------------------------------


def load_registry(path: str | os.PathLike[str] = REGISTRY_DEFAULT) -> list[Canary]:
    p = Path(path)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [Canary(**row) for row in data.get("canaries", []) if isinstance(row, dict)]


def save_registry(
    canaries: list[Canary],
    path: str | os.PathLike[str] = REGISTRY_DEFAULT,
    append: bool = False,
) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = load_registry(p) if append else []
    by_id = {c.id: c for c in existing}
    for c in canaries:
        by_id[c.id] = c
    payload = {"version": 1, "canaries": [c.to_dict() for c in by_id.values()]}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")


def values(canaries: list[Canary]) -> set[str]:
    """Credential strings to watch for in outbound or submitted data."""
    return {c.value for c in canaries if c.value}
