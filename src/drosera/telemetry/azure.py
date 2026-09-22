"""Ship events to Microsoft Sentinel via the Azure Monitor Logs Ingestion API.

Standard library only. The zero-dependency promise holds for this sink too:
authentication is a single OAuth2 token request, and ingestion is an HTTPS POST
of a gzipped JSON array, so there is nothing here the Azure SDK would add except
weight.

Enable it with a table in drosera.toml::

    [sinks.azure_monitor]
    endpoint = "https://drosera-dce-abcd.eastus-1.ingest.monitor.azure.com"
    rule_id  = "dcr-0123456789abcdef0123456789abcdef"
    stream   = "Custom-DroseraEvents"

and credentials in the environment (``AZURE_TENANT_ID``, ``AZURE_CLIENT_ID``,
``AZURE_CLIENT_SECRET``), or ``auth = "managed_identity"`` on Azure compute.
``integrations/sentinel/deploy/ingestion.json`` creates the table, the data
collection endpoint and rule, and the role assignment in one deployment.

Design rules, same as every other sink:

* **Never block serving.** ``emit`` is a non-blocking queue put. A background
  thread batches and ships.
* **Lossy on purpose.** If Azure is slow or down, events are dropped with a
  warning rather than allowed to back up into request handling. The JSONL sink
  is the durable record; ``drosera ship`` can backfill from it afterwards.
* **Filter before paying.** Ingestion is billed per GB. ``min_verdict``
  defaults to ``automation`` so ordinary human page views -- the bulk of
  traffic behind the middleware -- never leave the host. Canary events always
  ship.

The column list below is the contract with the Azure side. The table schema,
the data collection rule's stream declaration, the analytics rules and the
workbook are all generated from it by ``integrations/sentinel/_build.py``, and
CI fails if the committed templates drift from this file.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

from .export import confidence_of
from .sink import _warn, user_agent

API_VERSION = "2023-01-01"
MONITOR_RESOURCE = "https://monitor.azure.com"
DEFAULT_STREAM = "Custom-DroseraEvents"
DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"

# The Logs Ingestion API rejects calls over 1 MB after decompression. Stay
# well under it so one oversized event never poisons a batch.
MAX_BATCH_BYTES = 900_000

# (name, type) in Azure Monitor terms. Order is the order columns appear in the
# table. Types are the data collection rule's stream types; the table schema
# uses the same names except ``datetime`` becomes ``dateTime``.
COLUMNS: list[tuple[str, str]] = [
    ("TimeGenerated", "datetime"),
    ("EventType", "string"),
    ("Sensor", "string"),
    ("SessionId", "string"),
    ("Fingerprint", "string"),
    ("SrcIpAddr", "string"),
    ("HttpMethod", "string"),
    ("UrlPath", "string"),
    ("HttpUserAgent", "string"),
    ("Verdict", "string"),
    ("Confidence", "string"),
    ("Action", "string"),
    ("Agency", "real"),
    ("Automation", "real"),
    ("Hostility", "real"),
    ("Hits", "int"),
    ("TokensBurned", "long"),
    ("SignalIds", "dynamic"),
    ("Signals", "dynamic"),
    ("CanaryId", "string"),
    ("CanaryKind", "string"),
    ("CanaryChannel", "string"),
    ("Detail", "string"),
    ("FilePath", "string"),
    ("DroseraVersion", "string"),
]

_VERDICT_RANK = {"human": 0, "unknown": 1, "automation": 2, "agent": 3, "hostile_agent": 4}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_row(event: dict[str, Any], sensor: str) -> dict[str, Any]:
    """Map one Drosera event onto the DroseraEvents_CL columns."""
    from .. import __version__

    ts = float(event.get("ts") or time.time())
    if event.get("event") == "canary":
        channel = event.get("channel", "")
        return {
            "TimeGenerated": _iso(ts),
            "EventType": "canary",
            "Sensor": sensor,
            # Credential use is proof; a file timestamp moving is only a hint.
            # Same evidence-class rule as the export formats.
            "Confidence": "confirmed" if channel == "value_seen" else "low",
            "CanaryId": event.get("canary_id", ""),
            "CanaryKind": event.get("kind", ""),
            "CanaryChannel": channel,
            "Detail": event.get("detail", ""),
            "FilePath": event.get("path", ""),
            "DroseraVersion": __version__,
        }
    signals = event.get("signals") or []
    ids = [s.get("id", "") if isinstance(s, dict) else str(s) for s in signals]
    return {
        "TimeGenerated": _iso(ts),
        "EventType": "request",
        "Sensor": sensor,
        "SessionId": event.get("session_id", ""),
        "Fingerprint": event.get("fingerprint", ""),
        "SrcIpAddr": event.get("remote_addr", ""),
        "HttpMethod": event.get("method", ""),
        "UrlPath": event.get("path", ""),
        "HttpUserAgent": event.get("user_agent", ""),
        "Verdict": event.get("verdict", "unknown"),
        "Confidence": confidence_of(ids),
        "Action": event.get("action", ""),
        "Agency": float(event.get("agency") or 0),
        "Automation": float(event.get("automation") or 0),
        "Hostility": float(event.get("hostility") or 0),
        "Hits": int(event.get("hits") or 0),
        "TokensBurned": int(event.get("tokens_burned") or 0),
        "SignalIds": ids,
        "Signals": [s for s in signals if isinstance(s, dict)],
        "DroseraVersion": __version__,
    }


# -- credentials ---------------------------------------------------------------


class _CachedToken:
    """Refresh five minutes before expiry; tokens are good for about an hour."""

    SKEW = 300.0

    def __init__(self) -> None:
        self._token = ""
        self._expires = 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if not self._token or time.time() > self._expires - self.SKEW:
                self._token, self._expires = self._fetch()
            return self._token

    def invalidate(self) -> None:
        with self._lock:
            self._token = ""

    def _fetch(self) -> tuple[str, float]:  # pragma: no cover - abstract
        raise NotImplementedError

    @staticmethod
    def _parse(body: bytes) -> tuple[str, float]:
        data = json.loads(body)
        if "expires_on" in data:
            expires = float(data["expires_on"])
        else:
            expires = time.time() + float(data.get("expires_in", 3600))
        return data["access_token"], expires


class ClientSecretCredential(_CachedToken):
    """Entra ID app registration, client-credentials grant."""

    def __init__(
        self, tenant_id: str, client_id: str, client_secret: str,
        authority: str = DEFAULT_AUTHORITY, timeout: float = 10.0,
    ) -> None:
        super().__init__()
        if not (tenant_id and client_id and client_secret):
            raise ValueError(
                "azure_monitor: client_secret auth needs tenant_id, client_id and client_secret "
                "(or AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET)"
            )
        self.url = f"{authority.rstrip('/')}/{tenant_id}/oauth2/v2.0/token"
        self.form = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": f"{MONITOR_RESOURCE}/.default",
        }).encode()
        self.timeout = timeout

    def _fetch(self) -> tuple[str, float]:
        req = urllib.request.Request(
            self.url, data=self.form, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return self._parse(resp.read())


class ManagedIdentityCredential(_CachedToken):
    """Managed identity on Azure compute.

    App Service, Functions and Container Apps publish ``IDENTITY_ENDPOINT`` and
    ``IDENTITY_HEADER``; VMs and AKS use the instance metadata service.
    ``client_id`` selects a user-assigned identity; leave it empty for the
    system-assigned one.
    """

    def __init__(self, client_id: str = "", timeout: float = 10.0) -> None:
        super().__init__()
        self.client_id = client_id
        self.timeout = timeout

    def _fetch(self) -> tuple[str, float]:
        endpoint = os.environ.get("IDENTITY_ENDPOINT")
        header = os.environ.get("IDENTITY_HEADER")
        params = {"resource": MONITOR_RESOURCE}
        if endpoint and header:
            params["api-version"] = "2019-08-01"
            headers = {"X-IDENTITY-HEADER": header}
        else:
            endpoint = IMDS_ENDPOINT
            params["api-version"] = "2018-02-01"
            headers = {"Metadata": "true"}
        if self.client_id:
            params["client_id"] = self.client_id
        req = urllib.request.Request(f"{endpoint}?{urllib.parse.urlencode(params)}", headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return self._parse(resp.read())


# -- the sink ------------------------------------------------------------------


class AzureMonitorSink:
    """Batch events into a Log Analytics custom table through a DCR."""

    def __init__(
        self,
        endpoint: str,
        rule_id: str,
        credential: _CachedToken,
        stream: str = DEFAULT_STREAM,
        sensor: str = "",
        min_verdict: str = "automation",
        flush_interval: float = 5.0,
        batch_size: int = 500,
        capacity: int = 10_000,
        timeout: float = 15.0,
    ) -> None:
        if not endpoint or not rule_id:
            raise ValueError("azure_monitor: 'endpoint' and 'rule_id' are required")
        if min_verdict not in _VERDICT_RANK:
            raise ValueError(f"azure_monitor: unknown min_verdict {min_verdict!r}")
        self.url = (
            f"{endpoint.rstrip('/')}/dataCollectionRules/{urllib.parse.quote(rule_id)}"
            f"/streams/{urllib.parse.quote(stream)}?api-version={API_VERSION}"
        )
        self.credential = credential
        self.sensor = sensor or socket.gethostname()
        self.floor = _VERDICT_RANK[min_verdict]
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        self.timeout = timeout
        self.sent = 0
        self.dropped = 0
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=capacity)
        self._thread = threading.Thread(target=self._pump, name="drosera-azure", daemon=True)
        self._thread.start()

    def wants(self, event: dict[str, Any]) -> bool:
        if event.get("event") == "canary":
            return True
        return _VERDICT_RANK.get(event.get("verdict", "unknown"), 1) >= self.floor

    def emit(self, event: dict[str, Any]) -> None:
        if not self.wants(event):
            return
        try:
            self._q.put_nowait(to_row(event, self.sensor))
        except queue.Full:
            self.dropped += 1
            if self.dropped % 100 == 1:
                _warn(f"azure_monitor queue full, dropped {self.dropped} events")

    def close(self, timeout: float = 30.0) -> None:
        """Flush what is queued, then stop. Bounded so shutdown cannot hang."""
        with contextlib.suppress(queue.Full):
            self._q.put(None, timeout=1.0)
        self._thread.join(timeout)

    # -- background ------------------------------------------------------------

    def _pump(self) -> None:
        batch: list[dict[str, Any]] = []
        deadline = time.monotonic() + self.flush_interval
        while True:
            try:
                item = self._q.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                item = False  # timer expired
            if item is None:
                self._ship(batch)
                return
            if item:
                batch.append(item)
            if len(batch) >= self.batch_size or (batch and time.monotonic() >= deadline):
                self._ship(batch)
                batch = []
            if time.monotonic() >= deadline:
                deadline = time.monotonic() + self.flush_interval

    def _ship(self, rows: list[dict[str, Any]]) -> None:
        for chunk in _chunks(rows):
            self._post(chunk)

    def _post(self, rows: list[dict[str, Any]], retried: bool = False) -> None:
        body = gzip.compress(json.dumps(rows, separators=(",", ":")).encode())
        try:
            token = self.credential.token()
        except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
            _warn(f"azure_monitor: token request failed, dropped {len(rows)} events: {exc}")
            self.dropped += len(rows)
            return
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "User-Agent": user_agent(),
            },
        )
        try:
            urllib.request.urlopen(req, timeout=self.timeout).close()
            self.sent += len(rows)
        except urllib.error.HTTPError as exc:
            if not retried and exc.code == 401:
                self.credential.invalidate()
                return self._post(rows, retried=True)
            if not retried and exc.code in (429, 500, 502, 503, 504):
                time.sleep(min(30.0, _retry_after(exc)))
                return self._post(rows, retried=True)
            detail = exc.read()[:300].decode("utf-8", "replace")
            _warn(f"azure_monitor: HTTP {exc.code}, dropped {len(rows)} events: {detail}")
            self.dropped += len(rows)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            _warn(f"azure_monitor: POST failed, dropped {len(rows)} events: {exc}")
            self.dropped += len(rows)


def _retry_after(exc: urllib.error.HTTPError) -> float:
    try:
        return float(exc.headers.get("Retry-After", "2"))
    except (TypeError, ValueError):
        return 2.0


def _chunks(rows: list[dict[str, Any]]):
    """Split rows so no single POST exceeds the API's size ceiling."""
    chunk: list[dict[str, Any]] = []
    size = 2
    for row in rows:
        n = len(json.dumps(row, separators=(",", ":"))) + 1
        if n > MAX_BATCH_BYTES:
            _warn("azure_monitor: dropped one event larger than the 1 MB API limit")
            continue
        if chunk and size + n > MAX_BATCH_BYTES:
            yield chunk
            chunk, size = [], 2
        chunk.append(row)
        size += n
    if chunk:
        yield chunk


def make_sink(options: dict[str, Any], config: Any) -> AzureMonitorSink:
    """Plug-in factory for ``[sinks.azure_monitor]``.

    Every option falls back to an environment variable so a container can be
    configured without a file: ``DROSERA_AZURE_ENDPOINT``, ``DROSERA_AZURE_RULE_ID``,
    ``DROSERA_AZURE_STREAM``, ``DROSERA_AZURE_AUTH``, ``DROSERA_SENSOR``, and the
    standard ``AZURE_TENANT_ID`` / ``AZURE_CLIENT_ID`` / ``AZURE_CLIENT_SECRET``.
    """
    env = os.environ

    def opt(key: str, env_key: str, default: str = "") -> str:
        return str(options.get(key) or env.get(env_key) or default)

    auth = opt("auth", "DROSERA_AZURE_AUTH", "client_secret")
    if auth == "managed_identity":
        credential: _CachedToken = ManagedIdentityCredential(opt("client_id", "AZURE_CLIENT_ID"))
    elif auth == "client_secret":
        credential = ClientSecretCredential(
            opt("tenant_id", "AZURE_TENANT_ID"),
            opt("client_id", "AZURE_CLIENT_ID"),
            opt("client_secret", "AZURE_CLIENT_SECRET"),
            authority=opt("authority", "AZURE_AUTHORITY_HOST", DEFAULT_AUTHORITY),
        )
    else:
        raise ValueError(f"azure_monitor: auth must be 'client_secret' or 'managed_identity', not {auth!r}")

    return AzureMonitorSink(
        endpoint=opt("endpoint", "DROSERA_AZURE_ENDPOINT"),
        rule_id=opt("rule_id", "DROSERA_AZURE_RULE_ID"),
        stream=opt("stream", "DROSERA_AZURE_STREAM", DEFAULT_STREAM),
        credential=credential,
        sensor=opt("sensor", "DROSERA_SENSOR"),
        min_verdict=str(options.get("min_verdict", "automation")),
        flush_interval=float(options.get("flush_interval", 5.0)),
        batch_size=int(options.get("batch_size", 500)),
    )
