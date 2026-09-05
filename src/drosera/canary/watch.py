"""Watch planted canaries for reads, and scan traffic for their use.

Two detectors with very different strength, kept visibly separate so nobody
confuses them:

``FileWatcher``
    Polls access/modification times of planted files. Immediate and dependency
    free, but *soft*. Most Linux mounts use ``relatime``, so an access time
    only advances once a day; ``noatime`` disables it entirely; backup agents,
    antivirus and file indexers all touch files innocently. A hit here means
    "worth looking at", never "confirmed".

    Comparisons use integer nanosecond timestamps (``st_mtime_ns``) rather than
    the float seconds a stat reports by default. Float seconds carry roughly
    120ns of rounding error at current epoch values, which forces a tolerance --
    and any tolerance big enough to absorb that noise is also big enough to miss
    a fast edit. Integers need no tolerance at all.

``scan_for_canaries``
    Looks for a planted credential appearing somewhere it should not -- a
    request body, an outbound payload, a log line. This is *hard* evidence: the
    value exists nowhere except inside bait, so its presence anywhere else
    means the bait was read and the contents moved.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from ..util import stable_hash
from .mint import Canary, load_registry, parse_token

TOKEN_RE = re.compile(r"\bdrs[a-z0-9]{12}[a-f0-9]{10}\b")
AWS_RE = re.compile(r"\bAKIA[A-Z2-7]{16}\b")


# An access time must move by more than this to be reported. atime is a soft
# signal on a coarse clock, so a full second of slack costs nothing.
ATIME_TOLERANCE_NS = 1_000_000_000

# How far ahead of the planting record an mtime must sit to count as "changed
# while nobody was watching". Generous enough to ignore float rounding in the
# registry, tight enough to still be meaningful.
UNWATCHED_TOLERANCE_S = 1.0


@dataclass
class CanaryHit:
    canary_id: str
    kind: str
    channel: str  # "file_read" | "file_modified" | "value_seen"
    detail: str
    path: str = ""
    ts: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ts": self.ts or time.time(),
            "canary_id": self.canary_id,
            "kind": self.kind,
            "channel": self.channel,
            "detail": self.detail,
            "path": self.path,
        }


class FileWatcher:
    """Polls planted files for access. Soft signal -- see module docstring."""

    def __init__(self, registry: str | os.PathLike[str], quiet_atime: bool = True) -> None:
        self.registry_path = registry
        self.canaries: list[Canary] = load_registry(registry)
        self.quiet_atime = quiet_atime
        self._state: dict[str, tuple[int, int]] = {}
        self._backlog: list[CanaryHit] = []
        for c in self.canaries:
            self._baseline(c)

    def _baseline(self, canary: Canary) -> None:
        """Record where a file stands as watching begins.

        The baseline comes from a live stat rather than from the planting
        record, so every later comparison is exact. Whatever happened between
        planting and now is caught separately, by a coarse check that tolerates
        the float rounding in the registry and surfaces on the first poll.
        """
        try:
            st = Path(canary.path).stat() if canary.path else None
        except OSError:
            st = None
        if st is None:
            return
        if canary.mtime and st.st_mtime > canary.mtime + UNWATCHED_TOLERANCE_S:
            self._backlog.append(
                CanaryHit(
                    canary.id,
                    canary.kind,
                    "file_modified",
                    f"{canary.path} was modified before watching began",
                    canary.path,
                    time.time(),
                )
            )
        self._state[canary.id] = (st.st_atime_ns, st.st_mtime_ns)

    def reload(self) -> None:
        self.canaries = load_registry(self.registry_path)
        for c in self.canaries:
            if c.id not in self._state:
                self._baseline(c)

    def poll(self) -> list[CanaryHit]:
        hits, self._backlog = self._backlog, []
        now = time.time()
        for c in self.canaries:
            if not c.path:
                continue
            try:
                st = Path(c.path).stat()
            except OSError:
                continue
            prev = self._state.get(c.id)
            if prev is None:
                self._state[c.id] = (st.st_atime_ns, st.st_mtime_ns)
                continue
            prev_a, prev_m = prev
            if st.st_mtime_ns > prev_m:
                hits.append(
                    CanaryHit(c.id, c.kind, "file_modified", f"mtime advanced on {c.path}", c.path, now)
                )
            elif st.st_atime_ns > prev_a + ATIME_TOLERANCE_NS and not self.quiet_atime:
                hits.append(
                    CanaryHit(
                        c.id,
                        c.kind,
                        "file_read",
                        f"atime advanced on {c.path} (soft signal: relatime/backup agents also do this)",
                        c.path,
                        now,
                    )
                )
            self._state[c.id] = (st.st_atime_ns, st.st_mtime_ns)
        return hits

    def run(
        self,
        on_hit: Callable[[CanaryHit], None],
        interval: float = 5.0,
        stop: Callable[[], bool] | None = None,
    ) -> None:
        while not (stop and stop()):
            for hit in self.poll():
                on_hit(hit)
            time.sleep(interval)


def scan_for_canaries(text: str, secret: str, known: dict[str, Canary] | None = None) -> Iterator[CanaryHit]:
    """Find planted credentials inside arbitrary text. Hard evidence.

    Matches on shape first (cheap), then verifies the HMAC so an unrelated
    string that happens to look like a token is not reported.
    """
    if not text:
        return
    seen: set[str] = set()
    for m in TOKEN_RE.finditer(text):
        raw = m.group(0)
        if raw in seen:
            continue
        seen.add(raw)
        cid = parse_token(secret, raw)
        if not cid:
            continue
        kind = known[cid].kind if known and cid in known else "unknown"
        yield CanaryHit(cid, kind, "value_seen", f"canary credential present in content: {raw[:8]}...", ts=time.time())
    for m in AWS_RE.finditer(text):
        raw = m.group(0)
        if raw in seen or not known:
            continue
        seen.add(raw)
        for c in known.values():
            if c.value == raw:
                yield CanaryHit(c.id, c.kind, "value_seen", f"canary access key present in content: {raw}", ts=time.time())
                break


def index(canaries: list[Canary]) -> dict[str, Canary]:
    return {c.id: c for c in canaries}


def correlation_key(remote_addr: str, salt: str = "") -> str:
    """Stable key for tying a canary hit back to a session, without storing IPs."""
    return stable_hash(salt, remote_addr)
