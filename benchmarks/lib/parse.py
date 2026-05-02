"""
Parsing of the binaries' standard-output metrics lines.

All three protocols emit the same shapes:

    CLIENT METRICS -> Duration: 1.234ms, Sent: 320 bytes, Received: 240 bytes
    SERVER METRICS -> Some(127.0.0.1:53412) Duration: 2.5ms, Sent: 240 bytes, Received: 320 bytes

Rust's Debug print of a `Duration` uses one of: `Ns`, `Nms`, `Nµs`, `Nns`,
sometimes with a fractional component (e.g. `12.345ms`, `987.654µs`). We
normalise everything to milliseconds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

# Single regex that handles the whole client/server metrics line.
# Non-capturing alternation for the leading role.
# Duration spelled `Duration: <value><unit>` where unit ∈ {ns, µs, us, ms, s}.
# We intentionally accept both the proper `µs` and the ascii fallback `us`.
_METRICS_RE = re.compile(
    r"""
    (?P<role>CLIENT|SERVER)\s+METRICS\s*->         # role marker
    (?:\s*[^,]*?)?                                  # optional peer addr (server side)
    \s*Duration:\s*
    (?P<dur>\d+(?:\.\d+)?)
    (?P<unit>ns|µs|us|ms|s)
    \s*,\s*
    Sent:\s*(?P<sent>\d+)\s*bytes
    \s*,\s*
    Received:\s*(?P<recv>\d+)\s*bytes
    """,
    re.VERBOSE,
)


_UNIT_TO_MS = {
    "ns": 1e-6,
    "µs": 1e-3,
    "us": 1e-3,
    "ms": 1.0,
    "s":  1000.0,
}


@dataclass
class MetricsLine:
    role: str            # "CLIENT" or "SERVER"
    duration_ms: float
    sent_bytes: int
    recv_bytes: int

    @property
    def total_bytes(self) -> int:
        return self.sent_bytes + self.recv_bytes


def parse_line(line: str) -> Optional[MetricsLine]:
    """Return a MetricsLine if `line` is a metrics line, else None."""
    m = _METRICS_RE.search(line)
    if not m:
        return None
    dur = float(m.group("dur"))
    unit = m.group("unit")
    duration_ms = dur * _UNIT_TO_MS[unit]
    return MetricsLine(
        role=m.group("role"),
        duration_ms=duration_ms,
        sent_bytes=int(m.group("sent")),
        recv_bytes=int(m.group("recv")),
    )


def parse_stream(lines: Iterable[str]) -> list[MetricsLine]:
    """Pull out every metrics line from a stream of stdout text."""
    out: list[MetricsLine] = []
    for ln in lines:
        m = parse_line(ln)
        if m is not None:
            out.append(m)
    return out


def first_client_metrics(text: str) -> Optional[MetricsLine]:
    """Return the first CLIENT METRICS line found in `text`, or None."""
    for ln in text.splitlines():
        m = parse_line(ln)
        if m is not None and m.role == "CLIENT":
            return m
    return None
