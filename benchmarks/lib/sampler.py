"""
Lightweight `/proc`-based process resource sampler.

We avoid `psutil` because the harness needs to drop onto bare Raspberry Pi OS
images without extra Python wheels. Linux `/proc` gives us everything we need.

Usage:

    sampler = ProcSampler(server.pid, interval_s=0.05)
    sampler.start()
    ... run workload ...
    sampler.stop()
    summary = sampler.summary()
    summary.peak_rss_mb     # peak resident set size (MiB)
    summary.mean_cpu_pct    # mean total CPU% across the sampled interval
    summary.peak_cpu_pct    # peak instantaneous CPU% across samples
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
_CLK_TCK = os.sysconf("SC_CLK_TCK")
_NCPU = os.cpu_count() or 1


@dataclass
class ResourceSummary:
    samples: int
    duration_s: float
    peak_rss_bytes: int
    mean_cpu_pct: float          # 100% == one full core; can exceed 100%
    peak_cpu_pct: float
    cpu_pct_normalised: float    # mean_cpu_pct / NCPU * 100, i.e. fraction of system

    @property
    def peak_rss_mb(self) -> float:
        return self.peak_rss_bytes / (1024 * 1024)


def _read_stat(pid: int) -> Optional[tuple[int, int, int]]:
    """Return (utime_ticks, stime_ticks, rss_pages) or None if process gone."""
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    # The 'comm' field can contain spaces and parens. Slice from the last ')'.
    rparen = data.rfind(")")
    if rparen < 0:
        return None
    fields = data[rparen + 2:].split()
    # /proc/[pid]/stat layout (after the comm field, fields[0]==state):
    #   ... utime=fields[11], stime=fields[12], ... rss=fields[21] (in pages)
    try:
        utime = int(fields[11])
        stime = int(fields[12])
        rss_pages = int(fields[21])
    except (IndexError, ValueError):
        return None
    return utime, stime, rss_pages


def _read_status_vmrss_kb(pid: int) -> Optional[int]:
    """VmRSS in kB from /proc/[pid]/status, or None if unavailable."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return None
    return None


class ProcSampler:
    """Background thread that polls /proc for a single PID."""

    def __init__(self, pid: int, interval_s: float = 0.05):
        self.pid = pid
        self.interval_s = interval_s
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.peak_rss_bytes = 0
        self.cpu_pct_samples: list[float] = []
        self._first_ticks: Optional[tuple[int, int, float]] = None  # u, s, wall
        self._last_ticks: Optional[tuple[int, int, float]] = None

    def _sample_once(self) -> None:
        stat = _read_stat(self.pid)
        if stat is None:
            return
        utime, stime, rss_pages = stat

        # RSS via /proc/[pid]/stat uses pages; status gives kB. Use kB if
        # available because some kernels lazy-update stat's rss field.
        kb = _read_status_vmrss_kb(self.pid)
        rss_bytes = (kb * 1024) if kb is not None else (rss_pages * _PAGE_SIZE)
        if rss_bytes > self.peak_rss_bytes:
            self.peak_rss_bytes = rss_bytes

        now = time.monotonic()
        if self._first_ticks is None:
            self._first_ticks = (utime, stime, now)
            self._last_ticks = (utime, stime, now)
            return

        last_u, last_s, last_t = self._last_ticks  # type: ignore[misc]
        d_ticks = (utime + stime) - (last_u + last_s)
        d_t = now - last_t
        if d_t > 0:
            cpu_pct = (d_ticks / _CLK_TCK) / d_t * 100.0
            self.cpu_pct_samples.append(cpu_pct)
        self._last_ticks = (utime, stime, now)

    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            self._sample_once()
            self._stop_evt.wait(self.interval_s)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("sampler already started")
        self._thread = threading.Thread(target=self._loop, daemon=True, name=f"sampler-{self.pid}")
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop_evt.set()
        self._thread.join(timeout=1.0)
        self._thread = None

    def summary(self) -> ResourceSummary:
        if self._first_ticks and self._last_ticks:
            u0, s0, t0 = self._first_ticks
            u1, s1, t1 = self._last_ticks
            duration_s = max(t1 - t0, 1e-6)
        else:
            duration_s = 0.0

        if self.cpu_pct_samples:
            mean_cpu = sum(self.cpu_pct_samples) / len(self.cpu_pct_samples)
            peak_cpu = max(self.cpu_pct_samples)
        else:
            mean_cpu = 0.0
            peak_cpu = 0.0

        return ResourceSummary(
            samples=len(self.cpu_pct_samples),
            duration_s=duration_s,
            peak_rss_bytes=self.peak_rss_bytes,
            mean_cpu_pct=mean_cpu,
            peak_cpu_pct=peak_cpu,
            cpu_pct_normalised=mean_cpu / _NCPU,
        )
