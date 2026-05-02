"""
Result-file writers and small statistics helpers.

We keep everything as plain CSV/JSON so post-processing is trivial across hosts.

Schema (per-iteration CSV, one file per (test, protocol)):

    iter,client_id,success,duration_ms,sent_bytes,recv_bytes,wall_s

Schema (summary JSON, one file per (test, protocol)):

    {
      "test": "...", "protocol": "...", "host": "...", "device": "...",
      "n": 50, "n_success": 50,
      "latency_ms": { "mean": ..., "median": ..., "p95": ..., "min": ..., "max": ..., "stdev": ... },
      "bytes":      { "sent_mean": ..., "recv_mean": ..., "total_mean": ... },
      "resources":  { "peak_rss_mb": ..., "mean_cpu_pct": ..., "peak_cpu_pct": ..., "energy_per_auth_mJ": ... }
    }
"""

from __future__ import annotations

import csv
import json
import math
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from . import config
from .runner import ClientResult
from .sampler import ResourceSummary


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


def _safe_stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def _safe_mean(values: list[float]) -> float:
    if not values:
        return float("nan")
    return statistics.fmean(values)


@dataclass
class LatencyStats:
    mean: float
    median: float
    p95: float
    p99: float
    min: float
    max: float
    stdev: float

    @classmethod
    def from_values(cls, values: list[float]) -> "LatencyStats":
        if not values:
            nan = float("nan")
            return cls(nan, nan, nan, nan, nan, nan, 0.0)
        return cls(
            mean=_safe_mean(values),
            median=statistics.median(values),
            p95=_percentile(values, 95.0),
            p99=_percentile(values, 99.0),
            min=min(values),
            max=max(values),
            stdev=_safe_stdev(values),
        )


# ---------------------------------------------------------------------------
# CSV / JSON writers
# ---------------------------------------------------------------------------

def write_iterations_csv(path: Path, results: Iterable[ClientResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "iter", "client_id", "success",
            "duration_ms", "sent_bytes", "recv_bytes", "wall_s",
        ])
        for r in results:
            w.writerow([
                r.iteration, r.client_id, int(r.success),
                "" if r.duration_ms is None else f"{r.duration_ms:.6f}",
                "" if r.sent_bytes is None else r.sent_bytes,
                "" if r.recv_bytes is None else r.recv_bytes,
                f"{r.elapsed_wall_s:.6f}",
            ])


def estimate_energy_per_auth_mJ(
    resource_summary: ResourceSummary,
    n_successful_auths: int,
    profile: config.DevicePowerProfile,
) -> float:
    """Estimate per-authentication energy in millijoules.

    E_total = (P_idle + (P_max - P_idle) * cpu_fraction) * duration_s
    cpu_fraction is the *system-wide* CPU utilization fraction (0..1), so we
    use cpu_pct_normalised which is mean_cpu_pct / NCPU. The dynamic component
    scales with how busy the CPU is; idle leakage stays constant.

    Per-auth energy is E_total / n_auths.

    Returns NaN if no successful authentications.
    """
    if n_successful_auths <= 0 or resource_summary.duration_s <= 0:
        return float("nan")
    cpu_frac = max(0.0, min(1.0, resource_summary.cpu_pct_normalised / 100.0))
    p_avg_w = profile.idle_w + (profile.max_w - profile.idle_w) * cpu_frac
    energy_j = p_avg_w * resource_summary.duration_s
    return (energy_j / n_successful_auths) * 1000.0


@dataclass
class SummaryRecord:
    test: str
    protocol: str
    host: str
    device: str
    n: int
    n_success: int
    latency_ms: LatencyStats
    sent_bytes_mean: float
    recv_bytes_mean: float
    total_bytes_mean: float
    resources: Optional[dict] = field(default=None)
    notes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["latency_ms"] = asdict(self.latency_ms)
        return d


def summarise(
    test: str,
    protocol: str,
    results: list[ClientResult],
    resources: Optional[ResourceSummary] = None,
    energy: Optional[object] = None,    # lib.pmic.EnergyResult; typed loose to avoid import cycle
    profile: Optional[config.DevicePowerProfile] = None,
    extra_notes: Optional[dict] = None,
) -> SummaryRecord:
    profile = profile or config.detect_device()
    successful = [r for r in results if r.success and r.duration_ms is not None]
    durations = [r.duration_ms for r in successful]  # type: ignore[misc]
    sent = [r.sent_bytes for r in successful if r.sent_bytes is not None]
    recv = [r.recv_bytes for r in successful if r.recv_bytes is not None]

    latency = LatencyStats.from_values(durations)

    res_block: Optional[dict] = None
    if resources is not None:
        # Per-auth energy from the linear model (always available when we
        # sampled CPU). Even when a hardware meter is also present, keep
        # this so the plotter can compare model-vs-measured.
        res_block = {
            "peak_rss_mb": resources.peak_rss_mb,
            "mean_cpu_pct": resources.mean_cpu_pct,
            "peak_cpu_pct": resources.peak_cpu_pct,
            "cpu_pct_normalised": resources.cpu_pct_normalised,
            "samples": resources.samples,
            "duration_s": resources.duration_s,
            "energy_per_auth_mJ": estimate_energy_per_auth_mJ(resources, len(successful), profile),
            "energy_method": "static-model",
            "device_profile": {
                "name": profile.name,
                "idle_w": profile.idle_w,
                "max_w": profile.max_w,
                "cpu_cores": profile.cpu_cores,
            },
        }
        # When a live meter was attached, prefer its number for energy_per_auth_mJ
        # but keep the model number under `energy_per_auth_mJ_modelled` so the
        # comparison is still in the JSON for anyone who wants it.
        if energy is not None and hasattr(energy, "to_dict"):
            measured = energy.to_dict()
            if measured.get("energy_per_auth_mJ") == measured.get("energy_per_auth_mJ"):  # not NaN
                res_block["energy_per_auth_mJ_modelled"] = res_block["energy_per_auth_mJ"]
                res_block["energy_per_auth_mJ"] = measured["energy_per_auth_mJ"]
                res_block["energy_method"] = measured["method"]
                res_block["energy_measurement"] = measured

    return SummaryRecord(
        test=test,
        protocol=protocol,
        host=config.hostname(),
        device=profile.name,
        n=len(results),
        n_success=len(successful),
        latency_ms=latency,
        sent_bytes_mean=_safe_mean(list(map(float, sent))) if sent else float("nan"),
        recv_bytes_mean=_safe_mean(list(map(float, recv))) if recv else float("nan"),
        total_bytes_mean=_safe_mean([float(s + r) for s, r in zip(sent, recv)]) if sent and recv else float("nan"),
        resources=res_block,
        notes=extra_notes or {},
    )


def write_summary_json(path: Path, summary: SummaryRecord) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(summary.to_dict(), f, indent=2, default=str)
