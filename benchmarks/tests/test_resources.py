"""
Tests 4/5/6 — Resource Consumption (Memory, CPU, Energy)

The thesis presents three figures derived from resource sampling of the
authentication process across Pi 3B+/4/5: peak RSS, peak CPU, and estimated
per-authentication energy. All three come from the *same* run, so we capture
them together and write a single summary file containing every metric.

Workload pattern:
    `TEST_RESOURCES_CLIENTS` parallel sessions × `TEST_RESOURCES_RUNS_PER_CLIENT`
    sequential auths each — enough to drive a sustained representative load
    without making the test prohibitively long.

Output is written under three test names so the plotter can pick them up
the same way it picks up tests 1–3:

    results/raw/test4_memory_<proto>.csv     (just the duration column is meaningful)
    results/summary/test4_memory_<proto>.json
    results/raw/test5_cpu_<proto>.csv
    results/summary/test5_cpu_<proto>.json
    results/raw/test6_energy_<proto>.csv
    results/summary/test6_energy_<proto>.json

The CSVs and summary JSONs are identical for tests 4/5/6 — only the JSON
focus field differs ("focus": "memory" / "cpu" / "energy"). This redundancy
makes the plotter trivial.

Usage:
    python -m benchmarks.tests.test_resources zkarche
    python -m benchmarks.tests.test_resources all
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from benchmarks.lib import config
from benchmarks.lib.driver import TestContext, run_test
from benchmarks.lib.results import (
    SummaryRecord, write_summary_json, write_iterations_csv,
)
from benchmarks.lib.runner import ClientResult
from benchmarks.tests.test3_highload import _make_workload


_FOCUSES = ("test4_memory", "test5_cpu", "test6_energy")


def _fanout_summary(canonical: SummaryRecord) -> None:
    """Write the same canonical summary under each of test4/5/6 names."""
    for focus in _FOCUSES:
        # We re-load and overwrite to avoid sharing a mutable object.
        focus_summary = SummaryRecord(
            test=focus,
            protocol=canonical.protocol,
            host=canonical.host,
            device=canonical.device,
            n=canonical.n,
            n_success=canonical.n_success,
            latency_ms=canonical.latency_ms,
            sent_bytes_mean=canonical.sent_bytes_mean,
            recv_bytes_mean=canonical.recv_bytes_mean,
            total_bytes_mean=canonical.total_bytes_mean,
            resources=canonical.resources,
            notes={**canonical.notes, "focus": focus.split("_", 1)[1]},
        )
        out = config.RESULTS_DIR / "summary" / f"{focus}_{canonical.protocol}.json"
        write_summary_json(out, focus_summary)


def run_for_protocol(protocol_name: str) -> None:
    n_clients = config.TEST_RESOURCES_CLIENTS
    runs = config.TEST_RESOURCES_RUNS_PER_CLIENT
    print(
        f"=== test_resources / {protocol_name}: "
        f"{n_clients} × {runs} = {n_clients * runs} auths, sampling /proc ==="
    )
    canonical_test_name = "test4_memory"  # use this for the raw CSV path
    summary = run_test(
        test_name=canonical_test_name,
        protocol_name=protocol_name,
        n_clients_to_prep=n_clients,
        workload=_make_workload(n_clients, runs),
        sample_resources=True,
        extra_notes={
            "n_clients": n_clients,
            "runs_per_client": runs,
            "pattern": "resource_sampling",
        },
    )
    # Mirror the raw CSV under test5/test6 names so the plotter can find them.
    raw_src = config.RESULTS_DIR / "raw" / f"test4_memory_{protocol_name}.csv"
    if raw_src.exists():
        for focus in ("test5_cpu", "test6_energy"):
            dst = config.RESULTS_DIR / "raw" / f"{focus}_{protocol_name}.csv"
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(raw_src.read_bytes())
    _fanout_summary(summary)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    target = argv[1].lower()
    if target == "all":
        for p in ("zkarche", "edhoc", "mtls"):
            run_for_protocol(p)
    else:
        run_for_protocol(target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
