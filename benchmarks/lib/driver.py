"""
Common driver shared by tests/test1..test6.

Each individual test passes:
  * a Protocol object,
  * a callable producing a list[ClientResult] given (server_handle, prepared_workdirs),
  * the test name (used in output filenames).

This driver handles:
  * Spinning up the protocol's server with isolated state directory.
  * Generating mTLS certs / enrolling ZK-ARCHE workdirs once at test start.
  * Optionally attaching a /proc resource sampler for the duration.
  * Writing per-iteration CSV + summary JSON to results/raw/ and results/summary/.

This is the *only* place that knows about test orchestration: each test script
is a thin wrapper that says "use this protocol, run this workload."
"""

from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import config
from .protocols import (
    PROTOCOLS, Protocol, PAIRING_TOKEN,
    enroll_zkarche_clients, ensure_mtls_certs,
)
from .results import (
    SummaryRecord, summarise, write_iterations_csv, write_summary_json,
)
from .runner import (
    ClientResult, ServerHandle, start_server, stop_server,
    stamp_workdirs, temp_dir,
)
from .sampler import ProcSampler, ResourceSummary


@dataclass
class TestContext:
    """Information passed to the workload callback."""
    protocol: Protocol
    server: ServerHandle
    server_workdir: Path
    client_workdirs: list[Path]   # pre-prepared (and, for ZK-ARCHE, enrolled) per-client dirs


# A workload is a function that returns the list of per-iteration results.
WorkloadFn = Callable[[TestContext], list[ClientResult]]


def _bench_workdir(test_name: str, protocol_name: str) -> Path:
    """Working area under /tmp for this test/protocol run."""
    return Path(f"/tmp/zkb-{test_name}-{protocol_name}")


def run_test(
    test_name: str,
    protocol_name: str,
    *,
    n_clients_to_prep: int,
    workload: WorkloadFn,
    sample_resources: bool = False,
    extra_notes: Optional[dict] = None,
    setup_idle_warmup_s: float = 0.5,
) -> SummaryRecord:
    """Top-level helper: prep, run workload, sample resources, write results.

    `n_clients_to_prep` is the number of *isolated client workdirs* we need.
    For ZK-ARCHE this means that many enrolled devices; for EDHOC/mTLS the
    workdirs are still created (so client logs end up isolated) but no
    per-device state needs preparing.
    """
    if protocol_name not in PROTOCOLS:
        raise ValueError(f"unknown protocol: {protocol_name}")
    protocol = PROTOCOLS[protocol_name]
    config.require_binaries()

    if protocol.name == "mtls":
        ensure_mtls_certs(config.REPO_ROOT)

    work = _bench_workdir(test_name, protocol_name)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    server_workdir = work / "server"
    server_workdir.mkdir()
    clients_root = work / "clients"
    log_path = config.RESULTS_DIR / "logs" / f"{test_name}_{protocol_name}_server.log"

    # ZK-ARCHE: server needs --pairing during the (one-time) enrollment phase.
    # We then take the server down and bring it up again *without* pairing,
    # so the timed phase reflects normal-operation cost. server_workdir is
    # already fresh (we wiped `work` above), so the server starts with a clean
    # registry/replay/sk state.
    if protocol.name == "zkarche":
        # ----- Phase A: enrollment -----
        pairing_args = protocol.server_args_fn(server_workdir, True)
        server = start_server(
            protocol.server_bin,
            pairing_args,
            protocol.bind_addr,
            workdir=server_workdir,
            log_path=log_path.with_suffix(".pairing.log"),
        )
        try:
            client_workdirs = stamp_workdirs(
                template=None,  # fresh empty dirs; enrollment fills state/client/
                parent=clients_root, n=n_clients_to_prep, prefix="c",
            )
            print(f"[{test_name}/{protocol_name}] enrolling {n_clients_to_prep} clients ...")
            enroll_zkarche_clients(server, client_workdirs, PAIRING_TOKEN)
        finally:
            stop_server(server)
        # ----- Phase B: timed run, server *without* pairing -----
        timed_args = protocol.server_args_fn(server_workdir, False)
    else:
        timed_args = protocol.server_args_fn(server_workdir, False)
        client_workdirs = stamp_workdirs(
            template=None,
            parent=clients_root, n=n_clients_to_prep, prefix="c",
        )

    server = start_server(
        protocol.server_bin,
        timed_args,
        protocol.bind_addr,
        workdir=server_workdir,
        log_path=log_path,
    )
    sampler: Optional[ProcSampler] = None
    power_sampler = None  # type: Optional["pmic.PowerSampler"]
    try:
        # Brief idle warmup so the sampler captures real load, not spawn glitches.
        time.sleep(setup_idle_warmup_s)

        if sample_resources:
            sampler = ProcSampler(server.pid, interval_s=config.SAMPLER_INTERVAL_S)
            sampler.start()

            # Power meter: lazy import to avoid hard-coupling drivers that don't
            # need it. The static fallback reads CPU fraction from the proc
            # sampler so the two stay consistent.
            from . import pmic  # noqa: WPS433

            def _cpu_fraction_now() -> float:
                if not sampler.cpu_pct_samples:
                    return 0.0
                return sampler.cpu_pct_samples[-1] / 100.0

            meter = config.make_power_meter(_cpu_fraction_now)
            print(f"[{test_name}/{protocol_name}] power meter: {meter.describe()}")
            power_sampler = pmic.PowerSampler(meter, interval_s=0.1)
            power_sampler.start()

        ctx = TestContext(
            protocol=protocol,
            server=server,
            server_workdir=server_workdir,
            client_workdirs=client_workdirs,
        )
        results = workload(ctx)

        resources: Optional[ResourceSummary] = None
        energy = None  # type: Optional[pmic.EnergyResult]
        if sampler is not None:
            sampler.stop()
            resources = sampler.summary()
            print(
                f"[{test_name}/{protocol_name}] resources: "
                f"peak_rss={resources.peak_rss_mb:.2f} MB, "
                f"mean_cpu={resources.mean_cpu_pct:.1f}%, "
                f"peak_cpu={resources.peak_cpu_pct:.1f}%, "
                f"samples={resources.samples}"
            )
        if power_sampler is not None:
            power_sampler.stop()
            n_ok = sum(1 for r in results if r.success)
            energy = power_sampler.summary(n_auths=max(1, n_ok))
            print(
                f"[{test_name}/{protocol_name}] energy ({energy.method}): "
                f"mean={energy.mean_power_w:.2f} W over {energy.duration_s:.2f}s, "
                f"per-auth={energy.energy_per_auth_mJ:.2f} mJ "
                f"({energy.samples} samples)"
            )
    finally:
        stop_server(server)

    summary = summarise(
        test=test_name,
        protocol=protocol_name,
        results=results,
        resources=resources if sample_resources else None,
        energy=energy if sample_resources else None,
        extra_notes=extra_notes,
    )

    raw_csv = config.RESULTS_DIR / "raw" / f"{test_name}_{protocol_name}.csv"
    summary_json = config.RESULTS_DIR / "summary" / f"{test_name}_{protocol_name}.json"
    write_iterations_csv(raw_csv, results)
    write_summary_json(summary_json, summary)

    n_ok = sum(1 for r in results if r.success)
    print(
        f"[{test_name}/{protocol_name}] done: {n_ok}/{len(results)} ok, "
        f"mean latency={summary.latency_ms.mean:.3f} ms "
        f"(p95={summary.latency_ms.p95:.3f}, max={summary.latency_ms.max:.3f}), "
        f"-> {raw_csv.relative_to(config.REPO_ROOT)}"
    )
    return summary
