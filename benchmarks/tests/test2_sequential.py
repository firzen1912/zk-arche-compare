"""
Test 2 — Sequential Authentication (Single Client)

A single client performs N=50 authentications back-to-back against the server.
Tests whether per-session cost stays predictable across consecutive runs.

Usage:
    python -m benchmarks.tests.test2_sequential zkarche
    python -m benchmarks.tests.test2_sequential edhoc
    python -m benchmarks.tests.test2_sequential mtls
    python -m benchmarks.tests.test2_sequential all
"""

from __future__ import annotations

import sys

from benchmarks.lib import config
from benchmarks.lib.driver import TestContext, run_test
from benchmarks.lib.runner import ClientResult, run_clients_sequential


TEST_NAME = "test2_sequential"


def _make_workload(runs: int):
    def workload(ctx: TestContext) -> list[ClientResult]:
        wd = ctx.client_workdirs[0]
        args = ctx.protocol.client_args_fn(wd)
        return run_clients_sequential(
            ctx.protocol.client_bin, args, wd,
            runs=runs, timeout_s=30.0, client_id=0,
        )
    return workload


def run_for_protocol(protocol_name: str) -> None:
    n = config.TEST2_SEQUENTIAL_RUNS
    print(f"=== {TEST_NAME} / {protocol_name}: 1 client × {n} sequential auths ===")
    run_test(
        test_name=TEST_NAME,
        protocol_name=protocol_name,
        n_clients_to_prep=1,
        workload=_make_workload(n),
        sample_resources=False,
        extra_notes={"n_runs": n, "pattern": "sequential_single_client"},
    )


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
