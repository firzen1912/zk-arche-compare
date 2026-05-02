"""
Test 1 — Concurrent Clients (Single Authentication)

50 clients each perform a single authentication concurrently against the
server. Reports per-client latency for each protocol.

Usage:
    python -m benchmarks.tests.test1_concurrent zkarche
    python -m benchmarks.tests.test1_concurrent edhoc
    python -m benchmarks.tests.test1_concurrent mtls
    python -m benchmarks.tests.test1_concurrent all
"""

from __future__ import annotations

import sys
from pathlib import Path

from benchmarks.lib import config
from benchmarks.lib.driver import TestContext, run_test
from benchmarks.lib.runner import ClientResult, run_clients_concurrent


TEST_NAME = "test1_concurrent"


def _make_workload(n_clients: int):
    def workload(ctx: TestContext) -> list[ClientResult]:
        binary = ctx.protocol.client_bin
        wds = ctx.client_workdirs

        def factory(i: int):
            args = ctx.protocol.client_args_fn(wds[i])
            return binary, args, wds[i]

        results = run_clients_concurrent(
            factory=factory,
            n_clients=n_clients,
            timeout_s=60.0,
            max_workers=min(n_clients, 64),
        )
        # Tag iter=0, client_id=i so the CSV is consistent with other tests.
        for i, r in enumerate(results):
            r.iteration = 0
            r.client_id = i
        return results
    return workload


def run_for_protocol(protocol_name: str) -> None:
    n = config.TEST1_CONCURRENT_CLIENTS
    print(f"=== {TEST_NAME} / {protocol_name}: {n} concurrent clients ===")
    run_test(
        test_name=TEST_NAME,
        protocol_name=protocol_name,
        n_clients_to_prep=n,
        workload=_make_workload(n),
        sample_resources=False,
        extra_notes={"n_clients": n, "pattern": "concurrent_single_auth"},
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
