"""
Test 3 — High-Load Scenario (Busy Traffic)

N clients each perform M sequential authentication attempts. With the default
N=50, M=50 this generates 2500 authentications under sustained concurrent
demand.

We launch N parallel "session" workers; each worker holds its own enrolled
client workdir and runs M auths back-to-back. This mirrors the thesis's
50×50 setup.

Usage:
    python -m benchmarks.tests.test3_highload zkarche
    python -m benchmarks.tests.test3_highload edhoc
    python -m benchmarks.tests.test3_highload mtls
    python -m benchmarks.tests.test3_highload all
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from benchmarks.lib import config
from benchmarks.lib.driver import TestContext, run_test
from benchmarks.lib.runner import ClientResult, run_clients_sequential


TEST_NAME = "test3_highload"


def _make_workload(n_clients: int, runs_per_client: int):
    def workload(ctx: TestContext) -> list[ClientResult]:
        binary = ctx.protocol.client_bin
        wds = ctx.client_workdirs

        def session(i: int) -> list[ClientResult]:
            args = ctx.protocol.client_args_fn(wds[i])
            seq = run_clients_sequential(
                binary, args, wds[i],
                runs=runs_per_client, timeout_s=60.0,
                client_id=i, progress_every=0,
            )
            return seq

        all_results: list[ClientResult] = []
        with ThreadPoolExecutor(max_workers=min(n_clients, 64)) as ex:
            futs = {ex.submit(session, i): i for i in range(n_clients)}
            done = 0
            for fut in as_completed(futs):
                i = futs[fut]
                try:
                    all_results.extend(fut.result())
                except Exception as e:  # noqa: BLE001
                    all_results.append(ClientResult(
                        iteration=0, client_id=i, success=False,
                        duration_ms=None, sent_bytes=None, recv_bytes=None,
                        stderr_tail=f"session {i} crashed: {e}",
                    ))
                done += 1
                if done % max(1, n_clients // 10) == 0:
                    print(f"  [{TEST_NAME}] sessions done: {done}/{n_clients}")
        return all_results
    return workload


def run_for_protocol(protocol_name: str) -> None:
    n_clients = config.TEST3_CLIENTS
    runs = config.TEST3_RUNS_PER_CLIENT
    print(f"=== {TEST_NAME} / {protocol_name}: {n_clients} × {runs} = {n_clients*runs} auths ===")
    run_test(
        test_name=TEST_NAME,
        protocol_name=protocol_name,
        n_clients_to_prep=n_clients,
        workload=_make_workload(n_clients, runs),
        sample_resources=False,
        extra_notes={
            "n_clients": n_clients,
            "runs_per_client": runs,
            "pattern": "concurrent_sequential_highload",
        },
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
