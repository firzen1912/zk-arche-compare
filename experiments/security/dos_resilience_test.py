#!/usr/bin/env python3
"""
DoS resilience harness for authentication servers.

The harness sends malformed, oversized, idle, and slow-drip TCP inputs to a
running server and records whether the target remains reachable after the test.
It is intentionally protocol-agnostic and can be used against ZK-ARCHE, EDHOC,
or mTLS ports. For TLS, malformed plaintext will be rejected by the TLS stack;
that rejection is expected.

Examples:
  python3 security/dos_resilience_test.py --host 127.0.0.1 --port 4000 --protocol zkarche
  python3 security/dos_resilience_test.py --host 127.0.0.1 --port 5688 --protocol edhoc
  python3 security/dos_resilience_test.py --host 127.0.0.1 --port 7443 --protocol mtls
"""

import argparse
import csv
import os
import random
import socket
import struct
import threading
import time
from pathlib import Path


def connect(host: str, port: int, timeout: float = 2.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def send_random_bytes(host: str, port: int, count: int, payload_len: int) -> int:
    failures = 0
    for _ in range(count):
        try:
            with connect(host, port) as s:
                s.sendall(os.urandom(payload_len))
                try:
                    s.recv(64)
                except Exception:
                    pass
        except Exception:
            failures += 1
    return failures


def send_oversized_frames(host: str, port: int, count: int, claimed_len: int) -> int:
    failures = 0
    for _ in range(count):
        try:
            with connect(host, port) as s:
                s.sendall(struct.pack(">I", claimed_len))
                s.sendall(os.urandom(32))
        except Exception:
            failures += 1
    return failures


def idle_connection(host: str, port: int, hold_seconds: float) -> None:
    try:
        with connect(host, port, timeout=3.0) as s:
            time.sleep(hold_seconds)
    except Exception:
        pass


def slow_drip(host: str, port: int, bytes_to_send: int, delay: float) -> None:
    try:
        with connect(host, port, timeout=3.0) as s:
            for _ in range(bytes_to_send):
                s.sendall(bytes([random.randrange(0, 256)]))
                time.sleep(delay)
    except Exception:
        pass


def reachability_probe(host: str, port: int) -> bool:
    try:
        with connect(host, port, timeout=2.0):
            return True
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Protocol-agnostic malformed-traffic DoS test harness.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--protocol", default="zkarche")
    ap.add_argument("--random-connections", type=int, default=100)
    ap.add_argument("--oversized-connections", type=int, default=50)
    ap.add_argument("--idle-connections", type=int, default=25)
    ap.add_argument("--slow-connections", type=int, default=25)
    ap.add_argument("--hold-seconds", type=float, default=6.0)
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    output = Path(args.output or f"{args.protocol}_dos_resilience_results.csv")
    rows = []

    started_reachable = reachability_probe(args.host, args.port)
    rows.append({"test": "initial_reachability", "value": int(started_reachable), "note": "1 means TCP port accepted connection"})

    t0 = time.perf_counter()
    failures = send_random_bytes(args.host, args.port, args.random_connections, 128)
    rows.append({"test": "random_bytes", "value": failures, "note": f"failures out of {args.random_connections}"})

    failures = send_oversized_frames(args.host, args.port, args.oversized_connections, 10_000_000)
    rows.append({"test": "oversized_frame", "value": failures, "note": f"failures out of {args.oversized_connections}"})

    threads = []
    for _ in range(args.idle_connections):
        t = threading.Thread(target=idle_connection, args=(args.host, args.port, args.hold_seconds), daemon=True)
        t.start()
        threads.append(t)

    for _ in range(args.slow_connections):
        t = threading.Thread(target=slow_drip, args=(args.host, args.port, 16, 0.35), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=args.hold_seconds + 5)

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    finished_reachable = reachability_probe(args.host, args.port)
    rows.append({"test": "final_reachability", "value": int(finished_reachable), "note": "1 means server remained reachable"})
    rows.append({"test": "elapsed_ms", "value": f"{elapsed_ms:.3f}", "note": "total DoS harness wall time"})

    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["test", "value", "note"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved DoS resilience CSV: {output.resolve()}")
    for r in rows:
        print(f"{r['test']}: {r['value']} ({r['note']})")

    return 0 if finished_reachable else 2


if __name__ == "__main__":
    raise SystemExit(main())
