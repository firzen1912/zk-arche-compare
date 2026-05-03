#!/usr/bin/env python3
"""Security Test 6: packet parser fuzzing wrapper."""
import argparse
from _run_util import add_common_args, run_logged


def main() -> int:
    p = argparse.ArgumentParser(description="Run cargo-fuzz against packet parsers.")
    add_common_args(p, "06_packet_fuzzing.log")
    p.add_argument("--seconds", type=int, default=60, help="Fuzzing duration in seconds")
    args = p.parse_args()
    return run_logged(
        ["cargo", "fuzz", "run", "packet_parsers", "--", f"-max_total_time={args.seconds}"],
        project=args.project,
        log_dir=args.log_dir,
        log_name=args.log_name,
        timeout=args.seconds + 60,
    )


if __name__ == "__main__":
    raise SystemExit(main())
