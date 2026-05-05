#!/usr/bin/env python3
"""Security Test 8: side-channel/RNG checklist and source-code hygiene scan."""
import argparse
import sys
from _run_util import add_common_args, run_logged


def main() -> int:
    p = argparse.ArgumentParser(description="Run RNG smoke checks and side-channel review checklist.")
    add_common_args(p, "08_side_channel_rng_analysis.log")
    p.add_argument("--samples", type=int, default=10000, help="32-byte RNG samples")
    p.add_argument("--csv", default="results/security/rng_sidechannel_check.csv", help="CSV output path")
    args = p.parse_args()
    return run_logged(
        [sys.executable, "security/rng_sidechannel_check.py", "--project", args.project, "--samples", str(args.samples), "--output", args.csv],
        project=args.project,
        log_dir=args.log_dir,
        log_name=args.log_name,
    )


if __name__ == "__main__":
    raise SystemExit(main())
