#!/usr/bin/env python3
"""Security Test 7: replay-cache duplicate nonce and eviction behavior."""
import argparse
from _run_util import add_common_args, cargo_test_filter


def main() -> int:
    p = argparse.ArgumentParser(description="Run replay-cache regression tests.")
    add_common_args(p, "07_replay_cache.log")
    args = p.parse_args()
    return cargo_test_filter(args, "replay_cache", "07_replay_cache.log")


if __name__ == "__main__":
    raise SystemExit(main())
