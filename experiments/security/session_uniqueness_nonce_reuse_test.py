#!/usr/bin/env python3
"""Security Test 5: session-key freshness and nonce-reuse smoke tests."""
import argparse
from _run_util import add_common_args, cargo_test_filter


def main() -> int:
    p = argparse.ArgumentParser(description="Run session uniqueness and nonce-reuse tests.")
    add_common_args(p, "05_session_uniqueness_nonce_reuse.log")
    args = p.parse_args()
    return cargo_test_filter(args, "session_uniqueness", "05_session_uniqueness_nonce_reuse.log")


if __name__ == "__main__":
    raise SystemExit(main())
