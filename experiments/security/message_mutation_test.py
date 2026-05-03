#!/usr/bin/env python3
"""Security Test 2: near-valid message mutation regression test."""
import argparse
from _run_util import add_common_args, cargo_test_filter


def main() -> int:
    p = argparse.ArgumentParser(description="Run message mutation tests for packet/proof handling.")
    add_common_args(p, "02_message_mutation.log")
    args = p.parse_args()
    return cargo_test_filter(args, "message_mutation", "02_message_mutation.log")


if __name__ == "__main__":
    raise SystemExit(main())
