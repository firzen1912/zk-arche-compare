#!/usr/bin/env python3
"""Security Test 1: transcript-binding regression test."""
import argparse
from _run_util import add_common_args, cargo_test_filter


def main() -> int:
    p = argparse.ArgumentParser(description="Run transcript-binding tests for ZK-ARCHE.")
    add_common_args(p, "01_transcript_binding.log")
    args = p.parse_args()
    return cargo_test_filter(args, "transcript_binding", "01_transcript_binding.log")


if __name__ == "__main__":
    raise SystemExit(main())
