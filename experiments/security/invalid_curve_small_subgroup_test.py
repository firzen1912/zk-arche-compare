#!/usr/bin/env python3
"""Security Test 3: invalid curve, identity point, and scalar encoding checks."""
import argparse
from _run_util import add_common_args, cargo_test_filter


def main() -> int:
    p = argparse.ArgumentParser(description="Run invalid-curve/small-subgroup/canonical-scalar tests.")
    add_common_args(p, "03_invalid_curve_small_subgroup.log")
    args = p.parse_args()
    return cargo_test_filter(args, "invalid_curve_small_subgroup", "03_invalid_curve_small_subgroup.log")


if __name__ == "__main__":
    raise SystemExit(main())
