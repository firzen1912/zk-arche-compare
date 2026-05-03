#!/usr/bin/env python3
"""
RNG and side-channel checklist harness.

This script performs lightweight, automatable checks that support the manual
side-channel/RNG analysis section:
  - Linux entropy source availability
  - duplicate nonce scan over os.urandom samples
  - bit-balance smoke test
  - source-code grep for dangerous logging of secrets
  - source-code grep for zeroize usage

It is not a replacement for formal side-channel evaluation, power analysis, or
constant-time proof. It creates an auditable CSV checklist for the thesis repo.
"""

import argparse
import csv
import os
import re
import subprocess
from pathlib import Path

SECRET_PATTERNS = [
    r"println!.*(secret|private|scalar|session_key|pairing_token|device_root)",
    r"log::(debug|info|warn|error)!.*(secret|private|scalar|session_key|pairing_token|device_root)",
    r"dbg!\(.*(secret|private|scalar|session_key|pairing_token|device_root)",
]


def read_entropy_avail() -> str:
    p = Path("/proc/sys/kernel/random/entropy_avail")
    if p.exists():
        return p.read_text().strip()
    return "unavailable"


def rng_smoke(samples: int):
    seen = set()
    ones = 0
    duplicate = False
    for _ in range(samples):
        b = os.urandom(32)
        if b in seen:
            duplicate = True
        seen.add(b)
        ones += sum(x.bit_count() for x in b)
    total_bits = samples * 32 * 8
    ratio = ones / total_bits
    return duplicate, ratio


def grep_source(root: Path, patterns):
    findings = []
    src = root / "src"
    if not src.exists():
        return ["src directory not found"]
    for path in src.rglob("*.rs"):
        text = path.read_text(errors="ignore")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(f"{path.relative_to(root)}:{lineno}:{line.strip()}")
    return findings


def cargo_tree_has(root: Path, needle: str) -> bool:
    try:
        out = subprocess.run(
            ["cargo", "tree"], cwd=root, text=True, capture_output=True, timeout=30
        )
        return needle.lower() in (out.stdout + out.stderr).lower()
    except Exception:
        cargo_toml = (root / "Cargo.toml").read_text(errors="ignore") if (root / "Cargo.toml").exists() else ""
        return needle.lower() in cargo_toml.lower()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default=".", help="Repository root")
    ap.add_argument("--samples", type=int, default=10000)
    ap.add_argument("--output", default="rng_sidechannel_check.csv")
    args = ap.parse_args()

    root = Path(args.project).resolve()
    duplicate, bit_ratio = rng_smoke(args.samples)
    secret_log_findings = grep_source(root, SECRET_PATTERNS)
    zeroize_present = cargo_tree_has(root, "zeroize")
    subtle_present = cargo_tree_has(root, "subtle")

    rows = [
        {"check": "entropy_avail", "status": "INFO", "detail": read_entropy_avail()},
        {"check": "rng_duplicate_32byte_samples", "status": "FAIL" if duplicate else "PASS", "detail": f"samples={args.samples}"},
        {"check": "rng_bit_balance", "status": "PASS" if 0.48 <= bit_ratio <= 0.52 else "WARN", "detail": f"ones_ratio={bit_ratio:.6f}"},
        {"check": "zeroize_dependency", "status": "PASS" if zeroize_present else "WARN", "detail": "zeroize present" if zeroize_present else "zeroize not found"},
        {"check": "constant_time_dependency", "status": "PASS" if subtle_present else "WARN", "detail": "subtle present" if subtle_present else "subtle not found"},
        {"check": "secret_logging_grep", "status": "PASS" if not secret_log_findings else "WARN", "detail": "none" if not secret_log_findings else " | ".join(secret_log_findings[:20])},
        {"check": "manual_side_channel_review", "status": "TODO", "detail": "Review scalar multiplication, equality checks, logs, debug builds, power traces if available."},
    ]

    output = Path(args.output)
    with output.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["check", "status", "detail"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved RNG/side-channel checklist CSV: {output.resolve()}")
    for row in rows:
        print(f"{row['status']:>4} | {row['check']}: {row['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
