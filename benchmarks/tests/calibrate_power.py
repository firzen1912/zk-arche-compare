"""
Calibrate the static-linear DevicePowerProfile (`idle_w`, `max_w`) for this host.

The harness's `StaticLinearMeter` falls back to per-platform defaults pulled
from public Pi power measurements, but those defaults are 5–20% off depending
on your specific board, PSU, and what's plugged in. This helper drives the
host into two known states:

  1. **idle**  — `time.sleep(N)` with no other workload.
  2. **load**  — saturate every CPU core for N seconds.

…while you watch a wall-plug power meter (or any other reference). At the end
it prints a suggested `DevicePowerProfile` line you can paste into
`benchmarks/lib/config.py`.

If `vcgencmd pmic_read_adc` is available (Pi 5) or an INA hwmon sensor is
wired in, the helper will *also* read those automatically and print the
measured numbers — at that point you can either trust them directly or use
them to sanity-check what your wall meter says.

Usage:

    python3 -m benchmarks.tests.calibrate_power
    python3 -m benchmarks.tests.calibrate_power --duration 30 --device pi5
"""

from __future__ import annotations

import argparse
import multiprocessing
import os
import sys
import time
from typing import Optional

from benchmarks.lib import config
from benchmarks.lib import pmic


def _burn() -> None:
    """100% CPU loop — runs in a child process; killed with terminate()."""
    while True:
        # Cheap arithmetic to keep this in pure Python without imports.
        x = 0
        for i in range(1_000_000):
            x = (x + i) ^ ((x << 1) & 0xFFFFFFFF)


def _spawn_burners(n: int) -> list[multiprocessing.Process]:
    procs: list[multiprocessing.Process] = []
    for _ in range(n):
        p = multiprocessing.Process(target=_burn, daemon=True)
        p.start()
        procs.append(p)
    return procs


def _stop_burners(procs: list[multiprocessing.Process]) -> None:
    for p in procs:
        p.terminate()
    for p in procs:
        p.join(timeout=1.0)


def _measure_phase(
    label: str,
    duration: float,
    burn: bool,
) -> Optional[pmic.EnergyResult]:
    """Run for `duration` seconds in the named phase, sampling power if a
    hardware meter is present. Returns None if no meter was found."""
    # Try the live meters; we don't want the static fallback for calibration.
    meter: Optional[pmic.PowerMeter] = None
    if pmic.VcgencmdPmicMeter.is_available():
        meter = pmic.VcgencmdPmicMeter()
    else:
        meter = pmic.HwmonInaMeter.autodetect()

    procs: list[multiprocessing.Process] = []
    if burn:
        ncpu = os.cpu_count() or 4
        procs = _spawn_burners(ncpu)

    sampler: Optional[pmic.PowerSampler] = None
    if meter is not None:
        sampler = pmic.PowerSampler(meter, interval_s=0.1)
        sampler.start()

    print(f"[calibrate] {label}: hold steady for {duration:.0f}s ...")
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(0.5)
        remaining = max(0, deadline - time.monotonic())
        print(f"  {label}: {remaining:.0f}s remaining   \r", end="", flush=True)
    print()

    if procs:
        _stop_burners(procs)

    if sampler is None:
        return None
    sampler.stop()
    return sampler.summary(n_auths=1)  # not really per-auth here


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=20.0,
                        help="seconds per phase (default: 20)")
    parser.add_argument("--device", default=None,
                        help="device name to print in the suggested profile line")
    args = parser.parse_args(argv[1:])

    profile = config.detect_device()
    device_label = args.device or profile.name

    print(f"[calibrate] host: {config.hostname()}, detected: {profile.name}")
    print(f"[calibrate] CPU cores: {os.cpu_count()}")
    print()

    # Idle phase
    idle = _measure_phase("idle", args.duration, burn=False)
    print()

    # Load phase
    load = _measure_phase("full load", args.duration, burn=True)
    print()

    if idle is None or load is None:
        print("[calibrate] no live power meter detected.")
        print()
        print("Without a meter we can't compute idle/max watts on-board. Please")
        print("watch a wall-plug power meter during each phase and read off the")
        print("steady-state value. Then update `_DEVICE_PROFILES` in")
        print("`benchmarks/lib/config.py`:")
        print()
        print(f'    "{device_label.lower().replace(" ", "_")}":'
              f' DevicePowerProfile("{device_label}", idle_w=<P_idle>, max_w=<P_max>,'
              f' cpu_cores={os.cpu_count() or 4}),')
        return 0

    print(f"[calibrate] live measurement ({idle.method}):")
    print(f"  idle: mean = {idle.mean_power_w:.2f} W (peak {idle.peak_power_w:.2f} W)")
    print(f"  load: mean = {load.mean_power_w:.2f} W (peak {load.peak_power_w:.2f} W)")
    print()
    print("Suggested entry for `_DEVICE_PROFILES` in `benchmarks/lib/config.py`:")
    print()
    print(f'    "{device_label.lower().replace(" ", "_").replace("(", "").replace(")", "")}":'
          f' DevicePowerProfile("{device_label}",'
          f' idle_w={idle.mean_power_w:.2f},'
          f' max_w={load.mean_power_w:.2f},'
          f' cpu_cores={os.cpu_count() or 4}),')
    print()
    print("If you also have a wall-plug meter, prefer those numbers since they")
    print("include PSU efficiency loss; the on-board PMIC reports SoC consumption")
    print("only (typically 5–10% lower than wall power).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
