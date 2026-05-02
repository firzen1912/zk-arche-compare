"""
Centralized configuration for the ZK-ARCHE benchmark harness.

The same harness runs on Pi 3B+, Pi 4, Pi 5, and laptop/server-class machines.
Defaults below match the thesis's evaluation methodology; override via env vars
(ZKB_*) when running specific scenarios.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Repository layout
# ---------------------------------------------------------------------------

# benchmarks/lib/config.py  ->  benchmarks/  ->  repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_ROOT = REPO_ROOT / "benchmarks"
RESULTS_DIR = BENCH_ROOT / "results"
PLOTS_DIR = BENCH_ROOT / "plots"
GRAPHS_OUT_DIR = BENCH_ROOT / "graphs_tex"  # PGFPlots .tex files for the thesis
TARGET_BIN_DIR = REPO_ROOT / "target" / "release"


# ---------------------------------------------------------------------------
# Default test sizes (overridable via env)
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return int(v) if v else default

# Test 1: concurrent clients each performing a single authentication.
TEST1_CONCURRENT_CLIENTS = _env_int("ZKB_T1_CLIENTS", 50)

# Test 2: sequential authentications from a single client.
TEST2_SEQUENTIAL_RUNS = _env_int("ZKB_T2_RUNS", 50)

# Test 3: high-load — N clients each performing M sequential authentications.
TEST3_CLIENTS = _env_int("ZKB_T3_CLIENTS", 50)
TEST3_RUNS_PER_CLIENT = _env_int("ZKB_T3_RUNS", 50)

# Tests 4/5/6: resource sampling parameters. We re-use Test 3's load pattern
# because that's what the thesis describes ("during authentication") and it
# gives a realistic peak.
TEST_RESOURCES_CLIENTS = _env_int("ZKB_TR_CLIENTS", 50)
TEST_RESOURCES_RUNS_PER_CLIENT = _env_int("ZKB_TR_RUNS", 5)

# Sampler frequency for /proc-based monitoring.
SAMPLER_INTERVAL_S = float(os.environ.get("ZKB_SAMPLE_S", "0.05"))


# ---------------------------------------------------------------------------
# Server bind addresses (binaries' built-in defaults)
# ---------------------------------------------------------------------------

ZKARCHE_BIND = os.environ.get("ZKB_ZK_BIND", "127.0.0.1:4000")
EDHOC_BIND = os.environ.get("ZKB_EDHOC_BIND", "127.0.0.1:5688")
MTLS_BIND = os.environ.get("ZKB_MTLS_BIND", "127.0.0.1:7443")
MTLS_SNI = os.environ.get("ZKB_MTLS_SNI", "localhost")


# ---------------------------------------------------------------------------
# Device profiles for energy estimation
# ---------------------------------------------------------------------------
#
# Energy estimate uses the standard approach: E ≈ P_avg × t, where
#   P_avg ≈ P_idle + (P_max - P_idle) × cpu_fraction.
#
# The numbers below are typical wall-power figures for the named device under
# active CPU load with no display attached. They match values commonly cited
# in the embedded-systems literature (Raspberry Pi Foundation power notes,
# independent reviews). Override per-deployment by setting ZKB_DEVICE.

@dataclass(frozen=True)
class DevicePowerProfile:
    name: str
    idle_w: float       # idle wall-power draw (W)
    max_w: float        # peak wall-power draw under 100% CPU on all cores (W)
    cpu_cores: int      # for normalising CPU% across hosts


_DEVICE_PROFILES: dict[str, DevicePowerProfile] = {
    # Pi 3B+: ~2.0 W idle, ~3.7 W stress (Eames raspi.tv 2018; ecoenergygeek 2026).
    "pi3bplus": DevicePowerProfile("Raspberry Pi 3B+", idle_w=2.0, max_w=3.7, cpu_cores=4),
    # Pi 4 (4GB): 2.85 W idle (Eames), ~6.4 W stress (pidramble; tomshardware 7.6 W).
    "pi4":      DevicePowerProfile("Raspberry Pi 4 (4GB)", idle_w=2.85, max_w=6.4, cpu_cores=4),
    # Pi 5 (8GB): 3.0 W idle headless (raspberry.tips); up to 8.8 W stress.
    "pi5":      DevicePowerProfile("Raspberry Pi 5 (8GB)", idle_w=3.0, max_w=8.0, cpu_cores=4),
    "generic":  DevicePowerProfile("Generic Linux Host", idle_w=10.0, max_w=45.0,
                                   cpu_cores=os.cpu_count() or 4),
}


def detect_device() -> DevicePowerProfile:
    """Pick a power profile.

    Priority:
      1. $ZKB_DEVICE env var if it names a known profile
      2. /proc/device-tree/model for Pis
      3. fallback "generic"
    """
    override = os.environ.get("ZKB_DEVICE", "").strip().lower()
    if override and override in _DEVICE_PROFILES:
        return _DEVICE_PROFILES[override]

    model_path = Path("/proc/device-tree/model")
    if model_path.exists():
        try:
            model = model_path.read_text(errors="ignore").strip("\x00").strip().lower()
        except OSError:
            model = ""
        if "raspberry pi 5" in model:
            return _DEVICE_PROFILES["pi5"]
        if "raspberry pi 4" in model:
            return _DEVICE_PROFILES["pi4"]
        if "raspberry pi 3" in model and "+" in model:
            return _DEVICE_PROFILES["pi3bplus"]

    return _DEVICE_PROFILES["generic"]


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

def _bin(name: str) -> Path:
    """Path to a built binary; might not exist yet at import time."""
    suffix = ".exe" if platform.system() == "Windows" else ""
    return TARGET_BIN_DIR / f"{name}{suffix}"


ZKARCHE_SERVER = _bin("zkarche_server")
ZKARCHE_CLIENT = _bin("zkarche_client")
EDHOC_SERVER = _bin("edhoc_server")
EDHOC_CLIENT = _bin("edhoc_client")
MTLS_SERVER = _bin("mtls_server")
MTLS_CLIENT = _bin("mtls_client")


def all_binaries() -> dict[str, Path]:
    return {
        "zkarche_server": ZKARCHE_SERVER,
        "zkarche_client": ZKARCHE_CLIENT,
        "edhoc_server": EDHOC_SERVER,
        "edhoc_client": EDHOC_CLIENT,
        "mtls_server": MTLS_SERVER,
        "mtls_client": MTLS_CLIENT,
    }


def require_binaries() -> None:
    """Fail fast with a clear message if any binary is missing."""
    missing = [name for name, p in all_binaries().items() if not p.exists()]
    if missing:
        raise SystemExit(
            "Missing release binaries: "
            + ", ".join(missing)
            + "\nRun: bash benchmarks/setup.sh"
        )


# ---------------------------------------------------------------------------
# Misc utilities
# ---------------------------------------------------------------------------

def hostname() -> str:
    return socket.gethostname()


def short_git_rev() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT, stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# ---------------------------------------------------------------------------
# Power meter factory
# ---------------------------------------------------------------------------
#
# Picks the best available power-measurement back-end given the environment.
# Override with ZKB_POWER_METER=pmic|hwmon|static if you want to force one.

def make_power_meter(cpu_fraction_provider):
    """Return a `lib.pmic.PowerMeter` selected via environment + auto-detection.

    `cpu_fraction_provider` is a 0-arg callable returning the current
    system-wide CPU utilisation fraction (0..1). It's only used when we
    fall back to the static linear model.
    """
    # Local import so `config` stays import-cheap for callers that don't
    # need the meter (e.g. plot.py).
    from . import pmic

    forced = os.environ.get("ZKB_POWER_METER", "auto").strip().lower()
    profile = detect_device()

    def _static() -> "pmic.PowerMeter":
        return pmic.StaticLinearMeter(profile.idle_w, profile.max_w, cpu_fraction_provider)

    if forced == "static":
        return _static()
    if forced == "pmic":
        if pmic.VcgencmdPmicMeter.is_available():
            return pmic.VcgencmdPmicMeter()
        raise SystemExit("ZKB_POWER_METER=pmic but vcgencmd pmic_read_adc is unavailable")
    if forced == "hwmon":
        m = pmic.HwmonInaMeter.autodetect()
        if m is None:
            raise SystemExit("ZKB_POWER_METER=hwmon but no INA hwmon device found")
        return m

    # auto: try PMIC, then INA hwmon, then static
    if pmic.VcgencmdPmicMeter.is_available():
        return pmic.VcgencmdPmicMeter()
    m = pmic.HwmonInaMeter.autodetect()
    if m is not None:
        return m
    return _static()
