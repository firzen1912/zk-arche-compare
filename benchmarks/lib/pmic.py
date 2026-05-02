"""
Live power measurement for the energy figures.

Three meter back-ends, picked at runtime in this priority order:

  1. **VcgencmdPmicMeter** — Pi 5 only. Reads `vcgencmd pmic_read_adc` and
     sums per-rail power. This is *hardware-measured* SoC power consumption,
     not a model: the DA9091 PMIC exposes voltage/current per rail and the
     `vcgencmd` helper just dumps them. Numbers reported here are roughly
     5–10% lower than wall-plug power because they don't account for the
     5 V→PMIC regulator efficiency, but for "energy used by the cryptographic
     workload" that's actually the right number to report (we want the chip's
     consumption, not the PSU's losses).

  2. **HwmonInaMeter** — for Pi 4 / Pi 3B+ users who have wired up an INA219,
     INA226, or INA260 sensor on the input rail. The Linux `ina2xx` driver
     exposes it under `/sys/class/hwmon/hwmonN/{voltage_input,current_input,power_input}`.
     We just read those files. This is the gold standard if you have the
     hardware: actual wall-plug power.

  3. **StaticLinearMeter** — fallback. Uses the standard model
        P_avg ≈ P_idle + (P_max − P_idle) · u_cpu
     with `(P_idle, P_max)` from the configured DevicePowerProfile. This is
     what the harness shipped with originally; it's now one option among
     three rather than the only one.

The meter runs in a background sampler thread during the workload, and at
the end emits total energy (Joules) and per-auth energy (mJ).
"""

from __future__ import annotations

import abc
import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Common interface
# ---------------------------------------------------------------------------

@dataclass
class EnergyResult:
    method: str            # "pmic" | "hwmon-ina" | "static"
    duration_s: float
    samples: int
    mean_power_w: float
    peak_power_w: float
    energy_j: float        # mean_power × duration; preferred output
    energy_per_auth_mJ: float
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "duration_s": self.duration_s,
            "samples": self.samples,
            "mean_power_w": self.mean_power_w,
            "peak_power_w": self.peak_power_w,
            "energy_j": self.energy_j,
            "energy_per_auth_mJ": self.energy_per_auth_mJ,
            "note": self.note,
        }


class PowerMeter(abc.ABC):
    """Reads instantaneous power in watts on demand."""
    method_name: str = "abstract"

    @abc.abstractmethod
    def read_power_w(self) -> float:
        ...

    def describe(self) -> str:
        return self.method_name


# ---------------------------------------------------------------------------
# Pi 5 PMIC via vcgencmd
# ---------------------------------------------------------------------------

class VcgencmdPmicMeter(PowerMeter):
    """Read per-rail power from the Pi 5 PMIC via `vcgencmd pmic_read_adc`.

    Output of the command looks like:

        3V7_WL_SW_A current(0)=0.06420288A
        3V7_WL_SW_V volt(8)=3.69140625V
        ...
        EXT5V_V volt(24)=4.96093750V
        BATT_V volt(25)=4.20312500V

    Rails come in pairs of `<NAME>_A` (current) and `<NAME>_V` (voltage). We
    sum power across all named rails (excluding `EXT5V` and `BATT` which are
    bus voltages, not loads). The thread-safety story: vcgencmd is a separate
    process call so re-entrancy is not a concern, but the call itself takes
    ~5 ms which is why `PowerSampler` uses a 100 ms sample interval.
    """

    method_name = "pmic"
    _BUS_RAILS = {"EXT5V", "BATT"}  # voltage-only, no associated current rail

    def __init__(self, vcgencmd_path: str = "vcgencmd"):
        self.vcgencmd = vcgencmd_path

    @classmethod
    def is_available(cls) -> bool:
        if shutil.which("vcgencmd") is None:
            return False
        try:
            out = subprocess.run(
                ["vcgencmd", "pmic_read_adc"],
                capture_output=True, timeout=2.0, check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        if out.returncode != 0:
            return False
        # Pi 4 has `vcgencmd` but `pmic_read_adc` either returns an error or
        # a much shorter list. Pi 5 typically returns 30+ lines.
        return out.stdout.count(b"\n") >= 10

    def read_power_w(self) -> float:
        try:
            out = subprocess.run(
                [self.vcgencmd, "pmic_read_adc"],
                capture_output=True, timeout=2.0, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return float("nan")

        currents: dict[str, float] = {}
        voltages: dict[str, float] = {}
        for raw_line in out.stdout.decode(errors="replace").splitlines():
            line = raw_line.strip()
            if not line or "=" not in line:
                continue
            label_part, _, value_part = line.partition("=")
            label = label_part.split(" ", 1)[0]      # e.g. "3V7_WL_SW_A"
            if len(label) < 3 or label[-2] != "_":
                continue
            kind = label[-1]
            rail = label[:-2]
            try:
                value = float(value_part.rstrip().rstrip("AVavWw"))
            except ValueError:
                continue
            if kind == "A":
                currents[rail] = value
            elif kind == "V":
                voltages[rail] = value

        total_w = 0.0
        for rail, amps in currents.items():
            if rail in self._BUS_RAILS:
                continue
            volts = voltages.get(rail)
            if volts is None:
                continue
            total_w += abs(volts * amps)
        return total_w


# ---------------------------------------------------------------------------
# INA219 / INA226 / INA260 via /sys/class/hwmon
# ---------------------------------------------------------------------------

class HwmonInaMeter(PowerMeter):
    """Read input power from an INA2xx sensor exposed by the kernel hwmon driver.

    Wiring example (Pi GPIO I²C, INA260 module on the 5 V input rail):

        sudo modprobe ina2xx
        echo ina260 0x40 | sudo tee /sys/class/i2c-adapter/i2c-1/new_device

    The driver creates `/sys/class/hwmon/hwmonN/in1_input` (voltage in mV),
    `curr1_input` (current in mA), and `power1_input` (power in µW).
    We use `power1_input` if present, else compute V × I.

    Pass the explicit `hwmon_dir` if you have multiple hwmon devices and
    auto-detection isn't picking the right one.
    """

    method_name = "hwmon-ina"

    def __init__(self, hwmon_dir: Path):
        self.hwmon_dir = Path(hwmon_dir)
        # Probe which channel suffix the driver exposes (1, 2, 3, ...).
        self._channel = self._detect_channel()

    @classmethod
    def autodetect(cls) -> Optional["HwmonInaMeter"]:
        """Return a meter instance if a likely INA hwmon entry is present."""
        base = Path("/sys/class/hwmon")
        if not base.exists():
            return None
        for entry in sorted(base.iterdir()):
            try:
                name = (entry / "name").read_text().strip().lower()
            except (FileNotFoundError, OSError):
                continue
            if name.startswith("ina2"):
                return cls(entry.resolve())
        return None

    def _detect_channel(self) -> int:
        for ch in (1, 2, 3, 4):
            if (self.hwmon_dir / f"power{ch}_input").exists():
                return ch
            if (self.hwmon_dir / f"curr{ch}_input").exists() and (self.hwmon_dir / f"in{ch}_input").exists():
                return ch
        raise FileNotFoundError(f"no INA channel found under {self.hwmon_dir}")

    def read_power_w(self) -> float:
        ch = self._channel
        # Prefer power_input if the driver populated it (INA260 does; INA219 may not).
        p_path = self.hwmon_dir / f"power{ch}_input"
        if p_path.exists():
            try:
                return int(p_path.read_text().strip()) / 1_000_000.0  # µW → W
            except ValueError:
                pass
        # Fallback: V × I from in*_input (mV) and curr*_input (mA).
        try:
            v_mv = int((self.hwmon_dir / f"in{ch}_input").read_text().strip())
            i_ma = int((self.hwmon_dir / f"curr{ch}_input").read_text().strip())
        except (FileNotFoundError, ValueError):
            return float("nan")
        return (v_mv / 1000.0) * (i_ma / 1000.0)


# ---------------------------------------------------------------------------
# Static linear model fallback
# ---------------------------------------------------------------------------

class StaticLinearMeter(PowerMeter):
    """Linear-model power estimator from the device profile.

    `cpu_fraction_provider` is a 0-arg callable returning the *current*
    system-wide CPU utilisation fraction (0..1). The meter then returns
    `idle_w + (max_w − idle_w) × u_cpu`. The CPU fraction is normally
    supplied by the same /proc sampler that captures CPU% for the resource
    figures, so the two stay consistent.
    """

    method_name = "static"

    def __init__(self, idle_w: float, max_w: float, cpu_fraction_provider):
        self.idle_w = float(idle_w)
        self.max_w = float(max_w)
        self.cpu_fraction_provider = cpu_fraction_provider

    def read_power_w(self) -> float:
        try:
            u = float(self.cpu_fraction_provider())
        except (TypeError, ValueError):
            u = 0.0
        u = max(0.0, min(1.0, u))
        return self.idle_w + (self.max_w - self.idle_w) * u


# ---------------------------------------------------------------------------
# Sampler wrapper
# ---------------------------------------------------------------------------

class PowerSampler:
    """Background thread that polls a PowerMeter at fixed intervals.

    Use it as:

        sampler = PowerSampler(meter, interval_s=0.1)
        sampler.start()
        ... run workload ...
        sampler.stop()
        result = sampler.summary(n_auths=N)

    The sampler computes mean and peak watts across the captured interval,
    multiplies by the wall-clock duration to get total joules, and divides
    by `n_auths` to produce per-auth millijoules.
    """

    def __init__(self, meter: PowerMeter, interval_s: float = 0.1):
        self.meter = meter
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._samples: list[float] = []
        self._t0: Optional[float] = None
        self._t1: Optional[float] = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            p = self.meter.read_power_w()
            if p == p and p > 0:  # not NaN
                self._samples.append(p)
            self._stop.wait(self.interval_s)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("sampler already started")
        self._t0 = time.monotonic()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name=f"power-{self.meter.method_name}",
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=1.0)
        self._t1 = time.monotonic()
        self._thread = None

    def summary(self, n_auths: int) -> EnergyResult:
        duration = (self._t1 or time.monotonic()) - (self._t0 or time.monotonic())
        if not self._samples:
            return EnergyResult(
                method=self.meter.method_name, duration_s=duration, samples=0,
                mean_power_w=float("nan"), peak_power_w=float("nan"),
                energy_j=float("nan"), energy_per_auth_mJ=float("nan"),
                note="no power samples captured",
            )
        mean = sum(self._samples) / len(self._samples)
        peak = max(self._samples)
        energy_j = mean * duration
        per_auth_mJ = (energy_j / max(1, n_auths)) * 1000.0
        return EnergyResult(
            method=self.meter.method_name,
            duration_s=duration,
            samples=len(self._samples),
            mean_power_w=mean,
            peak_power_w=peak,
            energy_j=energy_j,
            energy_per_auth_mJ=per_auth_mJ,
        )
