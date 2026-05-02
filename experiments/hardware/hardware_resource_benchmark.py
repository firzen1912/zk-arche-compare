#!/usr/bin/env python3
"""
Hardware resource benchmark wrapper for authentication experiments.

Measures per-run:
  - wall-clock latency (ms)
  - process CPU time (user + system)
  - normalized CPU utilization (%) = cpu_time / (wall_time * cores) * 100
  - peak RSS memory (MB)
  - optional power and energy from a hardware power sensor
  - optional estimated energy from a fixed power value

Designed for Raspberry Pi 3B+, Raspberry Pi 4, Raspberry Pi 5 clients and
Ubuntu/x86 servers, but works on normal Linux systems as well.

Examples:
  python3 hardware_resource_benchmark.py \
    --protocol zkarche \
    --device "Raspberry Pi 4" \
    --role client \
    --runs 50 \
    --cmd './target/release/zkarche_client 192.168.1.10:9000' \
    --power-mode fixed \
    --fixed-power-watts 3.2

  python3 hardware_resource_benchmark.py \
    --protocol mtls \
    --device "Raspberry Pi 5" \
    --role client \
    --runs 50 \
    --cmd './target/release/mtls_client 192.168.1.10:7443 localhost' \
    --power-mode hwmon \
    --power-path /sys/class/hwmon/hwmon2/power1_input \
    --power-unit microwatt

  python3 hardware_resource_benchmark.py \
    --protocol edhoc \
    --device "Core i7-6770HQ" \
    --role server \
    --runs 1 \
    --cmd './target/release/edhoc_server 0.0.0.0:5688' \
    --workload-cmd './run_50_clients.sh' \
    --stop-target-after-workload
"""

import argparse
import csv
import os
import platform
import shlex
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    print("ERROR: psutil is required. Install it with: python3 -m pip install psutil", file=sys.stderr)
    sys.exit(1)


@dataclass
class PowerSample:
    watts: Optional[float]
    source: str


class PowerReader:
    def __init__(self, args: argparse.Namespace):
        self.mode = args.power_mode
        self.fixed_power_watts = args.fixed_power_watts
        self.power_path = Path(args.power_path) if args.power_path else None
        self.voltage_path = Path(args.voltage_path) if args.voltage_path else None
        self.current_path = Path(args.current_path) if args.current_path else None
        self.power_unit = args.power_unit
        self.voltage_unit = args.voltage_unit
        self.current_unit = args.current_unit

    @staticmethod
    def _read_float(path: Path) -> Optional[float]:
        try:
            return float(path.read_text().strip())
        except Exception:
            return None

    @staticmethod
    def _scale(value: float, unit: str) -> float:
        unit = unit.lower()
        if unit in ("w", "watt", "watts", "v", "volt", "volts", "a", "amp", "amps"):
            return value
        if unit in ("mw", "milliwatt", "millivolt", "ma", "milliamp"):
            return value / 1_000.0
        if unit in ("uw", "microwatt", "microvolt", "ua", "microamp"):
            return value / 1_000_000.0
        raise ValueError(f"Unsupported unit: {unit}")

    def read(self) -> PowerSample:
        if self.mode == "none":
            return PowerSample(None, "none")

        if self.mode == "fixed":
            return PowerSample(float(self.fixed_power_watts), "fixed")

        if self.mode == "hwmon":
            # Preferred: direct power input, commonly /sys/class/hwmon/.../power1_input.
            if self.power_path:
                raw = self._read_float(self.power_path)
                if raw is not None:
                    watts = self._scale(raw, self.power_unit)
                    return PowerSample(watts, f"hwmon:{self.power_path}")

            # Alternative: voltage * current.
            if self.voltage_path and self.current_path:
                raw_v = self._read_float(self.voltage_path)
                raw_i = self._read_float(self.current_path)
                if raw_v is not None and raw_i is not None:
                    volts = self._scale(raw_v, self.voltage_unit)
                    amps = self._scale(raw_i, self.current_unit)
                    return PowerSample(volts * amps, f"hwmon:{self.voltage_path},{self.current_path}")

            return PowerSample(None, "hwmon_unavailable")

        raise ValueError(f"Unsupported power mode: {self.mode}")


def process_tree_cpu_times(proc: psutil.Process) -> Tuple[float, float]:
    user = 0.0
    system = 0.0
    processes = [proc]
    try:
        processes.extend(proc.children(recursive=True))
    except psutil.Error:
        pass

    for p in processes:
        try:
            ct = p.cpu_times()
            user += ct.user
            system += ct.system
        except psutil.Error:
            continue
    return user, system


def process_tree_peak_rss_mb(proc: psutil.Process) -> float:
    rss = 0
    processes = [proc]
    try:
        processes.extend(proc.children(recursive=True))
    except psutil.Error:
        pass

    for p in processes:
        try:
            rss += p.memory_info().rss
        except psutil.Error:
            continue
    return rss / (1024 * 1024)


def terminate_process_group(popen: subprocess.Popen, timeout: float = 3.0) -> None:
    try:
        os.killpg(os.getpgid(popen.pid), signal.SIGTERM)
    except Exception:
        try:
            popen.terminate()
        except Exception:
            pass

    try:
        popen.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
    except Exception:
        try:
            popen.kill()
        except Exception:
            pass


def monitor_command(
    cmd: str,
    sample_interval: float,
    power_reader: PowerReader,
    workload_cmd: Optional[str] = None,
    stop_target_after_workload: bool = False,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, object]:
    start_wall = time.perf_counter()
    start_epoch = time.time()

    popen = subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        env=env,
        preexec_fn=os.setsid,
    )
    proc = psutil.Process(popen.pid)

    start_user, start_system = process_tree_cpu_times(proc)
    peak_rss_mb = 0.0
    peak_power_watts = None
    energy_joules = 0.0
    power_samples = 0
    last_t = time.perf_counter()
    power_source = "none"

    workload_popen = None
    if workload_cmd:
        # Give servers a short moment to bind before starting client workload.
        time.sleep(0.25)
        workload_popen = subprocess.Popen(
            shlex.split(workload_cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
            preexec_fn=os.setsid,
        )

    workload_done = False

    while True:
        now = time.perf_counter()
        dt = now - last_t
        last_t = now

        if proc.is_running():
            try:
                peak_rss_mb = max(peak_rss_mb, process_tree_peak_rss_mb(proc))
            except psutil.Error:
                pass

        ps = power_reader.read()
        power_source = ps.source
        if ps.watts is not None:
            power_samples += 1
            energy_joules += ps.watts * dt
            if peak_power_watts is None or ps.watts > peak_power_watts:
                peak_power_watts = ps.watts

        if workload_popen is not None and not workload_done:
            if workload_popen.poll() is not None:
                workload_done = True
                if stop_target_after_workload and popen.poll() is None:
                    terminate_process_group(popen)

        if workload_popen is None:
            if popen.poll() is not None:
                break
        else:
            if workload_done and popen.poll() is not None:
                break

        time.sleep(sample_interval)

    end_wall = time.perf_counter()
    wall_elapsed_s = end_wall - start_wall

    try:
        end_user, end_system = process_tree_cpu_times(proc)
    except psutil.Error:
        end_user, end_system = start_user, start_system

    stdout, stderr = popen.communicate(timeout=1)

    workload_stdout = ""
    workload_stderr = ""
    workload_returncode = ""
    if workload_popen is not None:
        try:
            workload_stdout, workload_stderr = workload_popen.communicate(timeout=1)
            workload_returncode = workload_popen.returncode
        except Exception:
            pass

    cpu_user_s = max(0.0, end_user - start_user)
    cpu_system_s = max(0.0, end_system - start_system)
    cpu_total_s = cpu_user_s + cpu_system_s
    cores = psutil.cpu_count(logical=True) or 1
    cpu_norm_percent = (cpu_total_s / (wall_elapsed_s * cores) * 100.0) if wall_elapsed_s > 0 else 0.0

    avg_power_watts = (energy_joules / wall_elapsed_s) if wall_elapsed_s > 0 and power_samples > 0 else None
    energy_mj = energy_joules * 1000.0 if power_samples > 0 else None

    return {
        "start_epoch": start_epoch,
        "wall_elapsed_ms": wall_elapsed_s * 1000.0,
        "cpu_user_s": cpu_user_s,
        "cpu_system_s": cpu_system_s,
        "cpu_total_s": cpu_total_s,
        "cpu_norm_percent": cpu_norm_percent,
        "peak_rss_mb": peak_rss_mb,
        "avg_power_watts": avg_power_watts,
        "peak_power_watts": peak_power_watts,
        "energy_mj": energy_mj,
        "power_source": power_source,
        "power_samples": power_samples,
        "returncode": popen.returncode,
        "stdout_tail": stdout[-500:].replace("\n", " | "),
        "stderr_tail": stderr[-500:].replace("\n", " | "),
        "workload_returncode": workload_returncode,
        "workload_stdout_tail": workload_stdout[-500:].replace("\n", " | "),
        "workload_stderr_tail": workload_stderr[-500:].replace("\n", " | "),
    }


def detect_device_label() -> str:
    model_file = Path("/proc/device-tree/model")
    if model_file.exists():
        try:
            return model_file.read_text(errors="ignore").replace("\x00", "").strip()
        except Exception:
            pass
    return platform.platform()


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure CPU, RAM, and power/energy for authentication binaries on actual hardware."
    )
    parser.add_argument("--protocol", required=True, help="Protocol label, e.g., zkarche, mtls, edhoc")
    parser.add_argument("--role", default="client", choices=["client", "server"], help="Measured role label")
    parser.add_argument("--device", default=None, help="Device label, e.g., Raspberry Pi 3B+, Raspberry Pi 4, Raspberry Pi 5")
    parser.add_argument("--server", default="", help="Server label or address for metadata")
    parser.add_argument("--runs", type=int, default=50, help="Number of repeated runs")
    parser.add_argument("--cmd", required=True, help="Authentication command to measure")
    parser.add_argument("--setup-cmd", default=None, help="Optional setup command executed before measured runs")
    parser.add_argument("--workload-cmd", default=None, help="Optional workload command used while measuring a long-running server")
    parser.add_argument("--stop-target-after-workload", action="store_true", help="Stop measured target after workload command finishes")
    parser.add_argument("--cwd", default=None, help="Working directory for commands")
    parser.add_argument("--sample-interval", type=float, default=0.01, help="Sampling interval in seconds")
    parser.add_argument("--output", default=None, help="CSV output path")

    parser.add_argument("--power-mode", choices=["none", "fixed", "hwmon"], default="none")
    parser.add_argument("--fixed-power-watts", type=float, default=None, help="Fixed/average measured power in watts")
    parser.add_argument("--power-path", default=None, help="Path to power input, e.g., /sys/class/hwmon/hwmon2/power1_input")
    parser.add_argument("--power-unit", default="microwatt", choices=["watt", "milliwatt", "microwatt"])
    parser.add_argument("--voltage-path", default=None, help="Path to voltage input if computing P=V*I")
    parser.add_argument("--voltage-unit", default="millivolt", choices=["volt", "millivolt", "microvolt"])
    parser.add_argument("--current-path", default=None, help="Path to current input if computing P=V*I")
    parser.add_argument("--current-unit", default="milliamp", choices=["amp", "milliamp", "microamp"])

    args = parser.parse_args()

    if args.power_mode == "fixed" and args.fixed_power_watts is None:
        parser.error("--power-mode fixed requires --fixed-power-watts")

    if args.power_mode == "hwmon" and not (args.power_path or (args.voltage_path and args.current_path)):
        parser.error("--power-mode hwmon requires --power-path or both --voltage-path and --current-path")

    if args.output is None:
        args.output = f"{args.protocol}_{args.role}_hardware_resource_results.csv"

    return args


def main() -> int:
    args = parse_args()
    device = args.device or detect_device_label()
    hostname = socket.gethostname()
    power_reader = PowerReader(args)

    if args.setup_cmd:
        print(f"[setup] {args.setup_cmd}")
        setup_start = time.perf_counter()
        setup_proc = subprocess.run(shlex.split(args.setup_cmd), cwd=args.cwd, text=True, capture_output=True)
        setup_ms = (time.perf_counter() - setup_start) * 1000.0
        print(f"[setup] returncode={setup_proc.returncode}, elapsed={setup_ms:.3f} ms")
        if setup_proc.returncode != 0:
            print(setup_proc.stderr, file=sys.stderr)
            return setup_proc.returncode

    rows: List[Dict[str, object]] = []

    print("=== Hardware Authentication Resource Benchmark ===")
    print(f"protocol={args.protocol}")
    print(f"role={args.role}")
    print(f"device={device}")
    print(f"server={args.server}")
    print(f"runs={args.runs}")
    print(f"cmd={args.cmd}")
    print(f"power_mode={args.power_mode}")
    print("")

    for run in range(1, args.runs + 1):
        result = monitor_command(
            cmd=args.cmd,
            sample_interval=args.sample_interval,
            power_reader=power_reader,
            workload_cmd=args.workload_cmd,
            stop_target_after_workload=args.stop_target_after_workload,
            cwd=args.cwd,
            env=os.environ.copy(),
        )

        status = "SUCCESS" if result["returncode"] == 0 else "FAILED"

        row = {
            "run": run,
            "protocol": args.protocol,
            "role": args.role,
            "device": device,
            "hostname": hostname,
            "server": args.server,
            "cmd": args.cmd,
            "status": status,
            **result,
        }
        rows.append(row)

        energy_text = "NA" if row["energy_mj"] is None else f"{row['energy_mj']:.4f}"
        avg_power_text = "NA" if row["avg_power_watts"] is None else f"{row['avg_power_watts']:.4f}"

        print(
            f"Run {run:02d} | {args.protocol:<8} | {args.role:<6} | {device:<24} | "
            f"wall={row['wall_elapsed_ms']:.3f} ms | "
            f"cpu={row['cpu_norm_percent']:.2f}% | "
            f"rss={row['peak_rss_mb']:.3f} MB | "
            f"Pavg={avg_power_text} W | "
            f"E={energy_text} mJ | "
            f"{status}"
        )

    output_path = Path(args.output)
    write_csv(output_path, rows)
    print(f"\nSaved CSV: {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
