#!/usr/bin/env python3
import argparse
import csv
import os
import shlex
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def parse_time_file(path):
    data = {
        "cpu_user_s": 0.0,
        "cpu_system_s": 0.0,
        "peak_rss_mb": 0.0,
    }

    text = Path(path).read_text(errors="replace")

    for line in text.splitlines():
        if line.startswith("TIME_USER_S="):
            data["cpu_user_s"] = float(line.split("=", 1)[1])
        elif line.startswith("TIME_SYSTEM_S="):
            data["cpu_system_s"] = float(line.split("=", 1)[1])
        elif line.startswith("TIME_MAX_RSS_KB="):
            kb = float(line.split("=", 1)[1])
            data["peak_rss_mb"] = kb / 1024.0

    return data


def tail_text(s, max_len=500):
    s = (s or "").replace("\n", " | ")
    return s[-max_len:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--role", required=True)
    ap.add_argument("--device", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--runs", type=int, default=50)
    ap.add_argument("--cmd", required=True)
    ap.add_argument("--power-mode", choices=["none", "fixed"], default="none")
    ap.add_argument("--fixed-power-watts", type=float, default=None)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    hostname = socket.gethostname()

    fields = [
        "run",
        "protocol",
        "role",
        "device",
        "hostname",
        "server",
        "cmd",
        "status",
        "start_epoch",
        "wall_elapsed_ms",
        "cpu_user_s",
        "cpu_system_s",
        "cpu_total_s",
        "cpu_norm_percent",
        "peak_rss_mb",
        "avg_power_watts",
        "peak_power_watts",
        "energy_mj",
        "power_source",
        "returncode",
        "stdout_tail",
        "stderr_tail",
    ]

    out_path = Path(args.output)
    if out_path.parent != Path("."):
        out_path.parent.mkdir(parents=True, exist_ok=True)

    print("=== Hardware Authentication Resource Benchmark using /usr/bin/time ===")
    print(f"protocol={args.protocol}")
    print(f"role={args.role}")
    print(f"device={args.device}")
    print(f"server={args.server}")
    print(f"runs={args.runs}")
    print(f"cmd={args.cmd}")
    print(f"power_mode={args.power_mode}")

    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for i in range(1, args.runs + 1):
            with tempfile.NamedTemporaryFile(prefix="zkarche_time_", delete=False) as tf:
                time_file = tf.name

            wrapped_cmd = [
                "/usr/bin/time",
                "-f",
                "TIME_USER_S=%U\nTIME_SYSTEM_S=%S\nTIME_MAX_RSS_KB=%M",
                "-o",
                time_file,
                "bash",
                "-lc",
                args.cmd,
            ]

            start_epoch = time.time()
            start = time.perf_counter()

            proc = subprocess.run(
                wrapped_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            end = time.perf_counter()
            wall_s = end - start
            wall_ms = wall_s * 1000.0

            usage = parse_time_file(time_file)
            try:
                os.remove(time_file)
            except OSError:
                pass

            cpu_user = usage["cpu_user_s"]
            cpu_system = usage["cpu_system_s"]
            cpu_total = cpu_user + cpu_system

            # Single-process CPU utilization over the measured wall interval.
            # 100% means one full CPU core was busy for the whole interval.
            cpu_percent = (cpu_total / wall_s) * 100.0 if wall_s > 0 else 0.0

            avg_power = ""
            peak_power = ""
            energy_mj = ""
            power_source = args.power_mode

            if args.power_mode == "fixed":
                if args.fixed_power_watts is None:
                    raise SystemExit("--fixed-power-watts is required when --power-mode fixed")
                avg_power = args.fixed_power_watts
                peak_power = args.fixed_power_watts
                energy_mj = args.fixed_power_watts * wall_s * 1000.0

            status = "SUCCESS" if proc.returncode == 0 else "FAIL"

            row = {
                "run": i,
                "protocol": args.protocol,
                "role": args.role,
                "device": args.device,
                "hostname": hostname,
                "server": args.server,
                "cmd": args.cmd,
                "status": status,
                "start_epoch": start_epoch,
                "wall_elapsed_ms": wall_ms,
                "cpu_user_s": cpu_user,
                "cpu_system_s": cpu_system,
                "cpu_total_s": cpu_total,
                "cpu_norm_percent": cpu_percent,
                "peak_rss_mb": usage["peak_rss_mb"],
                "avg_power_watts": avg_power,
                "peak_power_watts": peak_power,
                "energy_mj": energy_mj,
                "power_source": power_source,
                "returncode": proc.returncode,
                "stdout_tail": tail_text(proc.stdout),
                "stderr_tail": tail_text(proc.stderr),
            }

            writer.writerow(row)
            f.flush()

            print(
                f"Run {i:02d} | {args.protocol:<8} | {args.role:<6} | "
                f"{args.device:<24} | wall={wall_ms:.3f} ms | "
                f"cpu={cpu_percent:.4f}% | rss={usage['peak_rss_mb']:.3f} MB | "
                f"Pavg={avg_power if avg_power != '' else 'NA'} W | "
                f"E={energy_mj if energy_mj != '' else 'NA'} mJ | {status}"
            )


if __name__ == "__main__":
    main()