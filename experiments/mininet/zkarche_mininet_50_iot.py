#!/usr/bin/env python3
"""
Run the uploaded ZK-ARCHE authentication scheme inside a Mininet IoT simulation.

Topology:
  50 randomized Raspberry Pi-class clients -> 1 switch -> 1 server
  Server: Intel Core i7-6770HQ @ 2.60GHz

What this script does:
  1. Builds your Rust zkarche_client and zkarche_server binaries.
  2. Creates one Mininet server host at 10.0.0.1.
  3. Creates 50 client hosts, each randomly labeled as Pi 3B+, Pi 4, or Pi 5.
  4. Gives every client an independent working directory so each gets its own device identity.
  5. Enrolls every client using your scheme's --setup flow.
  6. Runs one online authentication per client using your zkarche_client.
  7. Saves results to CSV.

Run:
  sudo python3 zkarche_mininet_50_iot.py --project /path/to/zk-arche-compare-main

Example with your uploaded extraction path:
  sudo python3 zkarche_mininet_50_iot.py --project /mnt/data/zk1/zk-arche-compare-main
"""

import argparse
import csv
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info


NUM_CLIENTS = 50
SERVER_CPU = "Intel Core i7-6770HQ @ 2.60GHz"
SERVER_IP = "10.0.0.1"
SERVER_PORT = 4000
PAIRING_TOKEN = "mininet-pairing-token"

DEFAULT_OUTPUT_CSV = "zkarche_mininet_results.csv"
DEFAULT_WORKDIR = "/tmp/zkarche-mininet"

# Mininet network profiles. These do NOT emulate Raspberry Pi CPU hardware.
# They represent heterogeneous IoT network links for each device class.
DEVICE_PROFILES = {
    "Raspberry Pi 3B+": {
        "weight": 0.34,
        "bw_mbps": 100,
        "delay_ms_range": (12, 45),
        "jitter_ms_range": (2, 8),
        "loss_percent_range": (0.0, 1.5),
    },
    "Raspberry Pi 4": {
        "weight": 0.33,
        "bw_mbps": 100,
        "delay_ms_range": (8, 32),
        "jitter_ms_range": (1, 6),
        "loss_percent_range": (0.0, 1.0),
    },
    "Raspberry Pi 5": {
        "weight": 0.33,
        "bw_mbps": 100,
        "delay_ms_range": (4, 22),
        "jitter_ms_range": (1, 4),
        "loss_percent_range": (0.0, 0.6),
    },
}


def weighted_random_device():
    names = list(DEVICE_PROFILES.keys())
    weights = [DEVICE_PROFILES[name]["weight"] for name in names]
    return random.choices(names, weights=weights, k=1)[0]


def rand_range(profile, key):
    lo, hi = profile[key]
    return round(random.uniform(lo, hi), 4)


def run_local(cmd, cwd=None, check=True):
    print(f"[local] {cmd}")
    result = subprocess.run(
        cmd,
        cwd=cwd,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if check and result.returncode != 0:
        print(result.stdout)
        raise RuntimeError(f"Command failed: {cmd}")
    return result.stdout.strip()


def parse_duration_to_ms(duration_text):
    """Parse Rust Debug Duration fragments like 1.23ms, 450.1µs, 2.0s."""
    if not duration_text:
        return None
    text = duration_text.strip()
    m = re.match(r"([0-9.]+)\s*(ns|µs|us|ms|s)", text)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2)
    if unit == "ns":
        return value / 1_000_000.0
    if unit in ("µs", "us"):
        return value / 1_000.0
    if unit == "ms":
        return value
    if unit == "s":
        return value * 1_000.0
    return None


def parse_client_metrics(output):
    """
    Extracts:
      CLIENT METRICS -> Duration: 5.123ms, Sent: 417 bytes, Received: 192 bytes
    """
    metrics = {
        "scheme_duration_ms": None,
        "sent_bytes": None,
        "received_bytes": None,
    }

    pattern = re.compile(
        r"CLIENT METRICS\s*->\s*Duration:\s*([^,]+),\s*Sent:\s*(\d+)\s*bytes,\s*Received:\s*(\d+)\s*bytes"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            metrics["scheme_duration_ms"] = round(parse_duration_to_ms(m.group(1)), 4)
            metrics["sent_bytes"] = int(m.group(2))
            metrics["received_bytes"] = int(m.group(3))
    return metrics


def prepare_binaries(project_root):
    project_root = Path(project_root).resolve()
    if not (project_root / "Cargo.toml").exists():
        raise FileNotFoundError(f"Cargo.toml not found in {project_root}")

    # Debug build is compatible with your client's lab-only TOFU flag if needed,
    # but this script uses out-of-band pinning instead.
    run_local("cargo build --bins", cwd=project_root)

    server_bin = project_root / "target" / "debug" / "zkarche_server"
    client_bin = project_root / "target" / "debug" / "zkarche_client"

    if not server_bin.exists():
        raise FileNotFoundError(f"Missing server binary: {server_bin}")
    if not client_bin.exists():
        raise FileNotFoundError(f"Missing client binary: {client_bin}")

    return str(server_bin), str(client_bin)


def prepare_workdirs(workdir, server_bin):
    workdir = Path(workdir)
    if workdir.exists():
        shutil.rmtree(workdir)

    server_dir = workdir / "server"
    clients_dir = workdir / "clients"
    server_dir.mkdir(parents=True, exist_ok=True)
    clients_dir.mkdir(parents=True, exist_ok=True)

    # Create server key and capture public key before server starts.
    server_pub = run_local(f"{shlex.quote(server_bin)} --print-pubkey", cwd=server_dir)
    server_pub = server_pub.splitlines()[-1].strip()

    if not re.fullmatch(r"[0-9a-fA-F]{64}", server_pub):
        raise RuntimeError(f"Could not parse server public key. Output was: {server_pub}")

    return str(server_dir), str(clients_dir), server_pub


def build_network(assignments):
    net = Mininet(
        controller=Controller,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    info("*** Adding controller\n")
    net.addController("c0")

    info("*** Adding switch\n")
    sw = net.addSwitch("s1")

    info("*** Adding i7 authentication server\n")
    server = net.addHost("server", ip=f"{SERVER_IP}/24")
    net.addLink(server, sw, cls=TCLink, bw=1000, delay="1ms", jitter="0.2ms", loss=0)

    clients = []
    info("*** Adding randomized Raspberry Pi-class clients\n")

    for i, assignment in enumerate(assignments, start=1):
        client = net.addHost(f"pi{i}", ip=f"10.0.0.{i + 1}/24")
        net.addLink(
            client,
            sw,
            cls=TCLink,
            bw=assignment["bw_mbps"],
            delay=f"{assignment['network_delay_ms']}ms",
            jitter=f"{assignment['network_jitter_ms']}ms",
            loss=assignment["packet_loss_percent"],
        )
        clients.append(client)

    return net, server, clients


def host_cmd_checked(host, cmd, label):
    output = host.cmd(cmd).strip()
    # Mininet host.cmd does not directly expose exit status, so append a marker.
    if "__EXIT_0__" not in output:
        raise RuntimeError(f"{label} failed. Command output:\n{output}")
    return output.replace("__EXIT_0__", "").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="Path to zk-arche-compare-main project root")
    parser.add_argument("--clients", type=int, default=NUM_CLIENTS)
    parser.add_argument("--output", default=DEFAULT_OUTPUT_CSV)
    parser.add_argument("--workdir", default=DEFAULT_WORKDIR)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    setLogLevel("info")

    server_bin, client_bin = prepare_binaries(args.project)
    server_dir, clients_dir, server_pub = prepare_workdirs(args.workdir, server_bin)

    assignments = []
    for i in range(1, args.clients + 1):
        dtype = weighted_random_device()
        profile = DEVICE_PROFILES[dtype]
        client_dir = Path(clients_dir) / f"pi{i}"
        client_dir.mkdir(parents=True, exist_ok=True)
        assignments.append({
            "run": i,
            "client_host": f"pi{i}",
            "client_ip": f"10.0.0.{i + 1}",
            "client_type": dtype,
            "bw_mbps": profile["bw_mbps"],
            "network_delay_ms": rand_range(profile, "delay_ms_range"),
            "network_jitter_ms": rand_range(profile, "jitter_ms_range"),
            "packet_loss_percent": rand_range(profile, "loss_percent_range"),
            "client_workdir": str(client_dir),
        })

    net, server, clients = build_network(assignments)
    results = []

    try:
        info("*** Starting Mininet\n")
        net.start()

        info("*** Starting ZK-ARCHE server with pairing enabled\n")
        server_cmd = (
            f"cd {shlex.quote(server_dir)} && "
            f"{shlex.quote(server_bin)} --bind {SERVER_IP}:{SERVER_PORT} "
            f"--pairing --pairing-token {shlex.quote(PAIRING_TOKEN)} "
            f"> /tmp/zkarche_server_mininet.log 2>&1 &"
        )
        server.cmd(server_cmd)
        time.sleep(1.0)

        print("\n=== ZK-ARCHE Mininet IoT Authentication Simulation ===")
        print(f"Server CPU: {SERVER_CPU}")
        print(f"Server IP:  {SERVER_IP}:{SERVER_PORT}")
        print(f"Clients:    {args.clients}")
        print(f"CSV:        {args.output}")
        print("")

        for idx, client in enumerate(clients):
            a = assignments[idx]
            cdir = a["client_workdir"]

            # Pin server public key out-of-band so setup does not rely on TOFU.
            pin_cmd = (
                f"cd {shlex.quote(cdir)} && "
                f"{shlex.quote(client_bin)} --pin-server-pub {server_pub} >/tmp/{client.name}_pin.log 2>&1 && "
                f"echo __EXIT_0__"
            )
            host_cmd_checked(client, pin_cmd, f"pin server key for {client.name}")

            setup_cmd = (
                f"cd {shlex.quote(cdir)} && "
                f"{shlex.quote(client_bin)} --server {SERVER_IP}:{SERVER_PORT} "
                f"--setup --pairing-token {shlex.quote(PAIRING_TOKEN)} 2>&1 && "
                f"echo __EXIT_0__"
            )
            setup_output = host_cmd_checked(client, setup_cmd, f"setup for {client.name}")
            setup_metrics = parse_client_metrics(setup_output)

            auth_cmd = (
                f"cd {shlex.quote(cdir)} && "
                f"{shlex.quote(client_bin)} --server {SERVER_IP}:{SERVER_PORT} 2>&1 && "
                f"echo __EXIT_0__"
            )
            wall_start = time.perf_counter()
            auth_output = host_cmd_checked(client, auth_cmd, f"auth for {client.name}")
            wall_elapsed_ms = round((time.perf_counter() - wall_start) * 1000.0, 4)
            auth_metrics = parse_client_metrics(auth_output)

            row = {
                "run": a["run"],
                "client_host": a["client_host"],
                "client_ip": a["client_ip"],
                "client_type": a["client_type"],
                "server_cpu": SERVER_CPU,
                "network_delay_ms": a["network_delay_ms"],
                "network_jitter_ms": a["network_jitter_ms"],
                "packet_loss_percent": a["packet_loss_percent"],
                "setup_duration_ms": setup_metrics["scheme_duration_ms"],
                "setup_sent_bytes": setup_metrics["sent_bytes"],
                "setup_received_bytes": setup_metrics["received_bytes"],
                "auth_duration_ms": auth_metrics["scheme_duration_ms"],
                "auth_sent_bytes": auth_metrics["sent_bytes"],
                "auth_received_bytes": auth_metrics["received_bytes"],
                "auth_wall_elapsed_ms": wall_elapsed_ms,
                "status": "AUTH_SUCCESS",
            }
            results.append(row)

            print(
                f"Run {row['run']:02d} | {row['client_host']:>4} | "
                f"{row['client_type']:<17} | "
                f"delay={row['network_delay_ms']:>6} ms | "
                f"jitter={row['network_jitter_ms']:>5} ms | "
                f"loss={row['packet_loss_percent']:>4}% | "
                f"auth={row['auth_duration_ms']} ms | "
                f"sent={row['auth_sent_bytes']} B | recv={row['auth_received_bytes']} B | "
                f"{row['status']}"
            )

        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)

        print(f"\nSaved results to: {args.output}\n")

    finally:
        info("*** Stopping server and Mininet\n")
        try:
            server.cmd("pkill -f zkarche_server || true")
        except Exception:
            pass
        net.stop()


if __name__ == "__main__":
    main()
