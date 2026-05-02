#!/usr/bin/env python3
"""
Run the EDHOC authentication baseline inside a Mininet IoT simulation.

Topology:
  50 randomized Raspberry Pi-class clients -> 1 switch -> 1 server
  Server: Intel Core i7-6770HQ @ 2.60GHz

What this script does:
  1. Builds the required Rust binary for EDHOC-over-TCP.
  2. Creates one Mininet server host at 10.0.0.1.
  3. Creates randomized Raspberry Pi 3B+, Pi 4, and Pi 5 client hosts.
  4. Gives each client randomized latency, jitter, and packet loss.
  5. Runs one EDHOC-over-TCP authentication attempt per simulated IoT device.
  6. Saves a CSV including client_type for every run.

Example:
  sudo python3 edhoc_mininet_50_iot.py --project /mnt/data/zk1/zk-arche-compare-main
"""

import argparse
import csv
import random
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info


DEFAULT_CLIENTS = 50
SERVER_CPU = "Intel Core i7-6770HQ @ 2.60GHz"
SERVER_IP = "10.0.0.1"
DEFAULT_WORKDIR = "/tmp/baseline-mininet"

PROTOCOL = "edhoc"

PROTOCOL_CONFIG = {
    "edhoc": {
        "server_bin": "edhoc_server",
        "client_bin": "edhoc_client",
        "port": 5688,
        "server_args": "{bind}",
        "client_args": "{server}",
        "default_csv": "edhoc_mininet_results.csv",
        "title": "EDHOC-over-TCP",
        "needs_certs": False,
    },
}

# Mininet network profiles. These model heterogeneous IoT network links.
# They do not emulate Raspberry Pi CPU hardware.
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
    Extracts lines like:
      CLIENT METRICS -> Duration: 5.123ms, Sent: 417 bytes, Received: 192 bytes
    """
    metrics = {
        "protocol_duration_ms": None,
        "sent_bytes": None,
        "received_bytes": None,
    }

    pattern = re.compile(
        r"CLIENT METRICS\s*->\s*Duration:\s*([^,]+),\s*Sent:\s*(\d+)\s*bytes,\s*Received:\s*(\d+)\s*bytes"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            parsed = parse_duration_to_ms(m.group(1))
            metrics["protocol_duration_ms"] = round(parsed, 4) if parsed is not None else None
            metrics["sent_bytes"] = int(m.group(2))
            metrics["received_bytes"] = int(m.group(3))
    return metrics


def prepare_project(project_root, protocols):
    project_root = Path(project_root).resolve()
    if not (project_root / "Cargo.toml").exists():
        raise FileNotFoundError(f"Cargo.toml not found in {project_root}")

    if "mtls" in protocols:
        cert_dir = project_root / "certs"
        needed = ["ca.crt", "client.crt", "client.key", "server.crt", "server.key"]
        if not cert_dir.exists() or any(not (cert_dir / name).exists() for name in needed):
            run_local("bash scripts/gen_certs.sh", cwd=project_root)

    run_local("cargo build --bins", cwd=project_root)

    bins = {}
    for protocol in protocols:
        cfg = PROTOCOL_CONFIG[protocol]
        server_bin = project_root / "target" / "debug" / cfg["server_bin"]
        client_bin = project_root / "target" / "debug" / cfg["client_bin"]
        if not server_bin.exists():
            raise FileNotFoundError(f"Missing server binary: {server_bin}")
        if not client_bin.exists():
            raise FileNotFoundError(f"Missing client binary: {client_bin}")
        bins[protocol] = (str(server_bin), str(client_bin))

    return project_root, bins


def make_assignments(num_clients, protocol_workdir):
    clients_dir = Path(protocol_workdir) / "clients"
    clients_dir.mkdir(parents=True, exist_ok=True)

    assignments = []
    for i in range(1, num_clients + 1):
        dtype = weighted_random_device()
        profile = DEVICE_PROFILES[dtype]
        client_dir = clients_dir / f"pi{i}"
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
    return assignments


def copy_certs_if_needed(project_root, protocol, protocol_workdir, assignments):
    if not PROTOCOL_CONFIG[protocol]["needs_certs"]:
        return

    src = Path(project_root) / "certs"
    server_dir = Path(protocol_workdir) / "server"
    server_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, server_dir / "certs", dirs_exist_ok=True)

    for a in assignments:
        cdir = Path(a["client_workdir"])
        shutil.copytree(src, cdir / "certs", dirs_exist_ok=True)


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


def host_cmd_with_status(host, cmd):
    wrapped = f"({cmd}) 2>&1; rc=$?; echo __RC_${{rc}}__"
    output = host.cmd(wrapped).strip()
    m = re.search(r"__RC_(\d+)__", output)
    rc = int(m.group(1)) if m else 999
    cleaned = re.sub(r"__RC_\d+__", "", output).strip()
    return rc, cleaned


def run_protocol(project_root, protocol, server_bin, client_bin, num_clients, output_csv, base_workdir):
    cfg = PROTOCOL_CONFIG[protocol]
    protocol_workdir = Path(base_workdir) / protocol
    if protocol_workdir.exists():
        shutil.rmtree(protocol_workdir)
    (protocol_workdir / "server").mkdir(parents=True, exist_ok=True)

    assignments = make_assignments(num_clients, protocol_workdir)
    copy_certs_if_needed(project_root, protocol, protocol_workdir, assignments)

    net, server, clients = build_network(assignments)
    results = []
    bind = f"{SERVER_IP}:{cfg['port']}"
    server_addr = f"{SERVER_IP}:{cfg['port']}"

    try:
        info("*** Starting Mininet\n")
        net.start()

        title = cfg["title"]
        print(f"\n=== {title} Mininet IoT Authentication Simulation ===")
        print(f"Server CPU: {SERVER_CPU}")
        print(f"Server IP:  {server_addr}")
        print(f"Clients:    {num_clients}")
        print(f"CSV:        {output_csv}")
        print("")

        server_dir = protocol_workdir / "server"
        server_args = cfg["server_args"].format(bind=bind, server=server_addr)
        server_cmd = (
            f"cd {shlex.quote(str(server_dir))} && "
            f"{shlex.quote(server_bin)} {server_args} "
            f"> /tmp/{protocol}_server_mininet.log 2>&1 &"
        )
        info(f"*** Starting {title} server\n")
        server.cmd(server_cmd)
        time.sleep(1.0)

        for idx, client in enumerate(clients):
            a = assignments[idx]
            cdir = a["client_workdir"]
            client_args = cfg["client_args"].format(bind=bind, server=server_addr)
            auth_cmd = f"cd {shlex.quote(cdir)} && {shlex.quote(client_bin)} {client_args}"

            wall_start = time.perf_counter()
            rc, output = host_cmd_with_status(client, auth_cmd)
            wall_elapsed_ms = round((time.perf_counter() - wall_start) * 1000.0, 4)
            metrics = parse_client_metrics(output)
            status = "AUTH_SUCCESS" if rc == 0 and metrics["protocol_duration_ms"] is not None else "AUTH_FAILED"

            row = {
                "protocol": protocol,
                "run": a["run"],
                "client_host": a["client_host"],
                "client_ip": a["client_ip"],
                "client_type": a["client_type"],
                "server_cpu": SERVER_CPU,
                "network_delay_ms": a["network_delay_ms"],
                "network_jitter_ms": a["network_jitter_ms"],
                "packet_loss_percent": a["packet_loss_percent"],
                "auth_duration_ms": metrics["protocol_duration_ms"],
                "auth_sent_bytes": metrics["sent_bytes"],
                "auth_received_bytes": metrics["received_bytes"],
                "auth_wall_elapsed_ms": wall_elapsed_ms,
                "status": status,
                "return_code": rc,
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

            if status != "AUTH_SUCCESS":
                print(f"  Client output for {row['client_host']}: {output[:500]}")

        with open(output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)

        print(f"\nSaved results to: {output_csv}\n")

    finally:
        info(f"*** Stopping {cfg['title']} server and Mininet\n")
        try:
            server.cmd(f"pkill -f {shlex.quote(cfg['server_bin'])} || true")
        except Exception:
            pass
        net.stop()



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True, help="Path to zk-arche-compare-main project root")
    parser.add_argument("--clients", type=int, default=DEFAULT_CLIENTS)
    parser.add_argument("--output", default=PROTOCOL_CONFIG[PROTOCOL]["default_csv"])
    parser.add_argument("--workdir", default=DEFAULT_WORKDIR)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    setLogLevel("info")

    project_root, bins = prepare_project(args.project, [PROTOCOL])
    server_bin, client_bin = bins[PROTOCOL]

    run_protocol(
        project_root=project_root,
        protocol=PROTOCOL,
        server_bin=server_bin,
        client_bin=client_bin,
        num_clients=args.clients,
        output_csv=args.output,
        base_workdir=args.workdir,
    )


if __name__ == "__main__":
    main()
