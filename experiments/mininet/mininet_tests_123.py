#!/usr/bin/env python3
"""
Unified Mininet workload runner for Test 1, Test 2, and Test 3.

Protocols supported:
  - zkarche
  - mtls
  - edhoc
  - all

Workloads:
  Test 1: 50 randomized Raspberry Pi-class clients, one concurrent authentication each.
  Test 2: one client, 50 sequential authentications.
  Test 3: 50 randomized Raspberry Pi-class clients, 50 rounds each; each round runs all clients concurrently.

Topology:
  pi1..piN -> s1 -> server
  server: Intel Core i7-6770HQ @ 2.60GHz

Example:
  sudo python3 experiments/mininet/mininet_tests_123.py --project . --protocol zkarche --test all --seed 42
  sudo python3 experiments/mininet/mininet_tests_123.py --project . --protocol all --test all --seed 42

CSV outputs:
  results/mininet/zkarche_test1_concurrent.csv
  results/mininet/zkarche_test2_sequential.csv
  results/mininet/zkarche_test3_high_load.csv
  results/mininet/mtls_test1_concurrent.csv
  ...
"""

import argparse
import csv
import os
import random
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info


SERVER_CPU = "Intel Core i7-6770HQ @ 2.60GHz"
SERVER_IP = "10.0.0.1"
PAIRING_TOKEN = "mininet-pairing-token"
DEFAULT_CLIENTS = 50
DEFAULT_ITERATIONS = 50
DEFAULT_WORKDIR = "/tmp/zkcompare-mininet-tests123"
DEFAULT_RESULTS_DIR = "results/mininet"

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

PROTOCOLS = {
    "zkarche": {
        "server_bin": "zkarche_server",
        "client_bin": "zkarche_client",
        "port": 4000,
        "title": "ZK-ARCHE",
        "needs_certs": False,
        "needs_setup": True,
    },
    "mtls": {
        "server_bin": "mtls_server",
        "client_bin": "mtls_client",
        "port": 7443,
        "title": "mTLS",
        "needs_certs": True,
        "needs_setup": False,
    },
    "edhoc": {
        "server_bin": "edhoc_server",
        "client_bin": "edhoc_client",
        "port": 5688,
        "title": "EDHOC-over-TCP",
        "needs_certs": False,
        "needs_setup": False,
    },
}

TESTS = {
    "1": "concurrent",
    "2": "sequential",
    "3": "high_load",
}


def run_local(cmd: str, cwd: Optional[Path] = None, check: bool = True) -> str:
    print(f"[local] {cmd}")
    p = subprocess.run(
        cmd,
        shell=True,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if check and p.returncode != 0:
        print(p.stdout)
        raise RuntimeError(f"Command failed: {cmd}")
    return p.stdout.strip()


def weighted_random_device() -> str:
    names = list(DEVICE_PROFILES.keys())
    weights = [DEVICE_PROFILES[name]["weight"] for name in names]
    return random.choices(names, weights=weights, k=1)[0]


def rand_range(profile: Dict, key: str) -> float:
    lo, hi = profile[key]
    return round(random.uniform(lo, hi), 4)


def parse_duration_to_ms(duration_text: str) -> Optional[float]:
    if not duration_text:
        return None
    m = re.match(r"([0-9.]+)\s*(ns|µs|us|ms|s)", duration_text.strip())
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


def parse_client_metrics(output: str) -> Dict[str, Optional[float]]:
    metrics = {
        "auth_duration_ms": None,
        "auth_sent_bytes": None,
        "auth_received_bytes": None,
    }
    pattern = re.compile(
        r"CLIENT METRICS\s*->\s*Duration:\s*([^,]+),\s*Sent:\s*(\d+)\s*bytes,\s*Received:\s*(\d+)\s*bytes"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            parsed = parse_duration_to_ms(m.group(1))
            metrics["auth_duration_ms"] = round(parsed, 4) if parsed is not None else None
            metrics["auth_sent_bytes"] = int(m.group(2))
            metrics["auth_received_bytes"] = int(m.group(3))
    return metrics


def prepare_project(project_root: Path, protocol_names: List[str]) -> Dict[str, Tuple[str, str]]:
    project_root = project_root.resolve()
    if not (project_root / "Cargo.toml").exists():
        raise FileNotFoundError(f"Cargo.toml not found in {project_root}")

    if "mtls" in protocol_names:
        cert_dir = project_root / "certs"
        needed = ["ca.crt", "client.crt", "client.key", "server.crt", "server.key"]
        if not cert_dir.exists() or any(not (cert_dir / name).exists() for name in needed):
            run_local("bash scripts/gen_certs.sh", cwd=project_root)

    run_local("cargo build --bins", cwd=project_root)

    bins = {}
    for protocol in protocol_names:
        cfg = PROTOCOLS[protocol]
        server_bin = project_root / "target" / "debug" / cfg["server_bin"]
        client_bin = project_root / "target" / "debug" / cfg["client_bin"]
        if not server_bin.exists():
            raise FileNotFoundError(f"Missing server binary: {server_bin}")
        if not client_bin.exists():
            raise FileNotFoundError(f"Missing client binary: {client_bin}")
        bins[protocol] = (str(server_bin), str(client_bin))
    return bins


def make_assignments(num_clients: int, clients_dir: Path) -> List[Dict]:
    clients_dir.mkdir(parents=True, exist_ok=True)
    assignments = []
    for i in range(1, num_clients + 1):
        dtype = weighted_random_device()
        profile = DEVICE_PROFILES[dtype]
        cdir = clients_dir / f"pi{i}"
        cdir.mkdir(parents=True, exist_ok=True)
        assignments.append({
            "client_index": i,
            "client_host": f"pi{i}",
            "client_ip": f"10.0.0.{i + 1}",
            "client_type": dtype,
            "bw_mbps": profile["bw_mbps"],
            "network_delay_ms": rand_range(profile, "delay_ms_range"),
            "network_jitter_ms": rand_range(profile, "jitter_ms_range"),
            "packet_loss_percent": rand_range(profile, "loss_percent_range"),
            "client_workdir": str(cdir),
        })
    return assignments


def build_network(assignments: List[Dict]):
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
    for assignment in assignments:
        client = net.addHost(assignment["client_host"], ip=f"{assignment['client_ip']}/24")
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


def wrapped_shell_cmd(cmd: str) -> str:
    return f"bash -lc {shlex.quote('(' + cmd + ') 2>&1; rc=$?; echo __RC_${rc}__')}"


def parse_rc_output(output: str) -> Tuple[int, str]:
    m = re.search(r"__RC_(\d+)__", output)
    rc = int(m.group(1)) if m else 999
    cleaned = re.sub(r"__RC_\d+__", "", output).strip()
    return rc, cleaned


def host_cmd_with_status(host, cmd: str) -> Tuple[int, str]:
    output = host.cmd(wrapped_shell_cmd(cmd)).strip()
    return parse_rc_output(output)


def host_popen(host, cmd: str):
    return host.popen(wrapped_shell_cmd(cmd), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def copy_certs_if_needed(project_root: Path, protocol: str, protocol_workdir: Path, assignments: List[Dict]) -> None:
    if not PROTOCOLS[protocol]["needs_certs"]:
        return
    src = project_root / "certs"
    server_dir = protocol_workdir / "server"
    server_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, server_dir / "certs", dirs_exist_ok=True)
    for a in assignments:
        shutil.copytree(src, Path(a["client_workdir"]) / "certs", dirs_exist_ok=True)


def prepare_zkarche_state(server_bin: str, client_bin: str, protocol_workdir: Path, assignments: List[Dict], server, clients) -> None:
    server_dir = protocol_workdir / "server"
    server_pub = run_local(f"{shlex.quote(server_bin)} --print-pubkey", cwd=server_dir).splitlines()[-1].strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", server_pub):
        raise RuntimeError(f"Could not parse ZK-ARCHE server public key: {server_pub}")

    for idx, client in enumerate(clients):
        cdir = assignments[idx]["client_workdir"]
        pin_cmd = f"cd {shlex.quote(cdir)} && {shlex.quote(client_bin)} --pin-server-pub {server_pub}"
        rc, out = host_cmd_with_status(client, pin_cmd)
        if rc != 0:
            raise RuntimeError(f"ZK-ARCHE pin-server-pub failed for {client.name}:\n{out}")

        setup_cmd = (
            f"cd {shlex.quote(cdir)} && "
            f"{shlex.quote(client_bin)} --server {SERVER_IP}:{PROTOCOLS['zkarche']['port']} "
            f"--setup --pairing-token {shlex.quote(PAIRING_TOKEN)}"
        )
        rc, out = host_cmd_with_status(client, setup_cmd)
        if rc != 0:
            raise RuntimeError(f"ZK-ARCHE setup failed for {client.name}:\n{out}")


def client_auth_cmd(protocol: str, client_bin: str, client_workdir: str) -> str:
    cfg = PROTOCOLS[protocol]
    server_addr = f"{SERVER_IP}:{cfg['port']}"
    if protocol == "zkarche":
        args = f"--server {server_addr}"
    elif protocol == "mtls":
        args = f"{server_addr} localhost"
    elif protocol == "edhoc":
        args = f"{server_addr}"
    else:
        raise ValueError(protocol)
    return f"cd {shlex.quote(client_workdir)} && {shlex.quote(client_bin)} {args}"


def start_server(protocol: str, server_bin: str, protocol_workdir: Path, server) -> None:
    cfg = PROTOCOLS[protocol]
    bind = f"{SERVER_IP}:{cfg['port']}"
    server_dir = protocol_workdir / "server"
    server_dir.mkdir(parents=True, exist_ok=True)

    if protocol == "zkarche":
        args = f"--bind {bind} --pairing --pairing-token {shlex.quote(PAIRING_TOKEN)}"
    elif protocol == "mtls":
        args = bind
    elif protocol == "edhoc":
        args = bind
    else:
        raise ValueError(protocol)

    cmd = (
        f"cd {shlex.quote(str(server_dir))} && "
        f"{shlex.quote(server_bin)} {args} > /tmp/{protocol}_tests123_server.log 2>&1 &"
    )
    server.cmd(cmd)
    time.sleep(1.0)


def base_row(protocol: str, test_id: str, workload: str, a: Dict, run_index: int, round_index: int, iteration: int) -> Dict:
    return {
        "protocol": protocol,
        "test_id": test_id,
        "workload": workload,
        "run_index": run_index,
        "round_index": round_index,
        "iteration": iteration,
        "client_host": a["client_host"],
        "client_ip": a["client_ip"],
        "client_type": a["client_type"],
        "server_cpu": SERVER_CPU,
        "network_delay_ms": a["network_delay_ms"],
        "network_jitter_ms": a["network_jitter_ms"],
        "packet_loss_percent": a["packet_loss_percent"],
    }


def execute_concurrent_batch(protocol: str, client_bin: str, clients, assignments: List[Dict], test_id: str, workload: str, round_index: int) -> List[Dict]:
    batch_start = time.perf_counter()
    procs = []
    for i, client in enumerate(clients):
        cmd = client_auth_cmd(protocol, client_bin, assignments[i]["client_workdir"])
        procs.append((i, client, host_popen(client, cmd), time.perf_counter()))

    rows = []
    for i, client, proc, start_time in procs:
        output, _ = proc.communicate()
        end_time = time.perf_counter()
        rc, cleaned = parse_rc_output(output or "")
        metrics = parse_client_metrics(cleaned)
        status = "AUTH_SUCCESS" if rc == 0 and metrics["auth_duration_ms"] is not None else "AUTH_FAILED"
        row = base_row(protocol, test_id, workload, assignments[i], i + 1, round_index, i + 1)
        row.update({
            "auth_duration_ms": metrics["auth_duration_ms"],
            "auth_sent_bytes": metrics["auth_sent_bytes"],
            "auth_received_bytes": metrics["auth_received_bytes"],
            "auth_wall_elapsed_ms": round((end_time - start_time) * 1000.0, 4),
            "batch_elapsed_ms": round((end_time - batch_start) * 1000.0, 4),
            "status": status,
            "return_code": rc,
            "stdout_tail": cleaned[-300:].replace("\n", " | "),
        })
        rows.append(row)
    return rows


def execute_sequential(protocol: str, client_bin: str, client, assignment: Dict, iterations: int) -> List[Dict]:
    rows = []
    for iteration in range(1, iterations + 1):
        cmd = client_auth_cmd(protocol, client_bin, assignment["client_workdir"])
        start = time.perf_counter()
        rc, output = host_cmd_with_status(client, cmd)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 4)
        metrics = parse_client_metrics(output)
        status = "AUTH_SUCCESS" if rc == 0 and metrics["auth_duration_ms"] is not None else "AUTH_FAILED"
        row = base_row(protocol, "2", "sequential", assignment, iteration, 1, iteration)
        row.update({
            "auth_duration_ms": metrics["auth_duration_ms"],
            "auth_sent_bytes": metrics["auth_sent_bytes"],
            "auth_received_bytes": metrics["auth_received_bytes"],
            "auth_wall_elapsed_ms": elapsed_ms,
            "batch_elapsed_ms": elapsed_ms,
            "status": status,
            "return_code": rc,
            "stdout_tail": output[-300:].replace("\n", " | "),
        })
        rows.append(row)
        print(
            f"Test 2 | iter {iteration:02d} | {assignment['client_host']} | "
            f"{assignment['client_type']:<17} | auth={row['auth_duration_ms']} ms | {status}"
        )
    return rows


def write_csv(path: Path, rows: List[Dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved CSV: {path}")


def print_batch_summary(test_label: str, rows: List[Dict]) -> None:
    ok = [r for r in rows if r["status"] == "AUTH_SUCCESS" and r["auth_duration_ms"] is not None]
    failed = len(rows) - len(ok)
    if ok:
        avg = sum(float(r["auth_duration_ms"]) for r in ok) / len(ok)
        print(f"{test_label}: success={len(ok)}, failed={failed}, mean_auth_ms={avg:.4f}")
    else:
        print(f"{test_label}: success=0, failed={failed}")


def run_protocol_tests(project_root: Path, protocol: str, bins: Tuple[str, str], args) -> None:
    server_bin, client_bin = bins
    cfg = PROTOCOLS[protocol]
    selected_tests = ["1", "2", "3"] if args.test == "all" else [args.test]

    protocol_workdir = Path(args.workdir) / protocol
    if protocol_workdir.exists():
        shutil.rmtree(protocol_workdir)
    (protocol_workdir / "server").mkdir(parents=True, exist_ok=True)

    assignments = make_assignments(args.clients, protocol_workdir / "clients")
    copy_certs_if_needed(project_root, protocol, protocol_workdir, assignments)

    net, server, clients = build_network(assignments)
    try:
        info("*** Starting Mininet\n")
        net.start()
        info(f"*** Starting {cfg['title']} server\n")
        start_server(protocol, server_bin, protocol_workdir, server)

        if protocol == "zkarche":
            info("*** Preparing ZK-ARCHE per-client identity state\n")
            prepare_zkarche_state(server_bin, client_bin, protocol_workdir, assignments, server, clients)

        print(f"\n=== {cfg['title']} Tests 1/2/3 Mininet Runner ===")
        print(f"Server CPU: {SERVER_CPU}")
        print(f"Server IP:  {SERVER_IP}:{cfg['port']}")
        print(f"Clients:    {args.clients}")
        print(f"Iterations: {args.iterations}")
        print(f"Results:    {args.results_dir}")
        print("")

        if "1" in selected_tests:
            print("--- Test 1: 50 concurrent clients, single authentication ---")
            rows = execute_concurrent_batch(protocol, client_bin, clients, assignments, "1", "concurrent", 1)
            print_batch_summary("Test 1", rows)
            write_csv(Path(args.results_dir) / f"{protocol}_test1_concurrent.csv", rows)

        if "2" in selected_tests:
            print("--- Test 2: single client, 50 sequential authentications ---")
            rows = execute_sequential(protocol, client_bin, clients[0], assignments[0], args.iterations)
            print_batch_summary("Test 2", rows)
            write_csv(Path(args.results_dir) / f"{protocol}_test2_sequential.csv", rows)

        if "3" in selected_tests:
            print("--- Test 3: 50 clients x 50 authentication rounds under high load ---")
            all_rows = []
            for round_index in range(1, args.iterations + 1):
                rows = execute_concurrent_batch(protocol, client_bin, clients, assignments, "3", "high_load", round_index)
                all_rows.extend(rows)
                print_batch_summary(f"Test 3 round {round_index:02d}", rows)
            write_csv(Path(args.results_dir) / f"{protocol}_test3_high_load.csv", all_rows)

    finally:
        info(f"*** Stopping {cfg['title']} server and Mininet\n")
        try:
            server.cmd(f"pkill -f {shlex.quote(cfg['server_bin'])} || true")
        except Exception:
            pass
        net.stop()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Mininet Test 1, Test 2, and Test 3 for ZK-ARCHE, mTLS, and EDHOC.")
    p.add_argument("--project", required=True, help="Path to cohesive repo root containing Cargo.toml")
    p.add_argument("--protocol", default="zkarche", choices=["zkarche", "mtls", "edhoc", "all"])
    p.add_argument("--test", default="all", choices=["1", "2", "3", "all"], help="Which workload to run")
    p.add_argument("--clients", type=int, default=DEFAULT_CLIENTS, help="Number of clients for Test 1 and Test 3")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS, help="Iterations for Test 2 and rounds for Test 3")
    p.add_argument("--workdir", default=DEFAULT_WORKDIR)
    p.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR)
    p.add_argument("--seed", type=int, default=None)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)
    setLogLevel("info")
    project_root = Path(args.project).resolve()
    protocols = ["zkarche", "mtls", "edhoc"] if args.protocol == "all" else [args.protocol]
    bins = prepare_project(project_root, protocols)

    for protocol in protocols:
        run_protocol_tests(project_root, protocol, bins[protocol], args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
