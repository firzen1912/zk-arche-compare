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

CSV outputs include setup/full-session columns for ZK-ARCHE:
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


# Optional heterogeneous IoT device mix used by --device-mix heterogeneous-iot.
# Bandwidth values model access-link constraints; CPU is still the host CPU unless
# you add cgroup/CPU-limited Mininet hosts later.
HETEROGENEOUS_IOT_PROFILES = {
    "ESP32 sensor": {
        "weight": 0.24,
        "bw_mbps": 10,
        "delay_ms_range": (25, 95),
        "jitter_ms_range": (4, 18),
        "loss_percent_range": (0.2, 3.0),
        "traffic_role": "telemetry",
    },
    "Raspberry Pi 3B+": {
        "weight": 0.22,
        "bw_mbps": 100,
        "delay_ms_range": (12, 45),
        "jitter_ms_range": (2, 8),
        "loss_percent_range": (0.0, 1.5),
        "traffic_role": "edge_node",
    },
    "Raspberry Pi 4": {
        "weight": 0.20,
        "bw_mbps": 100,
        "delay_ms_range": (8, 32),
        "jitter_ms_range": (1, 6),
        "loss_percent_range": (0.0, 1.0),
        "traffic_role": "edge_node",
    },
    "Smart camera": {
        "weight": 0.14,
        "bw_mbps": 25,
        "delay_ms_range": (10, 40),
        "jitter_ms_range": (2, 12),
        "loss_percent_range": (0.0, 2.0),
        "traffic_role": "video",
    },
    "Smart meter": {
        "weight": 0.12,
        "bw_mbps": 5,
        "delay_ms_range": (35, 120),
        "jitter_ms_range": (6, 25),
        "loss_percent_range": (0.2, 4.0),
        "traffic_role": "low_rate",
    },
    "Industrial gateway": {
        "weight": 0.08,
        "bw_mbps": 100,
        "delay_ms_range": (5, 25),
        "jitter_ms_range": (1, 5),
        "loss_percent_range": (0.0, 0.8),
        "traffic_role": "gateway",
    },
}

BACKGROUND_TRAFFIC_PROFILES = {
    "none": {"ping": 0, "tcp": 0, "udp": 0, "udp_rate": "0M"},
    "light": {"ping": 4, "tcp": 1, "udp": 1, "udp_rate": "1M"},
    "medium": {"ping": 8, "tcp": 2, "udp": 2, "udp_rate": "3M"},
    "heavy": {"ping": 12, "tcp": 4, "udp": 4, "udp_rate": "8M"},
    "burst": {"ping": 12, "tcp": 2, "udp": 6, "udp_rate": "15M"},
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


def cert_fingerprint_sha256_pem(cert_path: Path) -> str:
    """Return SHA-256 over the certificate DER bytes, matching Rustls CertificateDer::as_ref()."""
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "der"],
        stderr=subprocess.STDOUT,
    )
    import hashlib
    return hashlib.sha256(der).hexdigest()


def prepare_mtls_authorized_clients(project_root: Path, protocol_workdir: Path) -> str:
    """Create the upgraded mTLS allowlist consumed by MTLS_ALLOWED_CLIENTS_FILE."""
    fp = cert_fingerprint_sha256_pem(project_root / "certs" / "client.crt")
    allowlist = protocol_workdir / "server" / "certs" / "authorized_clients.txt"
    allowlist.parent.mkdir(parents=True, exist_ok=True)
    allowlist.write_text(f"# Authorized mTLS client certificate fingerprints\n{fp}\n")
    return fp


def selected_device_profiles(device_mix: str) -> Dict:
    if device_mix == "heterogeneous-iot":
        return HETEROGENEOUS_IOT_PROFILES
    return DEVICE_PROFILES


def weighted_random_device(device_mix: str = "raspberry-pi") -> str:
    profiles = selected_device_profiles(device_mix)
    names = list(profiles.keys())
    weights = [profiles[name]["weight"] for name in names]
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
    """
    Supports both the original compact metric line and the upgraded mTLS line:
      CLIENT METRICS -> Duration: 5.123ms, Sent: 417 bytes, Received: 192 bytes
      CLIENT METRICS -> Protocol: mTLS/TCP, Duration: 5.123ms, Sent: 417 bytes, Received: 192 bytes, ...
    """
    metrics = {
        "auth_duration_ms": None,
        "auth_sent_bytes": None,
        "auth_received_bytes": None,
        "client_cert_sha256": None,
        "request_bytes": None,
        "response_bytes": None,
        "device_id": None,
    }
    pattern = re.compile(
        r"CLIENT METRICS\s*->\s*(?:Protocol:\s*[^,]+,\s*)?"
        r"Duration:\s*([^,]+),\s*Sent:\s*(\d+)\s*bytes,\s*Received:\s*(\d+)\s*bytes"
    )
    for line in output.splitlines():
        m = pattern.search(line)
        if m:
            parsed = parse_duration_to_ms(m.group(1))
            metrics["auth_duration_ms"] = round(parsed, 4) if parsed is not None else None
            metrics["auth_sent_bytes"] = int(m.group(2))
            metrics["auth_received_bytes"] = int(m.group(3))

            for key, metric_key in [
                ("ClientCertSHA256", "client_cert_sha256"),
                ("RequestBytes", "request_bytes"),
                ("ResponseBytes", "response_bytes"),
                ("DeviceID", "device_id"),
            ]:
                km = re.search(rf"{key}:\s*([^,]+)", line)
                if km:
                    val = km.group(1).strip()
                    if metric_key in ("request_bytes", "response_bytes"):
                        try:
                            metrics[metric_key] = int(val)
                        except ValueError:
                            metrics[metric_key] = None
                    else:
                        metrics[metric_key] = val
    return metrics


def parse_all_client_metrics(output: str) -> List[Dict[str, Optional[float]]]:
    metrics_list = []
    current_lines = []
    for line in output.splitlines():
        if "CLIENT METRICS ->" in line:
            m = parse_client_metrics(line)
            if m["auth_duration_ms"] is not None:
                metrics_list.append(m)
    return metrics_list



def zkarche_setup_fields(assignment: Dict) -> Dict[str, Optional[float]]:
    """Return per-client ZK-ARCHE setup metrics captured during enrollment."""
    return {
        "setup_duration_ms": assignment.get("setup_duration_ms"),
        "setup_sent_bytes": assignment.get("setup_sent_bytes"),
        "setup_received_bytes": assignment.get("setup_received_bytes"),
        "setup_wall_elapsed_ms": assignment.get("setup_wall_elapsed_ms"),
    }


def add_full_session_metrics(protocol: str, assignment: Dict, row: Dict, metrics: Dict) -> None:
    """Normalize all protocols to a full-session CSV schema.

    For ZK-ARCHE, full session = setup/enrollment + online authentication.
    For EDHOC and mTLS, the client metric already covers the full measured
    authenticated exchange, so setup is zero and full_session == auth.
    """
    auth_ms = metrics.get("auth_duration_ms")
    auth_sent = metrics.get("auth_sent_bytes")
    auth_recv = metrics.get("auth_received_bytes")

    if protocol == "zkarche":
        setup_ms = assignment.get("setup_duration_ms")
        setup_sent = assignment.get("setup_sent_bytes")
        setup_recv = assignment.get("setup_received_bytes")
        setup_wall = assignment.get("setup_wall_elapsed_ms")
    else:
        setup_ms = 0.0
        setup_sent = 0
        setup_recv = 0
        setup_wall = 0.0

    row.update({
        "setup_duration_ms": setup_ms,
        "setup_sent_bytes": setup_sent,
        "setup_received_bytes": setup_recv,
        "setup_wall_elapsed_ms": setup_wall,
        "auth_duration_ms": auth_ms,
        "auth_sent_bytes": auth_sent,
        "auth_received_bytes": auth_recv,
    })

    if auth_ms is not None and setup_ms is not None:
        row["full_session_duration_ms"] = round(float(setup_ms) + float(auth_ms), 4)
    else:
        row["full_session_duration_ms"] = auth_ms

    if auth_sent is not None and setup_sent is not None:
        row["full_session_sent_bytes"] = int(setup_sent) + int(auth_sent)
    else:
        row["full_session_sent_bytes"] = auth_sent

    if auth_recv is not None and setup_recv is not None:
        row["full_session_received_bytes"] = int(setup_recv) + int(auth_recv)
    else:
        row["full_session_received_bytes"] = auth_recv

    if row.get("full_session_sent_bytes") is not None and row.get("full_session_received_bytes") is not None:
        row["full_session_total_bytes"] = int(row["full_session_sent_bytes"]) + int(row["full_session_received_bytes"])
    else:
        row["full_session_total_bytes"] = None


def empty_server_metric_row(protocol: str, test_id: str, workload: str, round_index: int) -> Dict[str, Optional[float]]:
    return {
        "protocol": protocol,
        "test_id": test_id,
        "workload": workload,
        "round_index": round_index,
        "server_peer": None,
        "server_auth_duration_ms": None,
        "server_sent_bytes": None,
        "server_received_bytes": None,
        "server_device_id": None,
        "server_client_cert_sha256": None,
        "server_request_bytes": None,
        "server_response_bytes": None,
        "server_payload_bytes": None,
        "server_timestamp_ms": None,
        "server_status": "SERVER_METRIC",
        "server_stdout_tail": None,
    }


def parse_server_metrics_line(protocol: str, line: str, test_id: str, workload: str, round_index: int) -> Optional[Dict[str, Optional[float]]]:
    """
    Supports original and upgraded server metric lines, for example:
      SERVER METRICS -> 10.0.0.2:1234 Duration: 5.123ms, Sent: 100 bytes, Received: 200 bytes
      SERVER METRICS -> Peer: 10.0.0.2:1234, Protocol: mTLS/TCP, Duration: 5.123ms, Sent: 100 bytes, Received: 200 bytes, ...
      SERVER METRICS -> Peer: 10.0.0.2:1234, Protocol: EDHOC/TCP, Duration: 5.123ms, Sent: 100 bytes, Received: 200 bytes, ...
    """
    if "SERVER METRICS ->" not in line:
        return None

    row = empty_server_metric_row(protocol, test_id, workload, round_index)

    # Upgraded mTLS / EDHOC format.
    m = re.search(
        r"SERVER METRICS\s*->\s*Peer:\s*([^,]+),\s*Protocol:\s*[^,]+,\s*"
        r"Duration:\s*([^,]+),\s*Sent:\s*(\d+)\s*bytes,\s*Received:\s*(\d+)\s*bytes",
        line,
    )

    # Original compact ZK-ARCHE / EDHOC format.
    if not m:
        m = re.search(
            r"SERVER METRICS\s*->\s*([^,]+?)\s+Duration:\s*([^,]+),\s*"
            r"Sent:\s*(\d+)\s*bytes,\s*Received:\s*(\d+)\s*bytes",
            line,
        )

    if not m:
        return None

    row["server_peer"] = m.group(1).strip().strip('"')
    parsed = parse_duration_to_ms(m.group(2))
    row["server_auth_duration_ms"] = round(parsed, 4) if parsed is not None else None
    row["server_sent_bytes"] = int(m.group(3))
    row["server_received_bytes"] = int(m.group(4))

    optional_fields = [
        ("DeviceID", "server_device_id", str),
        ("ClientCertSHA256", "server_client_cert_sha256", str),
        ("RequestBytes", "server_request_bytes", int),
        ("ResponseBytes", "server_response_bytes", int),
        ("PayloadBytes", "server_payload_bytes", int),
        ("TimestampMs", "server_timestamp_ms", int),
    ]
    for label, key, cast in optional_fields:
        km = re.search(rf"{label}:\s*([^,]+)", line)
        if not km:
            continue
        val = km.group(1).strip()
        try:
            row[key] = cast(val)
        except Exception:
            row[key] = None

    row["server_stdout_tail"] = line[-300:].replace("\n", " | ")
    return row


def parse_server_metrics_log(protocol: str, log_text: str, start_line: int, test_id: str, workload: str, round_index: int) -> Tuple[List[Dict], int]:
    lines = log_text.splitlines()
    new_lines = lines[start_line:]
    rows = []
    for line in new_lines:
        row = parse_server_metrics_line(protocol, line, test_id, workload, round_index)
        if row is not None and row["server_auth_duration_ms"] is not None:
            rows.append(row)
    return rows, len(lines)


def collect_server_metrics(protocol: str, server, offset_state: Dict[str, int], test_id: str, workload: str, round_index: int) -> List[Dict]:
    # Give the server task/process a short chance to flush its final metric line.
    time.sleep(0.2)
    log_path = f"/tmp/{protocol}_tests123_server.log"
    output = server.cmd(f"cat {shlex.quote(log_path)} 2>/dev/null || true")
    rows, new_offset = parse_server_metrics_log(
        protocol=protocol,
        log_text=output,
        start_line=offset_state.get("line", 0),
        test_id=test_id,
        workload=workload,
        round_index=round_index,
    )
    offset_state["line"] = new_offset
    return rows


def prepare_project(project_root: Path, protocol_names: List[str]) -> Dict[str, Tuple[str, str]]:
    project_root = project_root.resolve()
    if not (project_root / "Cargo.toml").exists():
        raise FileNotFoundError(f"Cargo.toml not found in {project_root}")

    if "mtls" in protocol_names:
        cert_dir = project_root / "certs"
        needed = ["ca.crt", "client.crt", "client.key", "server.crt", "server.key"]
        if not cert_dir.exists() or any(not (cert_dir / name).exists() for name in needed):
            run_local("bash scripts/gen_certs.sh", cwd=project_root)

    run_local("cargo build --release --bins", cwd=project_root)

    bins = {}
    for protocol in protocol_names:
        cfg = PROTOCOLS[protocol]
        server_bin = project_root / "target" / "release" / cfg["server_bin"]
        client_bin = project_root / "target" / "release" / cfg["client_bin"]
        if not server_bin.exists():
            raise FileNotFoundError(f"Missing server binary: {server_bin}")
        if not client_bin.exists():
            raise FileNotFoundError(f"Missing client binary: {client_bin}")
        bins[protocol] = (str(server_bin), str(client_bin))
    return bins


def make_assignments(num_clients: int, clients_dir: Path, device_mix: str = "raspberry-pi", gateway_count: int = 4) -> List[Dict]:
    clients_dir.mkdir(parents=True, exist_ok=True)
    profiles = selected_device_profiles(device_mix)
    assignments = []
    for i in range(1, num_clients + 1):
        dtype = weighted_random_device(device_mix)
        profile = profiles[dtype]
        cdir = clients_dir / f"pi{i}"
        cdir.mkdir(parents=True, exist_ok=True)
        gateway_index = ((i - 1) % max(1, gateway_count)) + 1
        assignments.append({
            "client_index": i,
            "client_host": f"pi{i}",
            "client_ip": f"10.0.0.{i + 1}",
            "client_type": dtype,
            "traffic_role": profile.get("traffic_role", "auth_client"),
            "gateway_index": gateway_index,
            "gateway_name": f"edge{gateway_index}",
            "bw_mbps": profile["bw_mbps"],
            "network_delay_ms": rand_range(profile, "delay_ms_range"),
            "network_jitter_ms": rand_range(profile, "jitter_ms_range"),
            "packet_loss_percent": rand_range(profile, "loss_percent_range"),
            "client_workdir": str(cdir),
        })
    return assignments


def build_network(assignments: List[Dict], args=None):
    """Build either the original flat LAN or a more realistic multi-tier IoT network.

    multi-tier layout:
      clients -> edge switches -> aggregation switch -> core switch -> auth server
      background hosts are attached to edge/core switches and generate traffic separately.
    """
    net = Mininet(
        controller=Controller,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )
    info("*** Adding controller\n")
    net.addController("c0")

    network_model = getattr(args, "network_model", "simple") if args is not None else "simple"
    gateway_count = getattr(args, "gateway_count", 4) if args is not None else 4
    background_hosts = getattr(args, "background_hosts", 0) if args is not None else 0

    clients = []

    if network_model == "simple":
        info("*** Adding simple switch\n")
        sw = net.addSwitch("s1")
        info("*** Adding i7 authentication server\n")
        server = net.addHost("server", ip=f"{SERVER_IP}/24")
        net.addLink(server, sw, cls=TCLink, bw=1000, delay="1ms", jitter="0.2ms", loss=0)

        info("*** Adding randomized IoT clients on simple LAN\n")
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
        net.background_hosts = []
        return net, server, clients

    info("*** Adding multi-tier IoT switching fabric\n")
    core = net.addSwitch("core1")
    agg = net.addSwitch("agg1")
    net.addLink(core, agg, cls=TCLink, bw=1000, delay="2ms", jitter="0.3ms", loss=0)

    info("*** Adding i7 authentication server behind core switch\n")
    server = net.addHost("server", ip=f"{SERVER_IP}/24")
    net.addLink(server, core, cls=TCLink, bw=1000, delay="1ms", jitter="0.2ms", loss=0)

    edge_switches = []
    for gi in range(1, gateway_count + 1):
        edge = net.addSwitch(f"edge{gi}")
        # Edge uplinks represent gateway/backhaul variability.
        uplink_delay = round(random.uniform(2.0, 12.0), 3)
        uplink_jitter = round(random.uniform(0.2, 3.0), 3)
        uplink_loss = round(random.uniform(0.0, 0.6), 3)
        uplink_bw = random.choice([50, 100, 250, 500])
        net.addLink(edge, agg, cls=TCLink, bw=uplink_bw, delay=f"{uplink_delay}ms", jitter=f"{uplink_jitter}ms", loss=uplink_loss)
        edge_switches.append(edge)

    info("*** Adding randomized IoT clients across edge gateways\n")
    for assignment in assignments:
        client = net.addHost(assignment["client_host"], ip=f"{assignment['client_ip']}/24")
        edge = edge_switches[assignment["gateway_index"] - 1]
        net.addLink(
            client,
            edge,
            cls=TCLink,
            bw=assignment["bw_mbps"],
            delay=f"{assignment['network_delay_ms']}ms",
            jitter=f"{assignment['network_jitter_ms']}ms",
            loss=assignment["packet_loss_percent"],
        )
        clients.append(client)

    # Background endpoints create cross traffic independent from auth clients.
    bg_hosts = []
    for i in range(1, background_hosts + 1):
        ip_octet = 150 + i
        if ip_octet >= 254:
            break
        h = net.addHost(f"bg{i}", ip=f"10.0.0.{ip_octet}/24")
        if i % 4 == 0:
            attach = core
            bw, delay, jitter, loss = 500, "3ms", "0.5ms", 0.1
        else:
            attach = edge_switches[(i - 1) % len(edge_switches)]
            bw = random.choice([10, 25, 50, 100])
            delay = f"{round(random.uniform(5, 55), 3)}ms"
            jitter = f"{round(random.uniform(1, 12), 3)}ms"
            loss = round(random.uniform(0.0, 2.5), 3)
        net.addLink(h, attach, cls=TCLink, bw=bw, delay=delay, jitter=jitter, loss=loss)
        bg_hosts.append(h)
    net.background_hosts = bg_hosts
    return net, server, clients


def background_intensity_profile(level: str) -> Dict:
    return BACKGROUND_TRAFFIC_PROFILES.get(level, BACKGROUND_TRAFFIC_PROFILES["none"])


def start_background_traffic(net, server, args) -> List:
    """Start best-effort background traffic generators.

    These flows intentionally do not produce authentication metrics. They create queueing,
    jitter, packet loss pressure, and server-side interrupt/context-switch noise.
    """
    level = getattr(args, "background_traffic", "none")
    profile = background_intensity_profile(level)
    bg_hosts = getattr(net, "background_hosts", [])
    if level == "none" or not bg_hosts:
        return []

    procs = []
    sink_port_base = 5201
    info(f"*** Starting background traffic profile: {level}\n")

    # TCP/UDP sinks on the server. Multiple iperf servers are cheap and avoid port contention.
    total_sinks = max(profile["tcp"] + profile["udp"], 1)
    for offset in range(total_sinks):
        port = sink_port_base + offset
        procs.append(server.popen(f"iperf -s -p {port} >/tmp/bg_iperf_server_{port}.log 2>&1", shell=True))
    time.sleep(0.2)

    # Long-running ping flows: small, frequent control-plane-like traffic.
    for h in bg_hosts[:profile["ping"]]:
        interval = random.choice([0.1, 0.2, 0.5, 1.0])
        size = random.choice([32, 64, 128, 256])
        procs.append(h.popen(
            f"ping -i {interval} -s {size} {SERVER_IP} >/tmp/{h.name}_bg_ping.log 2>&1",
            shell=True,
        ))

    # TCP bulk telemetry / firmware-update-like flows.
    for idx, h in enumerate(bg_hosts[:profile["tcp"]]):
        port = sink_port_base + idx
        procs.append(h.popen(
            f"while true; do iperf -c {SERVER_IP} -p {port} -t 5 >/tmp/{h.name}_bg_tcp.log 2>&1; sleep {random.randint(1,4)}; done",
            shell=True,
        ))

    # UDP video/sensor burst-like flows.
    start = profile["tcp"]
    for idx, h in enumerate(bg_hosts[start:start + profile["udp"]]):
        port = sink_port_base + profile["tcp"] + idx
        rate = profile["udp_rate"]
        length = random.choice([256, 512, 1024, 1200])
        procs.append(h.popen(
            f"while true; do iperf -u -c {SERVER_IP} -p {port} -b {rate} -l {length} -t 6 >/tmp/{h.name}_bg_udp.log 2>&1; sleep {random.randint(1,3)}; done",
            shell=True,
        ))

    return procs


def stop_background_traffic(procs: List) -> None:
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(0.2)
    for p in procs:
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass


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
    """Pin server key and enroll each ZK-ARCHE client.

    Setup metrics are stored on each assignment so every later auth row can
    include full_session_duration_ms = setup_duration_ms + auth_duration_ms.
    The server-public-key pinning step is treated as out-of-band provisioning
    and is not included in setup_duration_ms.
    """
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
        setup_start = time.perf_counter()
        rc, out = host_cmd_with_status(client, setup_cmd)
        setup_wall_ms = round((time.perf_counter() - setup_start) * 1000.0, 4)
        if rc != 0:
            raise RuntimeError(f"ZK-ARCHE setup failed for {client.name}:\n{out}")

        setup_metrics = parse_client_metrics(out)
        assignments[idx]["setup_duration_ms"] = setup_metrics.get("auth_duration_ms")
        assignments[idx]["setup_sent_bytes"] = setup_metrics.get("auth_sent_bytes")
        assignments[idx]["setup_received_bytes"] = setup_metrics.get("auth_received_bytes")
        assignments[idx]["setup_wall_elapsed_ms"] = setup_wall_ms

        # Capture the server-side setup metric for the same enrollment. Setup
        # runs sequentially here, so the latest SERVER METRICS line belongs to
        # this client setup exchange.
        time.sleep(0.1)
        setup_log = server.cmd("cat /tmp/zkarche_tests123_server.log 2>/dev/null || true")
        setup_server_rows, _ = parse_server_metrics_log(
            protocol="zkarche",
            log_text=setup_log,
            start_line=0,
            test_id="setup",
            workload="setup",
            round_index=0,
        )
        if setup_server_rows:
            sr = setup_server_rows[-1]
            assignments[idx]["server_setup_duration_ms"] = sr.get("server_auth_duration_ms")
            assignments[idx]["server_setup_sent_bytes"] = sr.get("server_sent_bytes")
            assignments[idx]["server_setup_received_bytes"] = sr.get("server_received_bytes")
        else:
            assignments[idx]["server_setup_duration_ms"] = None
            assignments[idx]["server_setup_sent_bytes"] = None
            assignments[idx]["server_setup_received_bytes"] = None

        print(
            f"ZK-ARCHE setup | {client.name:>4} | {assignments[idx]['client_type']:<17} | "
            f"client_setup={assignments[idx]['setup_duration_ms']} ms | "
            f"server_setup={assignments[idx]['server_setup_duration_ms']} ms | "
            f"sent={assignments[idx]['setup_sent_bytes']} B | recv={assignments[idx]['setup_received_bytes']} B"
        )

def client_auth_cmd(protocol: str, client_bin: str, client_workdir: str) -> str:
    cfg = PROTOCOLS[protocol]
    server_addr = f"{SERVER_IP}:{cfg['port']}"
    if protocol == "zkarche":
        args = f"--server {server_addr}"
        zkenv = (
            "ZKARCHE_FAST_LOOKUP=${ZKARCHE_FAST_LOOKUP:-1} "
            "ZKARCHE_BENCH_MODE=${ZKARCHE_BENCH_MODE:-1} "
            "ZKARCHE_DEVICE_ONLY=${ZKARCHE_DEVICE_ONLY:-0} "
        )
        return f"cd {shlex.quote(client_workdir)} && {zkenv}{shlex.quote(client_bin)} {args}"
    elif protocol == "mtls":
        device_id = Path(client_workdir).name
        args = f"{server_addr} localhost"
        return (
            f"cd {shlex.quote(client_workdir)} && "
            f"MTLS_DEVICE_ID={shlex.quote(device_id)} "
            f"MTLS_PAYLOAD={shlex.quote('mininet-industry-style-mtls-auth-check')} "
            f"{shlex.quote(client_bin)} {args}"
        )
    elif protocol == "edhoc":
        device_id = Path(client_workdir).name
        args = f"{server_addr}"
        return (
            f"cd {shlex.quote(client_workdir)} && "
            f"EDHOC_DEVICE_ID={shlex.quote(device_id)} "
            f"EDHOC_PAYLOAD={shlex.quote('mininet-industry-style-edhoc-protected-request')} "
            f"{shlex.quote(client_bin)} {args}"
        )
    else:
        raise ValueError(protocol)
    return f"cd {shlex.quote(client_workdir)} && {shlex.quote(client_bin)} {args}"


def start_server(protocol: str, server_bin: str, protocol_workdir: Path, server) -> None:
    cfg = PROTOCOLS[protocol]
    bind = f"{SERVER_IP}:{cfg['port']}"
    server_dir = protocol_workdir / "server"
    server_dir.mkdir(parents=True, exist_ok=True)
    server_env = ""

    if protocol == "zkarche":
        args = f"--bind {bind} --pairing --pairing-token {shlex.quote(PAIRING_TOKEN)}"
        server_env = (
            "ZKARCHE_BENCH_MODE=${ZKARCHE_BENCH_MODE:-1} "
            "ZKARCHE_ALLOW_DEVICE_ONLY=${ZKARCHE_ALLOW_DEVICE_ONLY:-1} "
        )
    elif protocol == "mtls":
        args = bind
    elif protocol == "edhoc":
        args = bind
    else:
        raise ValueError(protocol)

    env_prefix = ""
    if protocol == "mtls":
        env_prefix = (
            "MTLS_MAX_ACTIVE_CONNECTIONS=128 "
            "MTLS_ALLOWED_CLIENTS_FILE=certs/authorized_clients.txt "
        )
    elif protocol == "edhoc":
        allowed_ids = ",".join(f"pi{i}" for i in range(1, 501))
        env_prefix = (
            "EDHOC_MAX_ACTIVE_CONNECTIONS=128 "
            "EDHOC_TIMEOUT_SECS=5 "
            f"EDHOC_ALLOWED_DEVICE_IDS={shlex.quote(allowed_ids)} "
        )

    cmd = (
        f"cd {shlex.quote(str(server_dir))} && "
        f"{env_prefix}{shlex.quote(server_bin)} {args} > /tmp/{protocol}_tests123_server.log 2>&1 &"
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
        "gateway_name": a.get("gateway_name"),
        "gateway_index": a.get("gateway_index"),
        "traffic_role": a.get("traffic_role"),
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
        add_full_session_metrics(protocol, assignments[i], row, metrics)
        row.update({
            "client_cert_sha256": metrics.get("client_cert_sha256"),
            "request_bytes": metrics.get("request_bytes"),
            "response_bytes": metrics.get("response_bytes"),
            "device_id": metrics.get("device_id"),
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
    if protocol == "zkarche" and os.environ.get("ZKARCHE_CLIENT_REPEAT", "1") != "0":
        cfg = PROTOCOLS[protocol]
        server_addr = f"{SERVER_IP}:{cfg['port']}"
        cmd = (
            f"cd {shlex.quote(assignment['client_workdir'])} && "
            f"ZKARCHE_FAST_LOOKUP=${{ZKARCHE_FAST_LOOKUP:-1}} "
            f"ZKARCHE_BENCH_MODE=${{ZKARCHE_BENCH_MODE:-1}} "
            f"ZKARCHE_DEVICE_ONLY=${{ZKARCHE_DEVICE_ONLY:-0}} "
            f"{shlex.quote(client_bin)} --server {server_addr} --repeat {iterations}"
        )
        start = time.perf_counter()
        rc, output = host_cmd_with_status(client, cmd)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 4)
        metric_rows = parse_all_client_metrics(output)
        for iteration in range(1, iterations + 1):
            metrics = metric_rows[iteration - 1] if iteration - 1 < len(metric_rows) else {
                "auth_duration_ms": None,
                "auth_sent_bytes": None,
                "auth_received_bytes": None,
                "request_bytes": None,
                "response_bytes": None,
                "device_id": None,
                "client_cert_sha256": None,
            }
            status = "AUTH_SUCCESS" if rc == 0 and metrics["auth_duration_ms"] is not None else "AUTH_FAILED"
            row = base_row(protocol, "2", "sequential", assignment, iteration, 1, iteration)
            add_full_session_metrics(protocol, assignment, row, metrics)
            row.update({
                "request_bytes": metrics.get("request_bytes"),
                "response_bytes": metrics.get("response_bytes"),
                "device_id": metrics.get("device_id"),
                "client_cert_sha256": metrics.get("client_cert_sha256"),
                "auth_wall_elapsed_ms": elapsed_ms if iteration == iterations else None,
                "batch_elapsed_ms": elapsed_ms if iteration == iterations else None,
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

    for iteration in range(1, iterations + 1):
        cmd = client_auth_cmd(protocol, client_bin, assignment["client_workdir"])
        start = time.perf_counter()
        rc, output = host_cmd_with_status(client, cmd)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 4)
        metrics = parse_client_metrics(output)
        status = "AUTH_SUCCESS" if rc == 0 and metrics["auth_duration_ms"] is not None else "AUTH_FAILED"
        row = base_row(protocol, "2", "sequential", assignment, iteration, 1, iteration)
        add_full_session_metrics(protocol, assignment, row, metrics)
        row.update({
            "client_cert_sha256": metrics.get("client_cert_sha256"),
            "request_bytes": metrics.get("request_bytes"),
            "response_bytes": metrics.get("response_bytes"),
            "device_id": metrics.get("device_id"),
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


def add_zkarche_server_full_session_fields(server_rows: List[Dict], assignments: List[Dict]) -> List[Dict]:
    """Add server-side ZK-ARCHE setup+auth columns to server metric rows.

    Server rows are produced during online auth. For ZK-ARCHE full-session
    accounting, attach the setup metric captured during per-client enrollment.
    The row is matched by server_peer IP address.
    """
    by_ip = {a["client_ip"]: a for a in assignments}
    for row in server_rows:
        peer = str(row.get("server_peer") or "")
        ip = peer.split(":", 1)[0].strip().strip('"')
        a = by_ip.get(ip)
        setup_ms = a.get("server_setup_duration_ms") if a else None
        setup_sent = a.get("server_setup_sent_bytes") if a else None
        setup_recv = a.get("server_setup_received_bytes") if a else None
        auth_ms = row.get("server_auth_duration_ms")
        auth_sent = row.get("server_sent_bytes")
        auth_recv = row.get("server_received_bytes")
        row["server_setup_duration_ms"] = setup_ms
        row["server_setup_sent_bytes"] = setup_sent
        row["server_setup_received_bytes"] = setup_recv
        if setup_ms is not None and auth_ms is not None:
            row["server_full_session_duration_ms"] = round(float(setup_ms) + float(auth_ms), 4)
        else:
            row["server_full_session_duration_ms"] = auth_ms
        if setup_sent is not None and auth_sent is not None:
            row["server_full_session_sent_bytes"] = int(setup_sent) + int(auth_sent)
        else:
            row["server_full_session_sent_bytes"] = auth_sent
        if setup_recv is not None and auth_recv is not None:
            row["server_full_session_received_bytes"] = int(setup_recv) + int(auth_recv)
        else:
            row["server_full_session_received_bytes"] = auth_recv
        if row.get("server_full_session_sent_bytes") is not None and row.get("server_full_session_received_bytes") is not None:
            row["server_full_session_total_bytes"] = int(row["server_full_session_sent_bytes"]) + int(row["server_full_session_received_bytes"])
        else:
            row["server_full_session_total_bytes"] = None
    return server_rows


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
    metric_key = "full_session_duration_ms" if rows and "full_session_duration_ms" in rows[0] else "auth_duration_ms"
    ok = [r for r in rows if r["status"] == "AUTH_SUCCESS" and r.get(metric_key) is not None]
    failed = len(rows) - len(ok)
    if ok:
        avg = sum(float(r[metric_key]) for r in ok) / len(ok)
        label = "mean_full_session_ms" if metric_key == "full_session_duration_ms" else "mean_auth_ms"
        print(f"{test_label}: success={len(ok)}, failed={failed}, {label}={avg:.4f}")
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

    assignments = make_assignments(args.clients, protocol_workdir / "clients", args.device_mix, args.gateway_count)
    copy_certs_if_needed(project_root, protocol, protocol_workdir, assignments)
    if protocol == "mtls":
        fp = prepare_mtls_authorized_clients(project_root, protocol_workdir)
        print(f"Prepared mTLS client certificate allowlist with SHA-256 fingerprint: {fp}")

    net, server, clients = build_network(assignments, args)
    try:
        info("*** Starting Mininet\n")
        net.start()
        bg_procs = start_background_traffic(net, server, args)
        info(f"*** Starting {cfg['title']} server\n")
        start_server(protocol, server_bin, protocol_workdir, server)
        server_metric_offset = {"line": 0}

        if protocol == "zkarche":
            info("*** Preparing ZK-ARCHE per-client identity state\n")
            prepare_zkarche_state(server_bin, client_bin, protocol_workdir, assignments, server, clients)
            # Exclude enrollment/setup log lines from online-authentication server metrics.
            server_metric_offset["line"] = len((server.cmd(f"cat /tmp/{protocol}_tests123_server.log 2>/dev/null || true") or "").splitlines())

        print(f"\n=== {cfg['title']} Tests 1/2/3 Mininet Runner ===")
        print(f"Server CPU: {SERVER_CPU}")
        print(f"Server IP:  {SERVER_IP}:{cfg['port']}")
        print(f"Clients:    {args.clients}")
        print(f"Iterations: {args.iterations}")
        print(f"Results:    {args.results_dir}")
        print(f"Network:    {args.network_model}, device_mix={args.device_mix}, gateways={args.gateway_count}, background={args.background_traffic}, bg_hosts={args.background_hosts}")
        print("")

        if "1" in selected_tests:
            print("--- Test 1: 50 concurrent clients, single authentication ---")
            rows = execute_concurrent_batch(protocol, client_bin, clients, assignments, "1", "concurrent", 1)
            print_batch_summary("Test 1", rows)
            write_csv(Path(args.results_dir) / f"{protocol}_test1_concurrent.csv", rows)
            server_rows = collect_server_metrics(protocol, server, server_metric_offset, "1", "concurrent", 1)
            if protocol == "zkarche":
                server_rows = add_zkarche_server_full_session_fields(server_rows, assignments)
            server_metric_key = "server_full_session_duration_ms" if protocol == "zkarche" else "server_auth_duration_ms"
            print_batch_summary("Test 1 server", [{"status": "AUTH_SUCCESS", "auth_duration_ms": r[server_metric_key]} for r in server_rows])
            write_csv(Path(args.results_dir) / f"{protocol}_test1_concurrent_server.csv", server_rows)

        if "2" in selected_tests:
            print("--- Test 2: single client, 50 sequential authentications ---")
            rows = execute_sequential(protocol, client_bin, clients[0], assignments[0], args.iterations)
            print_batch_summary("Test 2", rows)
            write_csv(Path(args.results_dir) / f"{protocol}_test2_sequential.csv", rows)
            server_rows = collect_server_metrics(protocol, server, server_metric_offset, "2", "sequential", 1)
            if protocol == "zkarche":
                server_rows = add_zkarche_server_full_session_fields(server_rows, assignments)
            server_metric_key = "server_full_session_duration_ms" if protocol == "zkarche" else "server_auth_duration_ms"
            print_batch_summary("Test 2 server", [{"status": "AUTH_SUCCESS", "auth_duration_ms": r[server_metric_key]} for r in server_rows])
            write_csv(Path(args.results_dir) / f"{protocol}_test2_sequential_server.csv", server_rows)

        if "3" in selected_tests:
            print("--- Test 3: 50 clients x 50 authentication rounds under high load ---")
            all_rows = []
            all_server_rows = []
            for round_index in range(1, args.iterations + 1):
                rows = execute_concurrent_batch(protocol, client_bin, clients, assignments, "3", "high_load", round_index)
                all_rows.extend(rows)
                print_batch_summary(f"Test 3 round {round_index:02d}", rows)
                server_rows = collect_server_metrics(protocol, server, server_metric_offset, "3", "high_load", round_index)
                if protocol == "zkarche":
                    server_rows = add_zkarche_server_full_session_fields(server_rows, assignments)
                all_server_rows.extend(server_rows)
                server_metric_key = "server_full_session_duration_ms" if protocol == "zkarche" else "server_auth_duration_ms"
                print_batch_summary(f"Test 3 server round {round_index:02d}", [{"status": "AUTH_SUCCESS", "auth_duration_ms": r[server_metric_key]} for r in server_rows])
            write_csv(Path(args.results_dir) / f"{protocol}_test3_high_load.csv", all_rows)
            write_csv(Path(args.results_dir) / f"{protocol}_test3_high_load_server.csv", all_server_rows)

    finally:
        try:
            stop_background_traffic(locals().get("bg_procs", []))
        except Exception:
            pass
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
    p.add_argument("--network-model", default="multi-tier", choices=["simple", "multi-tier"], help="Use the old flat LAN or a multi-tier IoT access/aggregation/core topology")
    p.add_argument("--gateway-count", type=int, default=4, help="Number of edge switches/gateways in multi-tier mode")
    p.add_argument("--device-mix", default="heterogeneous-iot", choices=["raspberry-pi", "heterogeneous-iot"], help="Authentication client device/link profile mix")
    p.add_argument("--background-hosts", type=int, default=16, help="Number of non-authentication background traffic hosts")
    p.add_argument("--background-traffic", default="medium", choices=["none", "light", "medium", "heavy", "burst"], help="Background traffic intensity")
    p.add_argument("--zkarche-device-only", action="store_true", help="Run optimized ZK-ARCHE device-only mode by setting ZKARCHE_DEVICE_ONLY=1")
    p.add_argument("--zkarche-full", action="store_true", help="Run full ZK-ARCHE proof mode while still using release build and fast handle lookup")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)
    if args.zkarche_device_only:
        os.environ["ZKARCHE_DEVICE_ONLY"] = "1"
    if args.zkarche_full:
        os.environ["ZKARCHE_DEVICE_ONLY"] = "0"
    os.environ.setdefault("ZKARCHE_FAST_LOOKUP", "1")
    os.environ.setdefault("ZKARCHE_BENCH_MODE", "1")
    os.environ.setdefault("ZKARCHE_ALLOW_DEVICE_ONLY", "1")
    setLogLevel("info")
    project_root = Path(args.project).resolve()
    protocols = ["zkarche", "mtls", "edhoc"] if args.protocol == "all" else [args.protocol]
    bins = prepare_project(project_root, protocols)

    for protocol in protocols:
        run_protocol_tests(project_root, protocol, bins[protocol], args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
