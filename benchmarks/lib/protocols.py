"""
Protocol-specific glue.

Each of the three protocols has its own:
  * server CLI (different bind flag style),
  * client CLI (zkarche has --server flag, edhoc/mtls take a positional arg),
  * client setup requirement (zkarche needs an enrollment step; edhoc/mtls don't),
  * fresh-state requirement (zkarche must enroll a clean device per workdir).

This module hides those differences behind a uniform Protocol object so the
test scripts can stay protocol-agnostic.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from . import config
from .runner import ServerHandle, run_client_once, start_server, stop_server


# A shared pairing token used by the bench harness for ZK-ARCHE enrollment.
PAIRING_TOKEN = "zkb-bench-token"


@dataclass
class Protocol:
    name: str            # short identifier: "zkarche" | "edhoc" | "mtls"
    display: str         # human label: "ZK-ARCHE" | "EDHOC" | "mTLS"
    server_bin: Path
    client_bin: Path
    bind_addr: str

    # build_server_args(workdir, pairing) -> argv for server
    server_args_fn: Callable[[Path, bool], list[str]]
    # build_client_args(workdir) -> argv for a normal authentication run
    client_args_fn: Callable[[Path], list[str]]
    # client_setup_args(workdir) -> argv for one-time enrollment, or None
    client_setup_args_fn: Optional[Callable[[Path], list[str]]]

    # whether each client workdir needs to be enrolled before it can auth
    requires_enroll: bool


# ---------------------------------------------------------------------------
# ZK-ARCHE
# ---------------------------------------------------------------------------

def _zk_server_args(_workdir: Path, pairing: bool) -> list[str]:
    args = ["--bind", config.ZKARCHE_BIND]
    if pairing:
        args += ["--pairing", "--pairing-token", PAIRING_TOKEN]
    return args


def _zk_client_args(_workdir: Path) -> list[str]:
    return ["--server", config.ZKARCHE_BIND]


def _zk_client_setup_args(_workdir: Path) -> list[str]:
    return ["--server", config.ZKARCHE_BIND, "--setup", "--pairing-token", PAIRING_TOKEN]


# ---------------------------------------------------------------------------
# EDHOC
# ---------------------------------------------------------------------------

def _edhoc_server_args(_workdir: Path, _pairing: bool) -> list[str]:
    return [config.EDHOC_BIND]


def _edhoc_client_args(_workdir: Path) -> list[str]:
    return [config.EDHOC_BIND]


# ---------------------------------------------------------------------------
# mTLS
# ---------------------------------------------------------------------------

def _mtls_server_args(_workdir: Path, _pairing: bool) -> list[str]:
    return [config.MTLS_BIND]


def _mtls_client_args(_workdir: Path) -> list[str]:
    return [config.MTLS_BIND, config.MTLS_SNI]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PROTOCOLS: dict[str, Protocol] = {
    "zkarche": Protocol(
        name="zkarche",
        display="ZK-ARCHE",
        server_bin=config.ZKARCHE_SERVER,
        client_bin=config.ZKARCHE_CLIENT,
        bind_addr=config.ZKARCHE_BIND,
        server_args_fn=_zk_server_args,
        client_args_fn=_zk_client_args,
        client_setup_args_fn=_zk_client_setup_args,
        requires_enroll=True,
    ),
    "edhoc": Protocol(
        name="edhoc",
        display="EDHOC",
        server_bin=config.EDHOC_SERVER,
        client_bin=config.EDHOC_CLIENT,
        bind_addr=config.EDHOC_BIND,
        server_args_fn=_edhoc_server_args,
        client_args_fn=_edhoc_client_args,
        client_setup_args_fn=None,
        requires_enroll=False,
    ),
    "mtls": Protocol(
        name="mtls",
        display="mTLS",
        server_bin=config.MTLS_SERVER,
        client_bin=config.MTLS_CLIENT,
        bind_addr=config.MTLS_BIND,
        server_args_fn=_mtls_server_args,
        client_args_fn=_mtls_client_args,
        client_setup_args_fn=None,
        requires_enroll=False,
    ),
}


# Lazy alias for type hints elsewhere
ProtocolName = str  # one of the keys above


# ---------------------------------------------------------------------------
# mTLS: cert dependency
# ---------------------------------------------------------------------------

def ensure_mtls_certs(repo_root: Path) -> None:
    """Generate certs if certs/server.crt is missing."""
    certs_dir = repo_root / "certs"
    if (certs_dir / "server.crt").exists() and (certs_dir / "client.crt").exists():
        return
    script = repo_root / "scripts" / "gen_certs.sh"
    if not script.exists():
        raise RuntimeError(
            f"mTLS certs missing and {script} not found. "
            "Run scripts/gen_certs.sh manually."
        )
    print(f"[mtls] generating certs via {script} ...")
    subprocess.run(["bash", str(script)], cwd=repo_root, check=True)


# ---------------------------------------------------------------------------
# ZK-ARCHE: per-workdir enrollment (one-time)
# ---------------------------------------------------------------------------

def enroll_zkarche_clients(
    server_handle: ServerHandle,
    workdirs: Sequence[Path],
    pairing_token: str = PAIRING_TOKEN,
    fail_on_error: bool = True,
) -> int:
    """Run --setup against `server_handle` from each workdir.

    Caller must have started the server with --pairing & --pairing-token.

    Returns the number of successfully enrolled workdirs.
    """
    proto = PROTOCOLS["zkarche"]
    ok = 0
    for wd in workdirs:
        # Wipe any leftover state to ensure a clean enrollment.
        for sub in ("state", ):
            p = wd / sub
            if p.exists():
                shutil.rmtree(p)
        result = run_client_once(
            proto.client_bin,
            ["--server", server_handle.addr, "--setup",
             "--pairing-token", pairing_token],
            wd,
            timeout_s=30.0,
        )
        if result.success or (wd / "state" / "client" / "device_root.bin").exists():
            ok += 1
        else:
            msg = (
                f"[zkarche] enrollment failed for {wd}: "
                f"{result.stderr_tail or 'no metrics line'}"
            )
            if fail_on_error:
                raise RuntimeError(msg)
            print(msg)
    return ok


def reset_server_state(repo_root: Path) -> None:
    """Wipe ZK-ARCHE server state for a clean run."""
    state = repo_root / "state" / "server"
    if state.exists():
        shutil.rmtree(state)
