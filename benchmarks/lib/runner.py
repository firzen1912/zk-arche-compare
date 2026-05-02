"""
Subprocess and lifecycle helpers for the benchmark harness.

The thing this layer must get right is *isolation*: ZK-ARCHE persists per-device
state under `state/client/...` relative to the client's CWD, so when we want
50 clients to look like 50 different devices we must give each its own CWD.

The harness:
  * Spawns the server in a subprocess, with stdout captured.
  * Waits for the listener to actually accept connections (TCP probe).
  * Runs N clients (sequentially or concurrently), each in an isolated workdir.
  * Tears down the server cleanly (SIGTERM with a short SIGKILL fallback).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

from . import config
from .parse import MetricsLine, first_client_metrics


# ---------------------------------------------------------------------------
# Port utilities
# ---------------------------------------------------------------------------

def parse_addr(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host or "127.0.0.1", int(port)


def wait_port_open(addr: str, timeout_s: float = 10.0) -> None:
    """Block until something is accept()-ing on `addr`, or raise TimeoutError."""
    host, port = parse_addr(addr)
    # Servers may bind 0.0.0.0; clients dial 127.0.0.1.
    dial_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host

    deadline = time.monotonic() + timeout_s
    last_err: Optional[BaseException] = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((dial_host, port), timeout=0.5):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.05)
    raise TimeoutError(f"server on {addr} never accepted (last error: {last_err})")


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

@dataclass
class ServerHandle:
    proc: subprocess.Popen
    addr: str
    log_path: Path
    workdir: Path

    @property
    def pid(self) -> int:
        return self.proc.pid


def start_server(
    binary: Path,
    args: Sequence[str],
    addr: str,
    workdir: Path,
    log_path: Path,
    env: Optional[dict[str, str]] = None,
    bind_retries: int = 6,
    bind_retry_sleep_s: float = 1.0,
) -> ServerHandle:
    """Spawn `binary args...` in `workdir`, redirecting stdout+stderr to `log_path`.

    If the bind fails (e.g. previous run is still in TIME_WAIT on this port),
    we retry up to `bind_retries` times before giving up.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    last_err: Optional[BaseException] = None
    for attempt in range(bind_retries):
        log = open(log_path, "wb")
        proc = subprocess.Popen(
            [str(binary), *args],
            cwd=str(workdir),
            stdout=log,
            stderr=subprocess.STDOUT,
            env=full_env,
            # New process group so we can SIGTERM cleanly without hitting our own.
            preexec_fn=os.setsid,
        )

        handle = ServerHandle(proc=proc, addr=addr, log_path=log_path, workdir=workdir)
        try:
            wait_port_open(addr, timeout_s=15.0)
            return handle
        except Exception as e:
            last_err = e
            stop_server(handle)
            # If process exited (e.g. EADDRINUSE), back off and retry.
            time.sleep(bind_retry_sleep_s * (attempt + 1))

    raise RuntimeError(
        f"failed to start {binary.name} on {addr} after {bind_retries} attempts: {last_err}\n"
        f"see server log at {log_path}"
    )


def stop_server(handle: ServerHandle) -> None:
    proc = handle.proc
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=1.0)


# ---------------------------------------------------------------------------
# Client invocation
# ---------------------------------------------------------------------------

@dataclass
class ClientResult:
    iteration: int
    client_id: int
    success: bool
    duration_ms: Optional[float]
    sent_bytes: Optional[int]
    recv_bytes: Optional[int]
    stderr_tail: str = ""
    elapsed_wall_s: float = 0.0


def run_client_once(
    binary: Path,
    args: Sequence[str],
    workdir: Path,
    timeout_s: float = 30.0,
    iteration: int = 0,
    client_id: int = 0,
    env: Optional[dict[str, str]] = None,
) -> ClientResult:
    """Run a single client invocation, capture metrics, return ClientResult."""
    workdir.mkdir(parents=True, exist_ok=True)
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    t0 = time.monotonic()
    try:
        cp = subprocess.run(
            [str(binary), *args],
            cwd=str(workdir),
            capture_output=True,
            timeout=timeout_s,
            env=full_env,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return ClientResult(
            iteration=iteration,
            client_id=client_id,
            success=False,
            duration_ms=None,
            sent_bytes=None,
            recv_bytes=None,
            stderr_tail=f"TIMEOUT after {timeout_s}s",
            elapsed_wall_s=time.monotonic() - t0,
        )

    elapsed = time.monotonic() - t0
    stdout = cp.stdout.decode(errors="replace")
    stderr = cp.stderr.decode(errors="replace")
    metrics = first_client_metrics(stdout)

    if cp.returncode != 0 or metrics is None:
        return ClientResult(
            iteration=iteration,
            client_id=client_id,
            success=False,
            duration_ms=metrics.duration_ms if metrics else None,
            sent_bytes=metrics.sent_bytes if metrics else None,
            recv_bytes=metrics.recv_bytes if metrics else None,
            stderr_tail=(stderr or stdout)[-500:],
            elapsed_wall_s=elapsed,
        )

    return ClientResult(
        iteration=iteration,
        client_id=client_id,
        success=True,
        duration_ms=metrics.duration_ms,
        sent_bytes=metrics.sent_bytes,
        recv_bytes=metrics.recv_bytes,
        elapsed_wall_s=elapsed,
    )


def run_clients_concurrent(
    factory: Callable[[int], tuple[Path, Sequence[str], Path]],
    n_clients: int,
    timeout_s: float = 60.0,
    max_workers: Optional[int] = None,
) -> list[ClientResult]:
    """Run `n_clients` clients in parallel.

    `factory(i)` returns (binary_path, argv, workdir) for client `i`.
    """
    workers = max_workers or min(n_clients, 64)
    results: list[ClientResult] = [None] * n_clients  # type: ignore[list-item]

    def _run(i: int) -> ClientResult:
        binary, args, workdir = factory(i)
        return run_client_once(
            binary, args, workdir,
            timeout_s=timeout_s, iteration=0, client_id=i,
        )

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_run, i): i for i in range(n_clients)}
        for fut in as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception as e:  # noqa: BLE001
                results[i] = ClientResult(
                    iteration=0, client_id=i, success=False,
                    duration_ms=None, sent_bytes=None, recv_bytes=None,
                    stderr_tail=f"runner exception: {e}",
                )
    return results


def run_clients_sequential(
    binary: Path,
    args: Sequence[str],
    workdir: Path,
    runs: int,
    timeout_s: float = 30.0,
    client_id: int = 0,
    progress_every: int = 10,
) -> list[ClientResult]:
    """Run the same client invocation `runs` times back-to-back from one workdir."""
    out: list[ClientResult] = []
    for i in range(runs):
        r = run_client_once(
            binary, args, workdir,
            timeout_s=timeout_s, iteration=i, client_id=client_id,
        )
        out.append(r)
        if progress_every and (i + 1) % progress_every == 0:
            _ok = sum(1 for x in out if x.success)
            print(f"  [seq client {client_id}] {i+1}/{runs} done ({_ok} ok)")
    return out


# ---------------------------------------------------------------------------
# Workdir templating: stamp a "template" directory (containing pre-enrolled
# ZK-ARCHE state) into N independent client workdirs.
# ---------------------------------------------------------------------------

def stamp_workdirs(
    template: Optional[Path],
    parent: Path,
    n: int,
    prefix: str = "client",
) -> list[Path]:
    """Produce `n` copies of `template/` named parent/{prefix}_NNN/ and return them.

    When `template` is None or doesn't exist as a directory, just create empty
    workdirs (used when we'll enroll into them later, or when the protocol
    needs no per-client state at all).
    """
    parent.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    use_copy = template is not None and template.is_dir()
    for i in range(n):
        d = parent / f"{prefix}_{i:03d}"
        if d.exists():
            shutil.rmtree(d)
        if use_copy:
            shutil.copytree(template, d)  # type: ignore[arg-type]
        else:
            d.mkdir(parents=True, exist_ok=True)
        out.append(d)
    return out


@contextlib.contextmanager
def temp_dir(prefix: str = "zkb_"):
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)
