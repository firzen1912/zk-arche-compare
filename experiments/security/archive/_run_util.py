#!/usr/bin/env python3
"""Shared helpers for security test wrappers."""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def add_common_args(parser: argparse.ArgumentParser, default_log_name: str) -> None:
    parser.add_argument("--project", default=str(repo_root_from_script()), help="Repository root")
    parser.add_argument("--log-dir", default="results/security/logs", help="Directory for .log files")
    parser.add_argument("--log-name", default=default_log_name, help="Log filename")


def run_logged(command: List[str], project: str, log_dir: str, log_name: str, timeout: Optional[int] = None) -> int:
    root = Path(project).resolve()
    out_dir = root / log_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / log_name

    header = [
        "=== Security Test Command ===",
        f"cwd: {root}",
        "cmd: " + " ".join(command),
        f"started_epoch: {time.time():.3f}",
        "",
    ]

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        rc = proc.returncode
        body = proc.stdout
    except FileNotFoundError as exc:
        rc = 127
        body = f"ERROR: command not found: {exc}\n"
    except subprocess.TimeoutExpired as exc:
        rc = 124
        body = (exc.stdout or "") + f"\nERROR: timeout after {timeout} seconds\n"

    elapsed = time.perf_counter() - start
    footer = [
        "",
        "=== Security Test Result ===",
        f"return_code: {rc}",
        f"elapsed_seconds: {elapsed:.3f}",
    ]
    text = "\n".join(header) + body + "\n" + "\n".join(footer) + "\n"
    log_path.write_text(text, encoding="utf-8")

    print(text)
    print(f"Saved log: {log_path}")
    return rc


def cargo_test_filter(args: argparse.Namespace, test_filter: str, log_name: str) -> int:
    return run_logged(
        ["cargo", "test", "--test", "security_zkarche", test_filter, "--", "--nocapture"],
        project=args.project,
        log_dir=args.log_dir,
        log_name=args.log_name or log_name,
    )
