#!/usr/bin/env bash
# benchmarks/setup.sh — prepare the host for benchmarking.
#
# What this does:
#   1. cargo build --release for all six binaries.
#   2. Generates mTLS certificates if they're missing.
#   3. Wipes ZK-ARCHE persistent state (so the first run is clean).
#
# Run from anywhere; resolves the repo root from this script's location.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
cd "$REPO_ROOT"

# ---------- toolchain check ----------
if ! command -v cargo >/dev/null 2>&1; then
    cat <<EOF >&2
error: cargo is not installed.

Install Rust on Debian/Raspberry Pi OS:
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Then re-source your shell and re-run this script.
EOF
    exit 1
fi

# ---------- build ----------
echo "[setup] cargo build --release ..."
cargo build --release \
    --bin zkarche_server \
    --bin zkarche_client \
    --bin edhoc_server   \
    --bin edhoc_client   \
    --bin mtls_server    \
    --bin mtls_client

# ---------- certs ----------
if [[ ! -f certs/server.crt || ! -f certs/client.crt ]]; then
    echo "[setup] generating mTLS certificates ..."
    bash scripts/gen_certs.sh
else
    echo "[setup] mTLS certs already present, skipping generation"
fi

# ---------- ZK-ARCHE state reset ----------
if [[ -d state ]]; then
    echo "[setup] wiping previous state/ tree for a clean run ..."
    rm -rf state
fi

# ---------- python deps ----------
if command -v python3 >/dev/null 2>&1; then
    echo "[setup] python3: $(python3 --version)"
    if ! python3 -c "import matplotlib" 2>/dev/null; then
        cat <<EOF
[setup] note: matplotlib is not installed. The plotter will still emit
        PGFPlots .tex files (which is what the thesis uses), but PNG
        previews will be skipped. To install:
            python3 -m pip install --user matplotlib
EOF
    fi
else
    echo "[setup] warning: python3 not found; install before running tests"
fi

echo "[setup] done. binaries in target/release/"
ls -lh target/release/{zkarche_,edhoc_,mtls_}{server,client} 2>/dev/null || true
