# ZK-ARCHE Comparative Authentication Evaluation

This repository combines the Rust implementations, benchmark harnesses, Mininet
network simulations, and hardware resource-measurement tools needed to evaluate
ZK-ARCHE against EDHOC and mTLS for IoT authentication.


## Security Testing

The repo now includes a dedicated security suite covering transcript binding, message mutation, invalid curve/small-subgroup rejection, DoS resilience, nonce/session uniqueness, packet-parser fuzzing, replay-cache behavior, and side-channel/RNG checks. See [`docs/SECURITY_TESTS.md`](docs/SECURITY_TESTS.md).

Quick start:

```bash
make security-test
make security-check
```

For packet fuzzing:

```bash
cargo install cargo-fuzz
make fuzz-packet
```

## Protocols included

- **ZK-ARCHE**: privacy-preserving zero-knowledge authentication prototype.
- **EDHOC-over-TCP**: lightweight constrained-device authentication baseline.
- **mTLS**: certificate-based mutual TLS baseline.

All protocol binaries emit a shared metrics line:

```text
CLIENT METRICS -> Duration: ..., Sent: ... bytes, Received: ... bytes
```

The Python harnesses parse that line to generate latency and communication
results.

## Repository layout

```text
src/bin/                 Rust server/client binaries for ZK-ARCHE, EDHOC, mTLS
src/common/              Shared Rust helpers for metrics, framing, certs, I/O
scripts/gen_certs.sh     Local CA/server/client certificate generation for mTLS
benchmarks/              LAN benchmark harness and graph/table generator
experiments/mininet/     50-client randomized IoT Mininet experiments
experiments/hardware/    Actual-hardware CPU/RAM/power benchmark wrapper
docs/                    Methodology and experiment runbooks
```

## One-time setup

Install Rust and Python dependencies, then build the binaries:

```bash
python3 -m pip install -r requirements.txt
bash benchmarks/setup.sh
```

Or use the Makefile:

```bash
make setup
```

## Run the local benchmark suite

```bash
bash benchmarks/run_all.sh
python3 -m benchmarks.plot
```

This produces raw CSV/JSON under `benchmarks/results/` and LaTeX PGFPlots files
under `benchmarks/graphs_tex/`.

## Run Mininet IoT simulations

Each simulation creates one i7-class server and randomized Raspberry Pi-class
clients. The output CSV includes `client_type` for every run.

```bash
sudo env   "PATH=$HOME/.cargo/bin:$PATH"   "RUSTUP_HOME=$HOME/.rustup"   "CARGO_HOME=$HOME/.cargo"   .venv/bin/python experiments/mininet/mininet_tests_123.py   --project .   --protocol all   --test all   --clients 50   --iterations 50   --seed 42   --network-model simple   --device-mix raspberry-pi   --background-traffic none
```

See `docs/MININET_EXPERIMENTS.md` for details.

## Run actual hardware resource tests

Run this on the physical device you want to measure:

```bash
python3 experiments/hardware/hardware_resource_benchmark.py \
  --protocol zkarche \
  --role client \
  --device "Raspberry Pi 4" \
  --server "Core i7-6770HQ 2.60GHz" \
  --runs 50 \
  --cmd './target/release/zkarche_client --server 192.168.1.10:4000' \
  --power-mode fixed \
  --fixed-power-watts 3.2
```

See `docs/HARDWARE_BENCHMARKING.md` for hwmon power-sensor examples.

## Recommended workflow for the thesis

1. Use actual Raspberry Pi hardware for CPU, RAM, and power claims.
2. Use Mininet for randomized 50-client network-latency scenarios.
3. Use `benchmarks/plot.py` to convert CSV/JSON results into PGFPlots files.
4. Clearly separate measured hardware power from fixed-power energy estimates.

## Notes

- Mininet does not emulate Raspberry Pi CPU performance. It emulates network
  behavior such as delay, jitter, bandwidth, and packet loss.
- mTLS requires generated certificates. `benchmarks/setup.sh` and the mTLS
  Mininet runner generate them if missing.
- ZK-ARCHE clients use separate working directories in multi-client experiments
  so each simulated device has independent state.
## Security tests

The security test suite is organized under `security/`. Each test has its own script, and both Bash and PowerShell launchers can run one test or the safe regression subset while saving per-test logs.

```bash
bash security/run_security_tests.sh --test all
bash security/run_security_tests.sh --test transcript
bash security/run_security_tests.sh --test fuzz --fuzz-seconds 300
bash security/run_security_tests.sh --test dos --protocol zkarche --port 4000
```

PowerShell is also supported:

```powershell
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test all
```

See `docs/SECURITY_TESTS.md` for the full list of the eight security tests and their output logs.
