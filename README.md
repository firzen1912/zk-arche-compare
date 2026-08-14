# ZK-ARCHE Comparative Authentication Evaluation

This repository is the comparative evaluation workspace for **ZK-ARCHE**, **EDHOC-over-TCP**, and **mTLS**. It contains the Rust protocol implementations used for comparative measurements, a separate C/libsodium ZK-ARCHE implementation for portability and cross-language validation, LAN benchmark tooling, Mininet experiments, physical-device resource measurement, and security-testing utilities.

The repository has evolved beyond the original three-protocol benchmark scaffold. The current `main` branch also includes ZK-ARCHE v2 privacy/authorization features, C benchmark ablations, lookup-optimization experiments, and a consolidated security-test runner.

## Current protocol implementations

### ZK-ARCHE v2

The Rust ZK-ARCHE client/server under `src/bin/` implement the current v2 authentication model:

- raw-public-key (RPK) setup rather than certificate-based ZK-ARCHE enrollment;
- Schnorr proofs over Ristretto255 for mutual authentication;
- a per-session `pid` instead of transmitting the stable device identifier during online authentication;
- re-randomized role commitments;
- CDS/OR-style zero-knowledge role-set membership proofs;
- ephemeral Ristretto Diffie-Hellman session establishment;
- HKDF-SHA256 session-key derivation;
- HMAC-based key confirmation;
- persistent replay protection and input/timeout hardening.

The former outer **X25519 + ChaCha20-Poly1305** authentication tunnel was removed. Current ZK-ARCHE handshake payloads are sent directly over TCP; the derived session key and key-confirmation exchange remain part of the protocol, but the current implementation does not provide an application-layer AEAD wrapper for those handshake payloads.

### EDHOC-over-TCP

`edhoc_client` and `edhoc_server` provide the constrained-authentication comparison baseline used by the benchmark harness. The repository uses EDHOC over the same general experimental environment so latency and communication measurements can be compared consistently.

### mTLS

`mtls_client` and `mtls_server` provide the certificate-based mutual-TLS baseline. Local certificate generation is handled by `scripts/gen_certs.sh` and the benchmark setup tooling.

## Rust binaries

```text
src/bin/
├── zkarche_client.rs
├── zkarche_server.rs
├── edhoc_client.rs
├── edhoc_server.rs
├── mtls_client.rs
└── mtls_server.rs
```

Build all Rust binaries with:

```bash
cargo build --release --bins
```

or:

```bash
make release
```

## C ZK-ARCHE implementation

The repository also contains a standalone C/libsodium implementation:

```text
c_implementation/
├── zkarche_client.c
├── zkarche_server.c
└── README.md
```

It implements the same core ZK-ARCHE v2 setup/authentication model and adds two research modes used to isolate scalability and proof-layer costs.

| Mode | Wire mode | Purpose |
| --- | --- | --- |
| Full ZK-ARCHE | `MSG_AUTH_V2 = 0x03` | Default authentication with PID and role proofs |
| Fast handle lookup | `MSG_AUTH_V3 = 0x04` + handle flag | Avoids server-side PID scanning by using a short device handle |
| Device-only ablation | `MSG_AUTH_V3 = 0x04` + device-only flag | Measures authentication cost with role proof layer disabled |

The device-only mode is a **benchmark ablation**, not the primary security configuration.

Build the C implementation with:

```bash
make c-build
```

Useful targets:

```bash
make c-run-server
make c-setup-client
make c-run-client
make c-run-client-fast
make c-run-server-bench
make c-run-client-device-only
```

The C benchmark modes use these environment variables internally or can be invoked manually:

```text
ZKARCHE_FAST_LOOKUP=1
ZKARCHE_DEVICE_ONLY=1
ZKARCHE_ALLOW_DEVICE_ONLY=1
ZKARCHE_BENCH_MODE=1
```

See `c_implementation/README.md` for the C-specific workflow.

## Shared metrics interface

Protocol clients emit a common measurement line of the form:

```text
CLIENT METRICS -> Duration: ..., Sent: ... bytes, Received: ... bytes
```

The benchmark tooling parses this output to build latency and communication datasets. Server-side and benchmark-specific instrumentation is also present where needed for setup and resource measurements.

## Repository layout

```text
src/bin/                  Rust ZK-ARCHE, EDHOC, and mTLS clients/servers
src/common/               Shared Rust framing, metrics, certificate, I/O, and network helpers
c_implementation/         C/libsodium ZK-ARCHE implementation and ablation modes
benchmarks/               LAN benchmark harness, result processing, plotting, and power helpers
experiments/mininet/      Multi-client network experiments
experiments/hardware/     Physical-device CPU/RAM/power measurement tooling
experiments/security/     Consolidated security-test runner and archived earlier scripts
docs/                     Methodology and experiment documentation
scripts/gen_certs.sh      Local certificate generation for the mTLS baseline
Makefile                  Build, benchmark, security, and C convenience targets
requirements.txt          Python dependencies for benchmark/experiment tooling
```

## One-time setup

Install the Python requirements and build/setup the benchmark environment:

```bash
python3 -m pip install -r requirements.txt
bash benchmarks/setup.sh
```

or use:

```bash
make setup
```

For the C implementation on Debian/Ubuntu-class systems:

```bash
make c-deps
```

## Local comparative benchmarks

Run the local benchmark suite with:

```bash
bash benchmarks/run_all.sh
```

Generate plots/tables with:

```bash
python3 -m benchmarks.plot
```

or:

```bash
make bench
make plot
```

Runtime output is written beneath `benchmarks/results/`; generated graph material is written beneath the benchmark graph/plot directories.

## Mininet experiments

The Mininet tooling is intended for controlled multi-client **network** experiments, including delay, jitter, bandwidth, packet loss, randomized device mixes, and concurrent authentication behavior.

Example:

```bash
sudo env \
  "PATH=$HOME/.cargo/bin:$PATH" \
  "RUSTUP_HOME=$HOME/.rustup" \
  "CARGO_HOME=$HOME/.cargo" \
  .venv/bin/python experiments/mininet/mininet_tests_123.py \
  --project . \
  --protocol all \
  --test all \
  --clients 50 \
  --iterations 50 \
  --seed 42 \
  --network-model simple \
  --device-mix raspberry-pi \
  --background-traffic none
```

See `docs/MININET_EXPERIMENTS.md` for the experiment methodology.

> Mininet emulates network conditions; it does **not** reproduce Raspberry Pi CPU, memory, or power characteristics. Use physical hardware for those claims.

## Hardware resource benchmarking

Use `experiments/hardware/hardware_resource_benchmark.py` on the physical device being evaluated.

Example:

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

See `docs/HARDWARE_BENCHMARKING.md` for measurement guidance and power-sensor options.

## Security testing

The current security tooling has been consolidated under:

```text
experiments/security/security_test.py
```

It covers the current security-regression areas, including:

- transcript/domain binding;
- near-valid message mutation;
- invalid Ristretto/identity-point and scalar handling;
- session-key uniqueness and nonce reuse;
- replay-cache behavior;
- packet-parser fuzzing support;
- RNG/source-hygiene and side-channel-oriented checks; and
- an optional local DoS-resilience harness.

Start by inspecting the runner's current options:

```bash
python3 experiments/security/security_test.py --help
```

Earlier per-test scripts are retained under:

```text
experiments/security/archive/
```

### Makefile security-target note

Some security-related recipes in the current top-level `Makefile` still reference the repository's **older top-level `security/` layout**. The active consolidated runner is under `experiments/security/`, so use `experiments/security/security_test.py` directly when a legacy Make target points at a path that no longer exists. The README intentionally documents the current filesystem layout rather than preserving those stale commands.

See `docs/SECURITY_TESTS.md` for the security-test methodology/history, while treating the current `experiments/security/` tree as authoritative for executable paths.

## Recommended evaluation workflow

For research results, keep the measurement domains separate:

1. Use the full ZK-ARCHE mode for the primary security/performance comparison with EDHOC and mTLS.
2. Use fast-handle lookup as a scalability optimization experiment rather than silently mixing it into baseline results.
3. Use device-only mode only as an ablation to quantify the cost of role privacy/authorization proofs.
4. Use Mininet for network-condition and concurrent-client experiments.
5. Use actual Raspberry Pi or other target hardware for CPU, RAM, and measured power claims.
6. Clearly distinguish measured power from fixed-power energy estimates.
7. Record protocol mode, client count, network model, device class, and iteration count alongside every dataset.

## Important implementation notes

- ZK-ARCHE v2 no longer uses the former outer X25519/ChaCha20-Poly1305 layer.
- The stable ZK-ARCHE device identifier is used during enrollment; online AUTH uses a session-derived PID.
- The full ZK-ARCHE role proof demonstrates membership in the compiled allowed role set without revealing which allowed role is held.
- The standard PID lookup can require scanning enrolled records; the C fast-handle mode exists specifically to study that scalability tradeoff.
- mTLS still requires certificate material; ZK-ARCHE's current setup path is RPK/Schnorr based instead.
- Multi-client experiments must use independent client state directories so simulated devices do not accidentally share protocol identity/state.
- This repository is a research evaluation environment, not a production authentication library.

## Related repositories

The standalone implementations used as protocol-development references are:

- `firzen1912/ZK-ARCHE-Rust` — standalone Rust implementation.
- `firzen1912/ZK-ARCHE-C` — standalone C/libsodium implementation.

This comparison repository is where cross-protocol measurement, C/Rust validation, scalability experiments, hardware experiments, and security testing are brought together.
