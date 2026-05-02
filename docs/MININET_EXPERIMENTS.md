# Mininet IoT Experiments

This repository includes three protocol-specific Mininet runners under
`experiments/mininet/`:

- `zkarche_mininet_50_iot.py`
- `mtls_mininet_50_iot.py`
- `edhoc_mininet_50_iot.py`

Each script builds the required Rust binaries, creates one server node at
`10.0.0.1`, creates randomized Raspberry Pi-class clients, applies per-client
link delay/jitter/loss using `TCLink`, executes one authentication per client,
and writes a CSV that includes the client type for each run.

## Important limitation

Mininet emulates the network, not Raspberry Pi CPU microarchitecture. The Pi
3B+, Pi 4, and Pi 5 labels represent heterogeneous IoT client classes and link
profiles. For actual CPU/RAM/power measurements, use the hardware benchmark
script in `experiments/hardware/` on the physical boards.

## Common options

All scripts support:

```bash
--project /path/to/repo
--clients 50
--output results.csv
--workdir /tmp/some-workdir
--seed 42
```

Use `--seed` when you want reproducible client-type assignments and link
profiles.

## Examples

```bash
sudo python3 experiments/mininet/zkarche_mininet_50_iot.py --project . --seed 42
sudo python3 experiments/mininet/mtls_mininet_50_iot.py    --project . --seed 42
sudo python3 experiments/mininet/edhoc_mininet_50_iot.py   --project . --seed 42
```
