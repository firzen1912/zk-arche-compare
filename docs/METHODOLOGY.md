# Experimental Methodology

The repository supports two complementary evaluation modes.

## 1. Controlled LAN / actual hardware benchmarking

Run the Rust protocol binaries on the actual Raspberry Pi 3B+, Raspberry Pi 4,
Raspberry Pi 5, and Ubuntu i7 server. Use
`experiments/hardware/hardware_resource_benchmark.py` to capture CPU, RSS, and
power/energy data around the authentication command. This mode is appropriate
for resource-consumption claims.

## 2. Mininet network emulation

Run `experiments/mininet/*_mininet_50_iot.py` to evaluate network effects for 50
randomized IoT clients authenticating to one server. This mode is appropriate
for comparing protocol behavior under randomized latency, jitter, and packet
loss. It should not be described as CPU emulation for Raspberry Pi hardware.

## Metrics

- Latency: authentication duration emitted by the protocol client, plus optional
  wall-clock elapsed time from the wrapper.
- Communication overhead: bytes sent and received as emitted by the Rust client.
- CPU: normalized process CPU percentage.
- Memory: peak resident set size.
- Energy: integrated measured power, or a clearly labeled fixed-power estimate.
