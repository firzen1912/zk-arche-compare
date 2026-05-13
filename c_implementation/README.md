# C Implementation of ZK-ARCHE

This folder contains the C/libsodium implementation of the ZK-ARCHE client and server.

The C implementation is designed to match the current Rust ZK-ARCHE protocol behavior, including setup, full authentication, optional fast handle lookup, and optional device-only benchmark mode.

## Files

```text
c_implementation/
  zkarche_client.c
  zkarche_server.c
  README.md
```

## Requirements

Install the C build tools and libsodium:

```bash
sudo apt update
sudo apt install -y build-essential libsodium-dev
```

## Build

From the repository root:

```bash
make c-build
```

This creates:

```text
target/c/zkarche_client_c
target/c/zkarche_server_c
```

## Run Full ZK-ARCHE Authentication

Start the C server:

```bash
make c-run-server
```

In a second terminal, enroll the client:

```bash
make c-setup-client
```

Then authenticate:

```bash
make c-run-client
```

## Fast Handle Lookup Mode

Fast lookup uses `MSG_AUTH_V3` with the `AUTH_FLAG_HANDLE_LOOKUP` flag.

```bash
make c-run-client-fast
```

This mode lets the server find the device using a short device handle instead of scanning all enrolled devices by recomputing the pseudonym.

## Device-Only Benchmark Mode

Device-only mode uses `MSG_AUTH_V3` with the `AUTH_FLAG_DEVICE_ONLY` flag.

Start the benchmark-mode server:

```bash
make c-run-server-bench
```

Then run the client:

```bash
make c-run-client-device-only
```

Device-only mode skips the role re-randomization proof and role set-membership proof. Use it only for benchmark ablation, not as the main security result.

## State Files

The C implementation uses the same local state layout as the Rust implementation:

```text
state/
  client/
    device_root.bin
    device_pub.bin
    server_pub.bin
    role_cred.bin

  server/
    server_sk.bin
    registry.bin
    registry.bak
    replay_cache.bin
```

These files are generated automatically during setup and authentication.

## Security Features

The C server includes:

- persistent replay cache
- replay protection across restarts
- peer failure-rate limiting
- optional fast handle lookup
- device-only benchmark gating
- private state-file permissions
- Ristretto255 point validation
- Schnorr proof verification
- role commitment re-randomization verification
- zero-knowledge role set-membership verification
- HKDF-based session key derivation
- HMAC-based key confirmation

## Protocol Modes

| Mode | Message Type | Purpose |
|---|---:|---|
| Full authentication | `MSG_AUTH_V2 = 0x03` | Default full ZK-ARCHE authentication |
| Fast lookup | `MSG_AUTH_V3 = 0x04` | Full authentication with device-handle lookup |
| Device-only | `MSG_AUTH_V3 = 0x04` | Benchmark mode without role proofs |

## Environment Variables

| Variable | Purpose |
|---|---|
| `ZKARCHE_FAST_LOOKUP=1` | Enables fast handle lookup |
| `ZKARCHE_DEVICE_ONLY=1` | Enables device-only client mode |
| `ZKARCHE_ALLOW_DEVICE_ONLY=1` | Allows the server to accept device-only mode |
| `ZKARCHE_BENCH_MODE=1` | Enables benchmark behavior and permits device-only mode |

## Clean Build Artifacts

```bash
make c-clean
```

To remove protocol state:

```bash
rm -rf state/
```

## Recommended Research Use

Use full mode for the main ZK-ARCHE security and performance results:

```bash
make c-run-server
make c-setup-client
make c-run-client
```

Use fast lookup to evaluate lookup optimization:

```bash
make c-run-client-fast
```

Use device-only mode only as an ablation study to isolate the cost of the role proof layer:

```bash
make c-run-server-bench
make c-run-client-device-only
```

## Notes

The C implementation is intended for portability and cross-language validation. The Rust implementation remains the primary research implementation, while the C version helps demonstrate that the protocol can be implemented outside the Rust ecosystem using libsodium and Ristretto255.
