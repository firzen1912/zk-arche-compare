# ZK comparative baselines: mTLS and EDHOC-over-TCP (Rust)

This folder gives you two baseline protocol pairs for your comparative section:

- `mtls_server` / `mtls_client`
- `edhoc_server` / `edhoc_client`

## What is fully runnable right now

### mTLS
The mTLS pair is intended to be runnable as-is after you generate local certificates.

Generate certificates:

```bash
bash scripts/gen_certs.sh
```

Run:

```bash
cargo run --bin mtls_server
cargo run --bin mtls_client
```

## EDHOC-over-TCP
The EDHOC pair is adapted from the official `lakers` example flow, but uses a simple length-prefixed TCP framing instead of CoAP.

Run:

```bash
cargo run --bin edhoc_server
cargo run --bin edhoc_client
```

## Important note
The EDHOC files are based on the official `lakers` example credentials and state-machine flow. If the exact `lakers` crate API changes across releases, you may need small import or type adjustments.

## Design notes
- mTLS uses `rustls` + `tokio-rustls`.
- EDHOC uses `lakers` + `lakers-crypto` with the RustCrypto backend.
- Both models emit JSON metrics to standard output.

## Files
- `src/common/metrics.rs`: shared metrics struct
- `src/common/framing.rs`: TCP length framing for EDHOC/TCP
- `src/common/certs.rs`: PEM certificate/key loading helpers
- `src/bin/mtls_*.rs`: mTLS server/client
- `src/bin/edhoc_*.rs`: EDHOC-over-TCP server/client
