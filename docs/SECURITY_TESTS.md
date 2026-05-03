# Security Test Suite

All runnable security tests are organized under `security/`. Each test category has its own standalone script. The Bash and PowerShell launchers allow you to choose one test or run the safe regression subset and save a separate log for each test.

## Test categories

| ID | Test | Script | Default log |
|---:|---|---|---|
| 1 | Transcript-binding tests | `security/transcript_binding_test.py` | `results/security/logs/01_transcript_binding.log` |
| 2 | Message mutation tests | `security/message_mutation_test.py` | `results/security/logs/02_message_mutation.log` |
| 3 | Invalid curve / small-subgroup tests | `security/invalid_curve_small_subgroup_test.py` | `results/security/logs/03_invalid_curve_small_subgroup.log` |
| 4 | DoS resilience tests | `security/dos_resilience_test.py` | `results/security/logs/04_dos_resilience_<protocol>.log` |
| 5 | Session uniqueness / nonce-reuse tests | `security/session_uniqueness_nonce_reuse_test.py` | `results/security/logs/05_session_uniqueness_nonce_reuse.log` |
| 6 | Packet parser fuzzing | `security/packet_fuzzing_test.py` | `results/security/logs/06_packet_fuzzing.log` |
| 7 | Replay-cache tests | `security/replay_cache_test.py` | `results/security/logs/07_replay_cache.log` |
| 8 | Side-channel / RNG analysis | `security/side_channel_rng_analysis_test.py` | `results/security/logs/08_side_channel_rng_analysis.log` |

The Rust regression-test implementation lives in `security/rust/security_zkarche.rs`. The integration-test file under `tests/security_zkarche.rs` is only a shim so `cargo test --test security_zkarche` can still run normally.

## Run with Bash

Run the safe regression subset:

```bash
bash security/run_security_tests.sh --test all
```

Run a specific test:

```bash
bash security/run_security_tests.sh --test transcript
bash security/run_security_tests.sh --test mutation
bash security/run_security_tests.sh --test invalid-curve
bash security/run_security_tests.sh --test session
bash security/run_security_tests.sh --test replay
bash security/run_security_tests.sh --test side-channel
```

Run packet-parser fuzzing:

```bash
cargo install cargo-fuzz
bash security/run_security_tests.sh --test fuzz --fuzz-seconds 300
```

Run DoS testing against a running ZK-ARCHE server:

```bash
./target/debug/zkarche_server --bind 127.0.0.1:4000 --pairing --pairing-token test-token
```

In another terminal:

```bash
bash security/run_security_tests.sh --test dos --protocol zkarche --host 127.0.0.1 --port 4000
```

For EDHOC or mTLS:

```bash
bash security/run_security_tests.sh --test dos --protocol edhoc --port 5688
bash security/run_security_tests.sh --test dos --protocol mtls --port 7443
```

## Run with PowerShell

Run the safe regression subset:

```powershell
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test all
```

Run one test:

```powershell
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test transcript
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test mutation
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test invalid-curve
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test session
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test replay
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test side-channel
```

Run fuzzing:

```powershell
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test fuzz -FuzzSeconds 300
```

Run DoS testing:

```powershell
powershell -ExecutionPolicy Bypass -File security/run_security_tests.ps1 -Test dos -Protocol zkarche -HostName 127.0.0.1 -Port 4000
```

## Output files

All tests create logs under:

```text
results/security/logs/
```

The DoS and RNG/side-channel scripts also create CSV files under:

```text
results/security/
```

## Notes

`--test all` intentionally excludes DoS and fuzzing by default. DoS requires a running server, and fuzzing can run for a long time. Run those explicitly when needed.
