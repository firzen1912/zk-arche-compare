# Security Test Suite

The current repository uses a **single consolidated security runner**:

```text
experiments/security/security_test.py
```

The older top-level `security/` directory and separate Bash/PowerShell wrappers are no longer the authoritative interface. The Makefile now points directly to the consolidated runner.

## Test categories

| Test | Purpose |
| --- | --- |
| `transcript` | Transcript/domain-separation and binding regressions |
| `mutation` | Systematic near-valid message mutation tests |
| `invalid-curve` | Invalid Ristretto/identity/canonical-scalar/parser boundary tests |
| `session` | Session-key uniqueness, nonce reuse, and concurrency checks |
| `replay` | Replay-cache state-machine and concurrency checks |
| `side-channel` | RNG, dependency, and source-hygiene screening |
| `fuzz` | `cargo-fuzz`/libFuzzer packet-parser campaign |
| `dos` | Authorized local malformed/resource-stressing TCP resilience test |

The runner can also install its embedded Rust regression/fuzz files when needed.

## Recommended safe regression run

Use the Makefile target:

```bash
make security-test
```

or:

```bash
make security-safe
```

These targets run:

```text
transcript
mutation
invalid-curve
session
replay
side-channel
```

They intentionally avoid the fuzz and live-server DoS categories.

## Run one category

```bash
python3 experiments/security/security_test.py --test transcript
python3 experiments/security/security_test.py --test mutation
python3 experiments/security/security_test.py --test invalid-curve
python3 experiments/security/security_test.py --test session
python3 experiments/security/security_test.py --test replay
python3 experiments/security/security_test.py --test side-channel
```

Equivalent Makefile targets are available:

```bash
make security-transcript
make security-mutation
make security-invalid-curve
make security-session
make security-replay
make security-side-channel
```

## Fuzzing

The fuzz category uses `cargo +nightly fuzz` and the `packet_parsers` target.

```bash
cargo install cargo-fuzz
python3 experiments/security/security_test.py --test fuzz --seconds 300
```

or:

```bash
make security-fuzz
```

The Makefile's default fuzz duration is 60 seconds. Use the runner directly for a custom duration.

## DoS resilience testing

Only run the DoS harness against systems you own or are explicitly authorized to test.

Start the protocol server first, then run for ZK-ARCHE:

```bash
python3 experiments/security/security_test.py \
  --test dos \
  --protocol zkarche \
  --host 127.0.0.1 \
  --port 4000
```

Makefile shortcuts:

```bash
make security-dos-zkarche
make security-dos-edhoc
make security-dos-mtls
```

Default ports used by those targets are:

| Protocol | Port |
| --- | ---: |
| ZK-ARCHE | 4000 |
| EDHOC | 5688 |
| mTLS | 7443 |

The DoS runner can optionally execute a recovery command before and after malformed traffic:

```bash
python3 experiments/security/security_test.py \
  --test dos \
  --protocol zkarche \
  --host 127.0.0.1 \
  --port 4000 \
  --recovery-cmd './target/release/zkarche_client --server 127.0.0.1:4000'
```

## Full runner

The runner's `--test all` mode currently includes **all eight categories**, including fuzzing and DoS:

```bash
python3 experiments/security/security_test.py --test all
```

or:

```bash
make security-all
```

Do not use `security-all` as a routine quick check unless the required server is running and you intend to execute both fuzzing and the DoS harness.

## Evidence and output

The consolidated runner writes raw logs under:

```text
results/security/logs/
```

Per-test evidence CSVs are written under:

```text
results/security/csv/
```

It also emits aggregate evidence artifacts:

```text
results/security/security_evidence.json
results/security/security_evidence.csv
```

The runner records test parameters and observed results so experiment claims can be tied to exact evidence rather than only a pass/fail label.

## Side-channel / RNG scope

The side-channel category is a **screening test**, not a full side-channel certification. It checks items such as:

- OS RNG sample duplication and bit balance;
- presence of `zeroize`;
- presence of `subtle`;
- source patterns that may log secret material; and
- items that still require manual timing/power analysis.

A passing result should not be interpreted as proving absence of timing, cache, electromagnetic, or power side channels.

## Notes

- Minimize environmental changes between comparative runs.
- Preserve raw logs and per-test CSV evidence for reproducibility.
- Run fuzzing for a materially longer campaign when using it as thesis/security evidence.
- DoS testing requires an authorized live target and should be separated from normal regression tests.
