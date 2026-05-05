#!/usr/bin/env bash
set -u

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST="all"
PROTOCOL="zkarche"
HOST="127.0.0.1"
PORT=""
LOG_DIR="results/security/logs"
FUZZ_SECONDS="60"
SAMPLES="10000"

usage() {
  cat <<USAGE
Usage: bash security/run_security_tests.sh [options]

Options:
  --test NAME             Test to run: all, transcript, mutation, invalid-curve, dos,
                          session, fuzz, replay, side-channel
  --protocol NAME         Protocol for DoS test: zkarche, edhoc, mtls (default: zkarche)
  --host HOST             DoS target host (default: 127.0.0.1)
  --port PORT             DoS target port. Defaults by protocol: zkarche=4000, edhoc=5688, mtls=7443
  --project PATH          Repository root (default: repo root)
  --log-dir PATH          Log directory relative to project root (default: results/security/logs)
  --fuzz-seconds N        Fuzzing time in seconds (default: 60)
  --samples N             RNG sample count for side-channel/RNG test (default: 10000)
  -h, --help              Show this help

Examples:
  bash security/run_security_tests.sh --test all
  bash security/run_security_tests.sh --test transcript
  bash security/run_security_tests.sh --test dos --protocol zkarche --port 4000
  bash security/run_security_tests.sh --test fuzz --fuzz-seconds 300
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test) TEST="$2"; shift 2 ;;
    --protocol) PROTOCOL="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --log-dir) LOG_DIR="$2"; shift 2 ;;
    --fuzz-seconds) FUZZ_SECONDS="$2"; shift 2 ;;
    --samples) SAMPLES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "$PORT" ]]; then
  case "$PROTOCOL" in
    zkarche) PORT=4000 ;;
    edhoc) PORT=5688 ;;
    mtls) PORT=7443 ;;
    *) echo "Unsupported protocol for DoS: $PROTOCOL"; exit 2 ;;
  esac
fi

cd "$PROJECT" || exit 1
mkdir -p "$LOG_DIR" results/security

run_one() {
  local name="$1"
  echo ""
  echo "============================================================"
  echo "Running security test: $name"
  echo "============================================================"
  case "$name" in
    transcript)
      python3 security/transcript_binding_test.py --project "$PROJECT" --log-dir "$LOG_DIR" ;;
    mutation)
      python3 security/message_mutation_test.py --project "$PROJECT" --log-dir "$LOG_DIR" ;;
    invalid-curve)
      python3 security/invalid_curve_small_subgroup_test.py --project "$PROJECT" --log-dir "$LOG_DIR" ;;
    dos)
      local log="$PROJECT/$LOG_DIR/04_dos_resilience_${PROTOCOL}.log"
      set +e
      python3 security/dos_resilience_test.py \
        --host "$HOST" \
        --port "$PORT" \
        --protocol "$PROTOCOL" \
        --output "results/security/${PROTOCOL}_dos_resilience.csv" 2>&1 | tee "$log"
      local rc=${PIPESTATUS[0]}
      set -e
      echo "Saved log: $log"
      return "$rc" ;;
    session)
      python3 security/session_uniqueness_nonce_reuse_test.py --project "$PROJECT" --log-dir "$LOG_DIR" ;;
    fuzz)
      python3 security/packet_fuzzing_test.py --project "$PROJECT" --log-dir "$LOG_DIR" --seconds "$FUZZ_SECONDS" ;;
    replay)
      python3 security/replay_cache_test.py --project "$PROJECT" --log-dir "$LOG_DIR" ;;
    side-channel)
      python3 security/side_channel_rng_analysis_test.py --project "$PROJECT" --log-dir "$LOG_DIR" --samples "$SAMPLES" ;;
    *) echo "Unknown test: $name"; return 2 ;;
  esac
}

FAILED=0
if [[ "$TEST" == "all" ]]; then
  for t in transcript mutation invalid-curve session replay side-channel; do
    run_one "$t" || FAILED=1
  done
  echo ""
  echo "NOTE: DoS and fuzzing are intentionally not included in 'all' by default because DoS requires a running server and fuzzing can be long-running."
  echo "Run them explicitly with --test dos or --test fuzz."
else
  run_one "$TEST" || FAILED=1
fi

exit "$FAILED"
