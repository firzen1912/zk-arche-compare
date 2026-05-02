#!/usr/bin/env bash
# benchmarks/run_all.sh — run every test across every protocol on this host.
#
# Designed so a single SSH session per Pi (3B+, 4, 5) collects the entire
# dataset for that platform. Results land under benchmarks/results/ which
# you then SCP back to your laptop and run `python -m benchmarks.plot` on.
#
# Knobs (env vars):
#   ZKB_T1_CLIENTS   default 50    test 1 concurrent clients
#   ZKB_T2_RUNS      default 50    test 2 sequential runs
#   ZKB_T3_CLIENTS   default 50    test 3 clients
#   ZKB_T3_RUNS      default 50    test 3 runs per client
#   ZKB_TR_CLIENTS   default 50    resource-sampling clients
#   ZKB_TR_RUNS      default 5     resource-sampling runs per client
#   ZKB_DEVICE       auto-detect   pi3bplus | pi4 | pi5 | generic
#   ZKB_PROTOS       all           comma list, e.g. "zkarche,edhoc"
#   ZKB_TESTS        all           comma list, e.g. "test1,test2,resources"

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
cd "$REPO_ROOT"

# ---------- preflight ----------
if [[ ! -x target/release/zkarche_server ]]; then
    echo "[run_all] release binaries missing; running setup.sh first"
    bash benchmarks/setup.sh
fi

PROTOS="${ZKB_PROTOS:-zkarche,edhoc,mtls}"
TESTS="${ZKB_TESTS:-test1,test2,test3,resources}"

PYTHON="${PYTHON:-python3}"

run_one () {
    local test_mod="$1" proto="$2"
    echo
    echo "======================================================================"
    echo "  $(date -u +%FT%TZ)  ${test_mod} / ${proto}"
    echo "======================================================================"
    "$PYTHON" -m "benchmarks.tests.${test_mod}" "${proto}"
}

IFS=',' read -ra PROTO_LIST <<<"$PROTOS"
IFS=',' read -ra TEST_LIST <<<"$TESTS"

for t in "${TEST_LIST[@]}"; do
    case "$t" in
        test1|t1) module="test1_concurrent" ;;
        test2|t2) module="test2_sequential" ;;
        test3|t3) module="test3_highload"   ;;
        resources|t456|t4|t5|t6) module="test_resources" ;;
        *)
            echo "[run_all] unknown test '$t' (expected: test1|test2|test3|resources)" >&2
            exit 2
            ;;
    esac
    for p in "${PROTO_LIST[@]}"; do
        run_one "$module" "$p"
    done
done

echo
echo "[run_all] all done. Results under: benchmarks/results/"
echo "[run_all] To produce graphs and the summary table, run:"
echo "    $PYTHON -m benchmarks.plot"
