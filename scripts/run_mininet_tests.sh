#!/usr/bin/env bash
set -Eeuo pipefail

# PAD-ONAP Mininet test runner.
# Run from WSL/Linux:
#   sudo bash scripts/run_mininet_tests.sh
# Optional:
#   sudo bash scripts/run_mininet_tests.sh --full-fat-tree
#   sudo bash scripts/run_mininet_tests.sh --e2e --duration 60

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="mininet-$(date -u +%Y%m%d-%H%M%S)"
LOG_DIR="$ROOT/results/mock_orchestration/$RUN_ID"
mkdir -p "$LOG_DIR" "$ROOT/results/metadata"

FULL_FAT_TREE=0
RUN_E2E=0
E2E_DURATION=60
E2E_K=2
FAT_TREE_TIMEOUT=180
FULL_FAT_TREE_TIMEOUT=900

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/run_mininet_tests.sh [options]

Options:
  --full-fat-tree       Also run fat-tree k=4 smoke test. This can be slow in WSL.
  --e2e                 Run Mininet + Kafka AI/Baseline E2E if Docker is available.
  --e2e-k K             Fat-tree k for E2E. Default: 2 smoke; use 4 for full run.
  --duration SEC        E2E attack duration in seconds. Default: 60.
  -h, --help            Show this help.

Default smoke run:
  1. Start Open vSwitch
  2. Cleanup stale Mininet state
  3. Run mn --test pingall
  4. Run 3-slice PAD topology test
  5. Run bounded UDP-flood Mininet scenario
  6. Run fat-tree k=2 topology smoke test
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full-fat-tree)
      FULL_FAT_TREE=1
      shift
      ;;
    --e2e)
      RUN_E2E=1
      shift
      ;;
    --duration)
      E2E_DURATION="${2:?missing duration value}"
      shift 2
      ;;
    --e2e-k)
      E2E_K="${2:?missing k value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[INFO] Re-running with sudo because Mininet requires root..."
  exec sudo -E bash "$0" "$@"
fi

run_step() {
  local name="$1"
  shift
  local log="$LOG_DIR/${name}.log"
  echo
  echo "==> $name"
  echo "    log: $log"
  set +e
  "$@" >"$log" 2>&1
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "    status: PASS"
  else
    echo "    status: FAIL rc=$rc"
  fi
  return "$rc"
}

run_step_allow_fail() {
  local name="$1"
  shift
  if ! run_step "$name" "$@"; then
    echo "    continuing after non-critical failure"
    return 0
  fi
}

command -v python3 >/dev/null || { echo "[ERROR] python3 not found"; exit 1; }
command -v mn >/dev/null || { echo "[ERROR] mininet not found"; exit 1; }
command -v ovs-vsctl >/dev/null || { echo "[ERROR] openvswitch not found"; exit 1; }
command -v hping3 >/dev/null || { echo "[ERROR] hping3 not found"; exit 1; }
command -v iperf3 >/dev/null || { echo "[ERROR] iperf3 not found"; exit 1; }

echo "PAD-ONAP Mininet test run"
echo "RUN_ID=$RUN_ID"
echo "ROOT=$ROOT"
echo "LOG_DIR=$LOG_DIR"

run_step "ovs_start" bash -lc "service openvswitch-switch start || true; ovs-vsctl show"
run_step "mn_cleanup_initial" mn -c
run_step "mn_pingall_sanity" mn --test pingall
run_step_allow_fail "pad_3slice_topology" python3 testbed/mininet/topology.py --test
run_step "basic_udp_attack" python3 testbed/mininet/basic_udp_attack_scenario.py \
  --run-id "${RUN_ID}-basic-udp" --duration 5 --iperf-seconds 3
run_step "fat_tree_k2_smoke" timeout "$FAT_TREE_TIMEOUT" python3 -u testbed/mininet/fat_tree_topology.py --k 2 --test

if [[ "$FULL_FAT_TREE" -eq 1 ]]; then
  run_step_allow_fail "fat_tree_k4_smoke" timeout "$FULL_FAT_TREE_TIMEOUT" \
    python3 -u testbed/mininet/fat_tree_topology.py --k 4 --test
fi

if [[ "$RUN_E2E" -eq 1 ]]; then
  if ! command -v docker >/dev/null; then
    echo
    echo "==> e2e"
    echo "    status: SKIP"
    echo "    reason: docker command not found in this WSL distro."
    echo "    fix: enable Docker Desktop WSL integration for Ubuntu-22.04 or install Docker inside WSL."
  else
    WSL_IP="$(ip -4 addr show eth0 | awk '/inet/{print $2}' | cut -d/ -f1 | head -1)"
    printf 'PAD_HOST=%s\nPAD_KAFKA_PORT=9092\n' "$WSL_IP" > testbed/.env
    run_step "docker_kafka_up" docker compose -f testbed/docker-compose.yml up -d --force-recreate kafka
    run_step_allow_fail "e2e_ai" timeout 900 python3 testbed/netflow_e2e_pipeline.py \
      --mode ai --k "$E2E_K" --duration "$E2E_DURATION" --broker localhost:9092 \
      --collector-kafka "${WSL_IP}:9092"
    run_step_allow_fail "e2e_baseline" timeout 900 python3 testbed/netflow_e2e_pipeline.py \
      --mode baseline --k "$E2E_K" --duration "$E2E_DURATION" --broker localhost:9092 \
      --collector-kafka "${WSL_IP}:9092"
  fi
fi

run_step_allow_fail "mn_cleanup_final" mn -c

SUMMARY="$LOG_DIR/run_summary.json"
python3 - "$SUMMARY" "$RUN_ID" "$LOG_DIR" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path

summary_path = Path(sys.argv[1])
run_id = sys.argv[2]
log_dir = Path(sys.argv[3])
logs = sorted(p.name for p in log_dir.glob("*.log"))
summary = {
    "run_id": run_id,
    "result_type": "simulated_testbed_result",
    "mode": "mininet_test_runner",
    "timestamp_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "log_dir": str(log_dir),
    "logs": logs,
    "notes": [
        "Local WSL/Mininet smoke and attack tests only.",
        "These are not real ONAP/Kubernetes execution results."
    ],
}
summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
print(summary_path)
PY

echo
echo "Done. Summary: $SUMMARY"
echo "Detailed logs are under: $LOG_DIR"
