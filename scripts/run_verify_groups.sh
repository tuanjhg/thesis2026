#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="${VENV:-.venv_wsl}"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[ERROR] Missing venv Python: $VENV/bin/python" >&2
  exit 2
fi

# shellcheck source=/dev/null
source "$VENV/bin/activate"

mkdir -p evaluation/verify_runs
RUN_TS="${RUN_TS:-$(date +%Y%m%d_%H%M%S)}"
RUN_ROOT="evaluation/verify_runs/$RUN_TS"
AI_DIR="$RUN_ROOT/group_b_ai"
BASE_DIR="$RUN_ROOT/group_b_baseline"
LOG_DIR="$RUN_ROOT/logs"
mkdir -p "$AI_DIR" "$BASE_DIR" "$LOG_DIR"
printf '%s\n' "$RUN_TS" > evaluation/verify_runs/LATEST

export PAD_DEPLOY_MODE="${PAD_DEPLOY_MODE:-stub}"
export PAD_ONAP_STUB="${PAD_ONAP_STUB:-true}"

SCENARIOS=(S1 S2 S3 S8)

echo "[INFO] RUN_ROOT=$RUN_ROOT"
echo "[INFO] Running Group B synthetic scenarios: ${SCENARIOS[*]}"

for s in "${SCENARIOS[@]}"; do
  echo "=== GROUP B AI $s ==="
  python - "$s" "$AI_DIR" <<'PY' 2>&1 | tee "$LOG_DIR/group_b_ai_${s}.log"
import sys
import os
from pathlib import Path

from evaluation.scenarios import SCENARIOS, run_scenario
from pipeline.s4_orchestration.orchestrator import Orchestrator

scenario_key = sys.argv[1].upper()
out_dir = Path(sys.argv[2])
scenario = next((s for s in SCENARIOS if scenario_key in s.name), None)
if scenario is None:
    raise SystemExit(f"Unknown scenario: {scenario_key}")

port_base = 19300 + {"S1": 10, "S2": 20, "S3": 30, "S8": 80}.get(scenario_key, 90)
os.environ["PAD_HEALTH_PORT"] = str(port_base + 1)

orch = Orchestrator(
    model_dir="pad_onap_v3/models",
    data_dir="pad_onap_v3/processed",
    mode="legacy",
    device="cpu",
    shap_enabled=False,
    latency_port=port_base,
    eval_mode=True,
)
run_scenario(scenario, orch, out_dir)
PY
done

for s in "${SCENARIOS[@]}"; do
  echo "=== GROUP B BASELINE $s ==="
  python -m evaluation.baseline_threshold \
    --scenario "$s" \
    --out-dir "$BASE_DIR" \
    2>&1 | tee "$LOG_DIR/group_b_baseline_${s}.log"
done

echo "[INFO] Group B done: $RUN_ROOT"
