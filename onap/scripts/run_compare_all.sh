#!/usr/bin/env bash
# run_compare_all.sh — Three-way comparison on real ONAP
#
# Runs the same UDP-flood / SYN+UDP traffic against a live ONAP cluster
# under three different detectors:
#   1. AI reactive (run_s2_real.py)               — XGBoost classifier
#   2. AI proactive + reactive (run_s8_real.py)   — Transformer forecast + XGBoost
#   3. ONAP rule-based (run_baseline_real.py)     — pkt_rate/syn_ratio thresholds
# Then emits evaluation/results/ai_vs_baseline.md with the latency
# breakdown and time-to-mitigation deltas.
#
# Prereqs: see requirements/onap_e2e_runbook.md (preflight green +
#          NetFlow collector running on port 7070).

set -euo pipefail

GNMI_URL="${GNMI_URL:-http://localhost:8888}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:7070}"
BRIDGE="${BRIDGE:-br-pad}"
SRC_IP="${SRC_IP:-10.0.0.1}"
VNF_PORT="${VNF_PORT:-9001}"
VNF_PORT_T2="${VNF_PORT_T2:-3}"
VNF_PORT_T3="${VNF_PORT_T3:-4}"
SUSTAIN="${SUSTAIN:-3}"
COOLDOWN="${COOLDOWN:-60}"
ATTACK_MODE="${ATTACK_MODE:-gnmi}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gnmi-url)      GNMI_URL="$2";      shift 2;;
    --collector-url) COLLECTOR_URL="$2"; shift 2;;
    --bridge)        BRIDGE="$2";        shift 2;;
    --src-ip)        SRC_IP="$2";        shift 2;;
    --vnf-port)      VNF_PORT="$2";      shift 2;;
    --vnf-port-t2)   VNF_PORT_T2="$2";   shift 2;;
    --vnf-port-t3)   VNF_PORT_T3="$2";   shift 2;;
    --sustain)       SUSTAIN="$2";       shift 2;;
    --attack-mode)   ATTACK_MODE="$2";   shift 2;;
    --cooldown)      COOLDOWN="$2";      shift 2;;
    -h|--help)
      grep -E '^# ' "$0" | sed 's/^# \?//'
      exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ "${PAD_ONAP_STUB:-true}" != "false" ]]; then
  echo "ERROR: PAD_ONAP_STUB must be 'false' (real ONAP)." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="$ROOT/evaluation/results"
mkdir -p "$RESULTS"

echo "================================================================"
echo "  Three-way detector comparison on REAL ONAP"
echo "  AI reactive  → s2_real_onap.json"
echo "  AI proactive → s8_real_onap.json"
echo "  Rule-based   → s2_baseline_real_onap.json"
echo "  Cooldown between runs: ${COOLDOWN}s"
echo "================================================================"

echo
echo "── RUN 1/3: AI reactive (S2, XGBoost) ─────────────────────────"
python "$ROOT/onap/scripts/run_s2_real.py" \
  --attack-mode "$ATTACK_MODE" --gnmi-url "$GNMI_URL" \
  --bridge "$BRIDGE" --src-ip "$SRC_IP" --vnf-port "$VNF_PORT" \
  --collector-url "$COLLECTOR_URL" \
  | tee "$RESULTS/s2_ai_run.log"
sleep "$COOLDOWN"

echo
echo "── RUN 2/3: AI proactive (S8, Transformer + XGBoost) ──────────"
python "$ROOT/onap/scripts/run_s8_real.py" \
  --attack-mode "$ATTACK_MODE" --gnmi-url "$GNMI_URL" \
  --bridge "$BRIDGE" --vnf-port-t2 "$VNF_PORT_T2" --vnf-port-t3 "$VNF_PORT_T3" \
  --collector-url "$COLLECTOR_URL" \
  | tee "$RESULTS/s8_ai_run.log"
sleep "$COOLDOWN"

echo
echo "── RUN 3/3: ONAP rule-based (no AI) ───────────────────────────"
python "$ROOT/onap/scripts/run_baseline_real.py" \
  --attack-mode "$ATTACK_MODE" --gnmi-url "$GNMI_URL" \
  --bridge "$BRIDGE" --src-ip "$SRC_IP" --vnf-port "$VNF_PORT" \
  --collector-url "$COLLECTOR_URL" \
  --sustain-windows "$SUSTAIN" \
  | tee "$RESULTS/baseline_run.log"

echo
echo "── Comparison report ──────────────────────────────────────────"
python "$ROOT/onap/scripts/compare_ai_vs_baseline.py" \
  --ai-reactive  "$RESULTS/s2_real_onap.json" \
  --ai-proactive "$RESULTS/s8_real_onap.json" \
  --baseline     "$RESULTS/s2_baseline_real_onap.json" \
  --out          "$RESULTS/ai_vs_baseline.md"

echo
echo "Done. Artifacts in $RESULTS:"
echo "  - s2_real_onap.json             (AI reactive)"
echo "  - s8_real_onap.json             (AI proactive + reactive)"
echo "  - s2_baseline_real_onap.json    (ONAP rule-based, no AI)"
echo "  - ai_vs_baseline.md             (full comparison)"
