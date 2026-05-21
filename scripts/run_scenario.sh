#!/usr/bin/env bash
# Scenario runner — orchestrates one of S1..S8 against the running testbed.
#
#  ┌── timeline ──────────────────────────────────────────────────────────┐
#  │ t0  scenario_state.reset(scenario=Sx, attacker, victim, type)         │
#  │ t1  spawn benign background traffic (iperf3) — applies to S1..S8       │
#  │ t2  spawn attack via hping3/iperf3 inside attacker host's netns        │
#  │ t3  pipeline M3 detects → publish() → fast-path Ryu + slow-path CLAMP  │
#  │ t4  let it run --duration seconds (default 30)                         │
#  │ t5  stop attack, clear Ryu rules, reset state                          │
#  └──────────────────────────────────────────────────────────────────────┘
#
# Usage:
#   scripts/run_scenario.sh S3 [--duration 30]
#
# Required env: PAD_SANDBOX_NS (default mn-sandbox)

set -euo pipefail

SCENARIO="${1:-}"
DURATION=30
if [[ "${2:-}" == "--duration" ]]; then DURATION="${3:-30}"; fi
if [[ -z "$SCENARIO" ]]; then
    echo "Usage: $0 S1|S2|...|S8 [--duration N]" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${PAD_SANDBOX_NS:-mn-sandbox}"
STATE="${PAD_SCENARIO_STATE:-/tmp/pad-onap/scenario_state.json}"

# Scenario table: ATTACK_TOOL ATTACK_ARGS ATTACKER_HOST VICTIM_HOST ATTACK_TYPE
case "$SCENARIO" in
    S1) TOOL=iperf3;  ATKR=h0  VICTIM=h15 TYPE=BENIGN   ARGS='-c 10.3.1.4 -u -b 50M -t %D' ;;
    S2) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=SYN_LOW  ARGS='--flood -S -p 80 10.3.1.4' ;;
    S3) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=SYN_HIGH ARGS='--flood -S -p 80 --rand-source 10.3.1.4' ;;
    S4) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=UDP_AMP  ARGS='--udp -p 53 --flood --rand-source 10.3.1.4' ;;
    S5) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=MULTI    ARGS='--flood -S -p 80 10.3.1.4' ;;
    S6) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=CARPET   ARGS='--flood -S -p 80 --rand-dest 10.3.0.0/16' ;;
    S7) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=SLOW_RATE ARGS='-S -p 80 -i u1000 10.3.1.4' ;;
    S8) TOOL=hping3;  ATKR=h0  VICTIM=h15 TYPE=BURST    ARGS='--flood -S -p 80 10.3.1.4' ;;
    stop) :;;
    *)  echo "Unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac

# Mark scenario start in shared state
python3 - <<PY
import sys
sys.path.insert(0, "${ROOT}")
from pipeline.s5_fastpath import scenario_state
scenario_state.reset(
    scenario="${SCENARIO}",
    attacker="${ATKR:-}", victim="${VICTIM:-}",
    attack_type="${TYPE:-}")
PY

if [[ "$SCENARIO" == "stop" ]]; then
    echo "[info] scenario stop — clearing state and Ryu rules"
    curl -s -X DELETE "${PAD_RYU_URL:-http://10.99.99.2:8080}/pad/tier" >/dev/null || true
    exit 0
fi

echo "[info] $SCENARIO  ${ATKR}→${VICTIM}  type=${TYPE}  duration=${DURATION}s"

# Resolve attack args (substitute %D = duration)
ARGS="${ARGS//%D/$DURATION}"

# Launch attack inside the sandbox netns, inside the attacker host's veth.
# Mininet hosts use their own netns; `ip netns exec mn-sandbox` is enough
# because the attacker host's netns is reachable from inside the sandbox.
case "$TOOL" in
    hping3)  ATTACK_CMD="hping3 $ARGS" ;;
    iperf3)  ATTACK_CMD="iperf3 $ARGS" ;;
esac

# In Mininet, hosts share the sandbox netns by default unless inNamespace.
# This works for the fat_tree_topology.py defaults.
ATTACK_LOG="/tmp/pad-onap/attack_${SCENARIO}_$(date +%s).log"
mkdir -p "$(dirname "$ATTACK_LOG")"

echo "[info] launching: $ATTACK_CMD"
sudo ip netns exec "$NS" timeout "${DURATION}s" $ATTACK_CMD \
    >"$ATTACK_LOG" 2>&1 &
ATTACK_PID=$!

# Wait for attack to finish (timeout handles upper bound)
wait $ATTACK_PID 2>/dev/null || true

echo "[info] $SCENARIO complete (attack pid $ATTACK_PID). Clearing fast-path."
curl -s -X DELETE "${PAD_RYU_URL:-http://10.99.99.2:8080}/pad/tier" >/dev/null || true

python3 - <<PY
import sys
sys.path.insert(0, "${ROOT}")
from pipeline.s5_fastpath import scenario_state
scenario_state.push_event("scenario_done", scenario="${SCENARIO}")
PY
