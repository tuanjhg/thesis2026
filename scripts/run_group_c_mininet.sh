#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV="${VENV:-.venv_wsl}"
if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[ERROR] Missing venv Python: $VENV/bin/python" >&2
  exit 2
fi

mkdir -p evaluation/verify_runs
RUN_TS="${RUN_TS:-$(cat evaluation/verify_runs/LATEST 2>/dev/null || date +%Y%m%d_%H%M%S)}"
RUN_ROOT="evaluation/verify_runs/$RUN_TS"
LOG_DIR="$RUN_ROOT/logs"
mkdir -p "$LOG_DIR" evaluation/results
printf '%s\n' "$RUN_TS" > evaluation/verify_runs/LATEST

WSL_IP="$(ip -4 addr show eth0 | awk '/inet/{print $2}' | cut -d/ -f1 | head -1)"
printf 'PAD_HOST=%s\nPAD_KAFKA_PORT=9092\n' "$WSL_IP" > testbed/.env

export PYTHONPATH="/usr/lib/python3/dist-packages:${PYTHONPATH:-}"
export PAD_ONAP_STUB=true
export PAD_DEPLOY_MODE=stub

SITE_PACKAGES="$("$VENV/bin/python" - <<'PY'
import site
print(site.getsitepackages()[0])
PY
)"
if [[ ! -e "$SITE_PACKAGES/mininet" ]]; then
  ln -s /usr/lib/python3/dist-packages/mininet "$SITE_PACKAGES/mininet"
fi
unset PYTHONPATH

echo "[INFO] RUN_ROOT=$RUN_ROOT"
echo "[INFO] WSL_IP=$WSL_IP"
echo "[INFO] E2E_K=${E2E_K:-4}"
echo "[INFO] E2E_DURATION=${E2E_DURATION:-60}"
echo "[INFO] E2E_ATTACK_CLASS=${E2E_ATTACK_CLASS:-udpflood}"
echo "[INFO] E2E_MODE_TIMEOUT=${E2E_MODE_TIMEOUT:-900}"
echo "[INFO] E2E_TRANSPORT=${E2E_TRANSPORT:-kafka}"

sudo service openvswitch-switch start | tee "$LOG_DIR/group_c_ovs_start.log"
sudo mn -c > "$LOG_DIR/group_c_mn_cleanup_initial.log" 2>&1 || true
sudo pkill -9 -f hping3 2>/dev/null || true
sudo pkill -9 -f iperf 2>/dev/null || true
sudo pkill -9 -f softflowd 2>/dev/null || true

if [[ "${E2E_TRANSPORT:-kafka}" == "kafka" ]]; then
  docker compose -f testbed/docker-compose.yml up -d --force-recreate kafka \
    2>&1 | tee "$LOG_DIR/group_c_docker_kafka_up.log"
  docker compose -f testbed/docker-compose.yml ps \
    2>&1 | tee "$LOG_DIR/group_c_docker_compose_ps.log"
else
  echo "[INFO] Kafka skipped: E2E_TRANSPORT=${E2E_TRANSPORT:-kafka}" \
    | tee "$LOG_DIR/group_c_docker_kafka_up.log"
  echo "[INFO] Kafka skipped: E2E_TRANSPORT=${E2E_TRANSPORT:-kafka}" \
    | tee "$LOG_DIR/group_c_docker_compose_ps.log"
fi

echo "=== GROUP C AI ==="
timeout --foreground "${E2E_MODE_TIMEOUT:-900}" sudo -E env \
  PAD_ONAP_STUB=true \
  PAD_DEPLOY_MODE=stub \
  PAD_HEALTH_PORT=19298 \
  "$VENV/bin/python" testbed/netflow_e2e_pipeline.py \
    --mode ai \
    --k "${E2E_K:-4}" \
    --duration "${E2E_DURATION:-60}" \
    --broker localhost:9092 \
    --collector-kafka "$WSL_IP:9092" \
    --transport "${E2E_TRANSPORT:-kafka}" \
    --attack-class "${E2E_ATTACK_CLASS:-udpflood}" \
  2>&1 | tee "$LOG_DIR/group_c_e2e_ai.log"

sudo mn -c > "$LOG_DIR/group_c_mn_cleanup_between.log" 2>&1 || true

echo "=== GROUP C BASELINE ==="
timeout --foreground "${E2E_MODE_TIMEOUT:-900}" sudo -E env \
  PAD_ONAP_STUB=true \
  PAD_DEPLOY_MODE=stub \
  "$VENV/bin/python" testbed/netflow_e2e_pipeline.py \
    --mode baseline \
    --k "${E2E_K:-4}" \
    --duration "${E2E_DURATION:-60}" \
    --broker localhost:9092 \
    --collector-kafka "$WSL_IP:9092" \
    --transport "${E2E_TRANSPORT:-kafka}" \
    --attack-class "${E2E_ATTACK_CLASS:-udpflood}" \
  2>&1 | tee "$LOG_DIR/group_c_e2e_baseline.log"

sudo mn -c > "$LOG_DIR/group_c_mn_cleanup_final.log" 2>&1 || true

echo "[INFO] Group C done: $RUN_ROOT"
