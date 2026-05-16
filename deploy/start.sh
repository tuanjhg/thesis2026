#!/usr/bin/env bash
# PAD-ONAP Pipeline — Start Script
# ==================================
# Khởi động toàn bộ pipeline: infrastructure (Docker) + native Python components.
# Chạy từ thư mục gốc project (Src_2/):
#   chmod +x deploy/start.sh
#   ./deploy/start.sh
#
# Dừng lại: ./deploy/stop.sh
# Xem logs:
#   tail -f logs/kafka_producer.log
#   tail -f logs/flink_processor.log
#   tail -f logs/live_pipeline.log

set -euo pipefail

# ── Resolve project root ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Load .env if present ───────────────────────────────────────────────────────
ENV_FILE="${PROJECT_ROOT}/testbed/.env"
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    source "${ENV_FILE}"
    set +a
    echo "[start.sh] Loaded config from ${ENV_FILE}"
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
PAD_HOST="${PAD_HOST:-localhost}"
PAD_KAFKA_PORT="${PAD_KAFKA_PORT:-9092}"
PAD_GNMI_PORT="${PAD_GNMI_PORT:-8080}"
BROKER="${PAD_HOST}:${PAD_KAFKA_PORT}"

MODEL_DIR="${PAD_MODEL_DIR:-${PROJECT_ROOT}/pad_onap_v3/models}"
DATA_DIR="${PAD_DATA_DIR:-${PROJECT_ROOT}/pad_onap_v3/processed}"
LOG_DIR="${PROJECT_ROOT}/logs"
PID_DIR="${PROJECT_ROOT}/.pids"

mkdir -p "${LOG_DIR}" "${PID_DIR}"

# ── Python virtualenv ──────────────────────────────────────────────────────────
VENV="${PROJECT_ROOT}/.venv"
if [[ ! -d "${VENV}" ]]; then
    echo "[start.sh] Creating Python venv at ${VENV}..."
    python3 -m venv "${VENV}"
    "${VENV}/bin/pip" install --upgrade pip -q
    "${VENV}/bin/pip" install -r "${PROJECT_ROOT}/requirements-pipeline.txt" -q
    echo "[start.sh] Python venv ready."
fi
PYTHON="${VENV}/bin/python"

# ── 1. Start Docker infrastructure ────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  [1/4] Starting Docker infrastructure..."
echo "═══════════════════════════════════════════════════════════"
cd "${PROJECT_ROOT}/testbed"
docker compose up -d kafka gnmi-simulator netflow-collector
cd "${PROJECT_ROOT}"

# ── 2. Wait for Kafka to be healthy ───────────────────────────────────────────
echo ""
echo "  [2/4] Waiting for Kafka to be ready (max 60s)..."
for i in $(seq 1 12); do
    if docker inspect pad-kafka --format='{{.State.Health.Status}}' 2>/dev/null | grep -q "healthy"; then
        echo "  Kafka is healthy."
        break
    fi
    echo "  Kafka not ready yet (attempt ${i}/12)..."
    sleep 5
done

# ── 3. Start Python pipeline components ───────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  [3/4] Starting Python pipeline components..."
echo "═══════════════════════════════════════════════════════════"

start_component() {
    local name="$1"
    local cmd="$2"
    local log="${LOG_DIR}/${name}.log"
    local pid_file="${PID_DIR}/${name}.pid"

    # Kill existing instance if running
    if [[ -f "${pid_file}" ]]; then
        local old_pid
        old_pid=$(cat "${pid_file}")
        if kill -0 "${old_pid}" 2>/dev/null; then
            echo "  Stopping existing ${name} (PID ${old_pid})..."
            kill "${old_pid}" 2>/dev/null || true
            sleep 1
        fi
    fi

    echo "  Starting ${name}..."
    # shellcheck disable=SC2086
    nohup ${PYTHON} ${cmd} >> "${log}" 2>&1 &
    echo $! > "${pid_file}"
    echo "  ${name} started (PID $(cat "${pid_file}"), log: ${log})"
}

start_component "kafka_producer" \
    "-u ${PROJECT_ROOT}/pipeline/s1_telemetry/kafka_producer.py \
     --gnmi http://localhost:${PAD_GNMI_PORT} \
     --broker ${BROKER} \
     --interval 0.5"

sleep 2   # give producer a moment before flink connects

# Two-track Flink processor (v3 schema):
#   --flow-window/-slide  → telemetry.features.flow   (Track A 22-dim, 5s sliding)
#   --ts-window           → telemetry.features.timeseries (Track B 6-dim, 60s tumbling)
start_component "flink_processor" \
    "-u ${PROJECT_ROOT}/pipeline/s2_features/flink_processor.py \
     --broker ${BROKER} \
     --flow-window 5.0 \
     --flow-slide  1.0 \
     --ts-window   60.0"

sleep 2

# Two-track inference engine (Kafka mode). Mode `spec` activates native 22+6
# CICDDoS / 12-class operation; switch to `legacy` only if running with the
# bridged 17-feature / 7-class artefacts.
PAD_MODE="${PAD_INFERENCE_MODE:-spec}"
start_component "live_pipeline" \
    "-u ${PROJECT_ROOT}/pipeline/s3_ai/live_pipeline.py \
     --source kafka \
     --broker ${BROKER} \
     --mode ${PAD_MODE} \
     --model-dir ${MODEL_DIR} \
     --data-dir  ${DATA_DIR} \
     --out       ${LOG_DIR}/inference_output.jsonl"

# ── 4. Status ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  [4/4] Pipeline status"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Docker services:"
cd "${PROJECT_ROOT}/testbed" && docker compose ps --format "table {{.Name}}\t{{.Status}}"
cd "${PROJECT_ROOT}"
echo ""
echo "  Python processes:"
for name in kafka_producer flink_processor live_pipeline; do
    pid_file="${PID_DIR}/${name}.pid"
    if [[ -f "${pid_file}" ]]; then
        pid=$(cat "${pid_file}")
        if kill -0 "${pid}" 2>/dev/null; then
            echo "  ✓ ${name} (PID ${pid})"
        else
            echo "  ✗ ${name} — not running (check logs/${name}.log)"
        fi
    fi
done

echo ""
echo "  Logs:"
echo "    tail -f ${LOG_DIR}/kafka_producer.log"
echo "    tail -f ${LOG_DIR}/flink_processor.log"
echo "    tail -f ${LOG_DIR}/live_pipeline.log"
echo "    tail -f ${LOG_DIR}/inference_output.jsonl"
echo ""
echo "  Monitoring:"
echo "    Prometheus : http://${PAD_HOST}:${PAD_PROMETHEUS_PORT:-9190}"
echo "    Grafana    : http://${PAD_HOST}:${PAD_GRAFANA_PORT:-3001}"
echo ""
echo "  Stop all: ./deploy/stop.sh"
echo ""
