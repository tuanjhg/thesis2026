#!/usr/bin/env bash
# PAD-ONAP Server Setup — One-time initialization
# =================================================
# Chạy lần đầu khi deploy lên server ONAP.
# Kiểm tra dependencies, tạo venv, cấu hình .env.
#
# Usage:
#   chmod +x deploy/setup_server.sh
#   ./deploy/setup_server.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "═══════════════════════════════════════════════════════════"
echo "  PAD-ONAP Server Setup"
echo "═══════════════════════════════════════════════════════════"
echo "  Project root: ${PROJECT_ROOT}"
echo ""

# ── 1. Check Docker ───────────────────────────────────────────────────────────
echo "[1/5] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "  ERROR: Docker not found. Install Docker first:"
    echo "    curl -fsSL https://get.docker.com | sh"
    exit 1
fi
DOCKER_VERSION=$(docker --version)
echo "  OK: ${DOCKER_VERSION}"

if ! docker compose version &>/dev/null; then
    echo "  ERROR: docker compose plugin not found."
    echo "    sudo apt install docker-compose-plugin"
    exit 1
fi
echo "  OK: $(docker compose version)"

# ── 2. Check Python ───────────────────────────────────────────────────────────
echo ""
echo "[2/5] Checking Python..."
PYTHON_BIN=""
for py in python3.11 python3.12 python3.10 python3; do
    if command -v "${py}" &>/dev/null; then
        PYTHON_VERSION=$("${py}" --version 2>&1)
        echo "  OK: ${PYTHON_VERSION} (${py})"
        PYTHON_BIN="${py}"
        break
    fi
done
if [[ -z "${PYTHON_BIN}" ]]; then
    echo "  ERROR: Python 3.10+ not found."
    echo "    sudo apt install python3.11 python3.11-venv"
    exit 1
fi

# ── 3. Configure .env ─────────────────────────────────────────────────────────
echo ""
echo "[3/5] Configuring .env..."
ENV_FILE="${PROJECT_ROOT}/testbed/.env"

# Detect server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

if [[ -f "${ENV_FILE}" ]]; then
    echo "  Found existing ${ENV_FILE}"
    echo "  Current PAD_HOST=$(grep '^PAD_HOST' "${ENV_FILE}" | cut -d= -f2 || echo 'not set')"
else
    cp "${PROJECT_ROOT}/testbed/.env" "${ENV_FILE}" 2>/dev/null || true
fi

echo ""
echo "  Detected server IP: ${SERVER_IP}"
read -rp "  Enter PAD_HOST (press Enter to use ${SERVER_IP}): " USER_HOST
PAD_HOST="${USER_HOST:-${SERVER_IP}}"

# Check for ONAP port conflicts
echo ""
echo "  Checking port availability..."
check_port() {
    local port=$1 name=$2 suggested=$3
    if ss -tlnp "sport = :${port}" 2>/dev/null | grep -q LISTEN; then
        echo "  WARNING: Port ${port} (${name}) is already in use — ONAP may be using it."
        echo "    Set PAD_${name^^}_PORT=${suggested} in ${ENV_FILE}"
    else
        echo "  OK: Port ${port} (${name}) is free."
    fi
}
check_port 9092  "kafka"      "19092"
check_port 9090  "prometheus" "9190"
check_port 3000  "grafana"    "3001"

# Update PAD_HOST in .env
if grep -q '^PAD_HOST=' "${ENV_FILE}"; then
    sed -i "s|^PAD_HOST=.*|PAD_HOST=${PAD_HOST}|" "${ENV_FILE}"
else
    echo "PAD_HOST=${PAD_HOST}" >> "${ENV_FILE}"
fi
echo ""
echo "  PAD_HOST set to ${PAD_HOST} in ${ENV_FILE}"
echo "  Review and edit ${ENV_FILE} if ports need changing."

# ── 4. Create Python venv ──────────────────────────────────────────────────────
echo ""
echo "[4/5] Creating Python virtual environment..."
VENV="${PROJECT_ROOT}/.venv"
if [[ -d "${VENV}" ]]; then
    echo "  Venv already exists at ${VENV} — skipping creation."
else
    "${PYTHON_BIN}" -m venv "${VENV}"
    echo "  Venv created at ${VENV}"
fi

echo "  Installing dependencies..."
"${VENV}/bin/pip" install --upgrade pip -q
"${VENV}/bin/pip" install -r "${PROJECT_ROOT}/requirements-pipeline.txt" -q
echo "  Dependencies installed."

# ── 5. Verify model files ──────────────────────────────────────────────────────
echo ""
echo "[5/5] Verifying model files..."
MODEL_DIR="${PROJECT_ROOT}/pad_onap_v3/models"
DATA_DIR="${PROJECT_ROOT}/pad_onap_v3/processed"

MISSING=0
for f in \
    "${MODEL_DIR}/xgb_model.json" \
    "${MODEL_DIR}/transformer_lstm.pt" \
    "${MODEL_DIR}/tf_best_config.json" \
    "${DATA_DIR}/scaler.pkl" \
    "${DATA_DIR}/y_train.npy"
do
    if [[ -f "$f" ]]; then
        echo "  OK: $(basename "${f}")"
    else
        echo "  MISSING: ${f}"
        MISSING=1
    fi
done

if [[ "${MISSING}" -eq 1 ]]; then
    echo ""
    echo "  Some model files are missing. Run training first:"
    echo "    python pipeline/s3_ai/run_training_v2.py"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Setup complete!"
echo "  Next steps:"
echo "    1. Review testbed/.env (especially check ports vs ONAP)"
echo "    2. chmod +x deploy/start.sh deploy/stop.sh"
echo "    3. ./deploy/start.sh"
echo "═══════════════════════════════════════════════════════════"
