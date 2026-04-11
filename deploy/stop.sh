#!/usr/bin/env bash
# PAD-ONAP Pipeline — Stop Script
# =================================
# Dừng toàn bộ pipeline: native Python components + Docker infrastructure.
# Chạy từ thư mục gốc project (Src_2/):
#   ./deploy/stop.sh
#
# Chỉ dừng Python (giữ Kafka/Docker chạy):
#   ./deploy/stop.sh --python-only
#
# Chỉ dừng Docker (giữ Python chạy — hiếm dùng):
#   ./deploy/stop.sh --docker-only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

PYTHON_ONLY=false
DOCKER_ONLY=false
for arg in "$@"; do
    case $arg in
        --python-only) PYTHON_ONLY=true ;;
        --docker-only) DOCKER_ONLY=true ;;
    esac
done

PID_DIR="${PROJECT_ROOT}/.pids"

# ── Stop Python components ─────────────────────────────────────────────────────
if [[ "${DOCKER_ONLY}" == false ]]; then
    echo "Stopping Python pipeline components..."
    for name in live_pipeline flink_processor kafka_producer; do
        pid_file="${PID_DIR}/${name}.pid"
        if [[ -f "${pid_file}" ]]; then
            pid=$(cat "${pid_file}")
            if kill -0 "${pid}" 2>/dev/null; then
                echo "  Stopping ${name} (PID ${pid})..."
                kill -SIGTERM "${pid}" 2>/dev/null || true
                # Wait up to 5s for graceful shutdown
                for i in $(seq 1 10); do
                    kill -0 "${pid}" 2>/dev/null || break
                    sleep 0.5
                done
                # Force kill if still running
                if kill -0 "${pid}" 2>/dev/null; then
                    echo "  Force killing ${name}..."
                    kill -9 "${pid}" 2>/dev/null || true
                fi
            else
                echo "  ${name} not running."
            fi
            rm -f "${pid_file}"
        else
            echo "  ${name} — no PID file found."
        fi
    done
    echo "Python components stopped."
fi

# ── Stop Docker services ───────────────────────────────────────────────────────
if [[ "${PYTHON_ONLY}" == false ]]; then
    echo ""
    echo "Stopping Docker infrastructure..."
    cd "${PROJECT_ROOT}/testbed"
    docker compose down
    cd "${PROJECT_ROOT}"
    echo "Docker services stopped."
fi

echo ""
echo "PAD-ONAP pipeline stopped."
