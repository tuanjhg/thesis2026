#!/usr/bin/env bash
# One-shot launcher for the PAD-ONAP demo dashboard on WSL2 / Linux.
# No Mininet / Kafka / Ryu / ONAP needed — the simulator feeds mock state.
#
# Usage:
#   bash scripts/start_demo_wsl.sh           # interactive (UI picks scenario)
#   bash scripts/start_demo_wsl.sh --auto S3 # auto-loop S3
#
# Stop: Ctrl+C (or `kill $(cat /tmp/pad-onap/*.pid)`)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"                                 # so uvicorn's relative imports work
PIDDIR="/tmp/pad-onap"
mkdir -p "$PIDDIR"

# Kill any stale backend from previous runs
if [[ -f "$PIDDIR/backend.pid" ]]; then
    kill "$(cat "$PIDDIR/backend.pid")" 2>/dev/null || true
    rm -f "$PIDDIR/backend.pid"
fi

# 1. Sanity: Python + venv
if [[ ! -d "$ROOT/.venv" ]]; then
    echo "[setup] creating venv .venv"
    python3 -m venv "$ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"

# 2. Install deps (idempotent)
if ! python -c "import fastapi, uvicorn, httpx" 2>/dev/null; then
    echo "[setup] installing frontend requirements"
    pip install -q -r "$ROOT/frontend/requirements.txt"
fi

export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

# 3. Start backend (background)
echo "[1/2] launching FastAPI backend on :8088"
nohup python -m uvicorn frontend.backend:app --host 0.0.0.0 --port 8088 \
      >"$PIDDIR/backend.log" 2>&1 &
echo $! >"$PIDDIR/backend.pid"

# Wait briefly for backend to come up
for _ in 1 2 3 4 5; do
    if curl -sf http://127.0.0.1:8088/api/state >/dev/null; then break; fi
    sleep 0.5
done

# 4. Start simulator (foreground so Ctrl+C cleans up)
echo "[2/2] launching demo state simulator"
echo
echo "    Open the dashboard at  http://localhost:8088"
echo "    Logs:  tail -f $PIDDIR/backend.log"
echo

cleanup() {
    kill "$(cat "$PIDDIR/backend.pid")" 2>/dev/null || true
    rm -f "$PIDDIR/backend.pid"
    exit 0
}
trap cleanup INT TERM

python "$ROOT/scripts/sim_demo_state.py" "$@"
cleanup
