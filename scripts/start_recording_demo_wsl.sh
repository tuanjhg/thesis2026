#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PIDDIR="/tmp/pad-onap"
mkdir -p "$PIDDIR"

if [[ -f "$PIDDIR/backend.pid" ]]; then
  kill "$(cat "$PIDDIR/backend.pid")" 2>/dev/null || true
  rm -f "$PIDDIR/backend.pid"
fi
pkill -f "uvicorn frontend.backend:app" 2>/dev/null || true
tmux kill-session -t pad-ui 2>/dev/null || true

PY="$ROOT/.venv_ubuntu2204/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$ROOT/.venv_wsl/bin/python"
fi
if [[ ! -x "$PY" ]]; then
  echo "[err] no WSL Python venv found (.venv_ubuntu2204 or .venv_wsl)" >&2
  exit 1
fi

export PAD_K="${PAD_K:-4}"
export PAD_RYU_URL="${PAD_RYU_URL:-http://127.0.0.1:8080}"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

echo "[1/3] starting FastAPI dashboard backend on :8088"
nohup env PAD_K="$PAD_K" PAD_RYU_URL="$PAD_RYU_URL" PYTHONPATH="$PYTHONPATH" \
  "$PY" -m uvicorn frontend.backend:app --host 0.0.0.0 --port 8088 --workers 1 \
  >"$PIDDIR/backend.log" 2>&1 &
echo $! >"$PIDDIR/backend.pid"

for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8088/api/state >/dev/null; then
    break
  fi
  sleep 0.5
done

curl -sf http://127.0.0.1:8088/api/state >/dev/null

echo "[2/3] starting demo state simulator in tmux session pad-ui"
tmux new-session -d -s pad-ui \
  "bash '$ROOT/scripts/run_demo_simulator_wsl.sh' --auto S3"

echo "[3/3] dashboard ready"
echo "  UI:          http://localhost:8088"
echo "  Backend log: tail -f $PIDDIR/backend.log"
echo "  Simulator:   tmux attach -t pad-ui"
echo "  Mininet:     tmux attach -t pad-mn"
echo "  Ryu REST:    $PAD_RYU_URL"
