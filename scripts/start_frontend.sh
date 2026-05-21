#!/usr/bin/env bash
# Start the frontend (FastAPI + static files) on port 8088.
#
# Runs in the ROOT netns (not the sandbox) so the browser can reach it via
# the host's mgmt IP. The backend talks to Ryu over the veth-mn-in side
# (10.99.99.1 → 10.99.99.2:8080 inside the sandbox).
#
# Usage:
#   scripts/start_frontend.sh             # foreground
#   scripts/start_frontend.sh --daemon    # background, pidfile

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIDFILE="/var/run/pad-frontend.pid"
LOGFILE="${PAD_FRONTEND_LOG:-/var/log/pad-frontend.log}"
DAEMON=0

[[ "${1:-}" == "--daemon" ]] && DAEMON=1

# Ryu listens at 10.99.99.2:8080 (sandbox side of the veth pair). If your
# topology differs, override:  PAD_RYU_URL=http://x.y.z.w:8080
export PAD_RYU_URL="${PAD_RYU_URL:-http://10.99.99.2:8080}"
export PAD_PROM_URL="${PAD_PROM_URL:-http://127.0.0.1:9190}"
export PAD_SCENARIO_STATE="${PAD_SCENARIO_STATE:-/tmp/pad-onap/scenario_state.json}"
export PAD_SCENARIO_RUNNER="${PAD_SCENARIO_RUNNER:-$ROOT/scripts/run_scenario.sh}"

cd "$ROOT"

# Already running?
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[info] frontend already running (pid $(cat "$PIDFILE"))" >&2
    exit 0
fi

CMD=(python3 -m uvicorn frontend.backend:app \
        --host 0.0.0.0 --port 8088 --workers 1)

if [[ $DAEMON -eq 1 ]]; then
    nohup "${CMD[@]}" >>"$LOGFILE" 2>&1 &
    echo $! >"$PIDFILE"
    echo "[ok] frontend started, pid $(cat "$PIDFILE")"
    echo "     UI  http://<host>:8088     log $LOGFILE"
else
    echo "[info] frontend (foreground). Open http://localhost:8088"
    exec "${CMD[@]}"
fi
