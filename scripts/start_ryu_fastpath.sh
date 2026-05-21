#!/usr/bin/env bash
# Start the Ryu fast-path controller inside the mn-sandbox netns so that
# Mininet OVS switches (also in the sandbox) can connect to 127.0.0.1:6633.
#
# Prereqs:
#   1. scripts/start_single_server_testbed.sh has been run (sandbox exists)
#   2. pip install ryu eventlet==0.30.2 (Ryu pins old eventlet — venv recommended)
#
# Usage:
#   sudo scripts/start_ryu_fastpath.sh             # foreground
#   sudo scripts/start_ryu_fastpath.sh --daemon    # detach, write pidfile

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${PAD_SANDBOX_NS:-mn-sandbox}"
PIDFILE="/var/run/pad-ryu-fastpath.pid"
LOGFILE="${PAD_RYU_LOG:-/var/log/pad-ryu-fastpath.log}"
DAEMON=0

[[ "${1:-}" == "--daemon" ]] && DAEMON=1

# Sanity: sandbox netns must exist
if ! ip netns list | grep -q "^${NS}\b"; then
    echo "[err] netns ${NS} not found. Run scripts/start_single_server_testbed.sh first." >&2
    exit 1
fi

# Sanity: ryu-manager on PATH
if ! command -v ryu-manager >/dev/null; then
    echo "[err] ryu-manager not found. pip install ryu eventlet==0.30.2" >&2
    exit 1
fi

# Already running?
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[info] Ryu fast-path already running (pid $(cat "$PIDFILE"))" >&2
    exit 0
fi

cd "$ROOT"
export PYTHONPATH="$ROOT:${PYTHONPATH:-}"

CMD=(ip netns exec "$NS" \
     ryu-manager \
        --observe-links \
        --ofp-tcp-listen-port 6633 \
        --wsapi-host 0.0.0.0 --wsapi-port 8080 \
        pipeline.s5_fastpath.ryu_app \
        ryu.topology.switches)

if [[ $DAEMON -eq 1 ]]; then
    nohup "${CMD[@]}" >>"$LOGFILE" 2>&1 &
    echo $! >"$PIDFILE"
    echo "[ok] Ryu fast-path started, pid $(cat "$PIDFILE")"
    echo "     OF :6633  REST :8080  log $LOGFILE"
else
    echo "[info] Ryu fast-path (foreground). Ctrl+C to stop."
    exec "${CMD[@]}"
fi
