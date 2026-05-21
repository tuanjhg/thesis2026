#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p results/fastpath_fattree/logs

sudo mn -c >/tmp/pad_mn_cleanup.log 2>&1 || true
sudo service openvswitch-switch start >/tmp/pad_ovs_start.log 2>&1 || true

if [[ "${PAD_RESTART_RYU:-1}" == "1" ]]; then
  if [[ -f /tmp/pad_ryu.pid ]]; then
    kill "$(cat /tmp/pad_ryu.pid)" 2>/dev/null || true
  fi
  pkill -f "ryu-manager --observe-links" 2>/dev/null || true
  sleep 1
fi

ts="$(date +%Y%m%d_%H%M%S)"
EVENTLET_NO_GREENDNS=yes PYTHONPATH="$ROOT" PAD_FATTREE_K=4 \
  nohup "$ROOT/.venv_wsl/bin/ryu-manager" \
    --observe-links \
    --ofp-tcp-listen-port 6633 \
    --wsapi-host 0.0.0.0 --wsapi-port 8080 \
    pipeline.s5_fastpath.ryu_app ryu.topology.switches \
    > "results/fastpath_fattree/logs/ryu_${ts}.log" 2>&1 &
echo $! >/tmp/pad_ryu.pid

for _ in $(seq 1 30); do
  if curl -s --max-time 2 http://127.0.0.1:8080/pad/stats >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -s --max-time 2 http://127.0.0.1:8080/pad/stats >/dev/null

EVENTLET_NO_GREENDNS=yes PYTHONPATH="$ROOT" \
  sudo -E "$ROOT/.venv_wsl/bin/python" \
    "$ROOT/scripts/run_fastpath_fattree_k4_report.py" --duration "${1:-5}"
