#!/usr/bin/env bash
set -Eeuo pipefail

echo "== processes =="
pgrep -af "ryu-manager" || true
pgrep -af "fat_tree_topology" || true
pgrep -af "uvicorn frontend.backend:app" || true
pgrep -af "sim_demo_state" || true

echo
echo "== tmux =="
tmux ls 2>/dev/null || true
tmux list-panes -t pad-mn -F "pad-mn pane: #{pane_pid} #{pane_current_command} dead=#{pane_dead}" 2>/dev/null || true
tmux list-panes -t pad-ui -F "pad-ui pane: #{pane_pid} #{pane_current_command} dead=#{pane_dead}" 2>/dev/null || true

echo
echo "== ryu topology =="
python3 - <<'PY'
import json, urllib.request
d = json.load(urllib.request.urlopen("http://127.0.0.1:8080/pad/topology", timeout=3))
print("switches", len(d.get("switches", [])), "links", len(d.get("links", [])), "hosts", len(d.get("hosts", [])))
PY

echo
echo "== dashboard state =="
python3 - <<'PY'
import json, urllib.request
d = json.load(urllib.request.urlopen("http://127.0.0.1:8088/api/state", timeout=3))
print("scenario", d.get("scenario"))
print("tier", d.get("active_tier"))
print("attack", d.get("attack_type"))
print("score", d.get("kpis", {}).get("attack_score"))
print("traffic_gbps", d.get("kpis", {}).get("traffic_rate_gbps"))
print("fastpath", d.get("fastpath", {}).get("last_action"), d.get("fastpath", {}).get("status"))
print("slowpath", d.get("slowpath", {}).get("stage"), d.get("slowpath", {}).get("status"))
PY
