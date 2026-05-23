#!/usr/bin/env bash
# Launch the FULL PAD-ONAP testbed with fat-tree k=2 — real Mininet,
# Ryu fast-path, Kafka, and the demo dashboard, end to end.
#
# Layout for k=2:
#   1 core   (c1)
#   2 agg    (a0_0, a1_0)
#   2 edge   (e0_0, e1_0)
#   2 hosts  (h0 = attacker, h1 = victim)
#
# Resource cost vs k=4:
#   ~ 25% RAM, ~ 25% CPU, ~ 4× faster ping-all / topology bring-up.
#
# Prereqs:
#   sudo apt install mininet openvswitch-switch hping3 iperf3 python3-venv
#   pip install ryu==4.34 eventlet==0.30.2 webob  (in a separate venv)
#
# Usage:
#   sudo bash scripts/start_full_k2.sh                # interactive
#   sudo bash scripts/start_full_k2.sh --auto S3      # auto-loop scenario S3

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[err] sudo required (Mininet needs root)"; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PAD_K=2
PIDDIR="/tmp/pad-onap"
mkdir -p "$PIDDIR"

echo "[1/5] dressing sandbox netns + private OVS daemon"
bash "$ROOT/scripts/start_single_server_testbed.sh" || true

echo "[2/5] starting Ryu fast-path controller (in sandbox)"
bash "$ROOT/scripts/start_ryu_fastpath.sh" --daemon

echo "[3/5] starting Mininet fat-tree k=2 (in sandbox)"
ip netns exec mn-sandbox env OVS_RUNDIR=/var/run/openvswitch-mn \
    python3 "$ROOT/testbed/mininet/fat_tree_topology.py" --k 2 --remote \
    >"$PIDDIR/mininet.log" 2>&1 &
MN_PID=$!
echo "$MN_PID" >"$PIDDIR/mininet.pid"
sleep 3

# Verify the topology came up
echo "[4/5] verifying topology"
ovs-vsctl --db=unix:/var/run/openvswitch-mn/db.sock list-br | head -5
curl -sf http://10.99.99.2:8080/pad/topology >/dev/null \
    && echo "    Ryu sees $(curl -s http://10.99.99.2:8080/pad/topology |
                            python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d[\"switches\"]),\"switches\")')"

echo "[5/5] launching frontend + simulator (k=2)"
echo
echo "    Open the dashboard at  http://localhost:8088"
echo "    Mininet log:           tail -f $PIDDIR/mininet.log"
echo

cleanup() {
    echo "[cleanup] tearing down…"
    [[ -f "$PIDDIR/mininet.pid" ]] && kill "$(cat "$PIDDIR/mininet.pid")" 2>/dev/null
    [[ -f "$PIDDIR/backend.pid" ]] && kill "$(cat "$PIDDIR/backend.pid")" 2>/dev/null
    ip netns exec mn-sandbox mn -c 2>/dev/null || true
    rm -f "$PIDDIR/mininet.pid" "$PIDDIR/backend.pid"
    exit 0
}
trap cleanup INT TERM

# Hand off to the standard demo launcher (which propagates PAD_K)
exec env PAD_K=2 bash "$ROOT/scripts/start_demo_wsl.sh" "$@"
