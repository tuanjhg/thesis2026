#!/usr/bin/env bash
# Launch the FULL PAD-ONAP testbed — real Mininet, Ryu fast-path, demo
# dashboard, end to end. Generic over fat-tree k (2, 4, 6, 8…).
#
# Layout summary:
#   k=2  →  1 core ·  2 agg ·  2 edge ·   2 hosts  (~64 MB RAM)
#   k=4  →  4 core ·  8 agg ·  8 edge ·  16 hosts  (~256 MB RAM)
#   k=6  →  9 core · 18 agg · 18 edge ·  54 hosts  (~700 MB RAM)
#   k=8  → 16 core · 32 agg · 32 edge · 128 hosts  (~1.5 GB RAM)
#
# Prereqs:
#   sudo apt install mininet openvswitch-switch hping3 iperf3 python3-venv
#   pip install ryu==4.34 eventlet==0.30.2 webob   (separate venv recommended)
#
# Usage:
#   sudo bash scripts/start_full.sh                # k=4 (default)
#   sudo bash scripts/start_full.sh --k 2          # smallest topology
#   sudo bash scripts/start_full.sh --k 4 --auto S3
#   sudo bash scripts/start_full.sh --k 4 --no-mininet   # skip Mininet (sim only)

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "[err] sudo required (Mininet needs root)"; exit 1; }

# ── arg parsing ──────────────────────────────────────────────────────────────
K=4
NO_MININET=0
DEMO_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --k)          K="$2"; shift 2;;
        --no-mininet) NO_MININET=1; shift;;
        --auto)       DEMO_ARGS+=("--auto" "$2"); shift 2;;
        *)            DEMO_ARGS+=("$1"); shift;;
    esac
done

if ! [[ "$K" =~ ^[0-9]+$ ]] || (( K < 2 )) || (( K % 2 != 0 )); then
    echo "[err] --k must be an even integer >= 2 (got $K)"; exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PAD_K="$K"
PIDDIR="/tmp/pad-onap"
mkdir -p "$PIDDIR"

N_CORE=$(( K * K / 4 ))
N_AGG=$(( K * K / 2 ))
N_EDGE=$N_AGG
N_HOSTS=$(( K * (K / 2) * (K / 2) ))

cat <<EOF
┌─────────────────────────────────────────────────────────────────┐
│  PAD-ONAP FULL TESTBED — fat-tree k=$K                          │
├─────────────────────────────────────────────────────────────────┤
│  $N_CORE core  ·  $N_AGG agg  ·  $N_EDGE edge  ·  $N_HOSTS hosts
│  attacker = h0     victim = h$(( N_HOSTS - 1 ))
$([ $NO_MININET -eq 1 ] && echo "│  Mininet     : SKIPPED (--no-mininet)" || echo "│  Mininet     : ENABLED")
└─────────────────────────────────────────────────────────────────┘
EOF
echo

if [[ $NO_MININET -eq 0 ]]; then
    echo "[1/5] dressing sandbox netns + private OVS daemon"
    bash "$ROOT/scripts/start_single_server_testbed.sh" 2>/dev/null || true

    echo "[2/5] starting Ryu fast-path controller (in sandbox)"
    bash "$ROOT/scripts/start_ryu_fastpath.sh" --daemon

    echo "[3/5] starting Mininet fat-tree k=$K (in sandbox)"
    ip netns exec mn-sandbox env OVS_RUNDIR=/var/run/openvswitch-mn \
        python3 "$ROOT/testbed/mininet/fat_tree_topology.py" \
            --k "$K" --remote \
        >"$PIDDIR/mininet.log" 2>&1 &
    echo $! >"$PIDDIR/mininet.pid"
    sleep 3

    echo "[4/5] verifying topology came up"
    SW_COUNT=$(ovs-vsctl --db=unix:/var/run/openvswitch-mn/db.sock list-br 2>/dev/null | wc -l)
    echo "    $SW_COUNT OVS bridges in sandbox (expected $((N_CORE + N_AGG + N_EDGE)))"
fi

echo "[5/5] launching frontend + simulator (k=$K)"
echo
echo "    Dashboard:   http://localhost:8088"
echo "    Mininet log: tail -f $PIDDIR/mininet.log"
echo

cleanup() {
    echo
    echo "[cleanup] stopping testbed components"
    [[ -f "$PIDDIR/mininet.pid" ]] && {
        kill "$(cat "$PIDDIR/mininet.pid")" 2>/dev/null
        rm -f "$PIDDIR/mininet.pid"
    }
    [[ -f "$PIDDIR/backend.pid" ]] && {
        kill "$(cat "$PIDDIR/backend.pid")" 2>/dev/null
        rm -f "$PIDDIR/backend.pid"
    }
    [[ $NO_MININET -eq 0 ]] && ip netns exec mn-sandbox mn -c 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM

# Hand off to the standard demo launcher (propagates PAD_K)
exec env PAD_K="$K" bash "$ROOT/scripts/start_demo_wsl.sh" "${DEMO_ARGS[@]+"${DEMO_ARGS[@]}"}"
