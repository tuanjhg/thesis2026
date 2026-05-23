#!/usr/bin/env bash
# Launch the PAD-ONAP demo dashboard with fat-tree k=2 sizing.
#
# k=2 fat-tree has only 2 hosts (h0, h1) and proportionally lower attack
# rates, so it's the lightest demo configuration possible. Useful for:
#   · low-spec VMs / laptops
#   · quick screenshots of the dashboard
#   · ONAP integration testing where the topology doesn't matter
#
# Usage:
#   bash scripts/start_demo_k2.sh             # interactive (UI picks scenario)
#   bash scripts/start_demo_k2.sh --auto S3   # auto-loop S3 every 45s

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PAD_K=2

echo "[demo-k2] fat-tree k=2: 1 core · 2 agg · 2 edge · 2 hosts (h0, h1)"
echo "[demo-k2] PAD_K=$PAD_K  →  rate targets scaled to 0.4× of k=4"
echo

exec bash "$ROOT/scripts/start_demo_wsl.sh" "$@"
