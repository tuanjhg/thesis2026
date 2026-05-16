#!/usr/bin/env bash
# Setup script for the LOCAL Mininet VM (laptop / dev box) when running
# in remote-pipeline mode against a K8s + ONAP server.
#
# Idempotent — safe to re-run.
#
# Usage:
#   chmod +x testbed/setup_mininet_vm.sh
#   PAD_NODE_PUBLIC_IP=10.50.0.1 ./testbed/setup_mininet_vm.sh
#
# Or, if you've sourced .env from the server:
#   source .env && ./testbed/setup_mininet_vm.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "════════════════════════════════════════════════════════════"
echo "  PAD-ONAP Mininet VM Setup (remote-pipeline mode)"
echo "════════════════════════════════════════════════════════════"

# ── 1. Resolve remote server IP ───────────────────────────────────────────────
if [[ -z "${PAD_NODE_PUBLIC_IP:-}" ]]; then
    echo "[ERROR] Set PAD_NODE_PUBLIC_IP=<server-ip> trước khi chạy."
    echo "        Đây là IP server từ Mininet VM nhìn thấy."
    exit 1
fi
echo "[1/6] Remote server IP: ${PAD_NODE_PUBLIC_IP}"

# ── 2. Install system deps (Mininet + traffic tools) ──────────────────────────
echo "[2/6] Installing Mininet + softflowd + traffic tools..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    mininet openvswitch-switch \
    softflowd iperf iperf3 hping3 curl \
    netcat-openbsd \
    python3-venv python3-pip \
    fuser psmisc chrony

# ── 3. Start OVS, sync clock ──────────────────────────────────────────────────
echo "[3/6] Starting OVS + chrony..."
sudo service openvswitch-switch start
sudo systemctl enable --now chrony
sudo chronyc -a 'makestep' >/dev/null || true

# ── 4. Hardening: prevent Mininet attack traffic from leaking ────────────────
echo "[4/6] Hardening: rp_filter on, block Mininet egress on real NICs..."
sudo sysctl -wq net.ipv4.ip_forward=0
sudo sysctl -wq net.ipv4.conf.all.rp_filter=1
sudo sysctl -wq net.ipv4.conf.default.rp_filter=1
sudo sysctl -wq net.netfilter.nf_conntrack_max=2000000 || true

for nic in $(ls /sys/class/net | grep -vE '^(lo|veth|ovs|tun|docker|cni|wg)'); do
    if ! sudo iptables -C OUTPUT -s 10.0.0.0/16 -o "$nic" -j DROP 2>/dev/null; then
        sudo iptables -I OUTPUT -s 10.0.0.0/16 -o "$nic" -j DROP
    fi
    if ! sudo iptables -C FORWARD -s 10.0.0.0/16 -o "$nic" -j DROP 2>/dev/null; then
        sudo iptables -I FORWARD -s 10.0.0.0/16 -o "$nic" -j DROP
    fi
done

# ── 5. Install Python deps into system Python (needed by sudo) ───────────────
echo "[5/6] Installing Python deps for system python3 (sudo path)..."
sudo /usr/bin/python3 -m pip install -q --upgrade pip
sudo /usr/bin/python3 -m pip install -q \
    kafka-python==2.0.2 numpy matplotlib

# Link mininet module into venv if any local venv exists (optional)
for vpy in "${PROJECT_ROOT}"/.venv/lib/python3*/site-packages; do
    [[ -d "$vpy" ]] && ln -sfn /usr/lib/python3/dist-packages/mininet "$vpy/mininet" || true
done

# ── 6. Probe remote endpoints ─────────────────────────────────────────────────
echo "[6/6] Probing remote Kafka + metrics endpoints..."
KAFKA_EP="${PAD_NODE_PUBLIC_IP}:30992"
METRICS_EP="http://${PAD_NODE_PUBLIC_IP}:30292/metrics"

if nc -zv -w 3 "${PAD_NODE_PUBLIC_IP}" 30992 2>&1 | grep -qiE 'succeeded|open'; then
    echo "    ✓ Kafka TCP ${KAFKA_EP} reachable"
else
    echo "    ✗ Kafka TCP ${KAFKA_EP} NOT reachable — check server firewall."
    exit 1
fi

if curl -fsS --max-time 5 "${METRICS_EP}" | head -1 | grep -q '^#'; then
    echo "    ✓ Metrics endpoint ${METRICS_EP} reachable"
else
    echo "    ⚠ Metrics endpoint ${METRICS_EP} reachable but no Prometheus output."
    echo "      Pod pad-onap-pipeline có thể chưa Ready. Check trên server:"
    echo "        kubectl -n pad-onap get pods"
fi

# Probe Kafka protocol-level (the listener fix verification)
python3 - <<EOF
from kafka import KafkaProducer
try:
    p = KafkaProducer(bootstrap_servers=['${KAFKA_EP}'],
                      request_timeout_ms=5000, max_block_ms=5000)
    parts = p.partitions_for('pad.telemetry.raw')
    print(f"    ✓ Kafka protocol-level OK; partitions = {parts}")
    p.close(timeout=2)
except Exception as e:
    print(f"    ✗ Kafka protocol-level FAILED: {e}")
    print("      Lỗi này thường là EXTERNAL advertised listener sai trên server.")
    print("      Trên server: PAD_NODE_PUBLIC_IP=${PAD_NODE_PUBLIC_IP} ./onap/scripts/setup_remote_testbed.sh")
    raise SystemExit(1)
EOF

# ── Persist exports ───────────────────────────────────────────────────────────
cat > "${PROJECT_ROOT}/testbed/.env.remote" <<EOF
# Sourced before invoking netflow_e2e_pipeline.py --remote-pipeline
export PAD_NODE_PUBLIC_IP=${PAD_NODE_PUBLIC_IP}
export PAD_REMOTE_KAFKA=${KAFKA_EP}
export PAD_REMOTE_METRICS=${METRICS_EP}
EOF

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✓ Mininet VM ready for remote-pipeline mode"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Source the env, then launch a scenario:"
echo ""
echo "  source testbed/.env.remote"
echo "  sudo -E python3 testbed/netflow_e2e_pipeline.py \\"
echo "       --mode ai --remote-pipeline \\"
echo "       --broker \$PAD_REMOTE_KAFKA \\"
echo "       --collector-kafka \$PAD_REMOTE_KAFKA \\"
echo "       --remote-metrics-url \$PAD_REMOTE_METRICS \\"
echo "       --skip-kafka-setup \\"
echo "       --duration 60"
