#!/usr/bin/env bash
# Bootstrap PAD-ONAP testbed for "local Mininet → remote K8s+ONAP" mode.
# Run this on the K8s SERVER, once. Idempotent — safe to re-run.
#
# What it does:
#   1. Discovers the public node IP that the Mininet VM will reach.
#   2. Renders kafka-pad-onap.yaml with that IP as the EXTERNAL advertised
#      listener (the #1 cause of "client connects but produce times out").
#   3. Applies Kafka + NodePort manifests in namespace `pad-onap`.
#   4. Applies the metrics NodePort so the Mininet VM can read tier decisions.
#   5. Restarts pad-onap-pipeline so it re-reads the ConfigMap.
#   6. Smoke-tests the broker from inside the cluster and reports the
#      exact NodePort URL the Mininet VM should use.
#
# Prereqs: kubectl context points to the cluster that runs ONAP + pad-onap.
#          onap/k8s/pad-onap-deployment.yaml already applied at least once.
#
# Usage:
#   chmod +x onap/scripts/setup_remote_testbed.sh
#   ./onap/scripts/setup_remote_testbed.sh                  # auto-detect node IP
#   PAD_NODE_PUBLIC_IP=10.50.0.1 ./onap/scripts/setup_remote_testbed.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

K8S_DIR="${PROJECT_ROOT}/onap/k8s"
PAD_NS="pad-onap"

echo "════════════════════════════════════════════════════════════"
echo "  PAD-ONAP Remote Testbed Bootstrap"
echo "════════════════════════════════════════════════════════════"

# ── 1. Detect node IP that external clients reach ─────────────────────────────
if [[ -z "${PAD_NODE_PUBLIC_IP:-}" ]]; then
    PAD_NODE_PUBLIC_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' 2>/dev/null || true)"
    if [[ -z "${PAD_NODE_PUBLIC_IP}" ]]; then
        PAD_NODE_PUBLIC_IP="$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
    fi
fi

if [[ -z "${PAD_NODE_PUBLIC_IP}" ]]; then
    echo "[ERROR] Không xác định được node IP. Set PAD_NODE_PUBLIC_IP=<ip> rồi chạy lại."
    exit 1
fi

echo "[1/6] Node IP for external clients: ${PAD_NODE_PUBLIC_IP}"

# ── 2. Render Kafka manifest with the right advertised listener ───────────────
TMPDIR="$(mktemp -d)"
trap "rm -rf '${TMPDIR}'" EXIT
RENDERED="${TMPDIR}/kafka-pad-onap.rendered.yaml"

sed "s|<NODE_PUBLIC_IP>|${PAD_NODE_PUBLIC_IP}|g" \
    "${K8S_DIR}/kafka-pad-onap.yaml" > "${RENDERED}"

echo "[2/6] Rendered Kafka manifest with EXTERNAL://${PAD_NODE_PUBLIC_IP}:30992"

# ── 3. Ensure pad-onap namespace exists ───────────────────────────────────────
if ! kubectl get ns "${PAD_NS}" >/dev/null 2>&1; then
    echo "[3/6] Creating namespace ${PAD_NS}"
    kubectl create namespace "${PAD_NS}"
else
    echo "[3/6] Namespace ${PAD_NS} already exists"
fi

# ── 4. Apply Kafka + NodePort manifests ───────────────────────────────────────
echo "[4/6] Applying Kafka manifests..."
kubectl apply -f "${RENDERED}"
kubectl apply -f "${K8S_DIR}/pad-onap-metrics-nodeport.yaml"

echo "      Waiting for Kafka pod to become Ready (max 180s)..."
kubectl -n "${PAD_NS}" rollout status statefulset/kafka --timeout=180s

# ── 5. Restart pipeline so it picks up the new in-cluster Kafka ───────────────
if kubectl -n "${PAD_NS}" get deploy/pad-onap-pipeline >/dev/null 2>&1; then
    echo "[5/6] Restarting pad-onap-pipeline..."
    kubectl -n "${PAD_NS}" rollout restart deploy/pad-onap-pipeline
    kubectl -n "${PAD_NS}" rollout status deploy/pad-onap-pipeline --timeout=120s
else
    echo "[5/6] pad-onap-pipeline Deployment chưa được apply — bỏ qua restart."
    echo "      Sau khi apply, chạy:"
    echo "        kubectl -n ${PAD_NS} rollout restart deploy/pad-onap-pipeline"
fi

# ── 6. Smoke-test broker from inside the cluster ──────────────────────────────
echo "[6/6] Smoke-testing Kafka broker from inside the cluster..."
kubectl -n "${PAD_NS}" run kafka-cli-$$ --rm -i --restart=Never --quiet \
    --image=apache/kafka:3.7.0 -- \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server kafka.${PAD_NS}.svc.cluster.local:9092 \
    --list || {
    echo "[ERROR] Internal broker probe failed. Check:"
    echo "  kubectl -n ${PAD_NS} logs statefulset/kafka --tail=50"
    exit 1
}

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✓ Remote testbed ready"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "From the Mininet VM, use these endpoints:"
echo ""
echo "  export PAD_REMOTE_KAFKA=${PAD_NODE_PUBLIC_IP}:30992"
echo "  export PAD_REMOTE_METRICS=http://${PAD_NODE_PUBLIC_IP}:30292/metrics"
echo ""
echo "Smoke-test from the Mininet VM:"
echo "  nc -zv ${PAD_NODE_PUBLIC_IP} 30992"
echo "  curl -s \$PAD_REMOTE_METRICS | head"
echo ""
echo "Run a scenario from the Mininet VM (after setup_mininet_vm.sh):"
echo "  sudo -E python3 testbed/netflow_e2e_pipeline.py \\"
echo "       --mode ai --remote-pipeline \\"
echo "       --broker \$PAD_REMOTE_KAFKA \\"
echo "       --collector-kafka \$PAD_REMOTE_KAFKA \\"
echo "       --remote-metrics-url \$PAD_REMOTE_METRICS \\"
echo "       --skip-kafka-setup \\"
echo "       --duration 60"
