#!/usr/bin/env bash
# Bootstrap PAD-ONAP pipeline Deployment on the K8s server.
# Run on the K8s server (where kubectl + docker/k3s/containerd live).
#
# What it does (idempotent — safe to re-run):
#   1. Build pad-onap/pipeline:1.0.0 from Dockerfile.pipeline.
#   2. Detect the K8s runtime (k3s | minikube | containerd | docker daemon)
#      and load the image so the kubelet can pull it without a private
#      registry.
#   3. Apply onap/k8s/pad-onap-deployment.yaml (Namespace, ConfigMap,
#      Secret, PVC, ServiceAccount, RBAC, Deployment, Service, HPA).
#   4. Copy pad_onap_v3/models/ into the PVC via a helper Pod
#      (`kubectl cp` requires an existing Pod, so we use a busybox
#      sidecar mounting the same PVC).
#   5. Wait for Deployment rollout and report readiness.
#
# Usage:
#   chmod +x onap/scripts/bootstrap_pad_pipeline.sh
#   ./onap/scripts/bootstrap_pad_pipeline.sh
#
#   # If using a private registry instead of local image load:
#   PAD_IMAGE=registry.example.com/pad-onap/pipeline:1.0.0 \
#     PAD_USE_REGISTRY=true \
#     ./onap/scripts/bootstrap_pad_pipeline.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

PAD_IMAGE="${PAD_IMAGE:-pad-onap/pipeline:1.0.0}"
PAD_USE_REGISTRY="${PAD_USE_REGISTRY:-false}"
PAD_NS="pad-onap"
MODEL_DIR="${PROJECT_ROOT}/pad_onap_v3/models"

echo "════════════════════════════════════════════════════════════"
echo "  PAD-ONAP Pipeline Bootstrap"
echo "  Image:     ${PAD_IMAGE}"
echo "  Registry?: ${PAD_USE_REGISTRY}"
echo "  Models:    ${MODEL_DIR}"
echo "════════════════════════════════════════════════════════════"

# ── Step 0: Sanity checks ─────────────────────────────────────────────────────
command -v kubectl >/dev/null || { echo "[ERROR] kubectl not in PATH"; exit 1; }
[[ -f "${PROJECT_ROOT}/Dockerfile.pipeline" ]] \
    || { echo "[ERROR] Dockerfile.pipeline not found in ${PROJECT_ROOT}"; exit 1; }
[[ -f "${PROJECT_ROOT}/onap/k8s/pad-onap-deployment.yaml" ]] \
    || { echo "[ERROR] pad-onap-deployment.yaml not found"; exit 1; }
[[ -d "${MODEL_DIR}" ]] \
    || { echo "[ERROR] Model directory not found: ${MODEL_DIR}"; exit 1; }

# Verify required model files exist
for f in xgboost_v3.json transformer_v3.pt scaler.pkl xgb_label_map.json; do
    [[ -f "${MODEL_DIR}/${f}" ]] \
        || { echo "[ERROR] Missing model file: ${MODEL_DIR}/${f}"; exit 1; }
done
echo "[0/5] All required files present ✓"

# ── Step 1: Build image ───────────────────────────────────────────────────────
echo ""
echo "[1/5] Building image ${PAD_IMAGE}"
docker build -t "${PAD_IMAGE}" -f Dockerfile.pipeline . \
    || { echo "[ERROR] docker build failed"; exit 1; }
echo "      ✓ Built ${PAD_IMAGE}"

# ── Step 2: Make image visible to kubelet ─────────────────────────────────────
echo ""
echo "[2/5] Loading image into K8s runtime..."

if [[ "${PAD_USE_REGISTRY}" == "true" ]]; then
    echo "      Pushing to registry..."
    docker push "${PAD_IMAGE}" || { echo "[ERROR] docker push failed"; exit 1; }
    echo "      ✓ Pushed (kubelet will pull on Pod creation)"
else
    # Auto-detect runtime
    if command -v k3s >/dev/null && systemctl is-active --quiet k3s 2>/dev/null; then
        echo "      Detected: k3s"
        TMP_TAR="/tmp/pad-pipeline-$$.tar"
        docker save "${PAD_IMAGE}" -o "${TMP_TAR}"
        sudo k3s ctr images import "${TMP_TAR}"
        rm -f "${TMP_TAR}"
    elif command -v minikube >/dev/null && minikube status >/dev/null 2>&1; then
        echo "      Detected: minikube"
        minikube image load "${PAD_IMAGE}"
    elif command -v ctr >/dev/null \
            && sudo ctr -n k8s.io version >/dev/null 2>&1; then
        echo "      Detected: containerd (kubeadm)"
        TMP_TAR="/tmp/pad-pipeline-$$.tar"
        docker save "${PAD_IMAGE}" -o "${TMP_TAR}"
        sudo ctr -n k8s.io images import "${TMP_TAR}"
        rm -f "${TMP_TAR}"
    else
        echo "[WARN] Couldn't auto-detect K8s runtime."
        echo "       Image stays in local Docker daemon — kubelet may"
        echo "       ImagePullBackOff if it uses a different runtime."
        echo "       Manually load with one of:"
        echo "         sudo k3s ctr images import <tar>"
        echo "         sudo ctr -n k8s.io images import <tar>"
        echo "         minikube image load ${PAD_IMAGE}"
    fi
    echo "      ✓ Image loaded"
fi

# ── Step 3: Apply manifest ────────────────────────────────────────────────────
echo ""
echo "[3/5] Applying onap/k8s/pad-onap-deployment.yaml"
kubectl apply -f onap/k8s/pad-onap-deployment.yaml
echo "      ✓ Applied"

# ── Step 4: Copy models into PVC ──────────────────────────────────────────────
echo ""
echo "[4/5] Copying models into PVC pad-onap-models-pvc"

# Helper Pod that mounts the same PVC
HELPER_POD="model-loader-$$"
kubectl apply -n "${PAD_NS}" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${HELPER_POD}
  labels:
    role: model-loader
spec:
  restartPolicy: Never
  containers:
    - name: loader
      image: busybox:1.36
      command: ["sh", "-c", "sleep 600"]
      volumeMounts:
        - name: models
          mountPath: /models
  volumes:
    - name: models
      persistentVolumeClaim:
        claimName: pad-onap-models-pvc
EOF

echo "      Waiting for helper Pod ${HELPER_POD} Ready..."
kubectl wait -n "${PAD_NS}" --for=condition=Ready pod/${HELPER_POD} --timeout=120s

echo "      Copying $(ls ${MODEL_DIR} | wc -l) files into PVC..."
for f in "${MODEL_DIR}"/*; do
    base="$(basename "${f}")"
    kubectl cp -n "${PAD_NS}" "${f}" "${HELPER_POD}:/models/${base}"
    echo "        ✓ ${base}"
done

# Verify
echo "      PVC contents after copy:"
kubectl exec -n "${PAD_NS}" "${HELPER_POD}" -- ls -la /models | sed 's/^/        /'

# Cleanup helper
kubectl delete pod -n "${PAD_NS}" "${HELPER_POD}" --now >/dev/null
echo "      ✓ Models loaded; helper Pod removed"

# ── Step 5: Restart Deployment to mount fresh PVC contents ────────────────────
echo ""
echo "[5/5] Restarting pad-onap-pipeline Deployment..."
kubectl rollout restart deploy/pad-onap-pipeline -n "${PAD_NS}"
kubectl rollout status  deploy/pad-onap-pipeline -n "${PAD_NS}" --timeout=180s
echo "      ✓ Deployment ready"

# ── Final report ──────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✓ PAD-ONAP pipeline deployed and ready"
echo "════════════════════════════════════════════════════════════"
echo ""
kubectl get pods -n "${PAD_NS}"
echo ""
echo "Live log tail (Ctrl-C to stop):"
echo "  kubectl logs -f -n ${PAD_NS} deploy/pad-onap-pipeline"
echo ""
echo "Next step — wire up Kafka NodePort + metrics NodePort:"
echo "  PAD_NODE_PUBLIC_IP=<ip> ./onap/scripts/setup_remote_testbed.sh"
