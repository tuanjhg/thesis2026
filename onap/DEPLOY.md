# PAD-ONAP — Real ONAP Deployment Guide

> **Trạng thái hiện tại:** Stub mode (PAD_ONAP_STUB=true)  
> **Mục tiêu:** Chuyển sang real ONAP với PAD_ONAP_STUB=false

---

## Tổng quan: Những gì cần làm

```
Bước 1: Chuẩn bị infrastructure (K8s cluster)
Bước 2: Cài ONAP OOM (chỉ các component cần)
Bước 3: Đăng ký VNF vào ONAP SDC catalog
Bước 4: Tạo CLAMP Closed Loop
Bước 5: Deploy PAD-ONAP pipeline lên K8s
Bước 6: Pre-flight check
Bước 7: Chuyển sang real mode và test
```

---

## Yêu cầu phần cứng tối thiểu

| Component | RAM | CPU | Disk |
|-----------|-----|-----|------|
| ONAP OOM (minimal) | 64 GB | 16 cores | 200 GB |
| PAD-ONAP pipeline | 8 GB | 4 cores | 10 GB |
| Kubernetes overhead | 4 GB | 2 cores | 50 GB |
| **Tổng** | **76 GB** | **22 cores** | **260 GB** |

> Single-node dev: 64 GB RAM, 16 CPU là vừa đủ với `values-override.yaml`

---

## Bước 1: Chuẩn bị Kubernetes Cluster

```bash
# Option A: Minikube (dev/test, single node)
minikube start \
  --cpus 16 \
  --memory 65536 \
  --disk-size 300g \
  --driver docker \
  --kubernetes-version v1.27.0

# Option B: kubeadm (production-like)
# Yêu cầu Ubuntu 22.04 + kubeadm + flannel CNI

# Verify
kubectl get nodes
kubectl top nodes
```

---

## Bước 2: Cài ONAP OOM

```bash
# 1. Clone OOM
git clone https://gerrit.onap.org/r/oom --branch montreal
cd oom/kubernetes

# 2. Cài cert-manager và strimzi (Kafka)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
kubectl apply -f https://strimzi.io/install/latest?namespace=onap

# 3. Cài ONAP với profile minimal (chỉ SO + DMaaP + Policy + CLAMP)
helm repo add onap https://nexus3.onap.org/repository/onap-helm-release/
helm repo update

helm install onap onap \
  --namespace onap \
  --create-namespace \
  --timeout 30m \
  --values ../../onap/values-override.yaml

# 4. Theo dõi tiến trình (~20-30 phút)
watch kubectl get pods -n onap

# 5. Verify SO health
kubectl port-forward svc/so 8080:8080 -n onap &
curl http://localhost:8080/manage/health
```

---

## Bước 3: Đăng ký VNF vào ONAP SDC

### 3.1 Build VNF Docker images

```bash
# Build tất cả VNF images
docker build -t pad-vnf-ratelimiter:latest docker/vnf-ratelimiter/
docker build -t pad-vnf-scrubber:latest    docker/vnf-scrubber/
docker build -t pad-vnf-blackhole:latest   docker/vnf-blackhole/

# Push lên registry (nếu dùng private registry)
docker tag pad-vnf-ratelimiter:latest registry.example.com/pad-onap/ratelimiter:1.0.0
docker push registry.example.com/pad-onap/ratelimiter:1.0.0
```

### 3.2 Upload VNFD lên SDC (hoặc dùng SO API trực tiếp)

**Option A: Upload qua SDC UI**
```
1. Mở http://<node-ip>:30200  (SDC Portal)
2. Login: cs0008 / demo123456!
3. Home → Add VSP → Upload CSAR
4. Upload từng file:
   - onap/vnfd/vnfd-ratelimiter-v1.yaml
   - onap/vnfd/vnfd-scrubber-v1.yaml
   - onap/vnfd/vnfd-blackhole-v1.yaml
5. Submit for Testing → Approve → Distribute
```

**Option B: Pre-load qua SO API (faster cho testbed)**
```bash
# SO sẽ tự nhận model info từ VNF catalog
# Cách nhanh hơn: seed trực tiếp vào SO database
kubectl exec -n onap deploy/so -- \
  curl -X POST http://localhost:8080/onap/so/infra/vnfs/v7 \
  -H "Content-Type: application/json" \
  -u so_admin:demo123456! \
  -d @onap/vnfd/so-preload-ratelimiter.json
```

---

## Bước 4: Import CLAMP Closed Loop Template

```bash
# Port-forward CLAMP
kubectl port-forward svc/clamp 2443:2443 -n onap &

# Import loop template
curl -k -X POST \
  https://localhost:2443/restservices/clds/v2/loop/import/PAD-ONAP-DDoS-ClosedLoop \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d @onap/clamp/pad-onap-loop-template.json

# Activate loop
curl -k -X PUT \
  https://localhost:2443/restservices/clds/v2/loop/deploy/PAD-ONAP-DDoS-ClosedLoop \
  -u admin:password
```

---

## Bước 5: Build và Deploy PAD-ONAP Pipeline

### 5.1 Build Docker image cho pipeline

```dockerfile
# Dockerfile.pipeline
FROM python:3.10-slim

WORKDIR /app
COPY requirements-pipeline.txt .
RUN pip install --no-cache-dir -r requirements-pipeline.txt

COPY pipeline/ pipeline/
COPY models_v2/ models_v2/

EXPOSE 9292
CMD ["python", "-m", "pipeline.s4_orchestration.orchestrator", \
     "--source", "http", "--max-windows", "0"]
```

```bash
docker build -t pad-onap/pipeline:1.0.0 -f Dockerfile.pipeline .
```

### 5.2 Copy models vào PVC

```bash
# Tạo namespace
kubectl apply -f onap/k8s/pad-onap-deployment.yaml

# Copy models
kubectl cp models_v2/ \
  pad-onap/$(kubectl get pod -n pad-onap -l app=pad-onap-pipeline -o name | head -1):/app/models_v2/
```

### 5.3 Deploy

```bash
kubectl apply -f onap/k8s/pad-onap-deployment.yaml

# Verify
kubectl get pods -n pad-onap
kubectl logs -f deploy/pad-onap-pipeline -n pad-onap
```

---

## Bước 6: Pre-flight Check

```bash
# Lấy NodePort IPs
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}')

# Chạy pre-flight check
python onap/scripts/preflight_check.py --host $NODE_IP

# Kết quả mong đợi:
# [PASS] ONAP SO — health endpoint
# [PASS] ONAP SO — API version
# [PASS] ONAP DMaaP — Message Router health
# [PASS] ONAP DMaaP — PAD topic exists or can be created
# [PASS] ONAP DMaaP — publish test event
# [PASS] ONAP Policy PAP — health endpoint
# [PASS] ONAP Policy PAP — PDP groups
# [PASS] PAD-ONAP models — XGBoost model file
# All checks PASSED.
```

---

## Bước 7: Chuyển sang Real Mode

```bash
# 1. Update ConfigMap
kubectl patch configmap pad-onap-config -n pad-onap \
  --type merge \
  -p '{"data": {"PAD_ONAP_STUB": "false"}}'

# 2. Restart pipeline để nhận config mới
kubectl rollout restart deploy/pad-onap-pipeline -n pad-onap

# 3. Verify logs — phải thấy "[DMaaP-MR] mode=mr-rest"
kubectl logs -f deploy/pad-onap-pipeline -n pad-onap | grep -E "DMaaP|ONAP|tier"

# 4. Kiểm tra DMaaP nhận events
kubectl port-forward svc/message-router 3904:3904 -n onap &
curl "http://localhost:3904/events/PAD_ONAP_AI_SIGNALS/cg1/c1?timeout=5000&limit=10"

# 5. Test end-to-end: chạy scenario S3
python -m evaluation.scenarios --scenario S3 --real-mode

# Mong đợi: CLAMP nhận event → SO tạo VNF ratelimiter → log "VNF active"
```

---

## Luồng Real Mode So Sánh Với Stub

```
STUB MODE (hiện tại):                REAL MODE (sau deploy):
─────────────────────                ──────────────────────
S3 AI → AIOutputPayload              S3 AI → AIOutputPayload
         ↓                                    ↓
  emit_to_dmaap_stub()           DMaaPPublisher._MRPublisher.publish()
  (write to /tmp/pad_dmaap/)          ↓ HTTP POST /events/PAD_ONAP_AI_SIGNALS
         ↓                                    ↓
  orchestrator reads file          CLAMP polls DMaaP (every 15s)
         ↓                                    ↓
  ONAPSOClient._docker_start()     Policy Framework evaluates Drools
  (sleep 0.5s, no real K8s)               ↓
         ↓                         SO.instantiate(vnfd-ratelimiter-v1)
  LatencyTracker records 505ms             ↓
                                   kubectl create pod pad-ratelimiter-xxxxx
                                           ↓ ~500ms
                                   /health OK → VNF active
                                           ↓
                                   LatencyTracker records REAL latency
```

---

## Các lỗi thường gặp

| Lỗi | Nguyên nhân | Fix |
|-----|-------------|-----|
| `Connection refused :3904` | DMaaP chưa ready | Chờ thêm, kiểm tra pod status |
| `HTTP 401` từ SO | Sai credentials | Kiểm tra PAD_ONAP_SO_USER/PASS |
| VNF không boot | Image không có trong registry | Push image lên registry |
| CLAMP không nhận event | Topic chưa tạo | Publish 1 event test thủ công |
| `OOMKilled` | ONAP pod hết RAM | Tăng node RAM hoặc giảm replica |

---

## NodePort Mapping (default OOM)

| Service | NodePort | URL |
|---------|----------|-----|
| ONAP SO | 30080 | `http://<node>:30080/manage/health` |
| DMaaP MR | 30904 | `http://<node>:30904/topics` |
| Policy PAP | 30969 | `http://<node>:30969/policy/pap/v1/healthcheck` |
| CLAMP | 30258 | `https://<node>:30258` |
| PAD Metrics | 9292 | `http://<node>:9292/metrics` |
