# Triển khai PAD-ONAP Pipeline lần đầu (trước khi chạy S2)

Hướng dẫn từng bước **trên SERVER** để biến cluster K8s + ONAP có sẵn
thành cluster có `pad-onap-pipeline` Pod đang chạy — tức điều kiện
"layer 3" mà [docs/S2_STEP_BY_STEP.md](S2_STEP_BY_STEP.md) đang giả định.

> **Đây là việc làm 1 LẦN.** Sau khi `kubectl get pods -n pad-onap`
> in `pad-onap-pipeline-xxxxx 1/1 Running`, không cần làm lại trừ khi:
> - Bạn đổi code Python trong `pipeline/` → rebuild image
> - Bạn đổi model trong `pad_onap_v3/models/` → copy lại vào PVC
> - PVC bị xoá → load lại model

---

## 0. Tiền điều kiện kiểm tra nhanh

Trên server, chạy:

```bash
cd /path/to/thesis2026
kubectl get nodes                            # K8s Ready
kubectl get pods -n onap | grep -v Running   # ONAP OOM healthy (rỗng = ok)
docker --version                             # cần để build image
ls pad_onap_v3/models/                       # phải có 4 file model v3
```

**Bắt buộc thấy:**
```
xgboost_v3.json
transformer_v3.pt
scaler.pkl
xgb_label_map.json
```

Nếu thiếu file model → bạn cần train trước. Xem [notebooks/](../notebooks/)
hoặc copy từ máy khác đã train.

---

## 1. Phương án triển khai (chọn 1)

### 1a. Auto-bootstrap (1 lệnh — khuyến nghị)

```bash
chmod +x onap/scripts/bootstrap_pad_pipeline.sh
./onap/scripts/bootstrap_pad_pipeline.sh
```

Script tự động làm bước 2 → 6 dưới đây. Nếu chạy ok thì bỏ qua phần
còn lại của doc này, chuyển luôn sang
[docs/S2_STEP_BY_STEP.md](S2_STEP_BY_STEP.md).

Nếu lỗi ở bước nào, đọc tiếp 1b để debug thủ công.

### 1b. Thủ công từng bước (debug khi 1a fail)

Tiếp tục đọc các phần dưới.

---

## 2. Build image `pad-onap/pipeline:1.0.0`

```bash
cd /path/to/thesis2026
docker build -t pad-onap/pipeline:1.0.0 -f Dockerfile.pipeline .
```

**Mong đợi:** Build mất ~5-10 phút lần đầu (cài torch CPU). Kết thúc:
```
Successfully tagged pad-onap/pipeline:1.0.0
```

Verify:
```bash
docker images | grep pad-onap/pipeline
# pad-onap/pipeline   1.0.0   abcdef1234   2 minutes ago   1.5GB
```

**Lỗi thường gặp:**
- `failed to fetch torch wheel` → kiểm tra mạng, có thể `--network=host`
- `no space left on device` → `docker system prune -a` rồi build lại

---

## 3. Load image vào K8s runtime

K8s kubelet **không** dùng `docker images` của bạn — nó dùng container
runtime riêng (containerd/CRI-O). Phải copy image vào đó.

Chọn 1 cách theo runtime của bạn:

### 3a. K3s

```bash
docker save pad-onap/pipeline:1.0.0 -o /tmp/pipeline.tar
sudo k3s ctr images import /tmp/pipeline.tar
sudo k3s ctr images list | grep pad-onap   # verify
rm /tmp/pipeline.tar
```

### 3b. kubeadm (containerd)

```bash
docker save pad-onap/pipeline:1.0.0 -o /tmp/pipeline.tar
sudo ctr -n k8s.io images import /tmp/pipeline.tar
sudo crictl images | grep pad-onap          # verify
rm /tmp/pipeline.tar
```

### 3c. minikube

```bash
minikube image load pad-onap/pipeline:1.0.0
minikube image ls | grep pad-onap            # verify
```

### 3d. Multi-node cluster (registry-based)

Nếu có private registry (Harbor, registry:2, Docker Hub):
```bash
docker tag pad-onap/pipeline:1.0.0 registry.example.com/pad-onap/pipeline:1.0.0
docker push registry.example.com/pad-onap/pipeline:1.0.0

# Rồi sửa deployment để pull từ registry:
sed -i 's|pad-onap/pipeline:1.0.0|registry.example.com/pad-onap/pipeline:1.0.0|' \
    onap/k8s/pad-onap-deployment.yaml
```

**Cách kiểm tra runtime của bạn:**
```bash
kubectl get nodes -o wide
# Cột CONTAINER-RUNTIME sẽ in: containerd://... hoặc docker://...

# Nếu là K3s:
systemctl is-active k3s

# Nếu là minikube:
minikube status
```

---

## 4. Apply deployment manifest

```bash
kubectl apply -f onap/k8s/pad-onap-deployment.yaml
```

**Tạo ra:**
- Namespace `pad-onap`
- ConfigMap `pad-onap-config` (PAD_DEPLOY_MODE, endpoints, ports)
- Secret `pad-onap-secrets` (SO/Policy credentials)
- PVC `pad-onap-models-pvc` (5 GiB cho model files)
- ServiceAccount `pad-onap-sa` + Role + RoleBinding
- Deployment `pad-onap-pipeline` (1 replica, 2-4 CPU, 4-8 GB)
- Service `pad-onap-metrics` (ClusterIP, port 9292/9293)
- HPA `pad-onap-hpa` (1-3 replicas, CPU 70%)

Verify:
```bash
kubectl get all -n pad-onap
kubectl get pvc -n pad-onap
```

**Mong đợi:**
```
NAME                                    READY   STATUS                   RESTARTS  AGE
pod/pad-onap-pipeline-xxxx-yyyy         0/1     ContainerCreating        0          15s
                                             hoặc Init:0/2 (đợi DMaaP + SO)

NAME                                    DESIRED   CURRENT  READY  AVAILABLE
deployment.apps/pad-onap-pipeline       1         1        0      0

NAME                          STATUS   VOLUME       CAPACITY  STORAGECLASS  AGE
persistentvolumeclaim/        Bound    pvc-xxxxxx   5Gi       default       20s
  pad-onap-models-pvc
```

> Pod sẽ stuck ở `Init:0/2` cho đến khi `wait-dmaap` và `wait-so`
> initContainer xác minh được ONAP DMaaP + SO. Nếu kẹt > 5 phút, bước 5
> dưới đây giải thích cách bypass tạm thời.

---

## 5. Xử lý nếu Pod stuck Init

```bash
kubectl describe pod -n pad-onap -l app=pad-onap-pipeline | tail -30
```

**Triệu chứng → Cách sửa:**

| Triệu chứng | Cách sửa |
|---|---|
| `wait-dmaap` log "waiting for DMaaP..." không bao giờ thoát | DMaaP MR Service không có tên đúng. Check: `kubectl get svc -n onap \| grep message-router`. Nếu service tên khác → sửa init container hoặc tạm bypass: `kubectl patch cm pad-onap-config -n pad-onap --type merge -p '{"data":{"PAD_BYPASS_DMAAP":"true"}}'` rồi `kubectl rollout restart deploy/pad-onap-pipeline -n pad-onap` |
| `wait-so` log "waiting for SO..." mãi | Service tên khác. Check `kubectl get svc -n onap \| grep -i ^so`. Nếu khác → sửa init container `nc -z so.onap.svc.cluster.local 8080` thành tên đúng |
| PVC stuck `Pending` | Không có default StorageClass. `kubectl get sc` — nếu rỗng, tạo: `kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml && kubectl patch storageclass local-path -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'` |
| `ImagePullBackOff` | Image chưa vào kubelet runtime. Quay lại Phần 3. Verify: `sudo crictl images \| grep pad-onap` hoặc `sudo k3s ctr images list \| grep pad-onap` |

---

## 6. Copy model files vào PVC

PVC vừa tạo là **rỗng** — Pod sẽ crash khi load model. Phải copy file
model vào PVC trước khi Pod start lần đầu (hoặc khởi động lại sau khi
copy).

```bash
# Tạo helper Pod để mount PVC
kubectl apply -n pad-onap -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: model-loader
spec:
  restartPolicy: Never
  containers:
    - name: loader
      image: busybox:1.36
      command: ["sh", "-c", "sleep 600"]
      volumeMounts:
        - { name: models, mountPath: /models }
  volumes:
    - name: models
      persistentVolumeClaim: { claimName: pad-onap-models-pvc }
EOF

# Đợi Ready
kubectl wait -n pad-onap --for=condition=Ready pod/model-loader --timeout=120s

# Copy từ máy server vào PVC qua helper Pod
for f in pad_onap_v3/models/*; do
    kubectl cp -n pad-onap "$f" model-loader:/models/$(basename $f)
done

# Verify
kubectl exec -n pad-onap model-loader -- ls -la /models

# Cleanup
kubectl delete pod -n pad-onap model-loader --now
```

**Mong đợi `ls -la /models` in:**
```
-rw-r--r--   1 root  root      ...   scaler.pkl
-rw-r--r--   1 root  root      ...   tf_best_config.json
-rw-r--r--   1 root  root      ...   transformer_metrics.json
-rw-r--r--   1 root  root      ...   transformer_v3.pt
-rw-r--r--   1 root  root      ...   xgb_label_map.json
-rw-r--r--   1 root  root      ...   xgb_tuned_configs.json
-rw-r--r--   1 root  root      ...   xgboost_v3.json
```

---

## 7. Restart Deployment để mount model

```bash
kubectl rollout restart deploy/pad-onap-pipeline -n pad-onap
kubectl rollout status  deploy/pad-onap-pipeline -n pad-onap --timeout=180s
```

**Mong đợi:**
```
deployment "pad-onap-pipeline" successfully rolled out
```

---

## 8. Verify Pod thực sự healthy

```bash
kubectl get pods -n pad-onap
# pad-onap-pipeline-xxxxx-yyyyy   1/1   Running   0   2m

# Log phải thấy 3 dấu hiệu:
kubectl logs -n pad-onap deploy/pad-onap-pipeline --tail=50 | grep -E \
    'XGBoost loaded|Transformer loaded|Kafka.*connected|tier_decision'
```

**Mong đợi:**
```
[INFO] XGBoost model loaded from /app/pad_onap_v3/models/xgboost_v3.json
[INFO] Transformer model loaded from /app/pad_onap_v3/models/transformer_v3.pt
[INFO] Kafka consumer connected to kafka.pad-onap.svc.cluster.local:9092
[INFO] Orchestrator ready (mode=legacy, source=kafka)
```

**Nếu không thấy 4 dòng này** trong vòng 1 phút sau rollout:
```bash
kubectl logs -n pad-onap deploy/pad-onap-pipeline --tail=100
```
Đọc kỹ exception trace.

---

## 9. Kiểm tra health endpoint

```bash
# Mở port-forward tạm để test
kubectl port-forward -n pad-onap svc/pad-onap-metrics 9293:9293 &

# Test
curl http://localhost:9293/healthz
# Mong đợi: {"status":"healthy"} hoặc HTTP 200

curl http://localhost:9293/readyz
# Mong đợi: {"status":"ready"} hoặc HTTP 200

# Cleanup
pkill -f 'port-forward -n pad-onap'
```

**Nếu healthz fail:** Pod chưa load xong model. Đợi 30s rồi thử lại.

---

## 10. Bây giờ đã sẵn sàng chạy S2

Tiếp theo:

```bash
# Vẫn trên server — chạy bootstrap testbed (Kafka NodePort + metrics NodePort)
PAD_NODE_PUBLIC_IP=<server-ip> ./onap/scripts/setup_remote_testbed.sh
```

Rồi chuyển sang [docs/S2_STEP_BY_STEP.md](S2_STEP_BY_STEP.md) Phần 3
(setup máy local) — bạn đã ở **layer 4** của Hình "PAD-ONAP server
readiness layers".

---

## Phụ lục — Tóm tắt lệnh

| Việc | Lệnh |
|---|---|
| Build image | `docker build -t pad-onap/pipeline:1.0.0 -f Dockerfile.pipeline .` |
| Load image (k3s) | `docker save ... \| sudo k3s ctr images import -` |
| Load image (containerd) | `docker save ... \| sudo ctr -n k8s.io images import -` |
| Apply manifest | `kubectl apply -f onap/k8s/pad-onap-deployment.yaml` |
| Copy model | dùng helper Pod model-loader + `kubectl cp` (Phần 6) |
| Restart Deployment | `kubectl rollout restart deploy/pad-onap-pipeline -n pad-onap` |
| Xem Pod status | `kubectl get pods -n pad-onap` |
| Xem log | `kubectl logs -f -n pad-onap deploy/pad-onap-pipeline` |
| Auto-bootstrap (1 lệnh) | `./onap/scripts/bootstrap_pad_pipeline.sh` |

## Phụ lục — Khi nào cần làm lại

| Tình huống | Bước cần lặp |
|---|---|
| Sửa code Python trong `pipeline/` | 2 → 3 → 7 |
| Train lại model | 6 → 7 |
| Đổi ConfigMap (endpoint, port…) | `kubectl apply` lại Phần 4, rồi 7 |
| Image vẫn cũ sau rebuild | 3 (force re-import), thêm `imagePullPolicy: Always` trong manifest |
| Xoá hết và làm lại | `kubectl delete ns pad-onap` rồi quay lại Phần 0 |
