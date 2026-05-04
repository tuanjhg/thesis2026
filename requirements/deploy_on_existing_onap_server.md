# Triển khai PAD-ONAP trên server đã có ONAP sẵn

> **Tình huống**: Server đã chạy ONAP OOM trên Kubernetes.  
> Bạn cần deploy thêm PAD-ONAP vào, kết nối vào ONAP đang có, chạy kịch bản S2/S8.

---

## Tổng quan: Cần làm gì trên server

```
SERVER ĐÃ CÓ ONAP
═══════════════════════════════════════════════════════════
│  [K8s namespace: onap]                                   │
│    ├── SO (Service Orchestrator)       ← dùng được rồi  │
│    ├── DMaaP (Message Router/Kafka)    ← dùng được rồi  │
│    ├── Policy PAP                      ← dùng được rồi  │
│    └── CLAMP                           ← dùng được rồi  │
│                                                          │
│  CẦN THÊM VÀO:                                           │
│  [K8s namespace: pad-onap]                               │
│    ├── pad-onap-pipeline   ← AI + Orchestrator           │
│    └── pad-onap-gnmi-sim   ← gNMI simulator (optional)  │
│                                                          │
│  [Linux host — cùng server hoặc VM]                     │
│    ├── Mininet topology    ← mạng ảo eMBB/URLLC/mMTC    │
│    └── OVS bridges         ← SFC rule điều hướng traffic │
═══════════════════════════════════════════════════════════
```

---

## Bước 0 — Kiểm tra ONAP đang có đủ không

SSH vào server, chạy các lệnh sau:

```bash
# 1. Kiểm tra namespace onap
kubectl get pods -n onap

# Cần thấy những pod này ở trạng thái Running:
# so-0                     Running   ← bắt buộc
# message-router-0         Running   ← bắt buộc
# policy-pap-xxx           Running   ← bắt buộc
# clamp-backend-xxx        Running   ← bắt buộc (có thể không có)
```

```bash
# 2. Lấy địa chỉ node
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}')
echo "Node IP: $NODE_IP"
```

```bash
# 3. Kiểm tra SO
curl http://$NODE_IP:30080/manage/health
# Mong đợi: {"status":"UP"}

# 4. Kiểm tra DMaaP
curl http://$NODE_IP:30904/topics
# Mong đợi: {"topics": [...]}

# 5. Kiểm tra Policy PAP
curl -u healthcheck:zb!XztG34 \
     http://$NODE_IP:30969/policy/pap/v1/healthcheck
# Mong đợi: {"code":200,"healthy":true}
```

> Nếu port khác, kiểm tra: `kubectl get svc -n onap | grep -E 'so|message-router|policy-pap'`

---

## Bước 1 — Copy source code PAD-ONAP lên server

```bash
# Từ máy của bạn, copy lên server
scp -r "D:\Khóa luận\Src_2" user@SERVER_IP:/home/user/pad-onap

# Hoặc dùng git (nếu có repo)
# ssh user@SERVER_IP
# git clone <repo-url> /home/user/pad-onap

# Vào thư mục
ssh user@SERVER_IP
cd /home/user/pad-onap
```

---

## Bước 2 — Ghi lại thông tin ONAP endpoints

Tạo file `.env` chứa thông tin kết nối vào ONAP đang có:

```bash
cat > /home/user/pad-onap/.env << 'EOF'
# === Thay bằng IP thật của server ===
NODE_IP=192.168.1.100          # ← đổi thành IP server của bạn

# ONAP endpoints (dùng NodePort mặc định của OOM)
SO_URL=http://${NODE_IP}:30080
DMAAP_URL=http://${NODE_IP}:30904
PAP_URL=http://${NODE_IP}:30969

# Credentials (mặc định OOM)
SO_USER=so_admin
SO_PASS=demo123456!
PAP_USER=healthcheck
PAP_PASS=zb!XztG34

# PAD-ONAP mode
PAD_ONAP_STUB=false

# OVS bridge (sẽ tạo ở Bước 4)
OVS_BRIDGE=br-pad
EOF
```

> **Lưu ý**: Nếu ONAP của bạn dùng port khác, kiểm tra:
> ```bash
> kubectl get svc -n onap | grep -E 'NodePort|LoadBalancer'
> ```

---

## Bước 3 — Build và đăng ký VNF Docker images

ONAP SO cần biết VNF image là gì để tạo instance. Có 2 cách:

### Cách A: Build image trực tiếp trên server (đơn giản hơn)

```bash
cd /home/user/pad-onap

# Tạo Dockerfile cho scrubber VNF (nếu chưa có)
mkdir -p onap/docker/scrubber
cat > onap/docker/scrubber/Dockerfile << 'EOF'
FROM python:3.10-slim
WORKDIR /app
RUN pip install flask gunicorn
COPY scrubber_main.py .
EXPOSE 8001
HEALTHCHECK --interval=5s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8001/health || exit 1
CMD ["python", "scrubber_main.py"]
EOF

cat > onap/docker/scrubber/scrubber_main.py << 'EOF'
from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "pad-scrubber"})

@app.route('/filter', methods=['POST'])
def filter_traffic():
    # SYN-proxy + DPI logic placeholder
    return jsonify({"filtered": True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)
EOF

# Build tất cả VNF images
docker build -t pad-vnf-scrubber:latest    onap/docker/scrubber/
docker build -t pad-vnf-ratelimiter:latest onap/docker/ratelimiter/ 2>/dev/null || \
  docker tag pad-vnf-scrubber:latest pad-vnf-ratelimiter:latest

# Verify
docker images | grep pad-vnf
```

### Cách B: Dùng Registry của ONAP (nếu server có Harbor/Nexus)

```bash
# Lấy registry URL
REGISTRY=$(kubectl get configmap -n onap global-config -o jsonpath='{.data.dockerHubRepository}' 2>/dev/null || echo "nexus3.onap.org:10001")

docker tag pad-vnf-scrubber:latest $REGISTRY/pad-onap/scrubber:1.0.0
docker push $REGISTRY/pad-onap/scrubber:1.0.0
```

---

## Bước 4 — Tạo OVS Bridge cho Mininet

```bash
# Cài Open vSwitch nếu chưa có
sudo apt-get install -y openvswitch-switch mininet

# Tạo bridge
sudo ovs-vsctl add-br br-pad

# Verify
sudo ovs-vsctl show
# Phải thấy: Bridge "br-pad"
```

---

## Bước 5 — Khởi động Mininet Topology

Đây là bước tạo mạng ảo eMBB/URLLC/mMTC — **cần chạy với sudo**:

```bash
cd /home/user/pad-onap

# Cài Python dependencies
pip install mininet 2>/dev/null || true

# Khởi động topology (3-slice)
sudo python3 testbed/mininet/topology.py
```

Khi Mininet CLI hiện ra, bạn thấy:
```
======================================================
  PAD-ONAP Testbed — Network Topology Summary
======================================================
  eMBB  (1Gbps):
    embb_src (10.1.0.1) → r1 → vnf_fw → r2 → embb_dst (10.1.0.2)

  URLLC (<1ms):
    urllc_src (10.2.0.1) → r1 → vnf_lb → r2 → urllc_dst (10.2.0.2)

  mMTC (10Mbps):
    mmtc_src (10.3.0.1) → r3 → r2 → mmtc_dst (10.3.0.2)
======================================================
mininet>
```

**Giữ nguyên terminal này** (Mininet phải đang chạy trong suốt quá trình test).

---

## Bước 6 — Chạy preflight check

Mở **terminal mới** (giữ Mininet chạy ở terminal kia):

```bash
cd /home/user/pad-onap
source .env

# Chạy preflight check
python onap/scripts/preflight_check.py \
  --so-url    $SO_URL \
  --dmaap-url $DMAAP_URL \
  --pap-url   $PAP_URL
```

Kết quả mong đợi:
```
[OK] SO        http://192.168.1.100:30080/manage/health → 200
[OK] DMaaP     http://192.168.1.100:30904/topics → 200
[OK] Policy PAP http://192.168.1.100:30969/policy/pap/v1/healthcheck → 200
All services reachable. Safe to set PAD_ONAP_STUB=false.
```

Nếu một trong các check FAIL → xem mục Troubleshooting bên dưới.

---

## Bước 7 — Tạo DMaaP topic

ONAP cần có topic `PAD_ONAP_AI_SIGNALS` trước khi pipeline publish event:

```bash
source .env

# Tạo topic
curl -X POST $DMAAP_URL/topics/create \
  -H "Content-Type: application/json" \
  -d '{
    "topicName": "PAD_ONAP_AI_SIGNALS",
    "topicDescription": "PAD-ONAP AI output signals",
    "partitionCount": 3,
    "replicationCount": 1
  }'

# Kiểm tra topic đã tồn tại
curl $DMAAP_URL/topics | python3 -m json.tool | grep PAD_ONAP
```

---

## Bước 8 — Chạy kịch bản S2 (UDP Flood → Tier 3)

Đây là kịch bản đơn giản nhất để xác nhận hệ thống hoạt động end-to-end:

```bash
source .env

# Bước 8a: Khởi động gNMI simulator (terminal riêng)
python3 testbed/gnmi_simulator/main.py --port 8888 &
sleep 2
curl http://localhost:8888/health   # phải trả về {"status":"ok"}

# Bước 8b: Chạy S2 với ONAP thật
python onap/scripts/run_s2_real.py \
  --attack-mode gnmi \
  --gnmi-url   http://localhost:8888 \
  --bridge     br-pad \
  --src-ip     10.1.0.1 \
  --vnf-port   9001
```

### Theo dõi trong khi chạy

Mở thêm các terminal để theo dõi song song:

```bash
# Terminal theo dõi ONAP SO log
kubectl logs -f -n onap deploy/so --tail=50 | grep -E 'instantiate|vnf|error'

# Terminal theo dõi DMaaP events
watch -n2 "curl -s $DMAAP_URL/events/PAD_ONAP_AI_SIGNALS/cg1/c1?timeout=1000&limit=5"

# Terminal theo dõi OVS flows
watch -n2 "sudo ovs-ofctl dump-flows br-pad"
```

### Kết quả mong đợi S2

```
[S2] Phase 1 — Preflight OK
[S2] Phase 2 — Normal baseline 30s ...
[S2] Phase 3 — Injecting UDP flood (gnmi) ...
[S2] Phase 4 — t_trigger = 1746000035.123
[S2] Phase 5 — CLAMP policy pushed (T3, conf=0.92) → PAP 200
[S2] Phase 6 — SO instantiate vnfd-scrubber-v1 ...
               instance_id = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
[S2] Phase 7 — VNF ACTIVE after 6134 ms  ← boot scrubber
[S2] Phase 8 — OVS SFC rule installed
[S2] Phase 10 — Cleanup done

══════════════════════════════════════════
  S2 End-to-End Latency
  Detection → Policy push  :   111 ms
  SO → VNF active          :  6134 ms
  End-to-end               :  6398 ms
══════════════════════════════════════════
Results → evaluation/results/s2_real_onap.json
```

---

## Bước 9 — Chạy kịch bản S8 (Proactive T2 → Reactive T3)

Đây là kịch bản **chứng minh đóng góp chính** của luận văn — proactive T2 (~500ms) kích hoạt trước reactive T3 (~6000ms):

```bash
source .env

python onap/scripts/run_s8_real.py \
  --gnmi-url    http://localhost:8888 \
  --bridge      br-pad \
  --vnf-port    9001 \
  --hold-seconds 30
```

### Kết quả mong đợi S8

```
[S8] Phase 1 — Normal 30s ...
[S8] Phase 2 — SYN flood injected on r1 ...
[S8] ── T2 Proactive ──
      CLAMP push T2 → 200  (98ms)
      VNF ratelimiter ACTIVE after 487ms
      t2_end_to_end = 612ms
[S8] Holding 30s với ratelimiter ...
[S8] Phase 3 — UDP flood (escalate) ...
[S8] ── T3 Reactive ──
      CLAMP push T3 → 200  (104ms)
      VNF scrubber ACTIVE after 6201ms
      t3_end_to_end = 6389ms

══════════════════════════════════════════════
  S8 Novelty Metric
  T2 Proactive end-to-end :    612 ms
  T3 Reactive end-to-end  :  6 389 ms
  Lead time (t3 - t2)     :   30.1 s   ★
══════════════════════════════════════════════
Results → evaluation/results/s8_real_onap.json
```

---

## Bước 10 — Xem và lưu kết quả

```bash
# Xem JSON kết quả
cat evaluation/results/s2_real_onap.json | python3 -m json.tool
cat evaluation/results/s8_real_onap.json | python3 -m json.tool

# Chụp màn hình ONAP pods đang chạy (bằng chứng)
kubectl get pods -n onap > logs/onap_pods_during_s8.txt
kubectl get pods -n pad-onap >> logs/onap_pods_during_s8.txt

# Lưu OVS flows tại thời điểm VNF active (bằng chứng SFC)
sudo ovs-ofctl dump-flows br-pad > logs/ovs_flows_s8.txt

# Lưu toàn bộ log chạy S8
PAD_ONAP_STUB=false python onap/scripts/run_s8_real.py \
  --gnmi-url http://localhost:8888 --bridge br-pad \
  2>&1 | tee logs/s8_run_$(date +%Y%m%d_%H%M).log
```

---

## Sơ đồ toàn bộ luồng khi chạy trên server

```
SERVER (có ONAP OOM trên K8s)
═══════════════════════════════════════════════════════════════════

  ┌─ Linux host (bare-metal / VM) ──────────────────────────────┐
  │                                                              │
  │  Mininet Topology (sudo python3 topology.py)                 │
  │  ┌──────────────────────────────────────────────────────┐   │
  │  │ embb_src[10.1.0.1] ──▶ r1(OVS) ──▶ embb_dst[10.1.0.2]│  │
  │  │ urllc_src[10.2.0.1] ─▶ r1(OVS) ──▶ urllc_dst[10.2.0.2]│ │
  │  │           ↑ hping3 flood (packet thật)                │   │
  │  └──────────────────────────────────────────────────────┘   │
  │              │ metrics (NetFlow / gNMI REST)                 │
  │              ▼                                               │
  │  gNMI Simulator (:8888)  ──▶  PAD-ONAP Pipeline             │
  │                               │  XGBoost: UDP_Flood 0.92    │
  │                               │  Transformer: P30s=0.71     │
  │                               │                              │
  │                               ▼                              │
  │                          DMaaP publish                       │
  │                               │                              │
  └───────────────────────────────│──────────────────────────────┘
                                  │ HTTP POST /events/PAD_ONAP_AI_SIGNALS
                                  ▼
  ┌─ K8s namespace: onap ────────────────────────────────────────┐
  │                                                              │
  │  CLAMP ─polls─▶ DMaaP ─reads─▶ Policy PAP                   │
  │                                    │ deploy policy           │
  │                                    ▼                         │
  │                              Drools PDP                      │
  │                                    │ trigger action          │
  │                                    ▼                         │
  │                            SO (Service Orchestrator)         │
  │                                    │ instantiate VNF         │
  │                                    ▼                         │
  │                         kubectl create pod                   │
  │                         pad-vnf-scrubber-xxxxx               │
  │                         (boot ~6000ms)                       │
  └──────────────────────────────────────────────────────────────┘
                                    │ VNF active
                                    ▼
  OVS br-pad: install flow rule ──▶ traffic → vnf_scrubber port
```

---

## Troubleshooting

### SO trả về 503 hoặc connection refused

```bash
# Kiểm tra SO pod
kubectl get pod -n onap | grep so
kubectl logs -n onap so-0 --tail=30

# Kiểm tra port đang dùng
kubectl get svc -n onap so
# Cột PORT(S) cho biết NodePort thật

# Thử port-forward thay vì NodePort
kubectl port-forward -n onap svc/so 8080:8080 &
curl http://localhost:8080/manage/health
```

### DMaaP không nhận event

```bash
# Kiểm tra topic tồn tại chưa
curl $DMAAP_URL/topics | python3 -m json.tool

# Tạo thủ công nếu chưa có
curl -X POST $DMAAP_URL/topics/create \
  -H "Content-Type: application/json" \
  -d '{"topicName":"PAD_ONAP_AI_SIGNALS","partitionCount":3,"replicationCount":1}'

# Test publish thủ công
curl -X POST $DMAAP_URL/events/PAD_ONAP_AI_SIGNALS \
  -H "Content-Type: application/json" \
  -d '{"test":"ping"}'
```

### Policy PAP trả về 401

```bash
# Lấy credentials thật từ ONAP secret
kubectl get secret -n onap policy-secret -o yaml
# Hoặc
kubectl get secret -n onap onap-policy -o jsonpath='{.data.POLICY_ADMIN_PASSWORD}' | base64 -d

# Cập nhật .env
echo "PAP_PASS=<password_thật>" >> .env
source .env
```

### VNF không bao giờ ACTIVE (timeout 120s)

```bash
# Kiểm tra Docker daemon
docker info

# Kiểm tra image tồn tại
docker images | grep pad-vnf

# Xem SO đã gửi request tạo gì
kubectl logs -n onap so-0 | grep -E 'instantiate|vnf|error' | tail -20

# Build lại image nếu cần
docker build -t pad-vnf-scrubber:latest onap/docker/scrubber/
```

### Mininet: host không ping được nhau

```bash
# Kiểm tra OVS
sudo ovs-vsctl show
sudo ovs-ofctl dump-flows r1

# Restart controller
mininet> r1 ovs-vsctl set-controller r1 tcp:127.0.0.1:6633
mininet> pingall
```

### Pipeline vẫn dùng stub mode dù đã set PAD_ONAP_STUB=false

```bash
# Kiểm tra env var thật sự được set
python3 -c "
import os
print('PAD_ONAP_STUB =', os.environ.get('PAD_ONAP_STUB', 'NOT SET'))
"

# Phải chạy với source .env trước
source .env && python onap/scripts/run_s2_real.py ...

# Hoặc export trực tiếp
export PAD_ONAP_STUB=false
export SO_URL=http://192.168.1.100:30080
python onap/scripts/run_s2_real.py ...
```

---

## Checklist trước khi demo / bảo vệ luận văn

```
PRE-DEMO CHECKLIST
─────────────────────────────────────────────────────────
□ Server bật, SSH vào được
□ kubectl get pods -n onap → tất cả Running
□ SO health: curl $SO_URL/manage/health → {"status":"UP"}
□ DMaaP health: curl $DMAAP_URL/topics → 200
□ PAP health: curl -u healthcheck:... $PAP_URL/... → healthy
□ docker images | grep pad-vnf → có scrubber + ratelimiter
□ sudo ovs-vsctl show → có bridge br-pad
□ Mininet đang chạy (terminal riêng, sudo)
□ gNMI simulator đang chạy (:8888)
□ preflight_check.py → All PASS
□ .env đã source, PAD_ONAP_STUB=false
─────────────────────────────────────────────────────────
RUN ORDER:
  1. python run_s2_real.py ... (UDP flood → T3, ~6s)
  2. python run_s8_real.py ... (T2 proactive 612ms vs T3 6389ms)
  3. cat evaluation/results/s8_real_onap.json → lead_time_s ≥ 25
─────────────────────────────────────────────────────────
```

---

## Tóm tắt nhanh — 10 lệnh chính

```bash
# 1. SSH vào server
ssh user@SERVER_IP && cd /home/user/pad-onap

# 2. Kiểm tra ONAP
kubectl get pods -n onap | grep -E 'so|message-router|policy|clamp'

# 3. Lấy NODE_IP và ghi .env
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}')

# 4. Tạo OVS bridge
sudo ovs-vsctl add-br br-pad

# 5. Khởi động Mininet (terminal 1)
sudo python3 testbed/mininet/topology.py

# 6. Khởi động gNMI simulator (terminal 2)
python3 testbed/gnmi_simulator/main.py --port 8888 &

# 7. Preflight check
source .env && python onap/scripts/preflight_check.py

# 8. Tạo DMaaP topic
curl -X POST $DMAAP_URL/topics/create -H "Content-Type:application/json" \
  -d '{"topicName":"PAD_ONAP_AI_SIGNALS","partitionCount":3,"replicationCount":1}'

# 9. Chạy S2
python onap/scripts/run_s2_real.py --attack-mode gnmi --gnmi-url http://localhost:8888 --bridge br-pad

# 10. Chạy S8 (key novelty)
python onap/scripts/run_s8_real.py --gnmi-url http://localhost:8888 --bridge br-pad
```
