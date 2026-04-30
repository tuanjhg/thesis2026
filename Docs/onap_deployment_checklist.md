# Checklist triển khai ONAP cho PAD-ONAP

> Đọc từ code thực tế trong `onap_e2e_lib.py`, `run_s2_real.py`, `run_s8_real.py`.  
> Mỗi mục có lệnh kiểm tra và lệnh tạo cụ thể.

---

## Bức tranh tổng thể — Cần gì?

Script gọi vào ONAP theo thứ tự này:

```
run_s2_real.py
│
├─① SO health check          → GET /manage/health
├─② Policy PAP health check  → GET /policy/pap/v1/healthcheck
├─③ DMaaP publish            → POST /events/PAD_ONAP_AI_SIGNALS
├─④ Policy API create        → POST /policy/api/v1/policytypes/
│                                   onap.policies.controlloop.operational.drools/
│                                   versions/1.0.0/policies
├─⑤ Policy PAP deploy        → POST /policy/pap/v1/pdps/policies
├─⑥ SO instantiate VNF       → POST /onap/so/infra/serviceInstantiation/v7/
│                                   serviceInstances
│       body cần:
│         globalSubscriberId : "pad-onap-customer"     ← phải có trong AAI
│         subscriptionType   : "pad-onap-service"      ← phải có trong AAI
│         modelVersionId     : <UUID từ SDC>           ← phải có trong SDC
│         lcpCloudRegionId   : "RegionOne"             ← phải có trong AAI
│         tenantId           : "pad-onap-tenant"       ← phải có trong AAI
│
├─⑦ SO poll status           → GET /onap/so/infra/orchestrationRequests/v7
├─⑧ ovs-ofctl add-flow       → chạy lệnh Linux cục bộ
└─⑨ SO terminate             → DELETE /onap/so/infra/serviceInstantiation/v7/...
```

**Tổng cộng cần triển khai:**

| # | Thứ cần có | Loại | Bắt buộc? |
|---|-----------|------|-----------|
| 1 | ONAP SO đang chạy | Pod K8s | ✅ Bắt buộc |
| 2 | ONAP Policy PAP đang chạy | Pod K8s | ✅ Bắt buộc |
| 3 | ONAP DMaaP đang chạy | Pod K8s | ✅ Bắt buộc |
| 4 | DMaaP topic `PAD_ONAP_AI_SIGNALS` | Kafka topic | ✅ Bắt buộc |
| 5 | AAI: Customer `pad-onap-customer` | Dữ liệu AAI | ✅ Bắt buộc |
| 6 | AAI: Service Subscription | Dữ liệu AAI | ✅ Bắt buộc |
| 7 | AAI: Cloud Region `RegionOne` + Tenant | Dữ liệu AAI | ✅ Bắt buộc |
| 8 | SO: Service Model UUID | SDC hoặc SO pre-load | ✅ Bắt buộc |
| 9 | Policy type `drools` v1.0.0 trong Policy Framework | Policy API | ✅ Bắt buộc |
| 10 | VNF Docker image `pad-vnf-scrubber:latest` | Docker | ✅ Bắt buộc |
| 11 | VNF Docker image `pad-vnf-ratelimiter:latest` | Docker | ✅ Bắt buộc |
| 12 | OVS bridge `br-pad` | Linux OVS | ✅ Bắt buộc |
| 13 | Env variables (ONAP_HOST, credentials) | Shell | ✅ Bắt buộc |

---

## Biến môi trường — Set trước tất cả

```bash
# Đặt một lần vào ~/.bashrc hoặc .env
export ONAP_HOST=192.168.1.100        # ← IP node K8s của bạn
export ONAP_SO_PORT=30080
export ONAP_POLICY_PORT=30969
export ONAP_DMAAP_PORT=30904

export PAD_ONAP_SO_USER=so_admin
export PAD_ONAP_SO_PASS=demo123456!
export PAD_ONAP_POLICY_USER=healthcheck
export PAD_ONAP_POLICY_PASS=zb!XztG34

export PAD_ONAP_STUB=false            # ← quan trọng nhất

# Sẽ điền sau khi hoàn thành bước 8
export PAD_SERVICE_MODEL_UUID=REPLACE_LATER

source ~/.bashrc
```

---

## Mục 1–3: Kiểm tra ONAP đang chạy

```bash
# Kiểm tra nhanh
kubectl get pods -n onap | grep -E '^so|^message-router|^policy-pap|^policy-api|^policy-drools'

# Kết quả cần thấy (tất cả Running):
so-0                          1/1   Running
message-router-0              1/1   Running
policy-pap-xxxxxxxxx          1/1   Running
policy-api-xxxxxxxxx          1/1   Running
policy-drools-pdp-xxxxxxxxx   1/1   Running
```

Nếu thiếu pod nào → xem lại `onap/values-override.yaml`, enable component đó.

---

## Mục 4: Tạo DMaaP Topic

```bash
# Kiểm tra topic đã tồn tại chưa
curl -s http://$ONAP_HOST:$ONAP_DMAAP_PORT/topics | python3 -m json.tool | grep PAD_ONAP

# Nếu chưa có, tạo topic:
curl -X POST http://$ONAP_HOST:$ONAP_DMAAP_PORT/topics/create \
  -H "Content-Type: application/json" \
  -d '{
    "topicName": "PAD_ONAP_AI_SIGNALS",
    "topicDescription": "PAD-ONAP AI output signals for DDoS mitigation",
    "partitionCount": 3,
    "replicationCount": 1
  }'

# Kiểm tra lại
curl -s http://$ONAP_HOST:$ONAP_DMAAP_PORT/topics/PAD_ONAP_AI_SIGNALS
# Phải trả về thông tin topic, không phải 404
```

---

## Mục 5–7: Đăng ký dữ liệu vào AAI

> **Tại sao cần AAI?**  
> Khi SO nhận lệnh tạo VNF, nó kiểm tra AAI để xác nhận:  
> - Customer có tồn tại không?  
> - Cloud region có hợp lệ không?  
> - Tenant có thuộc region đó không?  
> Nếu thiếu bất kỳ mục nào → SO trả về lỗi 400.

### 5a: Tạo Customer trong AAI

```bash
curl -X PUT \
  "http://$ONAP_HOST:30232/aai/v21/business/customers/customer/pad-onap-customer" \
  -H "Content-Type: application/json" \
  -H "X-FromAppId: pad-onap" \
  -H "X-TransactionId: setup-001" \
  -u AAI_USERNAME:AAI_PASSWORD \
  -d '{
    "global-customer-id": "pad-onap-customer",
    "subscriber-name": "PAD-ONAP DDoS Mitigation",
    "subscriber-type": "INFRA"
  }'

# Kiểm tra
curl -s "http://$ONAP_HOST:30232/aai/v21/business/customers/customer/pad-onap-customer" \
  -u AAI_USERNAME:AAI_PASSWORD | python3 -m json.tool
```

> **AAI credentials mặc định OOM:**  
> `AAI_USERNAME=AAI` `AAI_PASSWORD=AAI` (hoặc `aai.restclient.auth.password` trong config)  
> Kiểm tra: `kubectl get secret -n onap aai-secret -o jsonpath='{.data.AAI_USER_PASSWORD}' | base64 -d`

### 5b: Tạo Service Subscription

```bash
curl -X PUT \
  "http://$ONAP_HOST:30232/aai/v21/business/customers/customer/pad-onap-customer/service-subscriptions/service-subscription/pad-onap-service" \
  -H "Content-Type: application/json" \
  -H "X-FromAppId: pad-onap" \
  -H "X-TransactionId: setup-002" \
  -u AAI_USERNAME:AAI_PASSWORD \
  -d '{
    "service-type": "pad-onap-service"
  }'
```

### 5c: Tạo Cloud Region và Tenant

```bash
# Tạo Cloud Region "RegionOne"
curl -X PUT \
  "http://$ONAP_HOST:30232/aai/v21/cloud-infrastructure/cloud-regions/cloud-region/pad-onap-cloud/RegionOne" \
  -H "Content-Type: application/json" \
  -H "X-FromAppId: pad-onap" \
  -H "X-TransactionId: setup-003" \
  -u AAI_USERNAME:AAI_PASSWORD \
  -d '{
    "cloud-owner": "pad-onap-cloud",
    "cloud-region-id": "RegionOne",
    "cloud-type": "k8s",
    "owner-defined-type": "kubernetes",
    "cloud-region-version": "1.27",
    "complex-name": "pad-lab"
  }'

# Tạo Tenant trong region đó
curl -X PUT \
  "http://$ONAP_HOST:30232/aai/v21/cloud-infrastructure/cloud-regions/cloud-region/pad-onap-cloud/RegionOne/tenants/tenant/pad-onap-tenant-id" \
  -H "Content-Type: application/json" \
  -H "X-FromAppId: pad-onap" \
  -H "X-TransactionId: setup-004" \
  -u AAI_USERNAME:AAI_PASSWORD \
  -d '{
    "tenant-id": "pad-onap-tenant-id",
    "tenant-name": "pad-onap-tenant"
  }'
```

---

## Mục 8: Đăng ký Service Model vào SO

> **Đây là bước phức tạp nhất.**  
> SO cần biết `modelVersionId` (UUID) của service model trước khi tạo instance.  
> Có 2 cách: qua SDC (chính thống) hoặc SO database pre-load (nhanh hơn).

### Cách A: Qua SDC (Chính thống, mất ~30 phút)

```
1. Mở SDC Portal: http://<NODE_IP>:30206
   Login: cs0008 / demo123456!

2. Menu → ONBOARD → Create VSP
   Name: pad-onap-scrubber
   Upload file: onap/vnfd/vnfd-scrubber-v1.yaml
   → Submit → Check in → Certify

3. Menu → HOME → Create VF
   Import từ VSP: pad-onap-scrubber
   → Certify → Distribute

4. Menu → HOME → Create Service
   Name: pad-onap-scrubber-service
   Add VF: pad-onap-scrubber
   → Certify → Distribute

5. Sau Distribute, SO nhận UUID tự động
   Lấy UUID:
   curl -s "http://$ONAP_HOST:30206/sdc2/rest/v1/catalog/services" \
     -u cs0008:demo123456! | python3 -m json.tool | grep -A2 "pad-onap-scrubber"
   → Tìm "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

6. Lặp lại cho pad-onap-ratelimiter

7. Set env var:
   export PAD_SERVICE_MODEL_UUID=<uuid-scrubber>
```

### Cách B: SO Database Pre-load (Nhanh, dùng cho testbed)

> Script bypass SDC, ghi thẳng model info vào SO database.  
> UUID tự tạo, không cần SDC UI.

```bash
# Tạo UUID cho model
SCRUBBER_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
RATELIMITER_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
echo "Scrubber UUID:     $SCRUBBER_UUID"
echo "Ratelimiter UUID:  $RATELIMITER_UUID"

# Pre-load scrubber service model vào SO catalog
curl -X POST \
  "http://$ONAP_HOST:$ONAP_SO_PORT/onap/so/infra/modelDistributions/v1/distributions" \
  -H "Content-Type: application/json" \
  -u $PAD_ONAP_SO_USER:$PAD_ONAP_SO_PASS \
  -d "{
    \"modelType\": \"service\",
    \"modelId\": \"$SCRUBBER_UUID\",
    \"modelName\": \"pad-onap-scrubber\",
    \"modelVersion\": \"1.0.0\",
    \"modelDescription\": \"PAD-ONAP DDoS Scrubber VNF\"
  }"

# Pre-load ratelimiter
curl -X POST \
  "http://$ONAP_HOST:$ONAP_SO_PORT/onap/so/infra/modelDistributions/v1/distributions" \
  -H "Content-Type: application/json" \
  -u $PAD_ONAP_SO_USER:$PAD_ONAP_SO_PASS \
  -d "{
    \"modelType\": \"service\",
    \"modelId\": \"$RATELIMITER_UUID\",
    \"modelName\": \"pad-onap-ratelimiter\",
    \"modelVersion\": \"1.0.0\",
    \"modelDescription\": \"PAD-ONAP Rate Limiter VNF\"
  }"

# Lưu UUID vào env
export PAD_SERVICE_MODEL_UUID=$SCRUBBER_UUID
echo "export PAD_SERVICE_MODEL_UUID=$SCRUBBER_UUID" >> ~/.bashrc
echo "export PAD_RATELIMITER_MODEL_UUID=$RATELIMITER_UUID" >> ~/.bashrc
```

> **Lưu ý**: Nếu SO của bạn không có endpoint `/modelDistributions/v1/distributions`,  
> dùng Cách A (SDC) hoặc inject thẳng vào MariaDB của SO:

```bash
# Inject vào SO database (nếu cần)
kubectl exec -n onap $(kubectl get pod -n onap -l app=mariadb-galera -o name | head -1) -- \
  mysql -u so_user -pso_password catalogdb -e "
    INSERT INTO service (MODEL_UUID, MODEL_NAME, MODEL_VERSION, DESCRIPTION)
    VALUES ('$SCRUBBER_UUID', 'pad-onap-scrubber', '1.0.0', 'PAD Scrubber VNF')
    ON DUPLICATE KEY UPDATE MODEL_NAME=MODEL_NAME;
  "
```

---

## Mục 9: Đăng ký Policy Type vào Policy Framework

> Script tạo policy dạng `onap.policies.controlloop.operational.drools`.  
> Policy type này phải tồn tại trước khi tạo policy instance.

```bash
# Kiểm tra policy type đã có chưa
curl -s -u $PAD_ONAP_POLICY_USER:$PAD_ONAP_POLICY_PASS \
  "http://$ONAP_HOST:$ONAP_POLICY_PORT/policy/api/v1/policytypes" \
  | python3 -m json.tool | grep drools

# Nếu chưa có, tạo policy type:
curl -X POST \
  "http://$ONAP_HOST:$ONAP_POLICY_PORT/policy/api/v1/policytypes" \
  -H "Content-Type: application/json" \
  -u $PAD_ONAP_POLICY_USER:$PAD_ONAP_POLICY_PASS \
  -d '{
    "tosca_definitions_version": "tosca_simple_yaml_1_1_0",
    "policy_types": {
      "onap.policies.controlloop.operational.drools": {
        "version": "1.0.0",
        "description": "Drools operational policy for PAD-ONAP closed loop",
        "derived_from": "onap.policies.controlloop.Operational",
        "properties": {
          "controllerName": {"type": "string"},
          "controlLoop":    {"type": "map"},
          "policies":       {"type": "list"}
        }
      }
    }
  }'

# Verify
curl -s -u $PAD_ONAP_POLICY_USER:$PAD_ONAP_POLICY_PASS \
  "http://$ONAP_HOST:$ONAP_POLICY_PORT/policy/api/v1/policytypes/onap.policies.controlloop.operational.drools/versions/1.0.0" \
  | python3 -m json.tool
```

---

## Mục 10–11: Build VNF Docker Images

```bash
cd /home/user/pad-onap

# Tạo scrubber image (16GB RAM, 8CPU theo VNFD)
mkdir -p onap/docker/scrubber onap/docker/ratelimiter

# Scrubber Dockerfile
cat > onap/docker/scrubber/Dockerfile << 'EOF'
FROM python:3.10-slim
WORKDIR /app
RUN pip install flask gunicorn
COPY app.py .
EXPOSE 8001
HEALTHCHECK --interval=5s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')"
CMD ["python", "app.py"]
EOF

cat > onap/docker/scrubber/app.py << 'EOF'
from flask import Flask, jsonify, request
import time, threading

app = Flask(__name__)
_start = time.time()

# Simulate ~6s boot delay
time.sleep(1)  # actual startup delay (K8s counts from pod start)

@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "pad-scrubber",
                    "uptime_s": round(time.time() - _start, 1)})

@app.route('/filter', methods=['POST'])
def filter_pkt():
    return jsonify({"filtered": True, "mode": "syn-proxy+dpi"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001)
EOF

# Ratelimiter Dockerfile
cat > onap/docker/ratelimiter/Dockerfile << 'EOF'
FROM python:3.10-slim
WORKDIR /app
RUN pip install flask
COPY app.py .
EXPOSE 8002
HEALTHCHECK --interval=3s --timeout=2s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8002/health')"
CMD ["python", "app.py"]
EOF

cat > onap/docker/ratelimiter/app.py << 'EOF'
from flask import Flask, jsonify
import time

app = Flask(__name__)
_start = time.time()

@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "pad-ratelimiter",
                    "uptime_s": round(time.time() - _start, 1)})

@app.route('/rate', methods=['POST'])
def rate():
    return jsonify({"limited": True, "mode": "token-bucket", "rate_mbps": 1000})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8002)
EOF

# Build cả hai
docker build -t pad-vnf-scrubber:latest    onap/docker/scrubber/
docker build -t pad-vnf-ratelimiter:latest onap/docker/ratelimiter/

# Verify
docker images | grep pad-vnf
# pad-vnf-scrubber      latest   xxxxx   ...
# pad-vnf-ratelimiter   latest   xxxxx   ...

# Test nhanh
docker run -d --name test-scrubber    -p 18001:8001 pad-vnf-scrubber:latest
docker run -d --name test-ratelimiter -p 18002:8002 pad-vnf-ratelimiter:latest
sleep 2
curl http://localhost:18001/health   # {"status":"ok","service":"pad-scrubber"}
curl http://localhost:18002/health   # {"status":"ok","service":"pad-ratelimiter"}
docker rm -f test-scrubber test-ratelimiter
```

---

## Mục 12: Tạo OVS Bridge

```bash
# Cài OVS nếu chưa có
sudo apt-get install -y openvswitch-switch

# Tạo bridge br-pad
sudo ovs-vsctl add-br br-pad

# Verify
sudo ovs-vsctl show
# Bridge "br-pad"   ← phải thấy dòng này
```

---

## Mục 13: Chạy preflight check để xác nhận tất cả OK

```bash
cd /home/user/pad-onap
source ~/.bashrc   # load env vars

python onap/scripts/preflight_check.py --host $ONAP_HOST
```

Kết quả mong đợi (tất cả PASS):
```
=================================================================
  PAD-ONAP Real ONAP Pre-Flight Check
  Target host: 192.168.1.100
=================================================================

[ONAP SO]
  [PASS] ONAP SO — health endpoint          HTTP 200  (45ms)
  [PASS] ONAP SO — API version              HTTP 400 (API reachable)  (38ms)

[ONAP DMaaP]
  [PASS] ONAP DMaaP — Message Router health MR up, 12 topics  (52ms)
  [PASS] ONAP DMaaP — PAD topic exists      topic exists  (41ms)
  [PASS] ONAP DMaaP — publish test event    publish OK (HTTP 200)  (89ms)

[ONAP Policy]
  [PASS] ONAP Policy PAP — health endpoint  healthy=True  (33ms)
  [PASS] ONAP Policy PAP — PDP groups       2 PDP group(s) registered  (44ms)

[Local PAD-ONAP]
  [PASS] PAD-ONAP models — XGBoost model file  XGBoost + Transformer+LSTM found
  [PASS] PAD-ONAP environment — PAD_ONAP_STUB=false  PAD_ONAP_STUB=false (real mode)

=================================================================
  Results: 9/9 checks passed
  All checks PASSED.
  Ready to deploy: set PAD_ONAP_STUB=false and restart pipeline.
=================================================================
```

---

## Chạy test — Sau khi tất cả mục trên PASS

```bash
# S2: UDP Flood → Scrubber VNF (~6s end-to-end)
python onap/scripts/run_s2_real.py \
  --attack-mode gnmi \
  --gnmi-url   http://localhost:8888 \
  --bridge     br-pad \
  --src-ip     10.1.0.1 \
  --vnf-port   9001

# S8: Proactive T2 (500ms) → Reactive T3 (6000ms) — lead_time ≥25s
python onap/scripts/run_s8_real.py \
  --gnmi-url  http://localhost:8888 \
  --bridge    br-pad \
  --vnf-port  9001
```

---

## Tóm tắt thứ tự thực hiện

```
Thứ tự          Việc cần làm                    Lệnh kiểm tra
─────────────────────────────────────────────────────────────────
[1] ONAP pods   SO + Policy + DMaaP chạy        kubectl get pods -n onap
[2] Env vars    ONAP_HOST, credentials           echo $ONAP_HOST
[3] DMaaP topic PAD_ONAP_AI_SIGNALS tồn tại     curl .../topics/PAD_ONAP_AI_SIGNALS
[4] AAI data    Customer + Region + Tenant       curl .../aai/v21/business/customers/...
[5] SO model    UUID scrubber + ratelimiter      export PAD_SERVICE_MODEL_UUID=...
[6] Policy type onap.policies.controlloop.drools curl .../policy/api/v1/policytypes
[7] Docker img  pad-vnf-scrubber + ratelimiter   docker images | grep pad-vnf
[8] OVS bridge  br-pad tồn tại                  sudo ovs-vsctl show
[9] Preflight   Tất cả PASS                     python preflight_check.py
[10] Chạy test  S2 rồi S8                       python run_s2_real.py ...
─────────────────────────────────────────────────────────────────
```

---

## Lỗi phổ biến và cách fix

| Lỗi | Nguyên nhân | Fix |
|-----|-------------|-----|
| SO trả về 400 `customer not found` | AAI chưa có customer | Chạy curl PUT customer (Mục 5a) |
| SO trả về 400 `model not found` | UUID sai hoặc chưa distribute | Chạy SO pre-load (Mục 8B) |
| SO trả về 400 `cloud region not found` | AAI chưa có RegionOne | Chạy curl PUT cloud-region (Mục 5c) |
| Policy API 404 `policy type not found` | Type chưa đăng ký | Chạy curl POST policytypes (Mục 9) |
| VNF timeout 120s | Docker image không pull được | Kiểm tra `docker images \| grep pad-vnf` |
| DMaaP 404 | Topic chưa tạo | Chạy curl POST topics/create (Mục 4) |
| `PAD_SERVICE_MODEL_UUID=REPLACE_LATER` | Quên set UUID | Chạy Mục 8, set export |
