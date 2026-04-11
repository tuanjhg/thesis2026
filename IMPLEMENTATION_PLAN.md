# Kế Hoạch Triển Khai PAD-ONAP Pipeline
**Phiên bản:** 1.0
**Cập nhật:** 2026-04-04
**Dự án:** Probabilistic Anomaly Detection tích hợp ONAP Closed-Loop

---

## Tổng Quan

| Hạng mục | Chi tiết |
|----------|---------|
| **Mục tiêu** | Xây dựng hệ thống phát hiện & phản ứng DDoS tự động trên ONAP |
| **Testbed** | ONAP thực (production/staging) + Mininet |
| **Dataset** | CICDDoS2019 + Synthetic gNMI data |
| **AI Models** | XGBoost (detection) + Transformer (forecast) |
| **Tổng thời gian** | 8 tuần |

---

## Cấu Trúc Thư Mục Dự Án

```
Src_2/
├── datasets/
│   └── CICDDoS2019/             # Raw CSV files
├── testbed/
│   ├── docker-compose.yml       # Toàn bộ infrastructure
│   ├── mininet/
│   │   └── topology.py          # Mininet network slices
│   ├── gnmi_simulator/
│   │   ├── Dockerfile
│   │   └── main.py              # gRPC gNMI mock server
│   ├── netflow_collector/
│   │   └── collector.py         # NetFlow UDP listener
│   └── anomaly_injector/
│       └── scenarios.py         # DDoS / attack scenarios
├── pipeline/
│   ├── s1_telemetry/
│   │   └── collector.py         # gNMI + NetFlow ingest
│   ├── s2_features/
│   │   └── engine.py            # Feature extraction
│   ├── s3_ai/
│   │   ├── data_prep.py         # CICDDoS2019 preprocessing
│   │   ├── xgboost_model.py     # XGBoost trainer
│   │   ├── transformer_model.py # Transformer trainer
│   │   └── detector.py          # S3 inference layer
│   ├── s4_risk_policy/
│   │   └── decisioner.py        # Risk formula + Tier selection
│   ├── s5_nfv/
│   │   └── enforcer.py          # ONAP SO/SDNC calls
│   └── s6_outcome/
│       └── monitor.py           # SLA + efficacy tracking
├── onap/
│   ├── integration.py           # ONAP API connector
│   ├── dmaap_publisher.py       # DMaaP event sender
│   └── policy_client.py         # Policy Framework client
├── slow_loop/
│   ├── m1_drift.py              # Concept drift detection
│   ├── m2_model_ops.py          # Champion/challenger
│   ├── m3_policy_tuning.py      # Threshold optimization
│   └── m4_registry.py           # Model/policy versioning
├── models/                      # Trained model artifacts
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── scripts/
│   ├── verify_onap.sh
│   ├── verify_testbed.sh
│   └── run_scenario.sh
├── metrics/
│   └── dashboard.py             # Prometheus metrics exporter
└── configs/
    ├── onap_config.yaml         # ONAP endpoints
    └── pipeline_config.yaml     # Pipeline parameters
```

---

## Phase 0 — Chuẩn Bị & Xác Nhận Môi Trường
**Thời gian:** Tuần 1 (3-4 ngày)

### 0.1 Xác Nhận ONAP Connectivity

**Mục tiêu:** Đảm bảo pipeline có thể giao tiếp với ONAP thực

```bash
# Kiểm tra ONAP health
curl -k -u $ONAP_USER:$ONAP_PASS \
  https://<onap-host>:8443/aai/v16/util/echo

# Kiểm tra DMaaP topics
curl -k -u $ONAP_USER:$ONAP_PASS \
  https://<onap-host>:3905/topics

# Kiểm tra SO orchestrator
curl -k -u $ONAP_USER:$ONAP_PASS \
  https://<onap-host>:30277/onap/so/infra/healthcheck

# Kiểm tra Policy Framework
curl -k -u $ONAP_USER:$ONAP_PASS \
  https://<onap-host>:30240/policy/pap/v1/healthcheck
```

**Checklist:**
- [ ] AAI (A&AI) accessible
- [ ] DMaaP topics: PAD_DETECTION_EVENTS tồn tại (tạo nếu chưa có)
- [ ] SO API responds
- [ ] Policy Framework accessible
- [ ] CLAMP dashboard accessible

### 0.2 Tạo DMaaP Topic

```bash
# Tạo topic cho PAD events
curl -k -X POST \
  -u $ONAP_USER:$ONAP_PASS \
  -H "Content-Type: application/json" \
  -d '{"topicName":"PAD_DETECTION_EVENTS","topicDescription":"PAD anomaly detection events"}' \
  https://<onap-host>:3905/topics/create
```

### 0.3 Cài Đặt Môi Trường Local

```bash
# Python environment
python -m venv venv
source venv/bin/activate

# Core dependencies
pip install xgboost==2.0.3
pip install torch==2.2.0
pip install shap==0.44.0
pip install grpcio==1.62.0
pip install grpcio-tools==1.62.0
pip install pandas==2.2.0
pip install scikit-learn==1.4.0
pip install numpy==1.26.0
pip install requests==2.31.0
pip install prometheus-client==0.20.0
pip install pytest==8.0.0

# Docker
docker --version        # >= 24.0
docker compose version  # >= 2.24
```

**Deliverable:** `configs/onap_config.yaml` với tất cả endpoints đã verify

---

## Phase 1 — Testbed Infrastructure
**Thời gian:** Tuần 1-2 (5-6 ngày)

### 1.1 Mininet Network Topology

**Mục tiêu:** Tạo mạng 3 slices mô phỏng môi trường 5G/NFV

```
Topology:
  eMBB slice:  embb_src → r1 → vnf_firewall → r2 → embb_dst
  URLLC slice: urllc_src → r1 → vnf_lb → r2 → urllc_dst
  mMTC slice:  mmtc_src → r3 → r2 → mmtc_dst

Cross-slice attack vector: r1 ↔ r3 (100 Mbps link)

VNFs:
  - vnf_firewall: ACL enforcement (T1)
  - vnf_lb: Load balancer / pre-warm (T2)
  - vnf_scrubber: DDoS scrubbing (T3)
  - vnf_isolation: Tenant isolation (T4)
```

**File:** `testbed/mininet/topology.py`

**Kiểm tra:**
```bash
sudo python testbed/mininet/topology.py
# Mininet CLI > pingall  → expect 100%
# Mininet CLI > iperf embb_src embb_dst  → expect ~100 Mbps
```

### 1.2 gNMI Simulator

**Mục tiêu:** Mock gRPC gNMI server phát ra metrics từ các router/switch trong Mininet

**Metrics được simulate:**
| Path gNMI | Device | Giá trị bình thường |
|-----------|--------|---------------------|
| `/interfaces/eth0/state/in-octets` | r1, r2, r3 | 1K-100K bytes/s |
| `/interfaces/eth0/state/in-pkts` | r1, r2, r3 | 100-10K pkts/s |
| `/system/cpu/state/avg-usage` | r1, r2, r3 | 10-40% |
| `/system/memory/state/utilized` | r1, r2, r3 | 30-60% |
| `/qos/queues/state/depth` | r1, r2, r3 | 0-80% |

**File:** `testbed/gnmi_simulator/main.py`

**Chạy:**
```bash
docker compose -f testbed/docker-compose.yml up gnmi-simulator
# Verify: grpcurl -plaintext localhost:50051 list
```

### 1.3 NetFlow Collector

**Mục tiêu:** Thu thập NetFlow v5/v9 từ Mininet (softflowd hoặc pmacct)

```bash
# Cài softflowd trong Mininet host
apt-get install -y softflowd pmacct

# Cấu hình NetFlow export từ Mininet routers
softflowd -i r1-eth0 -n 127.0.0.1:6343 -v 9
```

**File:** `testbed/netflow_collector/collector.py`

### 1.4 Anomaly Injector

**4 test scenarios chính:**

| Scenario | Mô tả | Expected Detection |
|----------|-------|-------------------|
| **S1_DDoS_UDP** | UDP flood 100K pps vào eMBB | S3 detect <1s, Tier T3 |
| **S2_BW_Exhaustion** | Tăng dần BW 10%/min × 10 min | S3 forecast 5-7 min trước |
| **S3_CPU_Spike** | CPU r2 từ 30% → 95% đột ngột | S4 → T2 pre-warm VNF |
| **S4_Cross_Slice** | eMBB floods r1-r3, ảnh URLLC | Policy tenant isolation |

**File:** `testbed/anomaly_injector/scenarios.py`

**Deliverable:** `scripts/verify_testbed.sh` pass tất cả checks

---

## Phase 2 — Data Preparation & AI Training
**Thời gian:** Tuần 2-3 (7-8 ngày)

### 2.1 Download CICDDoS2019

**Dataset:** Canadian Institute for Cybersecurity DDoS 2019
**URL:** https://www.unb.ca/cic/datasets/ddos-2019.html
**Kích thước:** ~8 GB (CSV files)

**Files cần download:**
```
Friday-02-01-2019_TrafficForML_CIC.csv     # Benign + DDoS DNS/LDAP/MSSQL/NTP
Thursday-07-02-2019_TrafficForML_CIC.csv   # DDoS Portmap/NetBIOS/LDAP/MSSQL
Wednesday-13-02-2019_TrafficForML_CIC.csv  # DDoS SNMP/SSDP/HTTP/UDP
Tuesday-12-02-2019_TrafficForML_CIC.csv    # DDoS UDP/SYN
Monday-11-02-2019_TrafficForML_CIC.csv     # Benign only
```

**Đặt vào:** `datasets/CICDDoS2019/`

### 2.2 Data Preprocessing

**File:** `pipeline/s3_ai/data_prep.py`

**Các bước:**
1. Load & concat tất cả CSV files
2. Remove duplicates, NaN, Infinite values
3. Map labels: BENIGN → 0, tất cả DDoS → 1
4. Select 39 network flow features
5. Temporal train/test split (80/20 theo thời gian, không random)
6. StandardScaler normalization
7. Export: `datasets/processed/X_train.npy`, `y_train.npy`, `X_test.npy`, `y_test.npy`

**Thống kê kỳ vọng:**
```
Total samples: ~450,000 flows
Class distribution: ~80% BENIGN, ~20% DDoS
Features selected: 39
Train size: ~360,000
Test size: ~90,000
```

**Lệnh chạy:**
```bash
python pipeline/s3_ai/data_prep.py \
  --data-dir datasets/CICDDoS2019 \
  --output-dir datasets/processed
```

### 2.3 Train XGBoost Model

**File:** `pipeline/s3_ai/xgboost_model.py`

**Mục tiêu:** Detect DDoS trong <20ms per sample

**Hyperparameters:**
```yaml
objective: binary:logistic
max_depth: 6
learning_rate: 0.1
n_estimators: 500
subsample: 0.8
colsample_bytree: 0.8
scale_pos_weight: auto  # từ class imbalance ratio
early_stopping_rounds: 20
```

**SHAP Integration:**
- Sau khi train, tạo TreeExplainer
- Export top-5 SHAP features cho mỗi prediction → S4 sử dụng

**Metrics kỳ vọng:**
| Metric | Target |
|--------|--------|
| ROC-AUC | >= 0.98 |
| Precision (DDoS) | >= 0.95 |
| Recall (DDoS) | >= 0.97 |
| F1-Score | >= 0.96 |
| Inference latency | < 20ms |

**Output:** `models/xgboost_v1.json`

**Lệnh:**
```bash
python pipeline/s3_ai/xgboost_model.py \
  --data-dir datasets/processed \
  --output-dir models \
  --experiment-name cicdos2019_v1
```

### 2.4 Train Transformer Model

**File:** `pipeline/s3_ai/transformer_model.py`

**Mục tiêu:** Time-series forecast 30-120 giây vào tương lai

**Architecture:**
```
Input: (batch, window=20, features=39)
       ↓
Linear Projection (39 → 64)
       ↓
TransformerEncoder (2 layers, 4 heads, d_model=64)
       ↓
    ┌──┴──┐
    │     │
Detection  Forecast
(2 class) (39 features)
```

**Dataset construction:**
- Từ CICDDoS2019 → sliding windows (window=20 flows, step=1)
- Label window = 1 nếu bất kỳ flow nào là DDoS
- ~430K windows từ training data

**Training:**
```yaml
epochs: 100
batch_size: 32
optimizer: Adam (lr=1e-3)
loss: CrossEntropy (detection) + 0.1 * MSE (forecast)
device: GPU nếu có, CPU fallback
early_stopping: patience=15
```

**Metrics kỳ vọng:**
| Metric | Target |
|--------|--------|
| ROC-AUC | >= 0.96 |
| Forecast RMSE | <= 0.05 (normalized) |
| Inference latency | < 60ms |

**Output:** `models/transformer_v1.pth`

**Lệnh:**
```bash
python pipeline/s3_ai/transformer_model.py \
  --data-dir datasets/processed \
  --output-dir models \
  --epochs 100
```

### 2.5 Model Evaluation & Export

```bash
# Evaluate cả hai models
python pipeline/s3_ai/evaluate.py \
  --xgboost-model models/xgboost_v1.json \
  --transformer-model models/transformer_v1.pth \
  --test-data datasets/processed/X_test.npy

# Output:
# reports/model_evaluation_report.html
# reports/roc_curves.png
# reports/feature_importance.png
# reports/confusion_matrix.png
```

**Deliverable:** `reports/model_evaluation_report.html`

---

## Phase 3 — Pipeline Core Implementation
**Thời gian:** Tuần 3-4 (7-8 ngày)

### 3.1 S1 — Telemetry Ingest

**File:** `pipeline/s1_telemetry/collector.py`

**Nhiệm vụ:**
- Subscribe gNMI stream từ gnmi-simulator (gRPC)
- Thu thập NetFlow UDP từ netflow_collector
- Per-slice normalization (eMBB/URLLC/mMTC)
- Output: normalized feature vector vào queue → S2

**Interface:**
```python
class TelemetryCollector:
    def start_gnmi_subscribe(self, host, port, paths)
    def start_netflow_listener(self, port=6343)
    def normalize_for_slice(self, raw_data, slice_id) -> dict
    def get_feature_vector(self) -> np.ndarray  # → S2 queue
```

**Latency target:** 50-150ms

### 3.2 S2 — Feature Engine

**File:** `pipeline/s2_features/engine.py`

**Nhiệm vụ:**
- Sliding window aggregation (window=20 samples, step=1)
- Entropy features: Shannon entropy của packet sizes
- Statistical features: mean, std, min, max, percentiles
- Temporal features: IAT (Inter-Arrival Time) stats
- Output: 39-dimensional feature vector → S3

**Interface:**
```python
class FeatureEngine:
    def update_window(self, telemetry_vector)
    def compute_features(self) -> np.ndarray  # shape (39,)
    def compute_entropy(self, values) -> float
    def get_temporal_features(self) -> dict
```

**Latency target:** 20-80ms

### 3.3 S3 — AI Detection + Forecast

**File:** `pipeline/s3_ai/detector.py`

**Nhiệm vụ:**
- Nhận feature vector từ S2
- XGBoost: compute Pnow (anomaly probability ngay lập tức)
- Transformer: compute Pforecast (xác suất tấn công 30-120s tới)
- SHAP: top-5 factors gửi sang S4
- Output: (Pnow, Pforecast, shap_factors) → S4

**Interface:**
```python
class S3Detector:
    def load_models(self, xgb_path, transformer_path)
    def detect(self, features: np.ndarray) -> DetectionResult
    def explain(self, features: np.ndarray) -> dict  # SHAP

@dataclass
class DetectionResult:
    p_now: float          # XGBoost probability [0,1]
    p_forecast: float     # Transformer forecast [0,1]
    forecast_horizon: int # seconds (30-120)
    shap_factors: dict    # top-5 features + values
    inference_ms: float   # latency tracking
```

**Latency target:** 20-60ms

### 3.4 S4 — Risk & Policy Decision

**File:** `pipeline/s4_risk_policy/decisioner.py`

**Risk Formula:**
```
R = w1*Pnow + w2*Pforecast + w3*Severity + w4*Tenant - w5*Headroom

Default weights:
  w1 = 0.40  (immediate anomaly probability)
  w2 = 0.25  (forecast contribution)
  w3 = 0.20  (business severity per tenant tier)
  w4 = 0.10  (tenant priority level)
  w5 = 0.05  (available headroom reduces risk)
```

**Tier Mapping:**
```python
T0 (R < 0.20): Observe only → log event
T1 (R < 0.40): Soft controls → rate-limit / ACL / SYN protect
T2 (R < 0.60): Pre-warm VNFs → reserve SFC path
T3 (R < 0.80): Divert traffic → activate scrubber chain
T4 (R >= 0.80): Full isolation → cross-domain signaling
```

**Output:** DMaaP event → ONAP DCAE

**Latency target:** 50-150ms

### 3.5 S5 — NFV Enforcement (ONAP Integration)

**File:** `pipeline/s5_nfv/enforcer.py`

**Luồng ONAP:**
```
S4 risk event
     ↓
DMaaP publish (PAD_DETECTION_EVENTS)
     ↓
DCAE receives event
     ↓
Policy Framework evaluates rules
     ↓
CLAMP activates tiered template
     ↓
SO + SDNC + CDS execute
  - T1: ACL push via SDNC
  - T2: VNF pre-warm via SO
  - T3: SFC redirect via CDS
  - T4: Isolation + cross-domain via SO+AAI
```

**Interface:**
```python
class NFVEnforcer:
    def publish_risk_event(self, risk: RiskScore) -> bool
    def check_policy_decision(self, slice_id) -> PolicyDecision
    def query_topology(self, slice_id) -> TopologyContext  # AAI
    def get_enforcement_status(self, request_id) -> str
```

**Latency target:**
- Warm path (T1-T2): 0.3-3s
- Cold path (T3-T4): 5-30s

### 3.6 S6 — Outcome Monitor

**File:** `pipeline/s6_outcome/monitor.py`

**Metrics thu thập:**
```python
class OutcomeMetrics:
    suppression_efficacy: float   # % traffic blocked / total attack
    sla_impact: float             # % legitimate traffic affected
    resource_overhead: float      # CPU/memory delta during enforcement
    enforcement_latency: float    # S4 decision → S5 execution time
    false_positive_rate: float    # T1+ activations on benign traffic
```

**Prometheus export:**
```bash
# Metrics available at http://localhost:9090/metrics
pad_detection_total{tier="T3"} 42
pad_enforcement_latency_seconds{p99} 2.3
pad_sla_impact_ratio 0.002
pad_suppression_efficacy 0.97
```

**Feedback loop:** S6 metrics → S4 (điều chỉnh weights theo kết quả thực tế)

---

## Phase 4 — ONAP Closed-Loop Integration
**Thời gian:** Tuần 5-6 (8-9 ngày)

### 4.1 Cấu Hình DCAE / DMaaP

**Nhiệm vụ:**
1. Tạo DMaaP topic `PAD_DETECTION_EVENTS`
2. Deploy DCAE microservice để consume events
3. Cấu hình routing: DCAE → Policy Framework

**Config file:** `onap/dcae_blueprint.yaml`

```yaml
# DCAE event processor config
event_processor:
  topic: PAD_DETECTION_EVENTS
  consumer_group: pad-pipeline
  consumer_id: pad-detector-01
  fetch_limit: 100
  fetch_ms: 1000

routing:
  risk_threshold_policy: 0.2      # Send to Policy if R > 0.2
  risk_threshold_clamp: 0.4       # Activate CLAMP if R > 0.4
```

### 4.2 Policy Framework Rules

**4 policy rules cho 4 tiers:**

```json
{
  "policy-id": "PAD.Tier1.RateLimit",
  "policy-version": "1.0",
  "content": {
    "guard": {
      "PAD_risk_score": {"greater_than": "0.2", "less_than": "0.4"},
      "actions": ["apply_rate_limit", "enable_syn_protect"]
    }
  }
}
```

```json
{
  "policy-id": "PAD.Tier3.Scrubber",
  "policy-version": "1.0",
  "content": {
    "guard": {
      "PAD_risk_score": {"greater_than": "0.6", "less_than": "0.8"},
      "actions": ["divert_to_scrubber", "insert_sfc_chain"]
    }
  }
}
```

**File:** `onap/policies/` (4 JSON files cho T1-T4)

### 4.3 CLAMP Templates

**Tiered response templates:**
```
pad_tier1_template.yaml  → rate-limit + ACL enforcement
pad_tier2_template.yaml  → VNF pre-warm + SFC path reservation
pad_tier3_template.yaml  → traffic divert + scrubber activation
pad_tier4_template.yaml  → full isolation + cross-domain alert
```

**Rollback:** Mỗi template có rollback trigger nếu S6 báo false positive

### 4.4 AAI Topology Context

**Nhiệm vụ:** Khi S5 cần enforce, query AAI để tìm:
- Nearest feasible scrubber placement
- Available VNF instances
- Current slice topology
- Tenant priority metadata

```python
class AAIClient:
    def get_slice_topology(self, slice_id: str) -> dict
    def get_vnf_inventory(self, type: str) -> list
    def get_tenant_priority(self, tenant_id: str) -> int
    def find_nearest_scrubber(self, source_node: str) -> str
```

---

## Phase 5 — Slow Adaptation Loop
**Thời gian:** Tuần 6-7 (5-6 ngày)

### 5.1 M1 — Drift Monitor

**File:** `slow_loop/m1_drift.py`

**Checks:**
- **Concept drift:** So sánh feature distribution (KS test) mỗi 30 phút
- **Evasion detection:** Detect bất thường trong prediction confidence

```python
class DriftMonitor:
    def check_feature_drift(self, new_data, reference_data) -> DriftReport
    def check_evasion_anomaly(self, predictions) -> bool
    def compute_ks_statistic(self, dist1, dist2) -> float

    # Alert nếu p-value < 0.05 (drift detected)
```

### 5.2 M2 — Model Ops

**File:** `slow_loop/m2_model_ops.py`

**Champion/Challenger:**
- Champion: model đang chạy production
- Challenger: model mới train trên data gần nhất
- A/B test: 10% traffic → challenger, 90% → champion
- Promote challenger nếu metrics cải thiện > 2%

**Online fine-tuning:**
- Mỗi 1 giờ: fine-tune XGBoost trên 1000 samples gần nhất
- Validate trên holdout set trước khi deploy

### 5.3 M3 — Policy Tuning

**File:** `slow_loop/m3_policy_tuning.py`

**Threshold optimization mỗi 4 giờ:**
```python
# Tối ưu weights w1..w5 dựa trên S6 metrics
def optimize_weights(outcome_history: list) -> dict:
    # Bayesian optimization: minimize (FPR * cost + FNR * impact)
    # Constraint: enforcement_latency < 150ms
    ...
```

### 5.4 M4 — Artifact Registry

**File:** `slow_loop/m4_registry.py`

**Quản lý versioning:**
```
models/
├── xgboost_v1.json       # baseline
├── xgboost_v2.json       # after drift retrain
├── transformer_v1.pth    # baseline
└── transformer_v2.pth    # after 4h fine-tune

policies/
├── weights_v1.json       # baseline
└── weights_v2.json       # after optimization

rollback/
└── snapshots/            # hourly snapshots
```

---

## Phase 6 — Testing & Validation
**Thời gian:** Tuần 7-8 (8-9 ngày)

### 6.1 Unit Tests

**File:** `tests/unit/`

| Module | Tests |
|--------|-------|
| `s2_features/engine.py` | Feature computation correctness |
| `s4_risk_policy/decisioner.py` | Risk formula edge cases |
| `s3_ai/detector.py` | Model inference correctness |
| `onap/integration.py` | DMaaP publish/receive |

```bash
pytest tests/unit/ -v --cov=pipeline --cov-report=html
# Target: > 80% coverage
```

### 6.2 Integration Tests

**File:** `tests/integration/`

```bash
# Test S1 → S2 → S3 flow
pytest tests/integration/test_fast_loop.py

# Test S4 → ONAP integration
pytest tests/integration/test_onap_integration.py

# Test S6 → M1 feedback
pytest tests/integration/test_slow_loop.py
```

### 6.3 End-to-End Scenarios

**Chạy từng scenario, đo metrics:**

#### Scenario T1: Baseline (Normal Traffic)
```bash
python scripts/run_scenario.sh --scenario baseline --duration 300

Expected:
  - S1-S4 flows continuously
  - S5 stays at T0 (observe only)
  - False positive rate < 0.01
```

#### Scenario T2: DDoS UDP Flood (eMBB slice)
```bash
python scripts/run_scenario.sh --scenario ddos_udp --duration 120

Expected:
  - S3 detects anomaly < 1000ms
  - S4 risk > 0.8 → T3 activated
  - ONAP SO deploys scrubber chain < 30s
  - S6 reports suppression efficacy > 95%
```

#### Scenario T3: Bandwidth Exhaustion Forecast
```bash
python scripts/run_scenario.sh --scenario bw_ramp --duration 600

Expected:
  - S3 Transformer forecasts congestion 30-60s trước
  - S4 activates T2 (pre-warm) trước khi saturation
  - SLA impact < 1%
```

#### Scenario T4: Cross-Slice Attack
```bash
python scripts/run_scenario.sh --scenario cross_slice --duration 180

Expected:
  - eMBB flood detected
  - URLLC latency maintained < 5ms
  - Policy enforces slice isolation
```

#### Scenario T5: Slow Loop Adaptation
```bash
python scripts/run_scenario.sh --scenario drift_test --duration 14400  # 4 hours

Expected:
  - M1 detects drift after ~2 hours
  - M2 triggers fine-tune
  - M3 updates thresholds
  - Model performance maintained after drift
```

### 6.4 Performance Benchmarks

**Đo latency E2E cho từng stage:**

```python
# metrics/benchmark.py
LATENCY_TARGETS = {
    'S1_ingest':          (50, 150),   # (p50_ms, p99_ms)
    'S2_features':        (20, 80),
    'S3_detection':       (20, 60),
    'S4_decision':        (50, 150),
    'S5_enforcement_warm': (300, 3000),
    'S5_enforcement_cold': (5000, 30000),
    'fast_loop_total':    (150, 500),
}

# Run: python metrics/benchmark.py --iterations 1000
```

---

## Kết Quả Kỳ Vọng (Thesis Metrics)

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Detection AUC** | >= 0.98 | Offline (CICDDoS2019 test set) |
| **Detection Latency p99** | < 500ms | Online (fast loop) |
| **Forecast Horizon** | 30-120s | Transformer output |
| **Enforcement Latency (warm)** | < 3s | S4→S5 ONAP |
| **Enforcement Latency (cold)** | < 30s | S4→S5 ONAP |
| **Suppression Efficacy** | > 95% | S6 metrics |
| **False Positive Rate** | < 1% | S6 metrics |
| **SLA Impact** | < 2% | S6 metrics |
| **Drift Adaptation** | < 1h | M1-M3 cycle time |

---

## Lịch Trình Tổng Thể

```
Tuần 1:   Phase 0 (ONAP verify) + Phase 1 bắt đầu (Docker, Mininet)
Tuần 2:   Phase 1 hoàn thành (gNMI, NetFlow, Anomaly Injector)
           + Phase 2 bắt đầu (download CICDDoS2019, data prep)
Tuần 3:   Phase 2 hoàn thành (train XGBoost + Transformer)
           + Phase 3 bắt đầu (S1, S2)
Tuần 4:   Phase 3 hoàn thành (S3, S4, S5, S6)
Tuần 5:   Phase 4 bắt đầu (DCAE, Policy, CLAMP config)
Tuần 6:   Phase 4 hoàn thành + Phase 5 (Slow loop)
Tuần 7:   Phase 6 bắt đầu (Unit tests, Integration tests)
Tuần 8:   Phase 6 hoàn thành (E2E scenarios, benchmarks, reports)
```

```
W1   ████░░░░░░░░░░░░
W2   ████████░░░░░░░░
W3   ░░░████████░░░░░
W4   ░░░░░░████████░░
W5   ░░░░░░░░████░░░░
W6   ░░░░░░░░░░████░░
W7   ░░░░░░░░░░░░████
W8   ░░░░░░░░░░░░░░██

P0=Chuẩn bị  P1=Testbed  P2=AI Train  P3=Pipeline  P4=ONAP  P5=SlowLoop  P6=Test
```

---

## Rủi Ro & Giải Pháp

| Rủi Ro | Mức Độ | Giải Pháp |
|--------|--------|-----------|
| ONAP API thay đổi giữa versions | Cao | Abstract ONAP calls sau interface layer |
| CICDDoS2019 feature mismatch với live data | Trung bình | Thêm synthetic data, online fine-tune |
| Mininet không đủ realistic | Trung bình | Bổ sung EVE-NG nếu cần validation |
| Transformer latency > 60ms | Thấp | Fallback to XGBoost-only mode |
| ONAP SO timeout > 30s (cold path) | Trung bình | Pre-warm VNFs dự phòng |

---

## Checklist Hoàn Thành

### Phase 0
- [ ] ONAP health check pass
- [ ] DMaaP topic created
- [ ] Python env + dependencies installed

### Phase 1
- [ ] Mininet topology running (3 slices)
- [ ] gNMI simulator serving metrics
- [ ] NetFlow collector receiving flows
- [ ] Anomaly injector: 4 scenarios ready

### Phase 2
- [ ] CICDDoS2019 downloaded & preprocessed
- [ ] XGBoost AUC >= 0.98
- [ ] Transformer AUC >= 0.96
- [ ] Model artifacts saved

### Phase 3
- [ ] S1 telemetry collecting < 150ms
- [ ] S2 features computed correctly
- [ ] S3 inference < 60ms with SHAP
- [ ] S4 risk formula + tier selection
- [ ] S5 ONAP calls successful
- [ ] S6 metrics exported to Prometheus

### Phase 4
- [ ] DMaaP publish/consume working
- [ ] Policy rules deployed (T1-T4)
- [ ] CLAMP templates active
- [ ] AAI topology queries working

### Phase 5
- [ ] M1 drift detection working
- [ ] M2 champion/challenger setup
- [ ] M3 threshold optimization
- [ ] M4 versioning/rollback

### Phase 6
- [ ] Unit tests > 80% coverage
- [ ] Integration tests pass
- [ ] All 5 E2E scenarios pass
- [ ] Performance benchmarks meet targets
- [ ] Final report generated
