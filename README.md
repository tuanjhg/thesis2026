# PAD-ONAP: AI-Augmented NFV Orchestration for Proactive DDoS Defense

Hệ thống phát hiện và phòng thủ DDoS chủ động dựa trên AI kết hợp NFV/ONAP trong Cloud Data Center.

---

## Cấu trúc dự án

```
Src_2/
├── testbed/                    # Phase 1 – Môi trường kiểm thử
│   ├── gnmi_simulator/         # Mock gNMI server (REST) + Dockerfile
│   ├── netflow_collector/      # NetFlow v5 parser + synthetic mode
│   ├── anomaly_injector/       # 4 kịch bản tấn công DDoS
│   ├── mininet/                # Topo 3-slice (eMBB/URLLC/mMTC)
│   ├── docker-compose.yml      # 5 services: gNMI, collector, Prometheus, Grafana, exporter
│   └── prometheus.yml          # Cấu hình scrape
├── pipeline/
│   └── s3_ai/                  # AI pipeline (inference layer)
│       ├── inference_layer.py  # InferenceEngine: XGBoost + Transformer+LSTM
│       ├── transformer_lstm.py # Mô hình Transformer+LSTM 4-horizon
│       ├── ai_output.py        # AIOutputPayload → S4 ONAP
│       └── metrics_exporter.py # gNMI → Prometheus bridge
├── pad_onap_v3/                # Kết quả training (models + processed data)
│   ├── models/
│   │   ├── xgboost_v3.json     # XGBoost 4-class classifier
│   │   ├── transformer_v3.pt   # Transformer+LSTM 4-horizon forecaster
│   │   ├── scaler.pkl          # StandardScaler (17 features)
│   │   ├── xgb_label_map.json  # Label mapping {0,1,2,5}
│   │   └── tf_best_config.json # Best hyperparameters
│   └── processed/
│       ├── X_train.npy / y_train.npy
│       ├── X_test.npy  / y_test.npy
│       └── metadata.json       # Thông tin dataset và split
├── notebooks/
│   └── ddos-train.ipynb        # Kaggle training notebook
└── scripts/
    └── verify_testbed.sh       # Kiểm tra Phase 1 (bash)
```

---

## Kết quả mô hình (pad_onap_v3)

| Mô hình | Metric | Giá trị |
|---|---|---|
| XGBoost 4-class | Accuracy | 90.6% |
| XGBoost 4-class | Balanced Acc | 95.0% |
| XGBoost 4-class | Macro F1 | 93.6% |
| XGBoost 4-class | AUC (macro OvR) | 99.1% |
| Transformer+LSTM | AUC h0 (t+30s) | 99.4% |
| Transformer+LSTM | AUC mean (4 horizons) | 99.0% |

**Classes:** `0=Normal`, `1=UDP_Flood`, `2=SYN_Flood`, `5=Amplification`  
**Features:** 17 flow-level features từ sliding window (window=100, step=50)

---

## Phase 1 – Testbed Setup & Run

### Yêu cầu hệ thống

| Yêu cầu | Version |
|---|---|
| Python | 3.9+ |
| Docker | >= 24.0 |
| Docker Compose | >= 2.0 |
| OS | Linux / WSL2 (Mininet) hoặc Windows (gNMI + collector) |

**Python packages:**
```bash
pip install xgboost torch shap pandas scikit-learn prometheus-client
```

---

### Option A — Chạy trực tiếp (Windows / không cần Docker)

#### 1. Khởi động gNMI Simulator

```bash
# Terminal 1
cd D:/Khóa\ luận/Src_2
python testbed/gnmi_simulator/main.py
# → Listening on http://localhost:8080
```

Kiểm tra:
```bash
curl http://localhost:8080/health
# {"status":"ok","uptime":...}

curl http://localhost:8080/metrics
# {"r1":{"metrics":{...}},"r2":{...},"r3":{...}}

curl http://localhost:8080/metrics/r1
# {"device":"r1","metrics":{"in_pkts":...,"udp_ratio":...}}
```

Inject attack:
```bash
curl -X POST http://localhost:8080/attack/start \
     -H "Content-Type: application/json" \
     -d '{"type":"udp_flood","target":"r1"}'

curl -X POST http://localhost:8080/attack/stop \
     -H "Content-Type: application/json" \
     -d '{}'
```

Attack types: `udp_flood`, `syn_flood`, `bw_ramp`, `cpu_spike`

---

#### 2. Khởi động NetFlow Collector (synthetic mode)

```bash
# Terminal 2 — synthetic: kéo metrics từ gNMI simulator
python testbed/netflow_collector/collector.py \
    --mode synthetic \
    --gnmi http://localhost:8080 \
    --api-port 7070 \
    --interval 1.0
# → API at http://localhost:7070
```

Kiểm tra:
```bash
curl http://localhost:7070/health
# {"status":"ok"}

curl http://localhost:7070/flows/latest
# {"features":{"pkt_rate":...,"src_ip_entropy":...},"timestamp":...}

curl http://localhost:7070/flows
# {"flows":[...], "count":N}
```

---

#### 3. Khởi động Metrics Exporter (gNMI → Prometheus)

```bash
# Terminal 3
python pipeline/s3_ai/metrics_exporter.py \
    --gnmi http://localhost:8080 \
    --port 9091 \
    --interval 2.0
# → Prometheus metrics at http://localhost:9091/metrics
```

---

### Option B — Docker Compose (Full stack)

```bash
cd D:/Khóa\ luận/Src_2/testbed

# Build và khởi động toàn bộ stack
docker compose up -d

# Kiểm tra trạng thái
docker compose ps

# Logs
docker compose logs -f gnmi-simulator
docker compose logs -f netflow-collector
```

**Services sau khi khởi động:**

| Service | URL | Mô tả |
|---|---|---|
| gNMI Simulator | http://localhost:8080 | Mock gNMI metrics + attack injection |
| NetFlow Collector | http://localhost:7070 | Feature extraction API |
| Prometheus | http://localhost:9090 | Time-series metrics DB |
| Grafana | http://localhost:3000 | Dashboard (admin/padOnap2026) |
| Metrics Exporter | http://localhost:9091/metrics | Prometheus scrape endpoint |

Dừng stack:
```bash
docker compose down
```

---

### Option C — Mininet (Linux / WSL2 only)

```bash
# Yêu cầu: Linux với Mininet đã cài
sudo apt-get install mininet

# Chạy topology 3-slice (eMBB/URLLC/mMTC)
sudo python3 testbed/mininet/topology.py

# Hoặc chạy automated test (pingall + iperf)
sudo python3 testbed/mininet/topology.py --test
```

---

### Verification Script

```bash
# Linux / WSL2
chmod +x scripts/verify_testbed.sh
./scripts/verify_testbed.sh

# Kết quả mong đợi:
#   PASSED:    ~25+
#   FAILED:    0
#   WARNINGS:  ~3 (Mininet, Docker stack nếu không chạy)
```

---

### Anomaly Injector — 4 kịch bản

```bash
# Liệt kê các kịch bản
python testbed/anomaly_injector/scenarios.py --list

# Chạy một kịch bản (gNMI simulator phải đang chạy)
python testbed/anomaly_injector/scenarios.py --run ddos_udp
python testbed/anomaly_injector/scenarios.py --run bw_ramp
python testbed/anomaly_injector/scenarios.py --run cpu_spike
python testbed/anomaly_injector/scenarios.py --run cross_slice
```

| Kịch bản | Mô tả | Thời gian |
|---|---|---|
| `ddos_udp` | S1: UDP Flood — tấn công băng thông trực tiếp | 60s |
| `bw_ramp` | S2: BW Ramp — tăng dần traffic đến ngưỡng bão hòa | 300s |
| `cpu_spike` | S3: CPU Spike — tấn công tài nguyên tính toán | 60s |
| `cross_slice` | S4: Cross-Slice — lan rộng qua nhiều slice 5G | 90s |

---

## Live Pipeline — Kết nối Phase 1 → Phase 2 (end-to-end)

### Chạy toàn bộ luồng

Cần 3 terminal (hoặc Docker Compose đã chạy):

```bash
# Terminal 1 — gNMI Simulator
python testbed/gnmi_simulator/main.py

# Terminal 2 — NetFlow Collector (synthetic mode)
python testbed/netflow_collector/collector.py \
    --mode synthetic --gnmi http://localhost:8080 --interval 1.0

# Terminal 3 — Live Pipeline (Phase 1 → Phase 2)
python pipeline/s3_ai/live_pipeline.py \
    --collector http://localhost:7070 \
    --model-dir ./pad_onap_v3/models \
    --data-dir  ./pad_onap_v3/processed \
    --interval  1.0
```

Output mẫu mỗi window (1 giây):
```
[W0001] 2026-04-09T10:30:01Z  latency=5.2ms
  Attack   : Normal         conf=0.981
  Forecast : P30=0.031  P60=0.028  P90=0.025  P120=0.022
  Tier     : T0 — Normal — no action
  SHAP top5: pkt_rate=0.012  byte_rate=0.008  udp_ratio=0.004 ...

[W0002] 2026-04-09T10:30:02Z  latency=5.8ms [PROACTIVE]
  Attack   : UDP_Flood      conf=0.924
  Forecast : P30=0.881  P60=0.832  P90=0.775  P120=0.712
  Tier     : T3 — High   — scale-out scrubber
  *** PROACTIVE: PREPOSITION_TIER2_MITIGATION (P30=0.881 > 0.70) ***
  SHAP top5: proto_dist_udp=0.421  pkt_rate=0.312 ...
```

**Inject attack trong khi live pipeline đang chạy:**
```bash
# Terminal khác — tấn công r1
curl -X POST http://localhost:8080/attack/start \
     -H "Content-Type: application/json" \
     -d '{"type":"udp_flood","target":"r1"}'

# Quan sát live pipeline phát hiện và trigger proactive
# Dừng tấn công
curl -X POST http://localhost:8080/attack/stop \
     -H "Content-Type: application/json" -d '{}'
```

**Lưu output ra JSONL:**
```bash
python pipeline/s3_ai/live_pipeline.py \
    --out ./pad_onap_v3/live_output.jsonl \
    --max-windows 300   # Dừng sau 300 windows (~5 phút)
```

---

## AI Pipeline — Sử dụng mô hình pad_onap_v3

### Inference nhanh (single window)

```python
import numpy as np
from pipeline.s3_ai.inference_layer import InferenceEngine
from pipeline.s3_ai.ai_output import payload_to_dict

# Load engine (tự động tìm models trong pad_onap_v3/)
engine = InferenceEngine.load(
    model_dir='./pad_onap_v3/models',
    data_dir='./pad_onap_v3/processed',
    device='auto',       # 'cuda' hoặc 'cpu'
    shap_enabled=True,   # SHAP top-5 features
)

# Feature vector 17 chiều (raw, chưa scale)
features = np.array([
    1500.0,   # pkt_rate
    800000.0, # byte_rate
    3.2,      # src_ip_entropy
    2.1,      # dst_ip_entropy
    4.0,      # src_port_entropy
    1.5,      # dst_port_entropy
    0.3,      # proto_dist_tcp
    0.65,     # proto_dist_udp   ← cao → nghi UDP flood
    0.05,     # proto_dist_icmp
    0.05,     # syn_ratio
    0.02,     # fin_ratio
    548.0,    # avg_pkt_size
    120.0,    # pkt_size_std
    50.0,     # new_flows_rate
    200.0,    # flow_duration_mean
    0.8,      # inter_arrival_mean
    0.3,      # inter_arrival_std
], dtype=np.float32)

payload = engine.infer(features)
result = payload_to_dict(payload)

print(f"Attack type  : {result['detection']['attack_type']}")
print(f"Confidence   : {result['detection']['confidence']:.3f}")
print(f"P(attack+30s): {result['forecast']['p_attack_30s']:.3f}")
print(f"SHAP top-5   : {result['top_features']}")
print(f"Response tier: {result['response']['tier']}")
```

---

### Replay toàn bộ test set

```bash
# Chạy inference trên toàn bộ X_test.npy trong pad_onap_v3/processed/
python pipeline/s3_ai/inference_layer.py \
    --model-dir ./pad_onap_v3/models \
    --data-dir  ./pad_onap_v3/processed \
    --n-samples 500 \
    --device    auto \
    --out       ./pad_onap_v3/models/inference_replay_results.json

# Hoặc dùng default (đã trỏ vào pad_onap_v3):
python pipeline/s3_ai/inference_layer.py
```

Kết quả lưu tại `pad_onap_v3/models/inference_replay_results.json`.

---

### Luồng inference đầy đủ (end-to-end)

```
NetFlow Collector (7070/flows/latest)
    ↓  feature vector [17]
InferenceEngine.infer()
    ├─ StandardScaler.transform()
    ├─ XGBoost Booster → 4-class probs + SHAP top-5
    ├─ Rolling buffer [12 timesteps]
    └─ Transformer+LSTM → [P(t+30s), P(t+60s), P(t+90s), P(t+120s)]
    ↓
AIOutputPayload
    ├─ detection.attack_type    (Normal/UDP_Flood/SYN_Flood/Amplification)
    ├─ detection.confidence     (0–1)
    ├─ forecast.p_attack_30s/60s/90s/120s
    ├─ top_features             (SHAP top-5)
    └─ response.tier            (0–4: graduated NFV response)
    ↓
S4 ONAP Policy Framework (XACML → CLAMP → SO → VIM)
```

**5-tier graduated response:**

| Tier | Điều kiện | Hành động NFV |
|---|---|---|
| T0 | Normal | Không hành động |
| T1 | conf > 0.5 | Rate-limit nhẹ |
| T2 | conf > 0.8 hoặc P30 > 0.7 | Kích hoạt VNF firewall |
| T3 | conf > 0.9 và P30 > 0.9 | Scale-out VNF scrubber |
| T4 | Sustained attack | Traffic isolation |

---

## Các file mô hình trong pad_onap_v3/models/

| File | Mô tả |
|---|---|
| `xgboost_v3.json` | XGBoost Booster — 4-class (Normal/UDP/SYN/Amplification) |
| `transformer_v3.pt` | Transformer+LSTM state dict — 4-horizon binary forecast |
| `scaler.pkl` | StandardScaler fit trên 17 features của CICDDoS2019 |
| `xgb_label_map.json` | Mapping: label_to_idx và idx_to_label |
| `tf_best_config.json` | Best HP: hidden_dim=64, num_heads=2, lstm_hidden=128 |
| `transformer_metrics.json` | Kết quả: AUC h0=0.994, AUC mean=0.990 |

---

## Troubleshooting

**gNMI simulator không start:**
```bash
# Kiểm tra port 8080 có bị chiếm không
netstat -an | grep 8080
# Đổi port:
python testbed/gnmi_simulator/main.py --port 8081
```

**NetFlow collector lỗi kết nối gNMI:**
```bash
# Đảm bảo gNMI đang chạy trước
curl http://localhost:8080/health
# Nếu dùng Docker, dùng container hostname:
python testbed/netflow_collector/collector.py --gnmi http://gnmi-simulator:8080
```

**Inference lỗi load transformer:**
```bash
# Kiểm tra file tồn tại
ls pad_onap_v3/models/
# Phải có: xgboost_v3.json, transformer_v3.pt, scaler.pkl, tf_best_config.json

# Kiểm tra architecture khớp
python -c "
import json
with open('pad_onap_v3/models/tf_best_config.json') as f:
    print(json.load(f)['best_hp'])
"
# → {'hidden_dim':64,'num_heads':2,'num_layers':2,'lstm_hidden':128,'lstm_layers':1,...}
```

**Docker Compose không build được gnmi-simulator:**
```bash
cd testbed
docker build -t pad-gnmi-sim-test gnmi_simulator/
docker compose up -d
```
