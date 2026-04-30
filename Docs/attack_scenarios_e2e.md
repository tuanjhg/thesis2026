# Các kịch bản tấn công End-to-End

> Tài liệu này mô tả **toàn bộ luồng** từ khi tấn công được tạo ra → thu thập telemetry → AI phân tích → ONAP orchestration → VNF kích hoạt.  
> Gồm 3 tầng: Synthetic (test nhanh) · gNMI Simulator (có metric thật) · Mininet Real Traffic (full end-to-end).

---

## Kiến trúc luồng dữ liệu tổng quát

```
┌─────────────────────────────────────────────────────────────────────┐
│                       TẦNG TẤN CÔNG                                 │
│                                                                     │
│  [Synthetic]   numpy.array(17,) ──────────────────────┐            │
│  [gNMI Sim]    hping3/script → gNMI REST → metric     │            │
│  [Mininet]     h0 hping3 → OVS switch → softflowd     │            │
└───────────────────────────────────────────────────────┼────────────┘
                                                        │
┌───────────────────────────────────────────────────────▼────────────┐
│                       S1 TELEMETRY                                  │
│   NetFlow v5 collector (port 6343) / gNMI HTTP REST (port 8080)    │
│   Kafka topic: raw-metrics                                          │
└───────────────────────────────────────────────────────┬────────────┘
                                                        │
┌───────────────────────────────────────────────────────▼────────────┐
│                    S2 FEATURE EXTRACTION                             │
│   17 features: pkt_rate, byte_rate, entropy×4, protocol×3,          │
│   syn_ratio, fin_ratio, avg_pkt_size, pkt_size_std,                 │
│   new_flows_rate, flow_duration_mean, inter_arrival×2               │
│   Cửa sổ 5 giây · chuẩn hoá MinMaxScaler                           │
└───────────────────────────────────────────────────────┬────────────┘
                                                        │
┌───────────────────────────────────────────────────────▼────────────┐
│                       S3 AI INFERENCE                                │
│   XGBoost 7-class (attack_type, confidence)                         │
│   Transformer+LSTM 4-horizon (P30s/P60s/P90s/P120s)                │
│   AIOutputPayload → DMaaP bus                                       │
└───────────────────────────────────────────────────────┬────────────┘
                                                        │
┌───────────────────────────────────────────────────────▼────────────┐
│                    S4 ORCHESTRATION (ONAP)                           │
│   TierMapper → PolicyEngine → CLAMPClient → ONAPSOClient            │
│                                           → SFCManager              │
│                                           → SLAAllocator            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Tầng 1 — Synthetic Scenarios (S1–S8)

**Mục đích:** Test AI + Orchestration logic không cần Mininet. Sinh feature vector trực tiếp bằng numpy.

### Cách chạy

```bash
# Tất cả 8 kịch bản (cần model files trong pad_onap_v3/models/)
python -m evaluation.scenarios \
  --model-dir ./pad_onap_v3/models \
  --data-dir  ./pad_onap_v3/processed \
  --out-dir   ./evaluation/results

# Chạy 1 kịch bản
python -m evaluation.scenarios --scenario S8
```

### Chi tiết 8 kịch bản

---

#### S1 — Normal Baseline

**Luồng:**
```
numpy: _normal_features(100)
 ├─ pkt_rate ~ Uniform(50, 200)
 ├─ src_ip_entropy ~ Uniform(2.5, 3.5)   ← cao = lưu lượng đa dạng, bình thường
 └─ udp_ratio ~ Uniform(0.1, 0.3)
        │
        ▼
AI: confidence < 0.50 → attack_class = 0
        │
        ▼
Policy: HOLD → Tier T0 → không khởi VNF
```

**Mong đợi:** 100 cửa sổ đều T0, proactive = 0  
**Kiểm tra gì:** false positive rate = 0

---

#### S2 — UDP Flood Đột Ngột (Reactive T3)

**Luồng:**
```
numpy: 30 windows bình thường
       → 50 windows UDP flood
          ├─ pkt_rate ~ Uniform(7500, 30000)  intensity×1.5
          ├─ udp_ratio ~ Uniform(0.85, 1.0)
          └─ src_ip_entropy ~ Uniform(0.0, 0.5)  ← thấp = IP spoofed
       → 30 windows bình thường
        │
        ▼
AI: conf ≥ 0.85 → attack_type = UDP_Flood → Tier MITIGATE
        │
        ▼
SO: instantiate vnfd-scrubber-v1 (~6000ms)
SFC: install OVS rule → traffic qua scrubber
LatencyTracker: T3_p50 ≈ 6006ms
```

**Mong đợi:** max_tier = T3, T3_p50 ≈ 6006ms  
**Kiểm tra gì:** detection accuracy, VNF instantiation time

---

#### S3 — SYN Flood Tăng Dần (Proactive T2)

**Luồng:**
```
numpy: 30 bình thường
       → 30 windows RAMP: bình thường → SYN flood (tuyến tính)
          ├─ syn_ratio tăng từ 0.0 → 0.99
          └─ pkt_rate tăng từ ~100 → ~15000
       → 30 windows SYN flood mạnh
       → 30 bình thường
        │
        ▼
Transformer forecast: P(t+30s) vượt 0.50 sớm khi ramp ~50%
        │
        ▼
Policy: proactive = True → Tier T2 (PREEMPT)
SO: instantiate vnfd-ratelimiter-v1 (~500ms)
```

**Novelty:** T2 khởi động 500ms trong khi T3 cần 6000ms.  
**Proactive lead-time:** ~67 cửa sổ × 5s = **~335 giây** trước khi T3 reactive phải bật  
**Mong đợi:** max_tier = T2, proactive_count = 67, T2_p50 ≈ 506ms

---

#### S4 — HTTP Flood Out-of-Distribution (OOD Graceful)

**Luồng:**
```
numpy: _http_flood_features()
  ├─ pkt_rate ~ Uniform(1000, 5000)   ← vừa phải
  ├─ new_flows_rate ~ Uniform(50, 200) ← nhiều flows mới
  └─ proto_dist_tcp = 1.0              ← all TCP, trông giống người dùng thật
        │
        ▼
AI: XGBoost không nhận ra kiểu tấn công này (HTTP flood chưa có trong CICDDoS2019)
    → confidence thấp, class ambiguous
        │
        ▼
Policy: max tier = T1 (Alert), KHÔNG leo thang T3
```

**Mong đợi:** max_tier ≤ T1 — chứng minh robustness OOD  
**Kiểm tra gì:** không over-escalate khi gặp traffic lạ

---

#### S5 — ICMP Amplification Out-of-Distribution

**Luồng:**
```
numpy: _icmp_amp_features()
  ├─ proto_dist_icmp ~ Uniform(0.7, 1.0)  ← ICMP chiếm ưu thế
  ├─ pkt_rate ~ Uniform(2000, 8000)
  └─ avg_pkt_size ~ Uniform(512, 1500)    ← gói lớn (reflected)
        │
        ▼
AI: ICMP_Flood không trong train set → confidence dưới ngưỡng
        │
        ▼
Policy: Tier T0 (NORMAL)
```

**Mong đợi:** max_tier = T0 — không false positive  
**Kiểm tra gì:** hệ thống không "hoảng loạn" với protocol lạ

---

#### S6 — Multi-Attack (UDP → SYN kế tiếp)

**Luồng:**
```
numpy: 30 bình thường
       → 30 UDP flood (intensity=1.0)
       → 10 bình thường (cooldown)
       → 30 SYN flood
       → 30 bình thường
        │
        ▼
Phase 1 UDP:  conf ≥ 0.85 → T3 reactive
              SO: scrubber ON
Phase cooldown: de-escalate → scrubber OFF
Phase 2 SYN:  Transformer forecast → T2 proactive
              SO: ratelimiter ON
        │
        ▼
LatencyTracker: ghi 2 VNF instantiation events
```

**Mong đợi:** max_tier=T3, proactive_count=48, tier switching T3→T0→T2  
**Kiểm tra gì:** hysteresis (không flip tier liên tục), de-escalation đúng

---

#### S7 — SLA Fairness 3-Tenant

**Luồng:**
```
numpy: SYN flood intensity=1.2
  → AI: T2 proactive
  → SO: vnfd-ratelimiter (~500ms VNF overhead = 20 Mbps)
        │
        ▼
SLAAllocator.allocate():
  Input: overhead=20 Mbps, total_bw=1000 Mbps
  Tenants:
    eMBB  (demand=450, guarantee=200, weight=1.0)
    URLLC (demand=150, guarantee=100, weight=2.0)  ← ưu tiên cao
    mMTC  (demand=300, guarantee=50,  weight=0.5)
  LP solver (scipy.linprog):
    → URLLC nhận đủ guarantee 100 Mbps dù overhead
    → phần dư phân theo weighted proportional
```

**Mong đợi:** sla_satisfied = True với 120 cửa sổ; URLLC không bị cắt  
**Kiểm tra gì:** fairness LP hoạt động đúng khi có VNF overhead

---

#### S8 — Key Novelty: Proactive T2 vs Reactive T3

**Luồng chi tiết nhất — đây là slide trung tâm của luận văn:**

```
numpy:
  Phase 1: 30 windows bình thường (fill Transformer buffer)
  Phase 2: 25 windows SYN moderate (intensity=0.35, seed=99)
             └─ pkt_rate ~ 1050–5250, syn_ratio ~ 0.245–0.347
  Phase 3: 35 windows UDP mạnh   (intensity=1.5,  seed=77)
             └─ pkt_rate ~ 7500–30000, udp_ratio ~ 0.85–1.0
  Phase 4: 30 windows bình thường

                           │
          ┌────────────────┴────────────────┐
          │                                 │
          ▼ NHÁNH PROACTIVE                 ▼ NHÁNH REACTIVE
  Phase 2: P(t+30s) ≥ 0.5           Phase 3: conf ≥ 0.85
  → Tier T2 (PREEMPT)                → Tier T3 (MITIGATE)
  SO: ratelimiter                    SO: scrubber
  Latency: ~505ms                    Latency: ~6006ms
          │                                 │
          └─────────────┬───────────────────┘
                        │
                        ▼
              NOVELTY DELTA ≈ 5501ms
              (5.5 giây mỗi lần phản ứng)
```

**Mong đợi:**
- T2_p50 ≈ 505ms · T3_p50 ≈ 6006ms
- proactive_count = 30
- max_tier = T3 (thấy cả T2 và T3)

---

## Tầng 2 — gNMI Simulator Scenarios

**Mục đích:** Metric "chạy thật" theo thời gian thực, không cần Mininet. Simulator bóp méo in_pkts/syn_ratio trên 1 thiết bị.

### Khởi động stack

```bash
# Terminal 1 — gNMI Simulator (port 8080)
python3 testbed/gnmi_simulator/main.py

# Terminal 2 — NetFlow Collector synthetic mode (port 7070)
python3 testbed/netflow_collector/collector.py \
  --mode synthetic \
  --gnmi http://localhost:8080

# Terminal 3 — Orchestrator (đọc từ collector)
python3 -m pipeline.s4_orchestration.orchestrator \
  --source http \
  --collector http://localhost:7070 \
  --model-dir ./pad_onap_v3/models \
  --data-dir  ./pad_onap_v3/processed

# Terminal 4 — Chạy scenario
python3 testbed/anomaly_injector/scenarios.py --scenario ddos_udp --duration 60
```

### 4 kịch bản gNMI

| Kịch bản | Target | Loại | Duration | Mong đợi |
|---|---|---|---|---|
| `ddos_udp` | `r1` | UDP flood | 60s | XGBoost detect < 5s, T3 bật |
| `bw_ramp` | `r1` | Gradual BW | 300s | Transformer forecast ở bước 4 (~40%) |
| `cpu_spike` | `r2` | CPU 30→95% | 60s | T2 pre-warm bật khi CPU > 80% |
| `cross_slice` | `r1→r3` | Cross-slice | 90s | URLLC isolation T4 |

#### gNMI Scenario: ddos_udp

```
Anomaly Injector:
  POST /attack/start {type: udp_flood, target: r1}
        │
        ▼
gNMI Simulator (r1):
  tick_udp_flood(intensity=1.0):
    in_pkts   × (1 + 0.8 × scale)  ← nhân ~1.8 mỗi tick (500ms)
    udp_ratio → 0.85–0.98
    syn_ratio → 0.0–0.03
    cpu_pct   → 80–95%
        │
        ▼ HTTP GET /metrics/r1 mỗi 1s
NetFlow Collector (synthetic mode):
  fetch gNMI → compute 17 features → expose /flows/latest
        │
        ▼
Orchestrator:
  fetch /flows/latest → _step() → AI → tier → SO/SFC
        │
        ▼
LatencyTracker → Prometheus :9292
  (quan sát: detection_ms, tier_change_ms, vnf_active_ms)
```

#### gNMI Scenario: bw_ramp

```
ramp_steps = 10 bước × 30s = 300s tổng
Mỗi bước: in_pkts tăng thêm ~10%
Điểm quan trọng:
  Bước 4 (~40%): Transformer forecast P(t+30s) nên vượt 0.5
  Bước 7 (~70%): Saturation warning in log
  Bước 10 (100%): Congestion collapse
Mong đợi: T2 PREEMPT bật ở bước 3–5 (proactive)
```

#### gNMI Scenario: cross_slice

```
Inject flood trên r1
Đo spillover = avg_r3 / avg_r1
Nếu r1→r3 link bị bão hoà:
  → mMTC traffic trên r3 bị ảnh hưởng
  → SLA URLLC vi phạm
  → Policy escalate T4 ISOLATE
  → SFC: block cross-slice port trên r2
```

---

## Tầng 3 — Mininet Real Traffic (End-to-End thật sự)

**⚠️ Cần Linux + Mininet + softflowd**  
**Đây là tầng cần hoàn thiện (task P0.3 trong next-step-plan.md)**

### Chuẩn bị

```bash
# Cài phụ thuộc (Ubuntu 20.04+)
sudo apt-get install -y mininet hping3 iperf3 softflowd

# Terminal 1 — Khởi động Mininet topology
sudo python3 testbed/mininet/topology.py

# Trong Mininet CLI, chạy softflowd trên mỗi switch để export NetFlow:
mininet> r1 softflowd -d -i r1-eth0 -n 127.0.0.1:6343
mininet> r2 softflowd -d -i r2-eth0 -n 127.0.0.1:6343
mininet> r3 softflowd -d -i r3-eth0 -n 127.0.0.1:6343

# Terminal 2 — NetFlow Collector real mode
python3 testbed/netflow_collector/collector.py \
  --mode netflow --port 6343

# Terminal 3 — Orchestrator
python3 -m pipeline.s4_orchestration.orchestrator \
  --source http --collector http://localhost:7070 \
  --model-dir ./pad_onap_v3/models \
  --data-dir  ./pad_onap_v3/processed
```

### Kịch bản A — UDP Flood (eMBB slice)

```
Trong Mininet CLI:
  mininet> embb_dst iperf3 -s -u &
  mininet> embb_src hping3 --udp --flood -p 80 10.1.0.2

Luồng gói tin:
  embb_src (10.1.0.1)
      │ UDP flood ~100K pkt/s
      ▼
   switch r1 (OVS)
      │ softflowd capture flow records → UDP port 6343
      ▼
   collector.py parse NetFlow v5
      │ compute 17 features
      ▼
   Orchestrator: AI detect → T3 → SO scrubber ON
      │ SFCManager: ovs-ofctl add-flow r1 traffic→scrubber
      ▼
   embb_src traffic đi qua vnf_scrubber (192.168.1.12)
      │ rate limit áp dụng
      ▼
   embb_dst nhận traffic đã được lọc
```

**Đo lường:**
```bash
# Kiểm tra OVS flow rule được cài:
mininet> r1 ovs-ofctl dump-flows r1

# Đo throughput trước / sau khi scrubber bật:
mininet> embb_dst iperf3 -s &
mininet> embb_src iperf3 -c 10.1.0.2 -u -b 1G -t 10
```

### Kịch bản B — SYN Flood (URLLC slice)

```
Trong Mininet CLI:
  mininet> urllc_dst iperf3 -s &
  mininet> urllc_src hping3 -S --flood -p 443 10.2.0.2

Đặc trưng SYN flood:
  syn_ratio → 0.90+
  fin_ratio → ~0.0
  pkt_rate  → 3000–15000 pkt/s
        │
        ▼
Nếu ramp dần (intensity tăng):
  Transformer forecast P(t+30s) > 0.5
  → Proactive T2: ratelimiter ON trước
  → Khi đạt ngưỡng conf 0.85: T3 escalate
```

**Đo proactive lead-time thật:**
```bash
# Log orchestrator ghi thời điểm tier change:
grep "T0→T2\|T2→T3" orchestrator.log
# Tính: t(T2) - t(T3_would_have_been) = lead time thực
```

### Kịch bản C — Cross-Slice Attack (eMBB → URLLC)

```
Topology:   embb_src → r1 ←→ r3 → urllc_dst
                             ↑
                          cross-slice link (100 Mbps)

Tấn công: embb_src flood qua r1, tràn sang r3 link:
  mininet> embb_src hping3 --udp --flood -p 53 10.3.0.1

Hiệu ứng:
  r1 → r3 link bão hoà
  URLLC traffic bị tranh giành băng thông
  SLA URLLC vi phạm (latency tăng)
        │
        ▼
Orchestrator:
  SLA check: URLLC demand > allocation → sla_satisfied = False
  Policy: T4 ISOLATE → block cross-slice port r1-eth(r3)
  SFC: ovs-ofctl drop flows src=eMBB-subnet on r3
        │
        ▼
URLLC slice được cô lập, latency trở về < 1ms
```

**Đo SLA recovery time:**
```bash
# Ping URLLC liên tục, đo thời gian latency cao:
mininet> urllc_src ping -i 0.1 10.2.0.2 | ts '%H:%M:%.S'
# Quan sát: latency tăng khi tấn công → giảm sau khi SFC isolation bật
```

### Kịch bản D — Fat-Tree Multi-Pod Attack

```
Topology: fat-tree k=4 (sudo python3 testbed/mininet/fat_tree_topology.py)

Attacker: h0 (10.0.0.1, pod 0, edge 0)
Victim:   h15 (10.3.1.16, pod 3, edge 1)
Path: h0 → e0_0 → a0_0 → c1 → a3_0 → e3_1 → h15
      (xuyên 3 pod, qua core)

Inject attack:
  mininet> h0 hping3 --udp --flood 10.3.1.16

So sánh:
  # Cùng pod (h0 vs h1 — e0_0 → e0_1):
  #   SFC rule propagate: chỉ cần 1 edge switch rule → ~1ms
  # Khác pod (h0 vs h15 — 3 hop):
  #   SFC rule propagate: edge + agg + core rule → ~5ms?
  # → Chứng minh cost của multi-pod steering
```

---

## Metrics cần thu trong mỗi kịch bản

| Metric | Nguồn | Ý nghĩa |
|---|---|---|
| `detection_latency_ms` | log orchestrator | Từ cửa sổ đầu tiên feature → tier change |
| `vnf_instantiation_ms` | LatencyTracker | Từ SO request → VNF ACTIVE |
| `sfc_install_ms` | SFCManager | Từ VNF ACTIVE → OVS rule cài xong |
| `end_to_end_ms` | LatencyTracker | Tổng detection + VNF + SFC |
| `proactive_lead_time_s` | lead_time_analyzer | T2 sớm hơn T3 bao nhiêu giây |
| `sla_satisfied` | SLAAllocator | URLLC/eMBB/mMTC có đủ guaranteed BW |
| `false_positive_rate` | S1/S4/S5 | Tier > 0 khi không tấn công |
| `spillover_ratio` | cross_slice | Traffic r3/r1 khi cross-slice attack |

---

## Lệnh chạy nhanh — Quick Reference

```bash
# === Synthetic (không cần Mininet) ===
python -m evaluation.scenarios                    # S1–S8 all
python -m evaluation.scenarios --scenario S8      # chỉ S8
python -m evaluation.baseline_threshold           # baseline so sánh
python -m evaluation.lead_time_analyzer           # lead-time report

# === gNMI Simulator ===
python3 testbed/gnmi_simulator/main.py &
python3 testbed/netflow_collector/collector.py --mode synthetic &
python3 -m pipeline.s4_orchestration.orchestrator --source http &
python3 testbed/anomaly_injector/scenarios.py --list
python3 testbed/anomaly_injector/scenarios.py --scenario ddos_udp
python3 testbed/anomaly_injector/scenarios.py --all

# === Mininet (cần Linux + sudo) ===
sudo python3 testbed/mininet/topology.py --test
sudo python3 testbed/mininet/fat_tree_topology.py --k 4 --test

# === Prometheus metrics ===
curl http://localhost:9292/metrics | grep pad_onap
```

---

## Tổng hợp mapping kịch bản

| Kịch bản | Tầng | Target | Loại AI action | Mong đợi |
|---|---|---|---|---|
| S1 Normal | Synthetic | — | None | T0 suốt |
| S2 UDP flood | Synthetic | feature | Reactive T3 | T3 p50=6006ms |
| S3 SYN ramp | Synthetic | feature | **Proactive T2** | T2 p50=506ms |
| S4 HTTP OOD | Synthetic | feature | Graceful (T1) | max T1 |
| S5 ICMP OOD | Synthetic | feature | Graceful (T0) | max T0 |
| S6 Multi | Synthetic | feature | T3→T0→T2 | tier switching |
| S7 SLA | Synthetic | feature | T2 + LP alloc | sla_ok=True |
| S8 Novelty | Synthetic | feature | Proactive vs Reactive | Δ≈5.5s |
| ddos_udp | gNMI Sim | r1 | Reactive T3 | detect <5s |
| bw_ramp | gNMI Sim | r1 | **Proactive T2** | forecast @40% |
| cpu_spike | gNMI Sim | r2 | T2 pre-warm | peak CPU >80% |
| cross_slice | gNMI Sim | r1→r3 | T4 isolate | spillover đo |
| A: UDP Real | Mininet | embb_src→dst | T3 + SFC OVS | rule dump verify |
| B: SYN Real | Mininet | urllc slice | T2 proactive real | lead-time real |
| C: Cross-slice | Mininet | r1↔r3 | T4 + URLLC protect | latency recover |
| D: Fat-tree | Fat-tree | h0→h15 | T3 multi-pod | SFC cost cross-pod |

---

_Xem thêm: `Docs/thesis_explained_simply.md` (giải thích không kỹ thuật) · `evaluation/scenarios.py` (code S1–S8) · `testbed/anomaly_injector/scenarios.py` (gNMI scenarios)_
