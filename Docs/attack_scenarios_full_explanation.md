# Giải thích đầy đủ các kịch bản tấn công — PAD-ONAP

> **Câu hỏi cốt lõi**: Hệ thống đang tấn công vào 1 IP do Mininet tạo ra, hay cần tấn công vào thành phần thật trong hệ thống ONAP?
>
> **Trả lời ngắn gọn**: Tấn công vào **IP mạng ảo (Mininet/gNMI)**, **không phải** vào thành phần ONAP. ONAP là **hệ thống phản ứng**, không phải mục tiêu tấn công.

---

## Phần 1 — Kiến trúc tổng quan: Ai tấn công ai?

```
┌─────────────────────────────────────────────────────────────────────┐
│                    LUỒNG DỮ LIỆU TỔNG QUÁT                          │
│                                                                     │
│  [Attacker]  ──packet──▶  [Victim IP / Switch]                     │
│                                    │                                │
│                           đo traffic metrics                        │
│                                    │                                │
│                            [AI Pipeline]  ◀── phân tích            │
│                                    │                                │
│                           phát hiện tấn công                       │
│                                    │                                │
│                              [ONAP]  ◀── ra lệnh phản ứng          │
│                           SO / CLAMP / Policy                       │
│                                    │                                │
│                           triển khai VNF                            │
│                                    │                                │
│                           [VNF: Scrubber/Ratelimiter]               │
│                                    │                                │
│                          lọc traffic độc hại                        │
└─────────────────────────────────────────────────────────────────────┘

  ONAP = hệ thống ĐIỀU PHỐI phản ứng
  Không phải mục tiêu bị tấn công!
```

---

## Phần 2 — 3 Lớp kịch bản: Khác nhau hoàn toàn

Hệ thống có **3 lớp kịch bản độc lập** — mỗi lớp dùng khác nhau ở mức độ thực:

```
Lớp 1: SYNTHETIC  ←── Thuần python (không có mạng thật)
Lớp 2: gNMI SIM   ←── Giả lập số (không có packet thật)
Lớp 3: MININET    ←── Mạng ảo (có packet thật, IP ảo)
                                     ↕
                         (kết hợp với ONAP thật → Lớp 4)
Lớp 4: ONAP REAL  ←── Mininet + ONAP OOM thật (chưa chạy)
```

---

## Phần 3 — Lớp 1: Synthetic (evaluation/scenarios.py)

### Không có IP nào cả

```python
# Cách tạo tấn công:
X = np.array([
    [18000, 3000000, 0.1, 1.5, ...],   # ← vector 17 số
    [22000, 4500000, 0.08, 1.3, ...],  # ← không phải packet
])
# Đây là dữ liệu đặc trưng được tính toán sẵn
# Không có mạng, không có IP, không có packet nào chạy
```

### Cơ chế hoạt động

```
[numpy array 17 features]
        │
        ▼
[XGBoost / Transformer] ── phân loại ──▶ UDP_Flood, conf=0.92
        │
        ▼
[Orchestrator._step()]
        │
        ├──▶ CLAMPClient  (stub: giả vờ push policy)
        ├──▶ ONAPSOClient  (stub: giả vờ tạo VNF)
        └──▶ SFCManager    (stub: giả vờ cài flow)
```

### Các kịch bản S1–S8

| Kịch bản | Mô tả | Mục tiêu |
|----------|-------|---------|
| S1 | Normal traffic 100 windows | Tier 0 xuyên suốt |
| S2 | Normal → UDP Flood đột ngột | Phải đạt Tier 3 |
| S3 | SYN Flood tăng dần (ramp) | Proactive T2 trước T3 |
| S4 | HTTP Flood (OOD, không có trong training) | Không được leo thang sai |
| S5 | ICMP burst ngắn (OOD) | Không được leo thang sai |
| S6 | UDP Flood → SYN Flood (đổi kiểu) | Phải chuyển Tier đúng |
| S7 | SYN Flood + SLA 3 tenant | LP allocator giữ URLLC floor |
| S8 | SYN nhẹ (proactive T2) → UDP mạnh (T3) | Đo lead_time_s |

### Kết quả thực tế

```
8/8 PASS
T2_p50 ≈ 506 ms   (VNF ratelimiter, stub)
T3_p50 ≈ 6006 ms  (VNF scrubber, stub)
lead_time_s = 25–35 s  (S8 novelty)
```

> **Ý nghĩa**: Kịch bản Synthetic dùng để chứng minh AI pipeline hoạt động đúng.  
> Không cần mạng, không cần ONAP thật.

---

## Phần 4 — Lớp 2: gNMI Simulator (testbed/)

### Tấn công vào "device name" — không phải IP

```
POST http://localhost:8080/attack/start
Body: {"type": "udp_flood", "target": "r1"}
```

**"r1" ở đây là gì?**

```python
# testbed/gnmi_simulator/main.py
DEVICES = ['r1', 'r2', 'r3']   # ← chỉ là string trong Python dict

class SimulationState:
    def __init__(self):
        self.devices = {
            'r1': DeviceMetrics('r1'),   # ← object Python
            'r2': DeviceMetrics('r2'),   #    không phải switch thật
            'r3': DeviceMetrics('r3'),   #    không phải IP thật
        }
```

**r1 KHÔNG phải**:
- Switch OVS thật
- IP address thật
- Thiết bị vật lý

**r1 LÀ**:
- Một object Python `DeviceMetrics`
- Có các số giả lập: `in_pkts`, `cpu_pct`, `udp_ratio`, ...
- Được cập nhật mỗi 500ms theo công thức toán học

### Cách gNMI Simulator giả lập tấn công

```python
def tick_udp_flood(self, intensity=1.0):
    # Chỉ thay đổi CON SỐ trong bộ nhớ Python
    self.values['in_pkts']   *= (1 + 0.8)   # tăng 80% mỗi tick
    self.values['udp_ratio'] += 0.15         # tăng UDP ratio
    self.values['cpu_pct']   += 3.0          # tăng CPU
    # Không có packet thật nào chạy!
```

### Luồng dữ liệu gNMI

```
[anomaly_injector/scenarios.py]
  POST /attack/start {type: udp_flood, target: r1}
              │
              ▼
[gnmi_simulator/main.py] ── thay đổi số trong dict Python
              │
              ▼
[netflow_collector/collector.py] ── GET /metrics/r1
              │    trả về {in_pkts: 450000, udp_ratio: 0.92, ...}
              ▼
[AI Pipeline (Orchestrator)]
              │
              ▼
[ONAP (stub)] ── không gọi ONAP thật
```

### 4 kịch bản gNMI

| Tên | Code | Target | Mô tả |
|-----|------|--------|-------|
| S1_ddos_udp | `_run_ddos_udp()` | r1 | UDP flood 100K pkt/s giả lập |
| S2_bw_ramp | `_run_bw_ramp()` | r1 | BW tăng dần 10 bước |
| S3_cpu_spike | `_run_cpu_spike()` | r2 | CPU r2: 30% → 95% |
| S4_cross_slice | `_run_cross_slice()` | r1 → r3 | Tràn slice eMBB sang URLLC |

> **Ý nghĩa**: gNMI Simulator dùng để test pipeline thu thập + phân tích metric thật.  
> "Tấn công" chỉ là thay đổi con số trong bộ nhớ RAM của Python.

---

## Phần 5 — Lớp 3: Mininet (testbed/mininet/topology.py)

### Đây là lớp DUY NHẤT có packet thật và IP thật

**Nhưng IP này do Mininet tạo ra trong Linux namespace ảo — không phải thiết bị vật lý.**

### Sơ đồ IP topology

```
eMBB slice (1Gbps):
  embb_src  [10.1.0.1] ──▶ r1 (OVS) ──▶ vnf_fw [192.168.1.10] ──▶ r2 ──▶ embb_dst [10.1.0.2]

URLLC slice (<1ms RTT):
  urllc_src [10.2.0.1] ──▶ r1 (OVS) ──▶ vnf_lb [192.168.1.11] ──▶ r2 ──▶ urllc_dst [10.2.0.2]

mMTC slice (10Mbps):
  mmtc_src  [10.3.0.1] ──▶ r3 (OVS) ──────────────────────────▶ r2 ──▶ mmtc_dst [10.3.0.2]

VNFs dự phòng (gắn vào r2):
  vnf_scrubber  [192.168.1.12] ── T3 (DDoS Scrubber)
  vnf_isolation [192.168.1.13] ── T4 (Tenant Isolation)

Cross-slice attack vector: r1 ◀──▶ r3
```

### Cách chạy tấn công thật trong Mininet

```bash
# Bước 1: Khởi động Mininet topology
sudo python3 testbed/mininet/topology.py

# Bước 2: Trong Mininet CLI, tấn công UDP flood thật
# embb_src tấn công embb_dst (10.1.0.2)
mininet> embb_src hping3 -u --flood -p 80 10.1.0.2

# Hoặc tấn công SYN flood thật
mininet> embb_src hping3 -S --flood -p 443 10.1.0.2

# Bước 3: Đo traffic trên r1 (OVS switch)
mininet> r1 ovs-ofctl dump-flows r1
```

### Điều gì là thật trong Mininet?

| Thành phần | Thật không? | Giải thích |
|-----------|-------------|-----------|
| IP address (10.1.0.x) | ✅ Thật (trong namespace Linux) | Có thể ping, có thể route |
| OVS Switch (r1/r2/r3) | ✅ Thật | Open vSwitch kernel module |
| Packet (hping3, iperf) | ✅ Thật | Kernel xử lý packet thật |
| Network interface | ✅ Thật (veth pair) | `ip link show` thấy được |
| Physical hardware | ❌ Không | Chỉ là veth trong kernel |
| Internet reachable | ❌ Không | Namespace cô lập |

### Victim là ai?

Trong kịch bản Mininet:
- **Kịch bản UDP Flood**: `embb_src` tấn công `embb_dst` (10.1.0.2)
- **Kịch bản Cross-slice**: `embb_src` → r1 → r3 → ảnh hưởng `urllc_dst` (10.2.0.2)
- **Kịch bản fat-tree**: `h0` (pod 0) tấn công `h15` (pod 3)

> **Ý nghĩa**: Mininet dùng để test SFC rule cài xuống OVS thật, đo RTT thật, và chứng minh VNF divert traffic thật.

---

## Phần 6 — Lớp 4: ONAP OOM Thật (run_s2_real.py / run_s8_real.py)

### Đây là kịch bản hoàn chỉnh nhất — chưa thực sự chạy

```
[Mininet Topology đang chạy]
  embb_src → r1 → embb_dst
                   ↑
           hping3 flood (packet thật)
                   ↑
          [Netflow Collector]
          đọc traffic từ OVS r1
                   ↑
          [AI Pipeline]
          phát hiện tấn công
                   ↑
          [ONAP OOM Thật]
          ├── SO instantiate scrubber VNF
          ├── CLAMP push policy
          └── PAP xác nhận
                   ↑
          [OVS SFC Rule thật]
          traffic → vnf_scrubber (192.168.1.12)
```

### Các component ONAP liên quan (thật)

| ONAP Component | Vai trò | Endpoint |
|---------------|---------|---------|
| SO (Service Orchestrator) | Tạo/xóa VNF instance | `http://so.onap.svc:8080` |
| CLAMP | Push operational policy | gọi Policy PAP |
| Policy PAP | Deploy policy xuống PDP | `http://policy-pap.onap.svc:6969` |
| DMaaP (Kafka) | Event bus AI → CLAMP | topic `PAD_ONAP_AI_SIGNALS` |

### ONAP có phải victim bị tấn công không?

**KHÔNG.** ONAP là hệ thống điều phối, không phải victim.

```
                    TẤN CÔNG VÀO ĐÂY
                           ↓
[embb_src] ──flood──▶ [embb_dst: 10.1.0.2]
                                │
                        traffic metrics
                                │
                          [AI Pipeline]
                                │
                        ra lệnh phản ứng
                                │
                          [ONAP SO/CLAMP]  ← điều phối ở đây
                                │
                     triển khai VNF
                                │
                    [vnf_scrubber: 192.168.1.12]
                                │
                      lọc packet độc hại
                                │
                       [embb_dst được bảo vệ]
```

---

## Phần 7 — So sánh 4 lớp đầy đủ

| Tiêu chí | Synthetic | gNMI Sim | Mininet | ONAP Real |
|---------|-----------|----------|---------|-----------|
| **Có packet thật?** | ❌ | ❌ | ✅ | ✅ |
| **Có IP thật?** | ❌ | ❌ | ✅ (namespace) | ✅ (namespace) |
| **Target là gì?** | numpy vector | string 'r1' | IP 10.1.0.2 | IP 10.1.0.2 |
| **AI pipeline chạy?** | ✅ | ✅ | ✅ | ✅ |
| **ONAP được gọi?** | Stub | Stub | Stub | ✅ Thật |
| **VNF thật?** | ❌ | ❌ | ❌ (placeholder) | ✅ Docker |
| **OVS rule thật?** | ❌ | ❌ | ✅ | ✅ |
| **Cần K8s?** | ❌ | ❌ | ❌ | ✅ (64GB RAM) |
| **Đã chạy được?** | ✅ 8/8 PASS | ✅ | Cần sudo Linux | Scripts mới viết |

---

## Phần 8 — Cách chạy từng lớp

### Lớp 1 — Synthetic (không cần gì)

```bash
# Chạy toàn bộ 8 kịch bản
python -m evaluation.scenarios \
  --model-dir pad_onap_v3/models \
  --data-dir  pad_onap_v3/processed \
  --out-dir   evaluation/results

# Kết quả: evaluation/results/evaluation_summary.json
# 8/8 PASS, mất ~2 phút
```

### Lớp 2 — gNMI Simulator (cần Python, không cần Linux đặc biệt)

```bash
# Terminal 1: Khởi động gNMI simulator
python testbed/gnmi_simulator/main.py --port 8888

# Terminal 2: Chạy kịch bản tấn công
python testbed/anomaly_injector/scenarios.py \
  --scenario ddos_udp \
  --gnmi http://localhost:8888 \
  --duration 60

# Hoặc chạy tất cả
python testbed/anomaly_injector/scenarios.py --all
```

### Lớp 3 — Mininet (cần Linux + sudo)

```bash
# Yêu cầu: Ubuntu/Debian, Mininet installed, Open vSwitch
# KHÔNG chạy được trên Windows trực tiếp

# Bước 1: Khởi động topology
sudo python3 testbed/mininet/topology.py

# Bước 2: Trong Mininet CLI
mininet> embb_src hping3 -u --flood -p 80 10.1.0.2 &
mininet> r1 ovs-ofctl dump-flows r1   # xem flow rules

# Bước 3: Dừng
mininet> embb_src kill %1
mininet> exit
```

### Lớp 4 — ONAP Real (cần K8s cluster 64GB RAM)

```bash
# Bước 1: Deploy ONAP OOM
helm install onap onap/onap -n onap -f onap/values-override.yaml

# Bước 2: Port-forward
kubectl port-forward -n onap svc/so 8080:8080
kubectl port-forward -n onap svc/policy-pap 6969:6969

# Bước 3: Chạy S2 (UDP flood → scrubber VNF ~6s)
PAD_ONAP_STUB=false python onap/scripts/run_s2_real.py \
  --attack-mode gnmi \
  --bridge br-pad

# Bước 4: Chạy S8 (Proactive T2 → Reactive T3, lead_time ≥25s)
PAD_ONAP_STUB=false python onap/scripts/run_s8_real.py \
  --bridge br-pad
```

---

## Phần 9 — Tại sao thiết kế như vậy?

### Câu hỏi: Tại sao không tấn công trực tiếp vào ONAP?

**Vì ONAP không phải là data center network.** Luận văn nghiên cứu:

```
"AI-Augmented NFV Orchestration for Proactive DDoS Mitigation
 in Data Center Network"
        ↑                    ↑                  ↑
  AI + NFV           ONAP = hệ thống     DCN = mạng
  là đóng góp        điều phối           bị bảo vệ
```

- **DCN** (Data Center Network) = Mininet topology (eMBB/URLLC/mMTC slices)
- **DDoS attack** nhắm vào máy chủ/switch trong DCN (`embb_dst`, `r1`, ...)
- **ONAP** ngồi ngoài DCN, nhận tín hiệu từ AI, ra lệnh deploy VNF
- **VNF** (scrubber/ratelimiter) được deploy vào DCN để lọc traffic

### Câu hỏi: Tại sao dùng 3 lớp thay vì 1 lớp thật?

| Lý do | Giải thích |
|-------|-----------|
| **Reproducibility** | Synthetic chạy được trên bất kỳ máy nào, kết quả nhất quán |
| **Speed** | 8 kịch bản synthetic chạy trong 2 phút; Mininet cần 30+ phút |
| **Resource** | ONAP thật cần 64GB RAM — hầu hết lab không có |
| **Unit testing** | Synthetic test riêng AI pipeline, không bị ảnh hưởng bởi network |
| **Scalability** | Dễ thêm kịch bản mới bằng numpy |

---

## Phần 10 — Kết luận và trả lời câu hỏi

### Hệ thống đang tấn công vào đâu?

```
┌──────────────────────────────────────────────────────────┐
│  KHÔNG tấn công vào ONAP                                 │
│  ONAP = hệ thống phản ứng, không phải victim            │
│                                                          │
│  TẤN CÔNG VÀO:                                           │
│                                                          │
│  • Synthetic: vector numpy (không có mạng)               │
│  • gNMI: object Python 'r1/r2/r3' (không có IP)         │
│  • Mininet: IP ảo 10.1.0.2 (Linux namespace, có thật)   │
│  • ONAP Real: IP ảo Mininet + ONAP OOM thật phản ứng    │
└──────────────────────────────────────────────────────────┘
```

### Cần ONAP thật không?

- **Để chứng minh AI pipeline**: ❌ Không cần (Synthetic đã PASS 8/8)
- **Để chứng minh latency (T2 vs T3)**: ❌ Không cần (Synthetic đã đo)
- **Để chứng minh hệ thống tích hợp end-to-end**: ✅ Cần (run_s2/s8_real.py)
- **Để luận văn thạc sĩ được chấp nhận**: Stub mode đủ nếu có phân tích tốt

### Roadmap chạy thực tế

```
Hiện tại (đã chạy):
  ✅ Synthetic S1–S8: 8/8 PASS
  ✅ gNMI Simulator: 4 kịch bản
  ⬜ Mininet: cần máy Linux + sudo

Tương lai (scripts đã viết):
  ⬜ run_s2_real.py: cần ONAP OOM cluster
  ⬜ run_s8_real.py: cần ONAP OOM cluster
  📖 Docs/onap_e2e_runbook.md: hướng dẫn đầy đủ
```
