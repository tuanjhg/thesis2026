# PAD-ONAP — Testbed Topology (Real ONAP + K8s)

> Thiết kế topology vật lý cho thí nghiệm closed-loop DDoS mitigation
> chạy trên ONAP + Kubernetes **thật**, có cô lập traffic tấn công khỏi
> production. Bổ sung cho [DEPLOY.md](DEPLOY.md) (cách dựng ONAP) và
> [TESTBED_ISOLATION.md](TESTBED_ISOLATION.md) (lý do không co-locate
> Mininet với K8s).

---

## 1. Yêu cầu thiết kế

| Mục tiêu | Ràng buộc kéo theo |
|---|---|
| Đo M1→M4 latency end-to-end thật | Không có stub. Traffic tấn công phải đi qua đường data thật của ONAP |
| Không ảnh hưởng K8s production OVS / iptables | Mininet **không** chạy chung host với K8s (xem TESTBED_ISOLATION §1) |
| Tái lập được scenario S1–S8 trên fat-tree k=4 | Cần ≥16 logical hosts trong attack zone |
| Spoofing traffic không thoát ra Internet | rp_filter=1, FORWARD DROP trên uplink |
| Tách rời control / data / measurement | 3 VLAN riêng (mgmt, data, telemetry) |

---

## 2. Sơ đồ tổng thể (3 zone)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZONE A — Attack (Mininet VM)                         │
│                                                                              │
│   Ubuntu 22.04 · 16 GB RAM · 8 vCPU · sudo mn (fat-tree k=4, 16 hosts)       │
│                                                                              │
│   ┌─ pod0 ──────┐ ┌─ pod1 ──────┐ ┌─ pod2 ──────┐ ┌─ pod3 ──────┐            │
│   │ h0 h1 h2 h3 │ │ h4 h5 h6 h7 │ │ h8 h9 h10h11│ │h12h13h14h15 │            │
│   │ attackers   │ │ benign      │ │ benign      │ │  victim     │            │
│   └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘            │
│         │ hping3 --flood --rand-source · iperf3 -u · tcpreplay              │
│         ▼                                                                    │
│   ┌─────────────────────────────────────────────────────────────┐            │
│   │  Egress NIC:  ens4 (host-only / VXLAN tunnel to Zone B)     │            │
│   │  IP:          10.50.0.10/24                                  │            │
│   │  rp_filter=1, ip_forward=0, FORWARD -o ens3 DROP             │            │
│   └─────────────────────────────────────────────────────────────┘            │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │  VXLAN id 4242 over UDP/4789
                                   │  (single L2 link, 1 routing entry)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                ZONE B — ONAP + K8s server (bare-metal hoặc 1 VM lớn)         │
│                                                                              │
│   Ubuntu 22.04 · 96 GB RAM · 24 vCPU · 500 GB NVMe · RTX-class GPU optional  │
│   IP data:  10.50.0.1/24 (vxlan0)   IP mgmt: 192.168.50.10/24                │
│                                                                              │
│   ┌───────────────── Kubernetes cluster (kubeadm/K3s) ──────────────────┐    │
│   │                                                                      │    │
│   │   ┌─ namespace: onap (OOM minimal profile) ──────────────────────┐ │    │
│   │   │   SO · DMaaP MR · Policy(PAP/PDP) · CLAMP · AAI · SDC        │ │    │
│   │   └────────────────────────────────────────────────────────────────┘ │  │
│   │                              ▲                                       │    │
│   │                              │ DMaaP REST + Policy/SO API           │    │
│   │   ┌─ namespace: pad-onap ────┴──────────────────────────────────┐  │    │
│   │   │  pad-onap-pipeline (M2→M3→M4 orchestrator)                  │  │    │
│   │   │     · NetFlow collector :7070                                │  │    │
│   │   │     · Flink job (feature aggregator)                         │  │    │
│   │   │     · XGBoost + Transformer/LSTM inference                   │  │    │
│   │   │     · DMaaP publisher → PAD_ONAP_AI_SIGNALS                  │  │    │
│   │   │                                                              │  │    │
│   │   │  VNF pods (spawn theo Tier):                                 │  │    │
│   │   │     pad-vnf-ratelimiter  (Tier 2)                            │  │    │
│   │   │     pad-vnf-scrubber     (Tier 3)                            │  │    │
│   │   │     pad-vnf-blackhole    (Tier 4)                            │  │    │
│   │   └────────────────────────────────────────────────────────────────┘ │  │
│   │                                                                      │    │
│   │   NetFlow ingress:  vxlan0 → host nfcapd :2055 → collector :7070    │    │
│   │   Pod CIDR:         10.244.0.0/16  (KHÔNG đè với 10.50.0.0/24)       │    │
│   └──────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │  Prometheus scrape :9292, :30904
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                ZONE C — Measurement / Control (laptop / VM nhỏ)              │
│                                                                              │
│   · Prometheus + Grafana (Docker Compose)                                    │
│   · scripts/run_scenarios.sh  · evaluation/scenarios.py                      │
│   · SSH tới Zone A (sinh attack) và Zone B (đọc K8s + DMaaP)                 │
│   · Lưu testbed/logs/*.json để vẽ biểu đồ luận văn                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Phân bổ tài nguyên

| Zone | Vai trò | RAM | vCPU | Disk | Network |
|---|---|---|---|---|---|
| A — Attack VM | Mininet fat-tree, hping3/iperf3 | 16 GB | 8 | 40 GB | 2 NIC (mgmt + data) |
| B — ONAP/K8s | OOM minimal + pad-onap pipeline | 96 GB | 24 | 500 GB NVMe | 2 NIC (mgmt + data) |
| C — Control | Grafana, scripts, log collection | 4 GB | 2 | 50 GB | 1 NIC (mgmt) |
| **Tổng** | | **116 GB** | **34** | **590 GB** | |

> Có thể chạy Zone A + C trên cùng laptop nếu thiếu máy: dùng KVM/VirtualBox
> cho Mininet VM, Grafana/scripts chạy trực tiếp trên host laptop.

---

## 4. Kết nối mạng giữa zone

### 4.1 Data plane (Zone A → Zone B)

**VXLAN tunnel** trên cổng UDP/4789, không qua router thật:

```bash
# Trên Zone B (ONAP server)
sudo ip link add vxlan0 type vxlan id 4242 \
    remote 10.50.0.10 dstport 4789 dev <mgmt-nic>
sudo ip addr add 10.50.0.1/24 dev vxlan0
sudo ip link set vxlan0 up

# Trên Zone A (Mininet VM)
sudo ip link add vxlan0 type vxlan id 4242 \
    remote 10.50.0.1 dstport 4789 dev <mgmt-nic>
sudo ip addr add 10.50.0.10/24 dev vxlan0
sudo ip link set vxlan0 up

# Verify
ping -c 3 10.50.0.1   # từ Zone A
```

Trong Mininet topology, đặt `default route` của edge switch trỏ vào
`vxlan0` để traffic ra ngoài đi qua tunnel.

### 4.2 Control plane (Zone C → Zone A & B)

- SSH key-based, qua `192.168.50.0/24` (mgmt-only).
- Không trộn với 10.50.0.0/24 → log mgmt và log attack tách bạch.

### 4.3 NetFlow / Telemetry (Zone A → Zone B collector)

Mininet edge switches xuất NetFlow v9 / sFlow về collector trên Zone B:

```bash
# Trong fat_tree_topology.py — thêm sFlow agent cho mỗi OVS switch
ovs-vsctl -- --id=@s create sFlow agent=vxlan0 \
    target=\"10.50.0.1:6343\" sampling=64 polling=5 \
    -- set bridge s1 sflow=@s
```

→ Collector ở Zone B: `testbed/netflow_collector/collector.py --mode sflow --port 6343`.

---

## 5. Đường đi của 1 sự kiện DDoS (closed loop thật)

```
t0   hping3 --flood -S -p 80 --rand-source -V → h15 (Mininet, Zone A)
       │
       ▼ VXLAN
t1   vxlan0 trên Zone B nhận packet → OVS bridge → veth → pod victim (giả lập)
       │  (đồng thời) sFlow agent gửi record sang 10.50.0.1:6343
       ▼
t2   netflow_collector :7070 → Kafka topic "pad.netflow.raw"
       ▼
t3   Flink job tính 22 feature → Kafka topic "pad.features.v3"
       ▼
t4   InferenceEngine: XGBoost (Track A) + Transformer/LSTM (Track B)
       → tier ∈ {0,1,2,3,4}, attack_type ∈ {SYN, UDP, AmpDNS, ...}
       ▼
t5   DMaaP publisher → topic PAD_ONAP_AI_SIGNALS (REST POST 30904)
       ▼
t6   CLAMP poll DMaaP (15s) → Policy PDP đánh giá Drools rule
       ▼
t7   SO.instantiate(vnfd-ratelimiter-v1) → kubectl create deploy/svc
       ▼
t8   pad-vnf-ratelimiter pod /health = 200 → ghi LatencyTracker
       ▼
t9   Khi traffic đã được mitigate, NetFlow rate giảm → tier giảm → SO.terminate
```

`LatencyTracker` đo Δt cho từng cặp (t1→t8 = M1→M4 end-to-end).
Kỳ vọng số liệu thật **lớn hơn** số liệu stub khoảng 1.5×–3× vì:

- CLAMP poll interval 15 s (không thể thấp hơn)
- SO + AAI cần ~2–8 s để spawn 1 VNF pod
- Kubernetes scheduler latency ~200–800 ms

→ Đây chính là số liệu cần báo cáo trong luận văn (thay cho 505 ms của stub).

---

## 6. Checklist cô lập (bắt buộc trước khi `mn`)

Trên Zone A, trước mỗi run:

```bash
# 1. Chặn mọi attack traffic thoát ra Internet
for nic in $(ls /sys/class/net | grep -vE '^(lo|vxlan|ovs|veth)'); do
    [ "$nic" = "ens3" ] && continue   # giữ mgmt NIC
    sudo iptables -I FORWARD -s 10.0.0.0/8 -o "$nic" -j DROP
done

# 2. Tắt routing toàn cục
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=1

# 3. Verify tunnel còn sống
ping -c 2 -W 1 10.50.0.1 || { echo "VXLAN down — abort"; exit 1; }

# 4. Snapshot K8s health trên Zone B
ssh onap-server 'kubectl get pods -A | grep -vE "(Running|Completed)"'
# Phải trả về rỗng. Nếu không, KHÔNG khởi động Mininet.
```

Đã có sẵn [scripts/verify_testbed.sh](../scripts/verify_testbed.sh) – mở rộng
thêm 4 bước trên là đủ.

---

## 7. Mapping với evaluation scenarios

| Scenario | Attacker (Mininet) | Victim | Mitigation kỳ vọng | Đo cái gì |
|---|---|---|---|---|
| S1 baseline | – (chỉ traffic benign) | h15 | Tier 0 (no-op) | False-positive rate |
| S2 SYN flood low | h0 → 5 kpps | h15 | Tier 2 (ratelimiter) | M1→M4 latency |
| S3 SYN flood high | h0+h1 → 50 kpps | h15 | Tier 3 (scrubber) | Latency + drop rate |
| S4 UDP amp | h0 (DNS amp) | h15 | Tier 3 (scrubber) | Latency |
| S5 multi-vector | h0,h4,h8 song song | h15 | Tier 4 (blackhole) | Convergence time |
| S6 carpet bombing | h0..h7 → /24 | pod3 cả block | Tier 4 + steering | Recovery time |
| S7 slow-rate | h0 (hping3 -i u1000) | h15 | Tier 1 (monitor) | Detection delay |
| S8 burst on-off | h0 (10s on / 10s off) | h15 | Tier 2 ↔ 0 oscillation | Stability |

→ Mỗi scenario chạy 3 lần, lưu `testbed/logs/<scenario>_<timestamp>.json`,
sau đó `evaluation/aggregate.py` tổng hợp ra bảng cho luận văn.

---

## 8. Việc cần làm để dựng testbed này

```
[ ] 1. Cấp VM Zone A (Ubuntu 22.04 + Mininet + hping3 + tcpreplay)
[ ] 2. Cấp server Zone B (96 GB RAM, K8s + ONAP OOM theo DEPLOY.md)
[ ] 3. Tạo VXLAN tunnel 4242 giữa 10.50.0.10 ↔ 10.50.0.1
[ ] 4. Cài sFlow agent trong fat_tree_topology.py
[ ] 5. Mở rộng scripts/verify_testbed.sh thêm 4 bước §6
[ ] 6. Chạy S1 (baseline) → xác nhận tier=0 trên Zone B
[ ] 7. Chạy S2..S8, log JSON, tổng hợp bảng latency thật
[ ] 8. Đối chiếu với số stub mode cũ → viết section "Real-mode evaluation"
```

---

## 9. Khác biệt so với cấu hình hiện tại

| Hiện tại (stub) | Sau khi áp dụng topology này |
|---|---|
| Mininet chung host với Docker Compose | Mininet trên VM riêng, qua VXLAN |
| PAD_ONAP_STUB=true, emit JSON ra /tmp | PAD_ONAP_STUB=false, REST POST tới DMaaP |
| Pipeline chạy native Python | Pipeline chạy trong K8s pod (pad-onap ns) |
| VNF = Docker container trên localhost | VNF = K8s deployment do SO tạo |
| Latency ~505 ms (1 host) | Latency thật ~1.5–3 s (closed loop ONAP) |
| Không có NetFlow agent | sFlow agent trên mọi OVS bridge |
