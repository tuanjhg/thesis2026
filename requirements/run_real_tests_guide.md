# Hướng dẫn chạy thật: gNMI · Mininet · ONAP Real

> **Yêu cầu hệ điều hành**  
> - gNMI: ✅ Windows / Linux / Mac (Python thuần)  
> - Mininet: ❌ **Linux only** (Ubuntu 20.04/22.04 + sudo)  
> - ONAP Real: ❌ **Linux + K8s cluster** với ONAP OOM đang chạy

---

## Lớp 1 — gNMI Simulator

### Mục tiêu
Chứng minh AI pipeline phát hiện đúng khi nhận **metric từ thiết bị mạng ảo** (không phải numpy thuần). Kết quả ghi vào `testbed/results/gnmi_*.json`.

### Yêu cầu
```bash
pip install requests
python -c "import requests; print('OK')"
```

### Cách chạy — 3 terminal song song

```
Terminal 1          Terminal 2                  Terminal 3
─────────────       ──────────────────────      ───────────────────────
gNMI Simulator  →   NetFlow Collector      →    Anomaly Injector
(sinh metric)       (đọc metric, expose API)    (inject attack pattern)
```

**Terminal 1 — Khởi động gNMI Simulator:**
```bash
cd /path/to/Src_2
python testbed/gnmi_simulator/main.py --port 8888

# Xác nhận:
curl http://localhost:8888/health
# → {"status": "ok", "uptime": ...}

curl http://localhost:8888/metrics/r1
# → {"device":"r1","metrics":{"in_pkts":5000,...}}
```

**Terminal 2 — Khởi động NetFlow Collector (chế độ synthetic):**
```bash
cd /path/to/Src_2
python testbed/netflow_collector/collector.py \
  --mode     synthetic \
  --gnmi     http://localhost:8888 \
  --api-port 7070 \
  --interval 1.0

# Output sẽ hiện liên tục:
# [Collector] Feature: pkt_rate=5032 udp_ratio=0.148 src_ip_entropy=0.499

# Xác nhận REST hoạt động:
curl http://localhost:7070/flows/latest
```

**Terminal 3 — Chạy kịch bản tấn công:**
```bash
cd /path/to/Src_2
mkdir -p testbed/results

# Kịch bản 1: UDP Flood (60s) — phát hiện trong <5s
python testbed/anomaly_injector/scenarios.py \
  --scenario ddos_udp \
  --gnmi     http://localhost:8888 \
  --duration 60 \
  2>&1 | tee testbed/results/gnmi_ddos_udp.log

# Kịch bản 2: Bandwidth Ramp — test Transformer proactive
python testbed/anomaly_injector/scenarios.py \
  --scenario bw_ramp \
  --gnmi     http://localhost:8888 \
  --duration 120

# Kịch bản 3: CPU Spike trên r2
python testbed/anomaly_injector/scenarios.py \
  --scenario cpu_spike \
  --gnmi     http://localhost:8888 \
  --duration 60

# Kịch bản 4: Cross-slice (eMBB → URLLC)
python testbed/anomaly_injector/scenarios.py \
  --scenario cross_slice \
  --gnmi     http://localhost:8888 \
  --duration 90

# Chạy tất cả 4 kịch bản liên tiếp
python testbed/anomaly_injector/scenarios.py \
  --all \
  --gnmi http://localhost:8888 \
  2>&1 | tee testbed/results/gnmi_all_scenarios.log
```

### Theo dõi collector trong khi inject

Mở terminal thứ 4 để thấy metric thay đổi theo thời gian thực:
```bash
# Xem metric r1 thay đổi khi bị tấn công
watch -n1 "curl -s http://localhost:8888/metrics/r1 | python3 -m json.tool | grep -E 'in_pkts|udp_ratio|cpu_pct'"

# Xem feature vector mà collector compute được
watch -n1 "curl -s http://localhost:7070/flows/latest | python3 -m json.tool | grep -E 'pkt_rate|proto_dist_udp|attack_intensity'"
```

Kết quả mong đợi khi inject `ddos_udp`:
```
# Normal (trước attack):
pkt_rate: 5000,  proto_dist_udp: 0.148,  attack_intensity: 0.0

# Sau POST /attack/start:
pkt_rate: 450000,  proto_dist_udp: 0.923,  attack_intensity: 0.87
```

### Lưu kết quả JSON

```bash
# Lưu metrics snapshot tại thời điểm attack peak
curl -s http://localhost:8888/metrics | python3 -m json.tool \
  > testbed/results/gnmi_metrics_during_attack.json

# Lưu feature vectors (50 vectors gần nhất)
curl -s http://localhost:7070/flows | python3 -m json.tool \
  > testbed/results/gnmi_features_during_attack.json

echo "Saved to testbed/results/"
ls testbed/results/
```

### Kết nối AI pipeline với gNMI (live mode)

```bash
# Script nhỏ kết nối collector → AI pipeline:
python3 - << 'EOF'
import sys, time, json, urllib.request
sys.path.insert(0, '.')
from pipeline.s4_orchestration.orchestrator import Orchestrator
import numpy as np

orch = Orchestrator(
    model_dir  = 'pad_onap_v3/models',
    data_dir   = 'pad_onap_v3/processed',
    eval_mode  = True,
)
FEATURE_NAMES = [
    'pkt_rate','byte_rate','src_ip_entropy','dst_ip_entropy',
    'src_port_entropy','dst_port_entropy','proto_dist_tcp',
    'proto_dist_udp','proto_dist_icmp','syn_ratio','fin_ratio',
    'avg_pkt_size','pkt_size_std','new_flows_rate',
    'flow_duration_mean','inter_arrival_mean','inter_arrival_std',
]

print("Live gNMI → AI pipeline (Ctrl+C to stop)")
decisions = []
for i in range(60):   # 60 windows × 1s = 60s
    try:
        with urllib.request.urlopen('http://localhost:7070/flows/latest', timeout=2) as r:
            data = json.loads(r.read())
        feats = data.get('features', {})
        x = np.array([feats.get(f, 0.0) for f in FEATURE_NAMES], dtype=np.float32)
        rec = orch._step(x)
        if rec:
            tier = rec.get('tier', 0)
            conf = rec.get('confidence', 0)
            proactive = rec.get('proactive', False)
            print(f"  Window {i:3d} | Tier={tier} | conf={conf:.3f} | proactive={proactive}")
            decisions.append(rec)
    except Exception as e:
        print(f"  [!] {e}")
    time.sleep(1.0)

with open('testbed/results/gnmi_live_decisions.json', 'w') as f:
    json.dump(decisions, f, indent=2)
print(f"\nSaved {len(decisions)} decisions → testbed/results/gnmi_live_decisions.json")
EOF
```

---

## Lớp 2 — Mininet

> **⚠️ Phải chạy trên Linux (Ubuntu 20.04/22.04) với sudo**  
> Không chạy được trực tiếp trên Windows. Dùng WSL2 hoặc VM nếu cần.

### Cài đặt (chạy 1 lần)

```bash
# Cài Mininet + công cụ cần thiết
sudo apt-get update
sudo apt-get install -y \
  mininet \
  openvswitch-switch \
  hping3 \
  iperf3 \
  net-tools \
  python3-pip

pip3 install mininet

# Xác nhận
sudo mn --test pingall
# Phải thấy: "*** Results: 0% dropped"
sudo mn --clean   # dọn dẹp sau test
```

### Cách A — 3-Slice Topology (eMBB/URLLC/mMTC)

```bash
cd /path/to/Src_2
mkdir -p testbed/results

# Terminal 1: Khởi động topology
sudo python3 testbed/mininet/topology.py

# Sẽ thấy:
# ======================================================
#   PAD-ONAP Testbed — Network Topology Summary
# ======================================================
#   eMBB  (1Gbps): embb_src (10.1.0.1) → r1 → vnf_fw → r2 → embb_dst (10.1.0.2)
#   URLLC (<1ms):  urllc_src (10.2.0.1) → r1 → vnf_lb → r2 → urllc_dst (10.2.0.2)
# mininet>
```

Trong Mininet CLI:
```
# Kiểm tra kết nối
mininet> pingall

# Đo bandwidth bình thường
mininet> embb_src iperf -c 10.1.0.2 -t 5 -f m

# Inject UDP flood thật (Terminal 2)
mininet> embb_src hping3 --udp --flood -p 80 10.1.0.2 &

# Xem traffic trên switch r1
mininet> r1 ovs-ofctl dump-flows r1

# Đo bandwidth trong khi bị tấn công
mininet> embb_dst iperf -s &
mininet> embb_src iperf -c 10.1.0.2 -t 5 -f m

# Dừng attack
mininet> embb_src pkill hping3

# Thoát
mininet> exit
```

### Cách B — Fat-Tree k=4 (khuyến nghị, có đo lường tự động)

```bash
# Chạy toàn bộ scenario tự động (5 phase: baseline → iperf → pod_latency → attack → SFC)
sudo python3 testbed/mininet/fat_tree_attack_scenario.py \
  --k 4 \
  --duration 30

# Kết quả lưu tự động vào:
# testbed/logs/fat_tree_attack_YYYYMMDD_HHMMSS.json
```

Output mong đợi:
```
*** Building fat-tree k=4 topology
*** pingall (initial connectivity check)
    pingall packet loss: 0.0%
*** [Phase 1] Baseline ping: h0 → h15 (no attack)
    RTT: {'min_ms': 0.2, 'avg_ms': 0.4, 'max_ms': 1.1}  loss=0.0%
*** [Phase 5] iperf3 bandwidth: h0 → h15 (10s)
    iperf3: 945.2 Mbps
*** [Phase 4] Same-pod vs cross-pod latency comparison
    Same-pod  h0→h1:  avg RTT = 0.3 ms
    Cross-pod h0→h15: avg RTT = 0.7 ms
    Core-layer overhead: 0.4 ms
*** [Phase 2] UDP flood: h0 → h15 for 30s
*** [Phase 3] Measuring SFC rule propagation time...
    t+2.5s  rx_rate=287.3 Mbps
    t+3.0s  rx_rate=291.1 Mbps
    [✓] SFC rule detected at t+8.2s (rate dropped 12.3 Mbps ← peak 291 Mbps)

================================================================
Fat-Tree k=4 Attack Scenario — Summary
================================================================
  Baseline RTT  h0→h15: avg=0.4 ms  loss=0.0%
  SFC propagation: detected=True  time=8.2 s
  Same-pod RTT:  0.3 ms
  Cross-pod RTT: 0.7 ms
  Core-layer overhead: 0.4 ms
  iperf3: 945.2 Mbps
================================================================
Log: testbed/logs/fat_tree_attack_20260429_142030.json
```

### Cách C — Kết hợp Mininet + gNMI pipeline (hoàn chỉnh nhất)

```bash
# Terminal 1: Khởi động gNMI + Collector
python3 testbed/gnmi_simulator/main.py --port 8888 &
python3 testbed/netflow_collector/collector.py \
  --mode synthetic --gnmi http://localhost:8888 --api-port 7070 &

# Terminal 2: Khởi động Mininet
sudo python3 testbed/mininet/topology.py

# Terminal 3: Trong khi Mininet đang chạy, inject gNMI attack đồng thời
# (Mininet tạo môi trường mạng, gNMI sinh metric tương ứng)
python3 testbed/anomaly_injector/scenarios.py \
  --scenario ddos_udp --gnmi http://localhost:8888 --duration 60

# Trong Mininet CLI (Terminal 2), đồng thời inject packet thật
# mininet> embb_src hping3 --udp --flood -p 80 10.1.0.2 &
```

### Lưu kết quả Mininet

```bash
# Lưu OVS flows (bằng chứng SFC rules)
sudo ovs-ofctl dump-flows r1 > testbed/results/mininet_ovs_flows_r1.txt
sudo ovs-ofctl dump-flows r2 > testbed/results/mininet_ovs_flows_r2.txt

# Lưu interface stats trong khi attack
ip -s link > testbed/results/mininet_interface_stats.txt

# Fat-tree results đã tự lưu:
ls testbed/logs/fat_tree_attack_*.json
```

### Dọn dẹp sau Mininet

```bash
# Bắt buộc sau khi thoát hoặc crash
sudo mn --clean

# Kiểm tra
sudo ovs-vsctl list-br   # phải trống hoặc chỉ còn br-pad
ip netns list            # phải trống
```

---

## Lớp 3 — ONAP Real

> **Yêu cầu**: Đã hoàn thành tất cả 10 mục trong `Docs/onap_deployment_checklist.md`

### Tóm tắt yêu cầu trước khi chạy

```bash
# Chạy checklist này, tất cả phải PASS:
python onap/scripts/preflight_check.py --host $ONAP_HOST
```

### Thiết lập môi trường (chạy mỗi phiên)

```bash
export ONAP_HOST=192.168.1.100          # ← IP server ONAP của bạn
export ONAP_SO_PORT=30080
export ONAP_POLICY_PORT=30969
export ONAP_DMAAP_PORT=30904
export PAD_ONAP_SO_USER=so_admin
export PAD_ONAP_SO_PASS=demo123456!
export PAD_ONAP_POLICY_USER=healthcheck
export PAD_ONAP_POLICY_PASS=zb!XztG34
export PAD_SERVICE_MODEL_UUID=<uuid-từ-SDC-hoặc-preload>
export PAD_ONAP_STUB=false              # ← quan trọng nhất
```

### Bước 0 — Khởi động gNMI Simulator

```bash
# Phải chạy trước khi chạy S2/S8 với attack-mode gnmi
python3 testbed/gnmi_simulator/main.py --port 8888 &

# Xác nhận
curl http://localhost:8888/health
```

### Bước 1 — Chạy S2: UDP Flood → Scrubber VNF (~6s)

```bash
mkdir -p evaluation/results

# Dry-run trước (kiểm tra không gọi ONAP)
python onap/scripts/run_s2_real.py --dry-run

# Chạy thật
python onap/scripts/run_s2_real.py \
  --attack-mode gnmi \
  --gnmi-url   http://localhost:8888 \
  --bridge     br-pad \
  --src-ip     10.1.0.1 \
  --vnf-port   9001 \
  2>&1 | tee evaluation/results/s2_run_$(date +%Y%m%d_%H%M).log
```

Theo dõi song song:
```bash
# Terminal khác: xem SO log
kubectl logs -f -n onap deploy/so --tail=20 | grep -iE 'instantiate|vnf|error|complete'

# Terminal khác: xem OVS flow được cài
watch -n2 "sudo ovs-ofctl dump-flows br-pad"

# Terminal khác: xem pod VNF được tạo
watch -n3 "kubectl get pods -n pad-onap"
```

Kết quả mong đợi S2:
```
══════════════════════════════════════════════════
  Latency breakdown — S2 (vnfd-scrubber-v1)
──────────────────────────────────────────────────
  AI trigger → Policy push       111 ms  
  Policy push → SO request       122 ms  
  SO request → VNF ACTIVE       6134 ms  ████████████████████████████
  VNF ACTIVE → SFC rule           31 ms  
  END-TO-END                    6398 ms  
──────────────────────────────────────────────────

Result saved → evaluation/results/s2_real_onap.json
```

### Bước 2 — Chạy S8: Proactive T2 → Reactive T3 (Key Novelty)

```bash
python onap/scripts/run_s8_real.py \
  --gnmi-url    http://localhost:8888 \
  --bridge      br-pad \
  --vnf-port    9001 \
  --hold-seconds 30 \
  2>&1 | tee evaluation/results/s8_run_$(date +%Y%m%d_%H%M).log
```

Kết quả mong đợi S8:
```
[S8] ── T2 Proactive ──
      CLAMP push T2 → PAP 200  (98ms)
      SO instantiate vnfd-ratelimiter-v1
      VNF ratelimiter ACTIVE after 487ms
      t2_end_to_end = 612ms

[S8] Holding 30s với ratelimiter ...

[S8] ── T3 Reactive ──
      CLAMP push T3 → PAP 200  (104ms)
      SO instantiate vnfd-scrubber-v1
      VNF scrubber ACTIVE after 6201ms
      t3_end_to_end = 6389ms

══════════════════════════════════════════════════
  S8 Novelty Metric
  T2 Proactive end-to-end :    612 ms
  T3 Reactive end-to-end  :  6 389 ms
  Lead time (t3 - t2)     :   30.1 s   ★
══════════════════════════════════════════════════
Result saved → evaluation/results/s8_real_onap.json
```

### Bước 3 — Lưu bằng chứng

```bash
# Chụp trạng thái sau khi test
kubectl get pods -n onap          > evaluation/results/onap_pods_evidence.txt
kubectl get pods -n pad-onap      >> evaluation/results/onap_pods_evidence.txt
sudo ovs-ofctl dump-flows br-pad  > evaluation/results/ovs_flows_evidence.txt
kubectl top nodes                  > evaluation/results/resource_usage.txt

# Xem kết quả JSON
python3 -m json.tool evaluation/results/s2_real_onap.json
python3 -m json.tool evaluation/results/s8_real_onap.json
```

---

## Tổng hợp tất cả kết quả

```bash
# Sau khi chạy xong cả 3 lớp, tổng hợp:
python - << 'EOF'
import json, pathlib, os

results_dir = pathlib.Path('evaluation/results')
testbed_dir = pathlib.Path('testbed/results')
log_dir     = pathlib.Path('testbed/logs')

print("=" * 60)
print("PAD-ONAP Test Results Summary")
print("=" * 60)

# Synthetic
synth = results_dir / 'evaluation_summary.json'
if synth.exists():
    d = json.loads(synth.read_text())
    print(f"\n[Synthetic]  {d['passed']}/{d['total_scenarios']} PASS")
    for sc in d['scenarios']:
        t2 = sc['tier2_latency_ms']['p50']
        t3 = sc['tier3_latency_ms']['p50']
        print(f"  {sc['scenario']:<40} {sc['pass_fail']}  T2={t2:.0f}ms T3={t3:.0f}ms")

# gNMI
gnmi_live = testbed_dir / 'gnmi_live_decisions.json'
if gnmi_live.exists():
    d = json.loads(gnmi_live.read_text())
    tiers = [r.get('tier',0) for r in d]
    print(f"\n[gNMI Live]  {len(d)} windows | max tier={max(tiers) if tiers else 0}")

# Mininet
for f in sorted(log_dir.glob('fat_tree_attack_*.json')):
    d = json.loads(f.read_text())
    sfc = next((p for p in d['phases'] if p.get('phase')=='sfc_propagation'), {})
    print(f"\n[Mininet]    {f.name}")
    print(f"  SFC detected={sfc.get('sfc_rule_detected')}  propagation={sfc.get('propagation_s')}s")

# ONAP Real
for name in ['s2_real_onap.json', 's8_real_onap.json']:
    f = results_dir / name
    if f.exists():
        d = json.loads(f.read_text())
        print(f"\n[ONAP Real]  {name}")
        if 'lead_time_s' in d:
            print(f"  lead_time_s = {d['lead_time_s']}")
        if 'end_to_end_ms' in d:
            print(f"  end_to_end  = {d['end_to_end_ms']:.0f} ms")
    else:
        print(f"\n[ONAP Real]  {name} — NOT YET RUN")

print("=" * 60)
EOF
```

---

## Bảng trạng thái nhanh

| Lớp | Cần gì | Lệnh chính | Kết quả lưu ở |
|-----|--------|-----------|---------------|
| gNMI | Python + pip | `python testbed/gnmi_simulator/main.py` | `testbed/results/gnmi_*.json` |
| Mininet | Linux + sudo | `sudo python3 testbed/mininet/fat_tree_attack_scenario.py` | `testbed/logs/fat_tree_*.json` |
| ONAP Real | K8s + ONAP | `PAD_ONAP_STUB=false python onap/scripts/run_s2_real.py` | `evaluation/results/s2_real_onap.json` |
