# S2 — Syn Flood — Hướng dẫn chạy từng bước (Mininet local ↔ ONAP+K8s remote)

> **Đối tượng:** Người mới, chưa quen testbed. Mỗi bước có **WHY** (vì sao
> phải làm), **WHAT** (bạn sẽ chạy gì), **EXPECT** (kết quả thành công
> trông thế nào), và **IF BROKEN** (lỗi thường gặp + cách sửa).
>
> **Mục tiêu:** Chạy 2 sub-scenario của S2 (Syn flood AI + Syn flood
> Baseline) để có bằng chứng so sánh "AI on vs AI off" cho luận văn.
>
> **Tổng thời gian:** ~30 phút setup + ~15 phút chạy 2 lần × 5 phút + cooldown.
>
> **Thư mục project:** `thesis2026` (KHÔNG phải `Src_2`).

---

## Phần 0 — Hiểu mình đang làm gì (đọc 5 phút)

```
┌─────────────────────────────┐         ┌────────────────────────────────┐
│ MÁY LOCAL (laptop của bạn)  │         │ SERVER (có ONAP + K8s)         │
│                             │         │                                │
│ Mininet giả lập 1 mạng     │         │ Kafka nhận telemetry           │
│ data center 16 máy.         │         │ ↓                              │
│ h0 là attacker.             │         │ AI Pod đọc, phân loại tấn công │
│ h15 là victim.              │         │ ↓                              │
│ softflowd ghi log mạng      │ Kafka   │ ONAP nhận quyết định, gọi SO   │
│ rồi đẩy lên Kafka qua VPN/ ─┼────────►│ ↓                              │
│ IP công cộng port 30992.    │  30992  │ SO Helm install pod CNF        │
│                             │         │ (Scrubber, Rate-limiter…)      │
│ Local đọc kết quả tier về   │ HTTP    │ Pipeline Pod publish metrics   │
│ qua port 30292 (Prometheus) │◄────────┤ tier hiện tại lên port 30292   │
│                             │  30292  │                                │
│ Cuối phiên: sinh PNG+JSON   │         │                                │
└─────────────────────────────┘         └────────────────────────────────┘
```

**S2 (Syn flood) là gì:** scenario tấn công SYN flood — attacker bắn
TCP SYN packet liên tục về victim với rate ~500 kpps. Đến đột ngột,
không có dấu hiệu trước. **Track A** (XGBoost) phải phát hiện nhanh
trong vòng vài giây. Track B (LSTM forecast) **không có lead time** vì
attack đột ngột — đó là chủ đích, S2 dùng để chứng minh detection chứ
không phải forecast.

**Vì sao chạy 2 lần:**

| # | Sub-scenario | Mục đích |
|---|---|---|
| 1 | Syn flood + AI on | Đo AI phát hiện Syn nhanh thế nào |
| 2 | Syn flood + AI off | Baseline so sánh (threshold tĩnh) |

**Bảng so sánh cuối cùng** (chính là dữ liệu cho chương 4 luận văn):

| Mode | Time-to-action (s) | Time-to-clean (s) | Victim goodput attack (Mbps) | Max tier | TPR | FPR |
|---|---|---|---|---|---|---|
| AI | … | … | … | … | … | … |
| Baseline | … | … | … | … | … | … |

→ AI phải có cột "time-to-action" thấp hơn rõ rệt so với baseline. Đó là contribution C3 + C6.

---

## Phần 1 — Checklist trước khi bắt đầu

### 1.1 Trên SERVER, kiểm tra

**WHY:** Phải chắc K8s + ONAP đang hoạt động ổn định trước khi nối Mininet vào.

**WHAT:** Đăng nhập server, chạy 4 lệnh kiểm tra.

```bash
# 1. K8s khoẻ mạnh
kubectl get nodes
# 2. Tất cả pod ONAP đang Running
kubectl get pods -n onap | grep -v Running | grep -v Completed
# (hoặc thử namespace onap-cnf nếu lệnh trên rỗng:)
kubectl get pods -n onap-cnf | grep -v Running | grep -v Completed
# 3. Pipeline PAD-ONAP đã deploy chưa
kubectl get pods -n pad-onap
# 4. Mode đang chạy là gì
kubectl get cm pad-onap-config -n pad-onap -o jsonpath='{.data.PAD_DEPLOY_MODE}'
echo
```

**EXPECT:**
- Lệnh 1: in danh sách node, status `Ready`
- Lệnh 2: in **rỗng** (không có pod nào lỗi)
- Lệnh 3: in `pad-onap-pipeline-xxxxx   1/1     Running`
- Lệnh 4: in `onap` (chế độ thật, không phải `stub`)

**IF BROKEN:**

| Triệu chứng | Cách sửa |
|---|---|
| Lệnh 2 báo nhiều pod `Init` hoặc `CrashLoopBackOff` | Đợi 5 phút. ONAP khởi động chậm. Vẫn lỗi thì `kubectl describe pod <tên-pod-lỗi> -n onap` để xem nguyên nhân. |
| Lệnh 3 báo `No resources found` | Pipeline chưa deploy. Chạy: `kubectl apply -f onap/k8s/pad-onap-deployment.yaml` |
| Lệnh 4 in `stub` hoặc rỗng | `kubectl patch cm pad-onap-config -n pad-onap --type merge -p '{"data":{"PAD_DEPLOY_MODE":"onap","PAD_ONAP_STUB":"false"}}'` rồi `kubectl rollout restart deploy/pad-onap-pipeline -n pad-onap` |

### 1.2 Trên MÁY LOCAL, kiểm tra

**WHY:** Máy local phải là Linux (Ubuntu/WSL2) vì Mininet không chạy trên Windows native, macOS chỉ qua VM.

**WHAT:**

```bash
# 1. Đảm bảo là Linux
uname -a
# Phải in "Linux"

# 2. Đảm bảo có sudo
sudo -v

# 3. Đảm bảo reach được server (thay 10.50.0.1 bằng IP server thật của bạn)
ping -c 3 10.50.0.1
```

**EXPECT:** ping 0% loss, RTT càng thấp càng tốt (nên < 50ms).

**IF BROKEN:**
- Ping fail → check VPN/network. Trong WSL2 mặc định ra được internet qua NAT của Windows.
- Không có Linux → Cài Ubuntu trong VirtualBox/VMware, hoặc bật WSL2: `wsl --install Ubuntu-22.04` từ PowerShell admin.

### 1.3 Lấy code repo trên máy local

```bash
# Trên máy local, vào thư mục mà bạn muốn để code
cd ~
# Clone hoặc rsync từ server, hoặc download zip
# Ví dụ rsync (chạy trên local):
rsync -av user@10.50.0.1:/path/to/thesis2026/ ./thesis2026/
cd thesis2026
```

> **Lưu ý:** từ đây trở đi, mọi lệnh đều giả định bạn đang ở trong thư mục `thesis2026/`.

---

## Phần 2 — Setup SERVER (10 phút, làm 1 lần)

### Bước 2.1 — Xác định IP server mà local nhìn thấy

**WHY:** Kafka cần biết IP để báo cho client khi handshake. Sai IP ở chỗ này là lỗi #1 khiến mọi thứ "kết nối được nhưng không nhận data".

**WHAT:** Trên server:

```bash
# Lệnh này lấy IP từ chính máy local nhìn thấy
# Cách 1: nếu cùng LAN
hostname -I | awk '{print $1}'

# Cách 2: nếu có VPN, dùng IP của VPN gateway
ip -4 addr show wg0 2>/dev/null | grep inet
```

Giả sử IP là `10.50.0.1`. **Ghi nhớ con số này** — sẽ dùng khắp các bước sau.

### Bước 2.2 — Mở firewall server

**WHY:** Server cần cho phép port 30992 (Kafka) và 30292 (metrics) đi vào từ máy local.

**WHAT:** Trên server, đổi `<LOCAL_IP>` thành IP máy local của bạn:

```bash
# Nếu dùng UFW (Ubuntu mặc định)
sudo ufw allow from <LOCAL_IP> to any port 30992 proto tcp
sudo ufw allow from <LOCAL_IP> to any port 30292 proto tcp
sudo ufw reload

# Nếu dùng iptables thuần
sudo iptables -A INPUT -p tcp --dport 30992 -s <LOCAL_IP> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 30292 -s <LOCAL_IP> -j ACCEPT
```

### Bước 2.3 — Chạy bootstrap script

**WHY:** Script này tự động: tạo Kafka trong K8s, tạo NodePort, restart pipeline, smoke-test broker. Idempotent (chạy nhiều lần không sao).

**WHAT:** Trên server, ở thư mục `thesis2026`:

```bash
cd /path/to/thesis2026
chmod +x onap/scripts/setup_remote_testbed.sh

# Thay 10.50.0.1 bằng IP của bạn lấy ở 2.1
PAD_NODE_PUBLIC_IP=10.50.0.1 ./onap/scripts/setup_remote_testbed.sh
```

**EXPECT:** Output kết thúc bằng:

```
✓ Remote testbed ready

From the Mininet VM, use these endpoints:

  export PAD_REMOTE_KAFKA=10.50.0.1:30992
  export PAD_REMOTE_METRICS=http://10.50.0.1:30292/metrics
```

→ **Copy 2 dòng `export` này lại** — sẽ paste vào máy local.

**IF BROKEN:**

| Triệu chứng | Cách sửa |
|---|---|
| `Waiting for Kafka pod to become Ready (max 180s)... error: timed out` | `kubectl describe pod -n pad-onap -l app=kafka` xem nguyên nhân (thường là PVC không cấp được). Trong cluster lab có thể cần đổi `storageClassName` trong [onap/k8s/kafka-pad-onap.yaml](../onap/k8s/kafka-pad-onap.yaml) |
| `Internal broker probe failed` | `kubectl logs -n pad-onap statefulset/kafka --tail=50` — thường là sai listener config |

### Bước 2.4 — Verify quick

```bash
# Trên server
kubectl get pods -n pad-onap
# Phải thấy:
#   kafka-0                          1/1   Running
#   pad-onap-pipeline-xxxxx-yyyyy   1/1   Running

kubectl get svc -n pad-onap
# Phải thấy:
#   kafka                       ClusterIP   10.x.x.x      <none>        9092/TCP
#   kafka-external              NodePort    10.x.x.x      <none>        9094:30992/TCP
#   kafka-headless              ClusterIP   None          <none>        9092,9093,9094/TCP
#   pad-onap-metrics            ClusterIP   10.x.x.x      <none>        9292,9293/TCP
#   pad-onap-metrics-external   NodePort    10.x.x.x      <none>        9292:30292,9293:30293/TCP
```

✅ Server ready. Đóng terminal server cũng được — phần sau chạy hết trên local.

---

## Phần 3 — Setup MÁY LOCAL (10 phút, làm 1 lần)

### Bước 3.1 — Chạy bootstrap local

**WHY:** Script cài Mininet + softflowd + hping3, bật OVS, hardening (chống attack traffic rò ra mạng thật), sync clock, test connectivity sang server.

**WHAT:** Trên máy local, trong thư mục `thesis2026`:

```bash
cd /path/to/thesis2026
chmod +x testbed/setup_mininet_vm.sh

# Thay 10.50.0.1 bằng IP server của bạn (từ bước 2.1)
PAD_NODE_PUBLIC_IP=10.50.0.1 ./testbed/setup_mininet_vm.sh
```

Lưu ý: script gọi `sudo apt-get install` và `sudo /usr/bin/python3 -m pip install`. Nhập mật khẩu sudo khi hỏi.

**EXPECT:** Output cuối:

```
✓ Mininet VM ready for remote-pipeline mode

Source the env, then launch a scenario:
  source testbed/.env.remote
  sudo -E python3 testbed/netflow_e2e_pipeline.py ...
```

Đặc biệt phải thấy:
```
✓ Kafka TCP 10.50.0.1:30992 reachable
✓ Metrics endpoint http://10.50.0.1:30292/metrics reachable
✓ Kafka protocol-level OK; partitions = {0}
```

**3 dấu ✓ này là dấu hiệu cuối cùng cho thấy server-local đã thông.**

**IF BROKEN:**

| Triệu chứng | Cách sửa |
|---|---|
| `✗ Kafka TCP 10.50.0.1:30992 NOT reachable` | Firewall server đang chặn. Quay lại Bước 2.2. |
| `Kafka protocol-level FAILED: NoBrokersAvailable` | Sai advertised listener IP. Quay lại Bước 2.3, đảm bảo `PAD_NODE_PUBLIC_IP` đúng IP local nhìn thấy. |
| `apt-get: command not found` | Bạn không trên Ubuntu/Debian. Cài thủ công: mininet, openvswitch-switch, softflowd, iperf, hping3, chrony. |
| `Cannot find dpctl` sau khi cài mininet | `sudo service openvswitch-switch start` |

### Bước 3.2 — Load env

```bash
source testbed/.env.remote

# Verify đã load
echo $PAD_REMOTE_KAFKA
# Phải in: 10.50.0.1:30992
echo $PAD_REMOTE_METRICS
# Phải in: http://10.50.0.1:30292/metrics
```

> **Lưu ý:** mỗi terminal mới phải `source testbed/.env.remote` lại.

---

## Phần 4 — Chạy S2 sub-scenario 1: Syn flood + AI

### Bước 4.1 — Chạy lệnh

**WHY:** Đây là lần chạy thật đầu tiên. Sau lần này bạn sẽ có 1 cặp PNG + JSON cho luận văn.

**WHAT:**

```bash
cd /path/to/thesis2026
source testbed/.env.remote      # nếu terminal mới

sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode ai \
    --attack-class syn \
    --duration 300 \
    --remote-pipeline \
    --broker          "$PAD_REMOTE_KAFKA" \
    --collector-kafka "$PAD_REMOTE_KAFKA" \
    --remote-metrics-url "$PAD_REMOTE_METRICS" \
    --skip-kafka-setup \
    --k 4
```

Giải thích từng flag:
- `--mode ai` — bật AI Track A + Track B trên server
- `--attack-class syn` — Phase 2 sẽ chạy `hping3 -S --flood` (Syn flood)
- `--duration 300` — Phase 2 kéo dài 5 phút (theo spec)
- `--remote-pipeline` — báo script: pipeline ở server, local chỉ sinh traffic
- `--broker`, `--collector-kafka` — cùng địa chỉ Kafka NodePort
- `--remote-metrics-url` — local poll tier từ Prometheus của Pod
- `--skip-kafka-setup` — KHÔNG `docker compose up kafka` local
- `--k 4` — fat-tree 4 pod × 4 host = 16 hosts

**EXPECT:** Script chạy ~6 phút (30s baseline + 300s attack + 20s recovery + cleanup). Output trông như:

```
[INFO] *** [remote-pipeline] Probe Kafka broker 10.50.0.1:30992
[INFO]     ✓ Remote Kafka 10.50.0.1:30992 reachable
[INFO] *** RemoteTierPoller started: http://10.50.0.1:30292/metrics @ 1.0s
[INFO] *** Khởi tạo Mininet Fat-Tree k=4
[INFO] *** Building fat-tree k=4 ...
[INFO] *** Total hosts: 16
[INFO] *** Attacker: h0 → Victim: h15
[INFO] *** Khởi động NetFlow Collector trên h0 (10.0.0.1)
[INFO]     ✓ Collector health: {"status": "ok", "buffered_features": 0}
[INFO] >>> Phase 1: Baseline (Normal traffic) - 30 giây
[INFO] >>> Phase 2: SYN Attack - 300s — hping3 -S --flood -p 80 10.3.1.4 &
[INFO] >>> Phase 3: Recovery - 20 giây
[INFO] *** Cleanup
[INFO] *** RemoteTierPoller: 351 samples collected
[INFO] [✓] Biểu đồ: evaluation/results/real_e2e_ai_syn_20260516_153000.png
[INFO] [✓] JSON:    evaluation/results/real_e2e_ai_syn_20260516_153000.json
```

Cuối cùng in summary:
```
─────────────────────────────────────────────────────────────
  Real Mininet + Kafka + Flink — mode=ai, k=4, attack=300s
─────────────────────────────────────────────────────────────
  Windows collected           : 351
  Detect lag (vs attack start): 4.2s          ← QUAN TRỌNG
  TPR/FPR/F1                  : 0.98 / 0.02 / 0.96
  Victim goodput (Mbps)       : baseline=4.85 | attack=3.92 | recovery=4.80
─────────────────────────────────────────────────────────────
```

**IF BROKEN:**

| Triệu chứng | Cách sửa |
|---|---|
| `❌ Remote Kafka 10.50.0.1:30992 không reach được` | Sai env. `echo $PAD_REMOTE_KAFKA`. Hoặc network rớt — `nc -zv 10.50.0.1 30992`. |
| `❌ Script này phải chạy bằng 'sudo'` | Đừng quên `sudo -E`. Flag `-E` giữ biến môi trường (kể cả `PAD_REMOTE_KAFKA`). |
| `Cannot find dpctl` / OVS không lên | `sudo service openvswitch-switch start` |
| `Thiếu công cụ: softflowd, hping3` | `sudo apt-get install -y softflowd hping3 iperf` |
| `RemoteTierPoller: 0 samples collected` | Pipeline Pod trên server không expose `pad_current_tier`. Test: `curl $PAD_REMOTE_METRICS \| grep pad_`. Nếu rỗng → pod chưa nhận data → check kafka log. |
| Sau Phase 2, không thấy detect | Pipeline Pod có thể đang `stub` mode. Quay lại Bước 1.1 lệnh 4. |
| `n_windows = 0` cuối phiên | softflowd không export về collector. `cat /tmp/collector.log` xem có nhận gói nào không. |

### Bước 4.2 — Kiểm tra kết quả

```bash
ls -la evaluation/results/real_e2e_ai_syn_*
# Phải có 2 file: .png và .json mới nhất
```

Mở PNG xem trực quan (nếu desktop), hoặc:

```bash
# Đọc nhanh JSON
python3 -c "
import json
import glob
f = sorted(glob.glob('evaluation/results/real_e2e_ai_syn_*.json'))[-1]
d = json.load(open(f))
m = d['metrics']
print(f'File: {f}')
print(f'  Detect lag: {m[\"detect_lag_s\"]} s')
print(f'  TPR: {m[\"classification\"][\"tpr\"]}')
print(f'  Victim goodput attack: {m[\"goodput_victim_mbps_by_phase\"][\"attack\"]:.2f} Mbps')
"
```

---

## Phần 5 — Chạy sub-scenario 2: Syn flood + Baseline

**WHY:** Cần baseline so sánh để chứng minh AI nhanh hơn threshold tĩnh.

### Bước 5.1 — Chuyển pipeline sang baseline mode (trên server)

**WHY:** Pipeline Pod ở server mặc định chạy AI. Để chạy baseline, đổi env.

**WHAT:** Trên server:

```bash
kubectl set env deploy/pad-onap-pipeline -n pad-onap \
    PAD_ORCHESTRATOR_MODE=baseline
kubectl rollout status deploy/pad-onap-pipeline -n pad-onap --timeout=120s
sleep 30
```

**EXPECT:** `deployment "pad-onap-pipeline" successfully rolled out`.

### Bước 5.2 — Chạy lệnh baseline

```bash
# Trên máy local
cd /path/to/thesis2026
source testbed/.env.remote
sleep 60        # đợi pipeline ổn định sau restart

sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode baseline \
    --attack-class syn \
    --duration 300 \
    --remote-pipeline \
    --broker          "$PAD_REMOTE_KAFKA" \
    --collector-kafka "$PAD_REMOTE_KAFKA" \
    --remote-metrics-url "$PAD_REMOTE_METRICS" \
    --skip-kafka-setup \
    --k 4
```

**EXPECT:** Tương tự bước 4.1 nhưng số liệu khác:
- `Detect lag` thường **cao hơn** (10-15s thay vì 4-5s) vì baseline phải đợi rate vượt threshold tĩnh
- `Victim goodput attack` thường **thấp hơn** vì phát hiện chậm → mitigation chậm

File output: `evaluation/results/real_e2e_baseline_syn_<ts>.{png,json}`

### Bước 5.3 — (Tuỳ chọn) Đổi pipeline về AI mode

Nếu sau này muốn chạy lại AI, đổi lại trên server:

```bash
kubectl set env deploy/pad-onap-pipeline -n pad-onap \
    PAD_ORCHESTRATOR_MODE=ai
kubectl rollout status deploy/pad-onap-pipeline -n pad-onap --timeout=120s
```

---

## Phần 6 — Tổng hợp kết quả 2 lần chạy

### Bước 6.1 — Kiểm tra đủ 2 file

```bash
ls -la evaluation/results/real_e2e_ai_syn_*.json evaluation/results/real_e2e_baseline_syn_*.json
# Phải có 2 file JSON (1 ai + 1 baseline)
```

### Bước 6.2 — Sinh bảng tổng hợp

```bash
python3 << 'EOF'
import json, glob

rows = []
for mode, pat in [
    ('ai',       'real_e2e_ai_syn_*.json'),
    ('baseline', 'real_e2e_baseline_syn_*.json'),
]:
    files = sorted(glob.glob(f'evaluation/results/{pat}'))
    if not files:
        print(f'⚠ Thiếu {pat}'); continue
    d = json.load(open(files[-1]))
    m = d['metrics']
    rows.append({
        'mode':      mode,
        'detect_s':  m.get('detect_lag_s'),
        'tpr':       m['classification']['tpr'],
        'fpr':       m['classification']['fpr'],
        'f1':        m['classification']['f1'],
        'goodput_baseline_mbps': m['goodput_victim_mbps_by_phase']['baseline'],
        'goodput_attack_mbps':   m['goodput_victim_mbps_by_phase']['attack'],
        'goodput_recovery_mbps': m['goodput_victim_mbps_by_phase']['recovery'],
        'max_tier':  max(d['series']['tiers']) if d['series']['tiers'] else 0,
    })

print('\n' + '─' * 100)
print(f'{"Mode":<10s} {"Detect(s)":>10s} {"TPR":>6s} {"FPR":>6s} {"F1":>6s} '
      f'{"Goodput-base":>13s} {"Goodput-atk":>12s} {"Goodput-rec":>12s} {"MaxTier":>8s}')
print('─' * 100)
for r in rows:
    ds = f"{r['detect_s']:.2f}" if r['detect_s'] is not None else 'n/a'
    print(f"{r['mode']:<10s} {ds:>10s} "
          f"{r['tpr']:>6.2f} {r['fpr']:>6.2f} {r['f1']:>6.2f} "
          f"{r['goodput_baseline_mbps']:>12.2f}M {r['goodput_attack_mbps']:>11.2f}M "
          f"{r['goodput_recovery_mbps']:>11.2f}M {r['max_tier']:>8d}")
print('─' * 100)

# Delta — bằng chứng quan trọng nhất
if len(rows) == 2:
    ai = rows[0] if rows[0]['mode'] == 'ai' else rows[1]
    bs = rows[1] if rows[0]['mode'] == 'ai' else rows[0]
    if ai['detect_s'] and bs['detect_s']:
        d_det = bs['detect_s'] - ai['detect_s']
        print(f"\n  Δ Detect lag (AI faster):     {d_det:+.2f} s")
    d_gp = ai['goodput_attack_mbps'] - bs['goodput_attack_mbps']
    print(f"  Δ Goodput during attack (AI):  {d_gp:+.2f} Mbps")
EOF
```

Bảng kết quả mong đợi cho luận văn (số liệu mẫu — của bạn sẽ khác):

```
Mode       Detect(s)    TPR    FPR     F1  Goodput-base  Goodput-atk  Goodput-rec  MaxTier
──────────────────────────────────────────────────────────────────────────────────────────
ai              4.20   0.98   0.02   0.96         4.85M       3.92M       4.80M        3
baseline       11.80   0.91   0.08   0.89         4.83M       2.18M       4.75M        3

  Δ Detect lag (AI faster):     +7.60 s
  Δ Goodput during attack (AI): +1.74 Mbps
```

→ Cho thấy **AI phát hiện Syn flood nhanh hơn baseline 7.6 giây**, **giữ goodput cho legit user cao hơn 1.74 Mbps** trong giai đoạn bị tấn công.

### Bước 6.3 — Sinh biểu đồ so sánh chồng

```bash
python3 << 'EOF'
import json, glob
import matplotlib.pyplot as plt

ai_file = sorted(glob.glob('evaluation/results/real_e2e_ai_syn_*.json'))[-1]
bs_file = sorted(glob.glob('evaluation/results/real_e2e_baseline_syn_*.json'))[-1]

ai = json.load(open(ai_file))
bs = json.load(open(bs_file))

fig, ax = plt.subplots(figsize=(12, 5))
ax.step(ai['series']['time_axis_rel_s'], ai['series']['tiers'],
        label='AI (Track A + B)', color='#1f77b4', linewidth=2, where='post')
ax.step(bs['series']['time_axis_rel_s'], bs['series']['tiers'],
        label='Baseline (threshold)', color='#d62728', linewidth=2,
        linestyle='--', where='post')
ax.axvline(0, color='gray', linestyle='-.', alpha=0.5, label='Attack start')
ax.axvline(300, color='gray', linestyle=':', alpha=0.5, label='Attack end')
ax.set_xlabel('Time relative to attack start (s)')
ax.set_ylabel('Response Tier')
ax.set_yticks([0, 1, 2, 3, 4])
ax.set_yticklabels(['T0 Normal', 'T1 Alert', 'T2 Preempt', 'T3 Mitigate', 'T4 Block'])
ax.set_title('S2 — Syn Flood: AI vs Baseline Response')
ax.legend()
ax.grid(True, linestyle=':', alpha=0.5)

out = 'evaluation/results/compare_s2_syn_ai_vs_baseline.png'
plt.tight_layout()
plt.savefig(out, dpi=200)
print(f'[✓] Biểu đồ so sánh: {out}')
EOF
```

### Bước 6.4 — Lấy artifact server cho C2 + C5

**WHY:** Bằng chứng ONAP đã thực sự gọi SO và SHAP đã sinh giải thích.

**WHAT:** Trên máy local có cài kubectl (hoặc SSH vào server):

```bash
TS=$(date +%Y%m%d_%H%M%S)

# Events: SO instantiate CNF pod
kubectl get events -n pad-onap \
    --sort-by='.lastTimestamp' \
    -o jsonpath='{range .items[*]}{.lastTimestamp}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}' \
    | grep -iE 'scrubber|ratelimit|cnf-' \
    > evaluation/results/s2_syn_cnf_events_${TS}.tsv

# SHAP explanation log
kubectl logs -n pad-onap deploy/pad-onap-pipeline --since=30m \
    | grep -iE 'shap_top_features|explanation_text|attack_type' \
    > evaluation/results/s2_syn_shap_${TS}.log
```

Mở `s2_syn_shap_*.log` — phải thấy các dòng kiểu:

```
shap_top_features=["syn_flag_count", "fwd_packet_length_mean", "flow_iat_std"]
explanation_text="Predicted Syn because high syn_flag_count (+0.43),
                  low fwd_packet_length_mean (+0.31), low flow_iat_std (+0.18)
                  indicate a TCP SYN flood pattern"
```

→ Đây là bằng chứng SHAP đúng — `syn_flag_count` phải là feature dominant
cho Syn attack.

---

## Phần 7 — Lặp lại để có CI95 (tuỳ chọn nhưng nên làm cho luận văn)

**WHY:** 1 lần chạy không đủ thuyết phục cho luận văn. Cần 5 lần × 2 sub = 10 lần để tính trung bình ± confidence interval 95%.

**WHAT:**

```bash
# Trên máy local, sau khi đã setup xong
cd /path/to/thesis2026
source testbed/.env.remote

# 5 lần AI
for i in {1..5}; do
    echo "=== AI run $i/5 ==="
    sudo -E python3 testbed/netflow_e2e_pipeline.py \
        --mode ai --attack-class syn --duration 300 \
        --remote-pipeline \
        --broker "$PAD_REMOTE_KAFKA" \
        --collector-kafka "$PAD_REMOTE_KAFKA" \
        --remote-metrics-url "$PAD_REMOTE_METRICS" \
        --skip-kafka-setup --k 4
    sleep 60
done

# Đổi pipeline sang baseline mode trên server trước khi chạy 5 lần tiếp
# kubectl set env deploy/pad-onap-pipeline -n pad-onap PAD_ORCHESTRATOR_MODE=baseline
# kubectl rollout status deploy/pad-onap-pipeline -n pad-onap

# 5 lần Baseline
for i in {1..5}; do
    echo "=== Baseline run $i/5 ==="
    sudo -E python3 testbed/netflow_e2e_pipeline.py \
        --mode baseline --attack-class syn --duration 300 \
        --remote-pipeline \
        --broker "$PAD_REMOTE_KAFKA" \
        --collector-kafka "$PAD_REMOTE_KAFKA" \
        --remote-metrics-url "$PAD_REMOTE_METRICS" \
        --skip-kafka-setup --k 4
    sleep 60
done
```

Tổng thời gian: ~7 phút × 10 = ~70 phút. Có thể để chạy lúc đi ăn trưa.

Sinh bảng có mean ± std:

```bash
python3 << 'EOF'
import json, glob, statistics

for mode in ['ai', 'baseline']:
    files = sorted(glob.glob(f'evaluation/results/real_e2e_{mode}_syn_*.json'))
    if len(files) < 2:
        print(f'⚠ {mode}: chỉ có {len(files)} file, không đủ tính CI95'); continue

    detects, tprs, gp_atks = [], [], []
    for f in files[-5:]:        # 5 lần mới nhất
        d = json.load(open(f))
        m = d['metrics']
        if m.get('detect_lag_s') is not None:
            detects.append(m['detect_lag_s'])
        tprs.append(m['classification']['tpr'])
        gp_atks.append(m['goodput_victim_mbps_by_phase']['attack'])

    def fmt(xs):
        if not xs: return 'n/a'
        m = statistics.mean(xs)
        s = statistics.stdev(xs) if len(xs) > 1 else 0
        ci95 = 1.96 * s / (len(xs)**0.5)
        return f'{m:.2f} ± {ci95:.2f}'

    print(f'\n[{mode.upper()}] n={len(detects)} runs')
    print(f'  Detect lag       : {fmt(detects)} s')
    print(f'  TPR              : {fmt(tprs)}')
    print(f'  Goodput in attack: {fmt(gp_atks)} Mbps')
EOF
```

---

## Phần 8 — Troubleshooting nâng cao

### 8.1 Mininet kẹt giữa chừng

```bash
sudo mn -c    # cleanup mọi bridge/host Mininet
sudo pkill -9 -f hping3
sudo pkill -9 -f iperf
sudo pkill -9 -f softflowd
```

### 8.2 Server Pod restart, mất data đang collect

```bash
# Trên server
kubectl logs -n pad-onap deploy/pad-onap-pipeline --previous
# Nếu OOMKilled → tăng resource limit trong onap/k8s/pad-onap-deployment.yaml
```

### 8.3 NodePort không reach được sau khi bootstrap

```bash
# Trên server
kubectl get endpoints -n pad-onap kafka-external
# Nếu cột ENDPOINTS rỗng → kafka pod không Ready
kubectl describe pod -n pad-onap kafka-0
```

### 8.4 Clock lệch khiến detect_lag âm hoặc kỳ quặc

```bash
# Trên CẢ local và server
sudo chronyc -a 'makestep'
chronyc tracking | grep 'System time'
# Offset phải < 10ms cho E2E claim chính xác
```

### 8.5 Muốn xem realtime tier trong khi chạy

Mở terminal thứ 2 trên máy local:

```bash
watch -n 1 'curl -s $PAD_REMOTE_METRICS | grep -E "^pad_(current_tier|tier_decisions_total)"'
```

---

## Phần 9 — Checklist cuối cùng cho luận văn

Sau khi xong, bạn phải có:

- [ ] `evaluation/results/real_e2e_ai_syn_*.{png,json}` (1 lần tối thiểu, 5 lần nếu có CI95)
- [ ] `evaluation/results/real_e2e_baseline_syn_*.{png,json}` (1 lần tối thiểu, 5 lần nếu có CI95)
- [ ] `evaluation/results/compare_s2_syn_ai_vs_baseline.png` (biểu đồ chồng từ Bước 6.3)
- [ ] `evaluation/results/s2_syn_cnf_events_*.tsv` (≥ 1 file)
- [ ] `evaluation/results/s2_syn_shap_*.log` (≥ 1 file, phải có `syn_flag_count` trong top SHAP)
- [ ] Bảng tổng hợp 2 dòng × 9 cột (sinh từ Bước 6.2)

Đây là dữ liệu thô cho **chương 4 luận văn**, chứng minh:

| Contribution | Bằng chứng từ S2 |
|---|---|
| **C3** — E2E latency 4 stage | `detect_lag_s` của AI thấp hơn baseline ~7-10s |
| **C4** — 5-tier graduated | `series.tiers` cho thấy chuyển từ T0 → T3 đúng spec |
| **C5** — SHAP trong VES | `s2_syn_shap_*.log` có `syn_flag_count` ở top features |
| **C6** — Lightweight AI | Pod 4-core CPU đủ inference real-time (không cần GPU) |

---

## Bảng tra nhanh các lệnh

| Việc | Lệnh |
|---|---|
| Setup server | `PAD_NODE_PUBLIC_IP=<ip> ./onap/scripts/setup_remote_testbed.sh` |
| Setup local | `PAD_NODE_PUBLIC_IP=<ip> ./testbed/setup_mininet_vm.sh` |
| Load env mỗi terminal | `source testbed/.env.remote` |
| Chạy AI | `sudo -E python3 testbed/netflow_e2e_pipeline.py --mode ai --attack-class syn --duration 300 --remote-pipeline --broker "$PAD_REMOTE_KAFKA" --collector-kafka "$PAD_REMOTE_KAFKA" --remote-metrics-url "$PAD_REMOTE_METRICS" --skip-kafka-setup --k 4` |
| Chạy Baseline | `... --mode baseline ...` (giống trên, đổi `--mode`) |
| Đổi pipeline mode | `kubectl set env deploy/pad-onap-pipeline -n pad-onap PAD_ORCHESTRATOR_MODE=baseline` (hoặc `ai`) |
| Cleanup Mininet | `sudo mn -c; sudo pkill -9 -f hping3` |
| Probe Kafka | `nc -zv $PAD_NODE_PUBLIC_IP 30992` |
| Probe metrics | `curl -s $PAD_REMOTE_METRICS \| head` |
| Xem pod ONAP | `kubectl get pods -A \| grep -v Running` |
| Xem log pipeline | `kubectl logs -f -n pad-onap deploy/pad-onap-pipeline` |
| Xem tier realtime | `watch -n 1 'curl -s $PAD_REMOTE_METRICS \| grep pad_current_tier'` |

---

## Tóm tắt cực ngắn (3 phút đọc)

Bạn cần **3 chuỗi lệnh**:

**(1) Setup 1 lần — server + local:**
```bash
# Server
PAD_NODE_PUBLIC_IP=<ip> ./onap/scripts/setup_remote_testbed.sh

# Local
PAD_NODE_PUBLIC_IP=<ip> ./testbed/setup_mininet_vm.sh
source testbed/.env.remote
```

**(2) Chạy AI:**
```bash
sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode ai --attack-class syn --duration 300 --remote-pipeline \
    --broker "$PAD_REMOTE_KAFKA" --collector-kafka "$PAD_REMOTE_KAFKA" \
    --remote-metrics-url "$PAD_REMOTE_METRICS" \
    --skip-kafka-setup --k 4
```

**(3) Chạy Baseline:**
```bash
# Trên server đổi mode
kubectl set env deploy/pad-onap-pipeline -n pad-onap PAD_ORCHESTRATOR_MODE=baseline
kubectl rollout status deploy/pad-onap-pipeline -n pad-onap

# Trên local chạy lại (chỉ đổi --mode)
sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode baseline --attack-class syn --duration 300 --remote-pipeline \
    --broker "$PAD_REMOTE_KAFKA" --collector-kafka "$PAD_REMOTE_KAFKA" \
    --remote-metrics-url "$PAD_REMOTE_METRICS" \
    --skip-kafka-setup --k 4
```

Xong! Kết quả ở `evaluation/results/real_e2e_*_syn_*.{png,json}`.

Khi gặp vấn đề ở bước nào, paste output (text, không phải screenshot)
của lệnh đó cho tôi — sẽ debug nhanh hơn xem nhiều log một lúc.
