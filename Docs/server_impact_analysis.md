# Phân tích ảnh hưởng đến server khi chạy PAD-ONAP tests

> **Tóm tắt**: Mỗi lớp test có mức độ ảnh hưởng khác nhau.  
> Synthetic = an toàn tuyệt đối. Mininet = cần cẩn thận. ONAP real = có rủi ro cụ thể.

---

## Tổng quan nhanh

| Lớp test | Ảnh hưởng ONAP? | Ảnh hưởng mạng? | Dùng tài nguyên? | Rủi ro |
|----------|----------------|-----------------|-----------------|--------|
| Synthetic (`evaluation/scenarios.py`) | ❌ Không | ❌ Không | RAM ~500MB | ✅ An toàn |
| gNMI Simulator | ❌ Không | ❌ Không | RAM ~50MB | ✅ An toàn |
| Mininet topology | ❌ Không | ⚠️ Namespace Linux | CPU, RAM ~200MB | ⚠️ Cần cleanup |
| ONAP Real (S2/S8) | ✅ Có ghi vào ONAP | ⚠️ OVS rules | **RAM ~16GB (VNF)** | ⚠️ Đọc kỹ bên dưới |

---

## Lớp 1: Synthetic — An toàn tuyệt đối

```bash
python -m evaluation.scenarios
```

**Không ảnh hưởng gì cả.** Code chỉ:
- Tính numpy array trong RAM
- Gọi `ONAPSOClient` ở **stub mode** (sleep 0.5s, không gọi K8s)
- Ghi file JSON vào `evaluation/results/`

```
❌ Không gọi ONAP SO
❌ Không gọi Policy PAP
❌ Không tạo pod nào
❌ Không động vào mạng
❌ Không cần sudo
✅ Chạy xong, dừng hết, không để lại gì
```

---

## Lớp 2: gNMI Simulator — An toàn

```bash
python testbed/gnmi_simulator/main.py --port 8888
python testbed/anomaly_injector/scenarios.py --scenario ddos_udp
```

**Không ảnh hưởng gì cả.** Code chỉ:
- Chạy HTTP server Python trên port 8888
- Thay đổi số trong dictionary Python (không có packet thật)
- Không động vào K8s, không động vào OVS, không cần sudo

```
❌ Không gọi ONAP
❌ Không tạo interface mạng
✅ Dừng process là sạch hoàn toàn
```

---

## Lớp 3: Mininet — Cần cẩn thận

```bash
sudo python3 testbed/mininet/topology.py
```

### Những gì Mininet làm với hệ thống

```
Mininet tạo ra:
├── Linux network namespaces   (kernel)
│   ├── namespace cho embb_src, embb_dst, ...
│   └── namespace cho r1, r2, r3 (OVS switches)
├── Virtual ethernet pairs     (veth0, veth1, ...)
│   └── nằm trong kernel, không ra physical NIC
├── OVS bridges r1, r2, r3     (ovs-vsctl)
│   └── OpenFlow rules trên kernel
└── iptables rules (trên một số host)
```

### Ảnh hưởng thật sự

| Thành phần | Bị ảnh hưởng? | Giải thích |
|-----------|--------------|-----------|
| Physical NIC (eth0) | ❌ Không | Mininet chỉ dùng veth ảo |
| Internet connectivity | ❌ Không | Namespace cô lập hoàn toàn |
| ONAP pods | ❌ Không | Khác namespace K8s |
| Các service khác trên server | ❌ Không | Namespace Linux cô lập |
| OVS (nếu đang dùng) | ⚠️ Có thể | Mininet thêm bridges r1/r2/r3 vào OVS |

### Rủi ro Mininet: Zombie processes khi crash

```
⚠️ NẾU Mininet crash (Ctrl+C sai cách, lỗi, mất SSH):
   → veth interfaces không bị xóa
   → OVS bridges r1/r2/r3 còn lại
   → Namespace Linux còn lại

Cách kiểm tra sau khi crash:
  sudo ovs-vsctl show           # xem bridge còn không
  ip netns list                  # xem namespace còn không
  sudo mn --clean                # cleanup tự động của Mininet
```

### Cách dừng Mininet đúng cách

```bash
# Trong Mininet CLI:
mininet> exit

# Verify sạch hoàn toàn:
sudo mn --clean
sudo ovs-vsctl list-br    # phải trống (trừ br-pad do mình tạo)
```

---

## Lớp 4: ONAP Real (S2/S8) — Phân tích chi tiết

Đây là lớp **CÓ ảnh hưởng thật** đến server và ONAP. Phân tích từng tác động:

---

### Tác động 1: Policy PAP — Ghi vào database ONAP ⚠️

```python
# run_s2_real.py dòng 230-233
clamp.push_policy(
    tier=3, attack_type="UDP_Flood",
    device_id="r1", confidence=0.92,
)
```

**Điều gì xảy ra trong ONAP:**
```
Script gửi: POST http://policy-pap:6969/policy/pap/v1/pdps/policies
ONAP ghi policy mới vào MariaDB (database persistent)
Policy này tồn tại cho đến khi bị revoke thủ công
```

**Cleanup của script:**
```python
# dòng 312-313
clamp.revoke_policy(TIER, DEVICE_ID)   # ← DELETE policy sau test
```

**Rủi ro nếu script bị kill giữa chừng:**
```
Policy còn trong PAP database
→ CLAMP sẽ tiếp tục enforce policy này
→ Có thể ảnh hưởng nếu ONAP đang dùng cho mục đích khác

Fix thủ công:
  curl -X DELETE http://$NODE_IP:30969/policy/pap/v1/pdps/policies/PAD_ONAP_T3_r1 \
    -u healthcheck:zb!XztG34
```

---

### Tác động 2: SO tạo VNF Pod — Dùng tài nguyên K8s ⚠️

```python
# dòng 246
instance_id = so.instantiate(VNF_PROFILE, DEVICE_ID)
```

**Điều gì xảy ra trong K8s:**
```
ONAP SO gọi K8s API → tạo Pod mới
Pod: pad-vnf-scrubber-<uuid>
Namespace: pad-onap (riêng biệt với namespace onap)

Tài nguyên bị dùng theo VNFD:
  vnfd-scrubber-v1:    16 GB RAM + 8 CPU    (boot ~6s)
  vnfd-ratelimiter-v1:  2 GB RAM + 2 CPU    (boot ~500ms)
```

**⚠️ Đây là tác động lớn nhất:**
```
S2 dùng: 16 GB RAM + 8 CPU trong ~60s
S8 dùng: 2 GB (T2, ~30s) + 16 GB (T3, ~35s) = tối đa 18 GB cùng lúc

Nếu server ONAP chỉ có vừa đủ RAM:
  → VNF pod bị OOMKilled
  → ONAP pods khác có thể bị ảnh hưởng
```

**Cleanup của script:**
```python
so.terminate(instance_id)   # ← DELETE pod sau test
```

**Kiểm tra sau khi chạy:**
```bash
kubectl get pods -n pad-onap   # phải trống
kubectl top nodes               # RAM phải trở về mức trước
```

---

### Tác động 3: OVS Flow Rules — Ảnh hưởng packet forwarding ⚠️

```python
# dòng 269-272
sfc.install(
    bridge="br-pad", src_ip="10.1.0.1/32",
    vnf_port=9001, tier=3, device_id="r1",
)
```

**Điều gì xảy ra:**
```
Script chạy: sudo ovs-ofctl add-flow br-pad "priority=100,ip,nw_src=10.1.0.1 actions=output:9001"

Flow rule này redirect packet từ 10.1.0.1 → VNF port
Nếu br-pad kết nối với traffic thật: ảnh hưởng packet thật
```

**Tuy nhiên:** `br-pad` là bridge riêng do bạn tạo, không phải bridge production:
```bash
sudo ovs-vsctl add-br br-pad   # ← bridge độc lập
# Không liên quan đến bridge production của ONAP
```

**Cleanup của script:**
```python
sfc.remove(DEVICE_ID)   # ← xóa flow rule sau test
```

**Kiểm tra:**
```bash
sudo ovs-ofctl dump-flows br-pad   # phải trống sau cleanup
```

---

### Tác động 4: DMaaP / Kafka — Nhẹ, không đáng ngại ✅

```python
publish_to_dmaap(ai_payload)
```

**Điều gì xảy ra:**
```
Ghi 1 message ~2KB vào Kafka topic PAD_ONAP_AI_SIGNALS
Topic retention: 1 giờ (theo values-override.yaml)
→ Tự động xóa sau 1 giờ
→ Không ảnh hưởng gì đến ONAP
```

---

## Tóm tắt: Nếu script chạy BÌNH THƯỜNG (cleanup đầy đủ)

```
SAU KHI CHẠY XONG — SERVER TRỞ VỀ TRẠNG THÁI BAN ĐẦU

✅ ONAP Policy PAP: policy bị revoke, database sạch
✅ K8s pods: VNF pod bị delete, namespace pad-onap trống
✅ OVS br-pad: flow rules bị xóa, bridge còn nhưng trống
✅ DMaaP: message tự hết hạn sau 1 giờ
✅ Mininet: exit đúng cách → namespace/veth xóa hết
✅ gNMI Simulator: dừng process → hết
```

---

## Tóm tắt: Nếu script bị KILL giữa chừng (không cleanup)

```
VẤN ĐỀ CÓ THỂ CÒN LẠI:

⚠️ VNF pod còn chạy → dùng 16GB RAM
⚠️ Policy còn trong PAP → CLAMP có thể enforce
⚠️ OVS rule còn → traffic r1 bị redirect
⚠️ Mininet namespace còn → ovs-vsctl show thấy r1/r2/r3

CÁCH DỌN DẸP THỦ CÔNG:
  # Xóa VNF pods
  kubectl delete pods -n pad-onap --all

  # Revoke policy
  curl -X DELETE http://$NODE_IP:30969/policy/pap/v1/pdps/policies/PAD_ONAP_T3_r1 \
    -u healthcheck:zb!XztG34

  # Xóa OVS rules
  sudo ovs-ofctl del-flows br-pad

  # Dọn Mininet
  sudo mn --clean
```

---

## Khuyến nghị trước khi chạy trên server production ONAP

### Nếu ONAP đang phục vụ mục đích khác (không phải test riêng)

```
❌ KHÔNG chạy S2/S8 real trực tiếp
→ Thay bằng dry-run mode:
   python run_s2_real.py --dry-run
   python run_s8_real.py --dry-run

→ Chỉ test preflight, không gọi SO/PAP/OVS
```

### Nếu ONAP là server test riêng cho luận văn

```
✅ An toàn để chạy, với điều kiện:
   1. Kiểm tra RAM còn trống ≥ 20 GB trước khi chạy
   2. Không Ctrl+C giữa chừng — để script tự cleanup
   3. Nếu lỡ kill: chạy cleanup thủ công ở trên
   4. Chạy preflight_check.py trước
```

### Kiểm tra tài nguyên trước khi chạy

```bash
# RAM còn trống
free -h
kubectl top nodes

# Ví dụ kết quả an toàn:
# NAME    CPU%   MEMORY%
# node1   35%    60%      ← còn 40% RAM → OK chạy S2/S8

# Ví dụ kết quả NGUY HIỂM:
# node1   80%    88%      ← chỉ còn 12% RAM → KHÔNG nên chạy
```

---

## Kịch bản thực tế: Server ONAP test riêng của lab

Đây là kịch bản phổ biến nhất cho luận văn:

```
Server: Ubuntu 22.04, 64GB RAM, 16 CPU, ONAP OOM đang chạy
RAM ONAP dùng: ~40-45 GB
RAM còn trống: ~20 GB

Ảnh hưởng khi chạy S8:
  T2 phase: +2 GB RAM (ratelimiter, 30s)    → tổng ~47 GB ✅
  T3 phase: +16 GB RAM (scrubber, 35s)      → tổng ~61 GB ⚠️

→ Sát giới hạn, nhưng chạy được
→ Sau khi cleanup: về lại ~45 GB

Khuyến nghị: Chạy S2 trước (chỉ T3 ~6s), xác nhận cleanup OK
             Rồi mới chạy S8 (T2+T3)
```

---

## Script dọn dẹp khẩn cấp (lưu lại để dùng)

```bash
#!/bin/bash
# emergency_cleanup.sh — Chạy khi script bị kill giữa chừng

echo "=== PAD-ONAP Emergency Cleanup ==="

# 1. Kill gNMI simulator
pkill -f "gnmi_simulator/main.py" && echo "[OK] gNMI stopped"

# 2. Kill hping3 nếu đang chạy
sudo pkill hping3 2>/dev/null && echo "[OK] hping3 stopped"

# 3. Xóa tất cả VNF pods
kubectl delete pods -n pad-onap --all --grace-period=0 2>/dev/null
echo "[OK] VNF pods deleted"

# 4. Revoke policies trong ONAP PAP
NODE_IP=${NODE_IP:-localhost}
for TIER in T1 T2 T3 T4; do
  curl -s -X DELETE \
    "http://$NODE_IP:30969/policy/pap/v1/pdps/policies/PAD_ONAP_${TIER}_r1" \
    -u healthcheck:zb!XztG34 -o /dev/null
done
echo "[OK] Policies revoked"

# 5. Xóa OVS rules trên br-pad
sudo ovs-ofctl del-flows br-pad 2>/dev/null && echo "[OK] OVS flows cleared"

# 6. Dọn Mininet
sudo mn --clean 2>/dev/null && echo "[OK] Mininet cleaned"

echo "=== Cleanup done. Verify: ==="
echo "  kubectl get pods -n pad-onap"
echo "  sudo ovs-ofctl dump-flows br-pad"
echo "  kubectl top nodes"
```

```bash
# Lưu và chạy:
chmod +x emergency_cleanup.sh
./emergency_cleanup.sh
```
