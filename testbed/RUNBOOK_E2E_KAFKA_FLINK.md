# E2E Pipeline trên WSL2 — Mininet + Kafka + Flink + Real s3_ai (ONAP stub)

Hướng dẫn chạy `testbed/netflow_e2e_pipeline.py` đầy đủ luồng:

```
softflowd → netflow_collector ──Kafka pad.telemetry.raw──▶ flink_processor
                                                        │
                                                        ▼
                                  Kafka pad.telemetry.features
                                                        │
                                                        ▼
                          Orchestrator (AI hoặc Baseline) ──▶ ONAP SO (stub)
```

So sánh AI vs Baseline = chạy script **2 lần** với `--mode ai` và `--mode baseline`.

---

## 1. Yêu cầu môi trường WSL2

WSL2 (Ubuntu 22.04 khuyến nghị) có:

- Kernel hỗ trợ network namespace (mặc định OK)
- Docker Desktop (Windows) đã bật **WSL2 integration** với distro của bạn,
  HOẶC cài Docker engine native trong WSL2
- Có quyền `sudo`

### 1.1 Cài gói hệ thống

```bash
sudo apt-get update
sudo apt-get install -y \
    mininet openvswitch-switch \
    softflowd iperf hping3 curl \
    python3-venv python3-pip \
    fuser psmisc
# Khởi động OVS (không tự bật trong WSL2)
sudo service openvswitch-switch start
```

Kiểm tra OVS:

```bash
sudo ovs-vsctl show          # phải in ra config rỗng, không lỗi
```

### 1.2 Cài Python venv + dependencies

Từ thư mục gốc project (`Src_2/`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-pipeline.txt
# Mininet Python module thường nằm /usr/lib/python3/dist-packages → link vào venv:
ln -s /usr/lib/python3/dist-packages/mininet .venv/lib/python3*/site-packages/ 2>/dev/null || true
```

Quan trọng: script chạy với `sudo` → Python interpreter mặc định là
`/usr/bin/python3`, KHÔNG dùng venv. Hai cách giải quyết:

- **Cách A (khuyến nghị)**: cài deps vào system Python:
  ```bash
  sudo /usr/bin/python3 -m pip install -r requirements-pipeline.txt
  ```
- **Cách B**: chạy bằng `sudo .venv/bin/python testbed/netflow_e2e_pipeline.py ...`
  và đảm bảo `mininet` có trong site-packages của venv.

---

## 2. Khởi động Apache Kafka

Dùng compose có sẵn (không bật toàn bộ stack, chỉ Kafka):

```bash
cd testbed
docker compose up -d kafka
docker compose ps           # pad-kafka phải healthy
cd ..
```

Kiểm tra broker:

```bash
docker exec pad-kafka /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 --list
# Lần đầu sẽ rỗng — topics tự tạo khi producer publish.
```

> Script `netflow_e2e_pipeline.py` cũng tự gọi `docker compose up -d kafka`
> nếu chưa chạy.

---

## 3. Địa chỉ Kafka từ Mininet host namespace

Mininet hosts chạy trong **netns riêng**, không có IP trùng host root. Có 2 lựa chọn:

### 3a. Đơn giản nhất — bind broker lên `0.0.0.0` và dùng IP host

Mặc định compose đã advertise `EXTERNAL://${PAD_HOST:-localhost}:9092`.
Cần đổi `PAD_HOST` sang IP mà Mininet host nhìn thấy được. Trong WSL2,
host root IP thường là `10.0.0.1` (IP của bridge `s0` Mininet) hoặc
IP eth0 của WSL2 instance.

Lấy IP WSL2:

```bash
ip -4 addr show eth0 | awk '/inet/ {print $2}' | cut -d/ -f1
```

Tạo file `testbed/.env`:

```bash
echo "PAD_HOST=$(ip -4 addr show eth0 | awk '/inet/ {print $2}' | cut -d/ -f1)" \
    > testbed/.env
echo "PAD_KAFKA_PORT=9092" >> testbed/.env
docker compose -f testbed/docker-compose.yml up -d --force-recreate kafka
```

Sau đó chạy script với:

```bash
sudo -E python3 testbed/netflow_e2e_pipeline.py --mode ai \
    --broker localhost:9092 \
    --collector-kafka $(cat testbed/.env | grep PAD_HOST | cut -d= -f2):9092
```

- `--broker` = địa chỉ host root dùng (host process gồm flink_processor + Orchestrator).
- `--collector-kafka` = địa chỉ Mininet host namespace dùng để đẩy lên Kafka.

### 3b. Cách thay thế: chạy collector trên host root thay vì trong Mininet

Nếu phương án 3a phiền phức, có thể sửa script để collector chạy ngoài
Mininet và Mininet hosts gửi NetFlow UDP về IP host root. Xem ghi chú
"netflow_collector trên root namespace" ở mục 6 dưới.

---

## 4. Chạy 1 lần với `--mode ai`

```bash
cd Src_2
sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode ai \
    --k 4 \
    --duration 60 \
    --broker localhost:9092 \
    --collector-kafka <PAD_HOST_IP>:9092
```

Script sẽ:

1. `docker compose up -d kafka` (idempotent)
2. Spawn `pipeline/s2_features/flink_processor.py` (subprocess) consume
   `pad.telemetry.raw` → publish `pad.telemetry.features`. Log:
   `evaluation/results/flink_ai.log`
3. Đăng ký `KafkaFeatureConsumer` group `pad-e2e-ai-<ts>` trên topic
   `pad.telemetry.features`
4. Khởi tạo Mininet Fat-Tree k=4
5. Bật `netflow_collector --mode netflow --kafka-broker <ip>:9092` trên host h0
6. softflowd trên mọi Mininet host → UDP 6343 về h0
7. iperf background + legit + victim
8. Phase 1 (30s baseline) → Phase 2 (`--duration` UDP flood) → Phase 3 (20s recovery)
9. Kafka consumer lấy feature vector mới nhất → `Orchestrator._step(x)` (s3_ai
   thật, ONAP stub)
10. Sinh báo cáo `evaluation/results/real_e2e_ai_<ts>.{png,json}`

---

## 5. Chạy lần 2 với `--mode baseline`

```bash
sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode baseline \
    --k 4 \
    --duration 60 \
    --broker localhost:9092 \
    --collector-kafka <PAD_HOST_IP>:9092
```

Output: `evaluation/results/real_e2e_baseline_<ts>.{png,json}`.

---

## 6. So sánh 2 lần chạy

Sau khi có cả 2 file JSON, dùng đoạn Python ngắn để vẽ biểu đồ chồng:

```python
import json, glob, matplotlib.pyplot as plt
ai = json.load(open(sorted(glob.glob('evaluation/results/real_e2e_ai_*.json'))[-1]))
bs = json.load(open(sorted(glob.glob('evaluation/results/real_e2e_baseline_*.json'))[-1]))
plt.step(ai['series']['time_axis_rel_s'], ai['series']['tiers'], label='AI', where='post')
plt.step(bs['series']['time_axis_rel_s'], bs['series']['tiers'], label='Baseline',
         where='post', linestyle='--')
plt.axvline(0, color='gray'); plt.legend(); plt.grid()
plt.savefig('evaluation/results/compare_ai_vs_baseline.png', dpi=200)
```

So sánh nhanh từ JSON `metrics`:

- `detect_lag_s` — thời gian từ lúc tấn công bắt đầu đến tier đầu tiên >= ngưỡng dương
- `classification.tpr/fpr/f1` — phân loại theo cửa sổ
- `goodput_victim_mbps_by_phase.attack` — băng thông hợp pháp tới được victim trong khi bị tấn công

---

## 7. Chế độ ONAP stub

Script tự đặt `PAD_ONAP_STUB=true` (mặc định, dùng Docker stub trong
`pipeline/s4_orchestration/onap_so_client.py`). Để dùng ONAP thật:

```bash
sudo -E PAD_ONAP_STUB=false python3 testbed/netflow_e2e_pipeline.py --mode ai ...
```

(Cần ONAP SO endpoint sẵn sàng — không thuộc phạm vi runbook này.)

---

## 8. Troubleshooting

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| `❌ Kafka broker localhost:9092 không phản hồi` | `docker ps` xem `pad-kafka` có healthy không. Xem log: `docker logs pad-kafka`. |
| `n_windows = 0` | Collector hoặc Flink không có message. Xem `cat /tmp/collector.log` và `evaluation/results/flink_*.log`. |
| Collector log: `Kafka publisher disabled: NoBrokers...` | Mininet host namespace không reach được broker. Đặt `--collector-kafka <PAD_HOST_IP>:9092` đúng IP eth0. |
| `softflowd: command not found` | `sudo apt-get install -y softflowd` |
| `Cannot find dpctl` / OVS không lên | `sudo service openvswitch-switch start` |
| Mininet treo / `mn` không xoá | `sudo mn -c` |
| Flink subprocess exit ngay | Thiếu `kafka-python` trong system Python. `sudo /usr/bin/python3 -m pip install kafka-python==2.0.2`. |
| `ModuleNotFoundError: mininet` | `ln -s /usr/lib/python3/dist-packages/mininet .venv/lib/python3*/site-packages/`, hoặc dùng system python với sudo. |

Xem log thời gian thực 3 luồng song song:

```bash
tail -f /tmp/collector.log &
tail -f evaluation/results/flink_ai.log &
# script chính in ra stdout
```

---

## 9. Kiểm tra mạch dữ liệu Kafka thủ công (debug)

Trước khi chạy E2E full, có thể test riêng từng tầng:

```bash
# Tầng 1: collector publish gì lên pad.telemetry.raw
docker exec pad-kafka /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic pad.telemetry.raw --from-beginning --max-messages 3

# Tầng 2: flink output trên pad.telemetry.features
docker exec pad-kafka /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server localhost:9092 \
    --topic pad.telemetry.features --from-beginning --max-messages 3
```

---

## 10. Tóm tắt câu lệnh

```bash
# 1. Cài deps (1 lần)
sudo apt-get install -y mininet openvswitch-switch softflowd iperf hping3 curl
sudo /usr/bin/python3 -m pip install -r requirements-pipeline.txt
sudo service openvswitch-switch start

# 2. Bật Kafka
docker compose -f testbed/docker-compose.yml up -d kafka

# 3. Chạy AI
sudo -E python3 testbed/netflow_e2e_pipeline.py --mode ai \
     --duration 60 \
     --collector-kafka $(ip -4 addr show eth0 | awk '/inet/{print $2}' | cut -d/ -f1):9092

# 4. Chạy Baseline
sudo -E python3 testbed/netflow_e2e_pipeline.py --mode baseline \
     --duration 60 \
     --collector-kafka $(ip -4 addr show eth0 | awk '/inet/{print $2}' | cut -d/ -f1):9092

# 5. Output
ls evaluation/results/real_e2e_*_*.{png,json}
```
