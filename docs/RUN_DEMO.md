# PAD-ONAP Demo Runbook

Hướng dẫn chạy + kịch bản trình bày cho luận văn.

> **Kiến trúc nhanh**: trong project này **frontend và backend là 1 process**
> (FastAPI uvicorn). Backend serve API tại `/api/*` + WebSocket tại `/ws`, và
> serve static files (HTML/CSS/JS) tại `/`. Không cần npm/webpack/Node.

---

## 1. Setup 1 lần (5 phút)

Trên WSL2 Ubuntu (hoặc Linux thật):

```bash
# 1. Lấy code
cd "/mnt/d/Khóa luận/Src_2"     # hoặc clone từ git

# 2. Fix line endings nếu cần (file từ Windows)
sed -i 's/\r$//' scripts/*.sh

# 3. Cấp quyền state directory
sudo mkdir -p /tmp/pad-onap && sudo chmod 777 /tmp/pad-onap

# 4. Setup venv (script tự làm nếu chưa có)
python3 -m venv .venv
source .venv/bin/activate
pip install -r frontend/requirements.txt
```

---

## 2. Khởi động — 3 mức tùy nhu cầu

### Mức A — Demo dashboard 1 lệnh (khuyến nghị cho defense)

```bash
bash scripts/start_demo_wsl.sh --auto S3
```

Mức A tự:
- Kích hoạt venv
- Start uvicorn (`frontend.backend:app`) ở `:8088` (background)
- Start `sim_demo_state.py --auto S3` ở foreground (giả lập state, lặp scenario S3 mỗi 45s)

→ Mở `http://localhost:8088` ở trình duyệt Windows.

Dừng: `Ctrl+C` (script tự kill backend).

### Mức B — Backend riêng, simulator riêng (debug)

```bash
# Terminal 1 — backend
source .venv/bin/activate
export PYTHONPATH="$PWD"
export PAD_K=4
python -m uvicorn frontend.backend:app --host 0.0.0.0 --port 8088 --reload

# Terminal 2 — simulator (chọn scenario thủ công qua UI)
source .venv/bin/activate
export PYTHONPATH="$PWD"
python scripts/sim_demo_state.py
```

`--reload` ở uvicorn tự reload khi sửa code Python. Hữu ích lúc dev.

### Mức C — Full pipeline với Mininet thật

```bash
sudo bash scripts/start_full.sh --k 4 --auto S3
# hoặc k=2, k=6, k=8
```

Cần `mininet`, `openvswitch-switch`, `hping3`, `ryu`. Chỉ chạy trên Linux thật
(không phải WSL1).

---

## 3. Verify dashboard chạy đúng

Sau khi khởi động ~5 giây:

```bash
# Health check API
curl -s http://localhost:8088/api/state | head -c 200

# Topology endpoint
curl -s http://localhost:8088/api/topology_info | python3 -m json.tool

# Expect:
# {
#   "k": 4,
#   "n_core": 4, "n_agg": 8, "n_edge": 8, "n_hosts": 16,
#   "attacker_default": "h0",
#   "victim_default": "h15"
# }
```

Trong trình duyệt, mở Dev Console (F12) — không có lỗi đỏ, WebSocket `/ws`
hiển thị status `101` (Switching Protocols).

---

## 4. Kịch bản demo — 10 phút (cho thesis defense)

> **Mục tiêu**: cho hội đồng thấy (1) closed-loop hoạt động end-to-end,
> (2) AI mode phát hiện sớm hơn rule-only, (3) hệ thống scale được.

### Scene 1 — Giới thiệu giao diện (0:00 – 0:30)

Trạng thái: dashboard idle (chưa scenario nào).

**Nói**:
> "Đây là dashboard giám sát hệ thống PAD-ONAP. Tôi sẽ chỉ ra 5 vùng chính."

**Trỏ vào**:
- **Header** (top): chip Scenario / Mode / Tier / Health / Topology k
- **KPI row** (4 card): Traffic Rate · Attack Score · Forecast Risk · CNF Status
- **Left panel**: scenario controls + 8 scenario card + profile + legend
- **Center topology**: 11 nodes, 3 layer (Network → Streaming & AI → ONAP Closed Loop)
- **Pipeline trace** dưới topology: 7 stage hiển thị waterfall thời gian
- **Right panel**: node details (click để xem)
- **Timeline** dưới cùng: chronological events

**Trỏ vào step card** (góc dưới-trái topology):
> "Card này kể từng bước — hiện đang ở step 0/8, system idle."

### Scene 2 — Baseline benign (0:30 – 1:30)

**Hành động**:
1. Click card **S1 — Baseline benign** ở sidebar trái

**Quan sát + nói**:
> "Tôi chạy S1, traffic benign UDP 4000 pps. Pipeline phải KHÔNG misclassify."
- Particle xanh cyan chạy chậm N1 → N2 → N3 → N4 → N5
- KPI Traffic Rate tăng nhẹ (~50 Mbps), Attack Score = 0–10 (Low)
- **Tier vẫn T0**, header xanh "System Healthy"
- Step card vẫn ở Step 2 (Attack ingress) hoặc Step 3 (Telemetry → Kafka → Flink)
- Pipeline trace: M1, M2 active nhưng M3 không emit tier

> "Đúng kỳ vọng — false-positive rate = 0%."

2. Click **Reset** trong scenario list

### Scene 3 — AI-assisted Volumetric UDP (1:30 – 4:00) ⭐ KEY

**Hành động**:
1. Đảm bảo toggle **Enable AI** đang ON (mặc định)
2. Click card **S3 — Volumetric UDP Flood**

**Quan sát theo timeline 30 giây**:

| t (s) | Diễn biến trên dashboard | Nói gì |
|---|---|---|
| 0–2 | Particle đỏ bắt đầu N1→N2 nhẹ; KPI Traffic = ~5 Mbps | "Tấn công bắt đầu, hping3 floods victim:80" |
| 2–4 | Particle đỏ dày lên; Traffic Rate ~750 Mbps; Attack Score = 30; Forecast Risk = Medium | "Telemetry sFlow đi qua collector → Kafka → Flink. AI bắt đầu thấy gì đó." |
| 4–5 | Step card: **Step 4 — AI inference**; N6 active xanh đậm; score = 70 | "M3 XGBoost + Transformer/LSTM. Confidence 0.94, forecast High." |
| 5 | Tier chip đổi T0 → **T3** màu cam; KPI Attack Score badge = "High" | "Policy chọn tier T3 từ score + forecast." |
| 5–6 | Step card: **Step 6 — Fast-path Ryu (~8 ms)**; pipeline trace bar Ryu hiện màu xanh lá 8ms | "Đây là fast-path: Ryu push Flow-Mod redirect tới tất cả OVS switch chỉ trong 8ms." |
| 6–8 | Step card: **Step 7 — SO instantiates CNF**; node N9, N10 active | "Slow-path: ONAP CLAMP → Policy PDP → SO chạy kubectl create scrubber VNF pod" |
| 8 | Step card: **Step 8 — Closed loop complete**; particle xanh lá dày N9→N10→N11 và N2→N11; KPI CNF Status: 1/1 Active, donut xanh; trace bar ONAP ~2400ms tím | "Scrubber pod /health OK. Loop hoàn tất. Clean traffic giờ đi qua scrubber tới protected service." |

**Trỏ pipeline trace**:
> "Đây là waterfall thời gian: M1 14ms, M2 60ms, M3 92ms, M4 8ms. Tổng AI inference 174ms. Fast-path Ryu thêm 8ms. Slow-path ONAP mất 2400ms — đây là 2 trục thời gian song song."

**Trỏ topology**:
> "Edge đỏ dashed = attack inbound vẫn tới (Ryu chặn ở switch). Edge xanh lá liền nét = clean traffic tới N11. Edge xanh lá dashed quanh N10 = Ryu rule installed."

3. Click **Reset** trong sidebar

### Scene 4 — Rule-only comparison (4:00 – 6:00) ⭐ KEY

**Hành động**:
1. Toggle **Compare Rule-only** ON (tự tắt Enable AI)
2. Click S3 lại

**Quan sát + nói**:

| t (s) | Khác với AI mode | Nói |
|---|---|---|
| 0–5 | Giống AI mode về particle/traffic | "Cùng tấn công, nhưng giờ pipeline KHÔNG dùng AI" |
| 5 | N6 (AI) **vẫn idle xám**; Forecast Risk = "n/a"; tier vẫn T0 | "AI node bị tắt. Policy chỉ dùng threshold rule." |
| 5–7 | Traffic vẫn tăng nhưng tier chưa kích hoạt | "Threshold chưa vượt — system chưa biết bị tấn công" |
| **7** | Tier nhảy T0 → **T3** (chậm hơn AI mode 2 giây) | "Bây giờ rule mới trigger vì pps > threshold. Chậm hơn 2 giây so với AI." |
| 7–10 | Closed loop tương tự nhưng tổng exposure window lâu hơn | "2 giây thêm này = ~100k packet tấn công lọt thêm tới victim." |

**Trỏ KPI Forecast Risk**:
> "Trong rule mode, Forecast Risk không tồn tại — không có dự báo proactive."

**Kết luận scene**:
> "AI mode phát hiện sớm hơn 2 giây và cung cấp forecast horizon 30s.
> Đây là lợi thế của hybrid XGBoost + Transformer/LSTM so với rule-only."

3. Toggle **Enable AI** trở lại; click **Reset**

### Scene 5 — Scalability k=2 ↔ k=4 (6:00 – 7:30)

**Hành động**:
1. Trong dropdown header **Topology k**, đổi từ 4 sang **2**

**Quan sát + nói**:
> "Vừa đổi sang fat-tree k=2 — chỉ 1 core, 2 agg, 2 edge, 2 hosts. Hệ thống
> tự reset, scenario list refresh: victim giờ là h1 thay h15, rate target
> scale xuống 40%."

- KPI tất cả về 0
- Scenario card S3 hiển thị rate target ~20k pps thay vì 50k

2. Click S3

**Quan sát + nói**:
> "Cùng pipeline, cùng closed loop, nhưng trên topology nhỏ hơn. AI vẫn
> detect, Ryu vẫn install rule, ONAP vẫn spawn VNF. Pipeline logic
> không phụ thuộc kích thước fabric."

3. Đợi 15s đến khi tier=3 stable
4. Đổi dropdown về **4** → reset tự xảy ra
5. Click S3 lại để show k=4

> "k=6 cho 54 hosts, k=8 cho 128 hosts — cùng cấu trúc fat-tree, cùng pipeline."

### Scene 6 — Multi-vector (7:30 – 8:30) tùy chọn

**Hành động**:
1. Reset
2. Click **S5 — Multi-vector**

**Quan sát + nói**:
> "S5 là tấn công đa hướng: SYN + UDP + ICMP từ 3 attacker đồng thời h0, h4, h8."

- Tier escalate lên **T4** (critical, đỏ đậm)
- Header chip Health đổi sang "Critical" (nền đỏ)
- CNF Status có thể chuyển "Degraded" trong lúc scaling
- Step card: closed loop hoàn tất với blackhole VNF

> "Tier T4 = blackhole policy. Ryu drop ở first switch hit, ONAP spawn
> blackhole VNF làm secondary defense."

### Scene 7 — Node inspection (8:30 – 9:30) tùy chọn

**Hành động**:
1. Click vào node **N6 (AI Detection & Forecasting)** trên topology

**Quan sát + nói trong panel phải**:
> "Right panel hiển thị runtime details của node được chọn. Với N6:
> attack_score, confidence, forecast_horizon, forecast_risk, model name."

2. Click N8 (Policy Framework):
> "Policy hiển thị tier được chọn, rule matched, decision basis."

3. Click N10 (CNF Scrubber):
> "Scrubber pod: replica 1/1, mode syn-proxy, action redirect."

4. Click edge nào đó:
> "Edge cũng có pps badge: 52,460 pps trên N1→N2, mitigated giảm còn
> 7,869 pps clean traffic tới N11."

### Scene 8 — Tổng kết (9:30 – 10:00)

**Hành động**: Reset, dropdown về k=4, mode về AI

**Nói**:
> "Hệ thống PAD-ONAP kết hợp:
> · **Network layer**: gNMI/gRPC telemetry từ fat-tree DCN
> · **Streaming & AI layer**: Kafka + Flink + hybrid XGBoost / Transformer-LSTM
> · **ONAP closed loop**: DCAE → Policy → SO → CNF
>
> Đóng góp chính của luận văn:
> 1. Hybrid AI model phát hiện DDoS sớm hơn rule-only 2 giây
> 2. Dual-path mitigation: Ryu fast-path (~ms) + ONAP slow-path (~giây)
> 3. Generic theo kích thước fat-tree (k=2..8) — không cần retrain"

---

## 5. Backup plan nếu UI hỏng giữa demo

```bash
# Restart toàn bộ
pkill -f sim_demo_state || true
kill $(cat /tmp/pad-onap/backend.pid 2>/dev/null) 2>/dev/null
bash scripts/start_demo_wsl.sh --auto S3
```

Nếu particle không chạy / topology không hiện:
- F12 → Console: check WebSocket connected
- F12 → Network → WS → `/ws` → Messages tab xem có payload không
- Nếu không: refresh trang (Ctrl+F5)

---

## 6. Checklist trước khi vào defense

- [ ] WSL Ubuntu đã active, `cd /mnt/d/Khoa luan/Src_2` đã cd OK
- [ ] `bash scripts/start_demo_wsl.sh --auto S3` chạy thành công ≥1 lần
- [ ] `http://localhost:8088` mở được, thấy UI light theme
- [ ] Particle hiển thị (Cytoscape canvas hoạt động)
- [ ] Toggle Compare Rule-only test được, AI node mờ đi
- [ ] Dropdown k=2 / k=4 đổi được, scenarios refresh
- [ ] Trình duyệt fullscreen F11 (đẹp hơn khi chiếu)
- [ ] Zoom Cytoscape về fit (Ctrl+0 không có; dùng nút wheel mouse hoặc refresh)

---

## 7. Command sheet (in mang vào defense)

```
START          bash scripts/start_demo_wsl.sh --auto S3
RESET          click "Reset" trong sidebar  (hoặc:  curl -X POST localhost:8088/api/scenario/reset)
SWITCH k       dropdown header  hoặc:  curl -X POST localhost:8088/api/topology/k -H 'Content-Type: application/json' -d '{"k": 2}'
AI MODE        toggle "Enable AI"     hoặc:  curl -X POST localhost:8088/api/scenario/enable-ai
RULE MODE      toggle "Compare Rule-only"  hoặc:  curl -X POST localhost:8088/api/scenario/compare-rule-only
PICK SCENARIO  click S1..S8 card      hoặc:  curl -X POST localhost:8088/api/scenario/S3
STOP           Ctrl+C trong terminal launcher
```

Endpoint tham chiếu nhanh trong [systemdesign.md §16] và backend file
`frontend/backend.py`.
