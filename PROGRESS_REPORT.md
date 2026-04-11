# BÁO CÁO TIẾN ĐỘ — PAD-ONAP
## Proactive AI-Driven DDoS Defense on ONAP
### Phase AI (M2) — Kết quả thực nghiệm

---

## SLIDE 1 — Tổng quan hệ thống

```
Luồng dữ liệu PAD-ONAP:

  Mạng        S1           S2            S3-AI          S4
  Traffic → [gNMI] → [Apache Flink] → [XGBoost   ] → [Risk/Policy]
                      Feature Extract   Transformer     ONAP VES
                      100-flow/5s        LSTM            Mitigation
                      17 features        4-horizon
```

**Phạm vi báo cáo:** S3-AI — Huấn luyện và đánh giá mô hình phát hiện DDoS

---

## SLIDE 2 — Dataset: CICDDoS2019

| Thuộc tính | Giá trị |
|---|---|
| Nguồn | Canadian Institute for Cybersecurity, 2019 |
| Raw data | 18 file CSV (~5GB), 2 ngày: 03/11 và 01/12 |
| Cửa sổ trích xuất | 100 flow / ~5 giây, slide 50 flow |
| **Tổng windows** | **35,928** |
| Train / Test | 28,742 / 7,186 (temporal split 80/20) |
| Features | 17 (entropy + rate) |
| BENIGN unique | 646 windows (oversampled ×21.9) |

**Phân phối class (Train):**

| Class | Số windows | Tỉ lệ |
|---|---|---|
| Normal (BENIGN) | 14,175 | 49.3% |
| Amplification (DNS/NTP/LDAP/…) | 10,575 | 36.8% |
| UDP_Flood | 1,996 | 6.9% |
| SYN_Flood | 998 | 3.5% |
| HTTP_Flood (TFTP proxy) | 998 | 3.5% |
| ICMP_Flood | 0 | — (không có trong dataset) |
| Slow_rate | 0 | — (không có trong dataset) |

> **Lưu ý:** Temporal split gây distribution shift — UDP tăng từ 6.9% (train) lên 27.1% (test)
> do các file attack phân bố không đều theo thời gian.

---

## SLIDE 3 — Bộ đặc trưng 17 Features

**Nhóm Rate:**
- `pkt_rate` — gói/giây
- `byte_rate` — byte/giây
- `new_flows_rate` — flow mới/giây
- `flow_duration_mean` — thời gian trung bình mỗi flow

**Nhóm Entropy (Shannon):**
- `src_ip_entropy` — proxy: entropy Avg Fwd Segment Size ×10
- `dst_ip_entropy` — proxy: entropy Avg Bwd Segment Size ×10
- `src_port_entropy` — đa dạng cổng nguồn
- `dst_port_entropy` — đa dạng cổng đích (**SHAP dominant**)

**Nhóm Protocol:**
- `proto_dist_tcp/udp/icmp` — tỉ lệ từng giao thức
- `syn_ratio`, `fin_ratio` — tỉ lệ cờ TCP

**Nhóm Packet Size:**
- `avg_pkt_size`, `pkt_size_std`

**Nhóm Inter-arrival:**
- `inter_arrival_mean`, `inter_arrival_std`

**ANOVA F-score top-3 (discriminative nhất):**
1. `dst_port_entropy` — DDoS flood 1 port → entropy≈0, BENIGN dùng nhiều port → entropy cao
2. `src_port_entropy`
3. `proto_dist_tcp`

---

## SLIDE 4 — EDA: Kết quả chính

**Tương quan cao (structural redundancy):**

| Cặp feature | Pearson r | Ghi chú |
|---|---|---|
| proto_dist_tcp ↔ proto_dist_udp | −0.9992 | Tổng với icmp ≈ 1 (không thể fix) |
| dst_ip_entropy ↔ dst_port_entropy | −0.9554 | Cả hai phân biệt DDoS vs BENIGN |
| inter_arrival_mean ↔ inter_arrival_std | +0.8868 | Trong DDoS, mean ≈ std |

**Outlier rate cao nhất:** `flow_duration_mean`, `inter_arrival_std`, `pkt_size_std`
(DDoS tạo ra outliers cực đoan — thực chất là signal tốt)

**PCA:** 2 thành phần đầu giải thích ~72% variance — feature set compact

**t-SNE:** 5 class tạo cluster rõ ràng, chỉ UDP↔Amplification có overlap nhỏ

---

## SLIDE 5 — Track A: XGBoost 7-class Classifier

**Kiến trúc:**
- Input: 17 features/window
- FGSM Adversarial Augmentation (ε=0.01) trên attack samples → 2× training data
- Auto HP search: 4 configs, early stopping 30 rounds
- GPU: hist + cuda (RTX 3050)

**Kết quả holdout (temporal test set):**

| Metric | Giá trị | Target | Đạt |
|---|---|---|---|
| Accuracy | **0.9825** | ≥ 0.95 | ✅ |
| Macro F1 | **0.9642** | ≥ 0.90 | ✅ |
| AUC (OvR macro) | **0.9958** | — | ✅ |
| P99 Inference | **2.2 ms** | < 10ms | ✅ |

**Confusion matrix (sai chủ yếu):**
- 77 UDP_Flood → Amplification (cùng dùng UDP, pkt size tương tự)
- 54 SYN_Flood → UDP_Flood (proto overlap ở một số file)

**SHAP Top-5 (7-class):**
1. `src_port_entropy` 2. `proto_dist_tcp` 3. `proto_dist_udp` 4. `avg_pkt_size` 5. `inter_arrival_mean`

---

## SLIDE 6 — Track A: Cross-Validation (Leak-free)

**Methodology:**
- 5-Fold Stratified CV
- BENIGN oversampling CHỈ trong train fold (646 raw windows saved riêng)
- Attack-only CV: 4-class [UDP, SYN, HTTP, Amplification]

**5-Fold CV kết quả (attack-only, không có Normal):**

| Metric | Mean | Std |
|---|---|---|
| Accuracy | 0.9987 | ±0.0004 |
| Macro F1 | 0.9981 | ±0.0005 |
| AUC | 1.0000 | — |

**Per-class F1 (attack-only CV):**

| Class | F1 |
|---|---|
| UDP_Flood | 0.9971 ±0.0009 |
| SYN_Flood | 0.9956 ±0.0010 |
| HTTP_Flood | 1.0000 |
| Amplification | 0.9998 |

> AUC=1.0 ở attack-only CV là **legitimate** — 4 loại attack có fingerprint network thực sự khác biệt
> (proto, port, packet size hoàn toàn khác nhau)

---

## SLIDE 7 — Track B: Transformer + LSTM 4-Horizon Forecaster

**Kiến trúc:**
```
Input: (batch, 12, 17)  ← 12 timesteps × 5s = 60s rolling window

Linear(17→64)
+ Sinusoidal Positional Encoding
→ TransformerEncoder (4 heads, d_model=64, 2 layers)
→ LSTM (hidden=128, 2 layers, dropout=0.2)
→ FC: 128 → 64 → 4
→ Sigmoid → [P(t+30s), P(t+60s), P(t+90s), P(t+120s)]
```

**Training:** BCE per horizon, class weight attack:normal = 10:1, Mixed Precision (AMP)

**Kết quả:**

| Horizon | AUC | Accuracy | Target AUC | Đạt |
|---|---|---|---|---|
| t+30s | **0.9884** | **0.9804** | ≥ 0.90 | ✅ |
| t+60s | **0.9833** | **0.9724** | ≥ 0.90 | ✅ |
| t+90s | **0.9772** | **0.9674** | ≥ 0.90 | ✅ |
| t+120s | **0.9711** | **0.9596** | ≥ 0.90 | ✅ |
| P99 Latency | **7.68 ms** | — | < 10ms | ✅ |

**Proactive trigger:** P(t+30s) > 0.70 → Tier 2 pre-position signal gửi đến S4

> AUC giảm đơn điệu 0.988→0.971 theo horizon — đúng hành vi forecasting, không phải lỗi

---

## SLIDE 8 — So sánh ML: XGBoost vs LightGBM vs Random Forest

**Holdout test (temporal 20%):**

| Model | Accuracy | Macro F1 | AUC | P99 Latency |
|---|---|---|---|---|
| **XGBoost** | 0.9812 | 0.9613 | 0.9978 | **2.2 ms** |
| LightGBM | 0.9786 | 0.9556 | 0.9980 | 5.1 ms |
| **Random Forest** | **0.9900** | **0.9842** | **0.9989** | 90.0 ms |

**5-Fold CV (leak-free, attack+normal):**

| Model | Accuracy | Macro F1 | AUC |
|---|---|---|---|
| XGBoost | 0.9992 ±0.0005 | 0.9990 ±0.0007 | 0.9999 |
| LightGBM | 0.9992 ±0.0007 | 0.9989 ±0.0010 | 0.9999 |
| Random Forest | **0.9996 ±0.0004** | **0.9995 ±0.0005** | **1.0000** |

**Kết luận chọn XGBoost:**
- RF có F1 cao nhất nhưng P99=90ms → **không đáp ứng real-time** (target <10ms)
- XGBoost: P99=2.2ms, F1=0.9613 — tốt nhất về latency
- LightGBM: trung gian, không có lợi thế rõ ràng
- **→ XGBoost được chọn cho production (Track A)**

---

## SLIDE 9 — Giới hạn đã biết (Documented Limitations)

| # | Giới hạn | Mức độ ảnh hưởng |
|---|---|---|
| L1 | BENIGN chỉ có 646 unique windows → oversampling ×21.9 | Trung bình — Binary AUC=1.0 (legitimate) |
| L2 | Distribution shift train↔test (temporal split) | Thấp — Realistic deployment scenario |
| L3 | ICMP_Flood (class 4) vắng trong CICDDoS2019 | Cao — Không evaluate được |
| L4 | Slow_rate (class 6) vắng trong CICDDoS2019 | Cao — Không evaluate được |
| L5 | proto_tcp ↔ proto_udp r=−0.9992 (structural) | Thấp — Không thể fix, documented |
| L6 | Single dataset (CICDDoS2019) — chưa test cross-dataset | Trung bình — Thesis scope |

> **Tất cả limitations đã được document và có justification** — thesis defensible

---

## SLIDE 10 — Tổng hợp kết quả

```
┌─────────────────────────────────────────────────────────┐
│           KẾT QUẢ PHASE AI (M2) — PAD-ONAP             │
├──────────────┬──────────────────────────────────────────┤
│  TRACK A     │  XGBoost 7-class Classifier              │
│              │  Acc=0.9825 | F1=0.9642 | AUC=0.9958    │
│              │  P99=2.2ms ← real-time đạt yêu cầu      │
├──────────────┼──────────────────────────────────────────┤
│  TRACK B     │  Transformer+LSTM 4-Horizon Forecast     │
│              │  t+30s: AUC=0.9884 | ACC=0.9804         │
│              │  t+120s: AUC=0.9711 | ACC=0.9596        │
│              │  P99=7.68ms ← real-time đạt yêu cầu     │
├──────────────┼──────────────────────────────────────────┤
│  PROACTIVE   │  P(t+30s) > 0.70 → kích hoạt pre-       │
│  TRIGGER     │  position trước 30-120 giây             │
├──────────────┼──────────────────────────────────────────┤
│  XAI         │  SHAP TreeExplainer — giải thích từng   │
│              │  quyết định inference theo feature       │
└──────────────┴──────────────────────────────────────────┘
```

---

## SLIDE 11 — Trạng thái & Bước tiếp theo

**Đã hoàn thành ✅**
- [x] S1: gNMI collector (giả lập)
- [x] S2: Apache Flink feature extractor (17 features)
- [x] S3-AI: Feature extraction + Training pipeline
- [x] S3-AI: Track A — XGBoost 7-class + SHAP
- [x] S3-AI: Track B — Transformer+LSTM 4-horizon
- [x] S3-AI: EDA (13 figures), ML comparison, CV analysis
- [x] Models saved: `models_v2/xgboost_7class_v2.json`, `transformer_lstm_v2.pt`

**Đang thực hiện / Tiếp theo 🔄**
- [ ] S3-AI: Inference layer (real-time scoring pipeline)
- [ ] S3-AI: ADWIN concept drift detection (spec §4.4)
- [ ] S4: Risk/Policy engine → ONAP VES Event
- [ ] Integration test: Flink → S3-AI → S4 end-to-end

**Timeline:** S4 + Integration dự kiến hoàn thành trong 3-4 tuần tới

---

*Tất cả code tại: `pipeline/s3_ai/` | Models: `models_v2/` | EDA: `notebooks/`*
