# Thesis Evidence Map

**Đề tài:** *AI-Augmented NFV Orchestration for Proactive DDoS Mitigation in Data Center Networks*

Mỗi chương luận văn → artifact cụ thể trong repo. Dùng file này làm bộ khung khi viết bản thảo: mỗi claim trong luận văn phải link về một artifact ở đây.

---

## Chương 1 — Giới thiệu & Động cơ

| Claim | Bằng chứng |
|---|---|
| DDoS ngày càng phức tạp, phòng thủ phản ứng (reactive) không đủ | Trích dẫn CICDDoS2019 báo cáo; dataset dùng thật ở [`Dataset/`](../Dataset/) |
| ONAP là framework NFV orchestration chuẩn của Linux Foundation | Mapping SO/CLAMP/Policy trong [`pipeline/s4_orchestration/`](../pipeline/s4_orchestration/) |
| AI có thể cung cấp tín hiệu *dự báo* (forecast) trước khi tấn công đạt đỉnh | Kết quả S3, S7, S8 trong `evaluation/results/` + phân tích lead-time (§5) |

## Chương 2 — Cơ sở lý thuyết

| Chủ đề | File / kết quả |
|---|---|
| NFV / SFC / OpenFlow | [`pipeline/s4_orchestration/sfc_manager.py`](../pipeline/s4_orchestration/sfc_manager.py) |
| Khung ONAP (SO, CLAMP, Policy, DMaaP) | [`onap_so_client.py`](../pipeline/s4_orchestration/onap_so_client.py), [`clamp_simulator.py`](../pipeline/s4_orchestration/clamp_simulator.py), [`policy_engine.py`](../pipeline/s4_orchestration/policy_engine.py) |
| XGBoost, Transformer+LSTM | [`pipeline/s3_ai/`](../pipeline/s3_ai/) + memory `project_ai_v2_training.md` |
| Fat-tree DCN (Al-Fares) | [`testbed/mininet/fat_tree_topology.py`](../testbed/mininet/fat_tree_topology.py) |

## Chương 3 — Kiến trúc đề xuất

Luồng 4 tầng S1→S4 đã mô tả trong [README.md](../README.md) và `graphify-out/GRAPH_REPORT.md` (god nodes: `Orchestrator`, `InferenceEngine`, `TransformerLSTMForecaster`, `AIOutputPayload`).

Sơ đồ cần vẽ trong luận văn:
- Kiến trúc 4 tầng (S1 telemetry → S2 features → S3 AI → S4 orchestration)
- Closed-loop ONAP (AI → DMaaP → CLAMP → Policy → SO → SFC)
- 5-tier escalation (T0…T4) — xem `tier_mapper.py`

## Chương 4 — Thành phần AI

| Mục | Artifact |
|---|---|
| 17 features (entropy/rate) | [`pipeline/s2_features/`](../pipeline/s2_features/) |
| XGBoost 7-class (AUC 0.9999) | memory `project_ai_v2_training.md`, models tại `models_v2/` |
| Transformer+LSTM 4-horizon | ibid. |
| Cross-validation (time-series + stratified) | Community 5 trong graph report |
| Adversarial robustness (FGSM) | Communities 12, 17, 23 |
| SHAP interpretability | `InferenceEngine.infer()` trả `top_features` |

## Chương 5 — Thực nghiệm & Đánh giá

### 5.1 Kịch bản S1–S8 (AI)

`evaluation/results/evaluation_summary.json` — **8/8 PASS**.

Bảng cần nhúng:
| Scenario | Max tier | Proactive# | T2 p50 (ms) | T3 p50 (ms) |
|---|---|---|---|---|
| S1 baseline | T0 | 0 | — | — |
| S2 UDP flood | T3 | 0 | — | 6006 |
| S3 SYN ramp | T2 | 67 | 506 | — |
| S4 HTTP OOD | T1 | 0 | — | — |
| S5 ICMP OOD | T0 | 0 | — | — |
| S6 multi | T3 | 48 | 505 | 6005 |
| S7 SLA 3-tenant | T2 | 78 | 506 | — |
| S8 novelty | T3 | 30 | 505 | 6006 |

**S8 novelty:** T2 proactive ≈ 505 ms vs T3 reactive ≈ 6006 ms → **advantage ≈ 5.5 s** mỗi lần kích hoạt.

### 5.2 So sánh với threshold baseline (non-AI)

Chạy:
```bash
python -m evaluation.baseline_threshold --out-dir evaluation/results_baseline
python -m evaluation.lead_time_analyzer
```

Kết quả → `evaluation/results/lead_time_comparison.md` (bảng Markdown + CSV).

Điểm cần diễn giải trong luận văn:
- Baseline không có cột `proactive` → không thể pre-position.
- S3/S7: baseline chỉ kích hoạt T≥3 khi tấn công đạt ngưỡng tuyệt đối — AI kích hoạt T2 sớm hơn N×5 giây.
- S4/S5 (OOD): AI giữ T0–T1; baseline có thể over-escalate do rule cứng — bằng chứng về giá trị của ML ở traffic OOD.

### 5.3 Lead-time (proactive vs reactive)

Metric: `lead_time_s = 5s × (window_reactive_first − window_proactive_first)`. Output: `lead_time_comparison.{md,csv}`.

### 5.4 Mở rộng sang fat-tree DCN

Chạy:
```bash
sudo python3 testbed/mininet/fat_tree_topology.py --k 4 --test
```

Topology 20 switch + 16 host. Mapping attacker = `h0` (pod 0), victim = `h15` (pod 3). Bottleneck xuyên 3 pod → exercise core-layer steering. So sánh:
- Connectivity (pingall)
- Bisection throughput (iperf h0↔h15)
- Thời gian cài đặt SFC rule trên path dài (agg + core) vs path ngắn (cùng pod)

## Chương 6 — Kết luận

| Đóng góp luận văn | Nguồn chứng minh |
|---|---|
| Kiến trúc 4 tầng AI-augmented ONAP | `pipeline/`, `graphify-out/GRAPH_REPORT.md` |
| Forecast + proactive T2 pre-positioning | S3, S7, S8 + lead-time analyzer |
| So sánh định lượng với baseline | `baseline_summary.json`, `lead_time_comparison.md` |
| Testbed DCN (fat-tree k=4) | `fat_tree_topology.py` |
| OOD robustness (HTTP/ICMP không nằm trong train set) | S4, S5 PASS với `expected_max_tier≤1` |

## Hạn chế & Hướng phát triển

- SO/CLAMP hiện vẫn là stub Docker + simulator → bước tiếp theo: ONAP OOM thật.
- Fat-tree k=4 = 16 host; production DCN cần k≥8 (128 host).
- Forecast mới dùng 4 horizons (30/60/90/120 s) → có thể mở rộng sang multi-step autoregressive.
- Adversarial: hiện chỉ FGSM; thêm PGD / BIM trong ablation.

---
_Cập nhật file này mỗi khi thêm artifact. Mỗi bảng/hình trong luận văn phải trỏ về một mục cụ thể ở đây._
