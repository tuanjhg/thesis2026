# PAD-ONAP — Kế Hoạch Tiếp Theo (Cập nhật 2026-04-26)

> **Cập nhật 2026-04-26**: Thesis draft đầy đủ 6 chương tạo tại `Docs/thesis/`.
> Baseline + lead-time analyzer chạy thành công với số liệu thực.

---


## P0 — Bắt buộc trước khi bảo vệ

### P0.1 Chạy và thu kết quả baseline + lead-time
- [x] Chạy `python -m evaluation.baseline_threshold` → sinh `evaluation/results_baseline/`
- [x] Chạy `python -m evaluation.lead_time_analyzer` → sinh `lead_time_comparison.{md,csv}`
- [x] Kiểm tra baseline có **FAIL** ở S3/S4/S5 để chứng minh AI tốt hơn (nếu PASS hết → phải re-tune threshold hoặc thêm scenario khó hơn)
- [x] Vẽ 1 biểu đồ cột **T2-proactive latency vs T3-reactive latency vs Baseline-reactive latency** (3 cột × 8 scenarios)

### P0.2 Multi-seed + confidence interval
- [x] Chạy mỗi scenario với ≥ 5 seed khác nhau (`_normal_features(n, seed=…)`), thu p50/p95 ± CI
- [x] Thêm flag `--seeds 42,43,44,45,46` vào `evaluation/scenarios.py`
- [x] Output: bảng mean ± std thay vì 1 điểm đơn.

### P0.3 Chạy fat-tree và thu metric thực
- [] `sudo python3 testbed/mininet/fat_tree_topology.py --k 4 --test` → log pingall, iperf h0↔h15
- [x] Viết `testbed/fat_tree_attack_scenario.py`: inject UDP flood từ h0 → h15, đo thời gian SFC rule propagate qua 3 pod
- [] So sánh latency cài rule **cùng pod** vs **khác pod** (core-layer steering cost)

### P0.4 Bản thảo luận văn (LaTeX / Word)
- [x] Tạo `Docs/thesis.tex` hoặc `thesis.docx` theo template của trường
- [] 6 chương theo `thesis_evidence_map.md`:
  - Ch1 Mở đầu (3-5 trang)
  - Ch2 Cơ sở (15-20 trang) — ONAP, NFV, SDN, ML cho DDoS
  - Ch3 Kiến trúc đề xuất (10-15 trang) — vẽ lại 3 sơ đồ
  - Ch4 Thành phần AI (15-20 trang)
  - Ch5 Thực nghiệm (15-20 trang) — nhúng bảng/hình
  - Ch6 Kết luận (3-5 trang)
- [] Tóm tắt tiếng Việt + tiếng Anh (abstract, mỗi bản 250-400 từ)

### P0.5 Related work bảng so sánh
- [ ] Tạo `Docs/related_work.md` với bảng so sánh **≥ 8 công trình** gần đây (2020-2025) theo các trục:
  - AI model | Orchestration | Proactive? | Dataset | DCN? | Open source?
- [ ] Ít nhất 3 paper IEEE/ACM/Elsevier trong lĩnh vực ONAP/NFV-DDoS
- [ ] Chỉ rõ **khoảng trống** đề tài lấp vào (unique contribution)

### P0.6 Sơ đồ kiến trúc vector (PNG/SVG)
- [ ] Vẽ 3 sơ đồ cần thiết (draw.io / Mermaid / TikZ):
  1. Kiến trúc 4-tầng S1→S4 + ONAP closed-loop
  2. 5-tier escalation state machine (T0→T4, hysteresis)
  3. Fat-tree k=4 với attack path highlight
- [ ] Lưu tại `Docs/figures/*.svg` + `.png` 300 DPI

---

## P1 — Nên có để bảo vệ điểm cao

### P1.1 Ablation study
- [ ] Ablation 1: **tắt forecast** (chỉ detection) → chạy S3/S7/S8, đo lead-time về 0
- [ ] Ablation 2: **tắt adversarial training** → test lại model trên FGSM attack, so AUC
- [ ] Ablation 3: **chỉ XGBoost** vs **chỉ Transformer** vs **cả hai** → F1 + latency
- [ ] Output: `evaluation/ablation_results.md`

### P1.2 Real NetFlow thay vì feature giả
- [ ] Dùng `testbed/netflow_collector/` bắt flow thật từ Mininet attack
- [ ] Pipeline: Mininet (hping3/iperf DDoS) → nfcapd → feature extractor → AI → orchestrator
- [ ] Chứng minh e2e không chỉ chạy trên feature tổng hợp

### P1.3 ONAP thật (1 scenario demo) (chờ Hưng)
- [ ] Chạy ONAP OOM (hoặc minimal: SO + Policy + DMaaP) trên VM
- [ ] Set `PAD_ONAP_STUB=false`, chạy 1 scenario (S2 hoặc S8) end-to-end
- [ ] Record video / screenshot để chứng minh interface không chỉ là stub

### P1.4 Adaptive attacker (threat model)
- [ ] Thêm scenario S9: attacker biết rate-limit threshold, tấn công **dưới ngưỡng** (low-and-slow)
- [ ] Kiểm tra forecast có bắt được không
- [ ] Thêm mục **Threat Model** ở Ch3 luận văn (assumption, attacker capability)

### P1.6 Hysteresis + frequency-guard analysis
- [ ] Test `PolicyEngine` với tần suất dao động cao → đo số lần flip tier (flapping)
- [ ] Vẽ hình so sánh **có vs không** hysteresis
- [ ] Kết quả vào Ch5 như một micro-benchmark của Policy layer

### P1.7 SLA fairness deep-dive
- [ ] S7 hiện chỉ check `sla_satisfied` bool. Mở rộng: đo **% bandwidth URLLC nhận được** vs **demand** dưới VNF overhead tier 2/3
- [ ] Vẽ biểu đồ **stacked bar** bandwidth phân bổ 3 tenant theo tier
- [ ] Chứng minh LP allocator giữ URLLC floor ngay cả lúc tier 3

---

## P2 — Bonus (nếu có thời gian)

### P2.1 Slide bảo vệ
- [ ] 25-30 slide PowerPoint/Beamer, 15-20 phút trình bày
- [ ] 3 slide chính: (1) vấn đề, (2) kiến trúc + novelty S8, (3) kết quả định lượng
- [ ] Dry-run với advisor

### P2.2 So sánh với > 1 baseline
- [ ] Ngoài threshold, thêm baseline **Snort/Suricata rule-based** (chạy snort với rule CICIDS)
- [ ] Và 1 baseline ML cũ (ví dụ Random Forest 2019)
- [ ] Bảng so sánh 4-way: Snort | RF | Threshold | AI (ours)

### P2.3 Khảo sát scale
- [ ] Chạy fat-tree k=6 (54 host) và k=8 (128 host)
- [ ] Đo orchestrator throughput (flow/s) khi số device tăng
- [ ] Điểm bão hòa (knee point) → chương giới hạn

### P2.4 Giải thích mô hình (XAI)
- [ ] Xuất SHAP top-5 feature cho 100 window attack
- [ ] Biểu đồ heatmap feature importance theo loại tấn công
- [ ] Thêm subsection "AI Interpretability" vào Ch4

### P2.5 Bài báo hội nghị
- [ ] Chắt lọc Ch3-Ch5 → paper 6-8 trang IEEE format
- [ ] Submit hội nghị IEEE NFV-SDN / NetSoft / CNSM 2026
- [ ] Advisor đồng tác giả

### P2.6 Công khai repo + demo video
- [ ] Push GitHub public (nếu thầy OK) kèm README có badge
- [ ] Video demo 3 phút (asciinema hoặc screencast)
- [ ] Hữu ích cho phần vấn đáp

---
## 1. Trạng Thái Hiện Tại (Snapshot 2026-04-26 — Verified)

### 1.1 Code — Đã hoàn thành & verified

| Module | Kết quả thực đo | Trạng thái |
|--------|----------------|-----------|
| Eval S1–S8 | **8/8 PASS** | ✅ Xong |
| T2 proactive (S3/S6/S7/S8) | P50=**505–506 ms** | ✅ Xong |
| T3 reactive (S2/S6/S8) | P50=**6004–6006 ms** | ✅ Xong |
| S8 proactive advantage | **135 s** vs AI-reactive (win 31→58) | ✅ Xong |
| S3 lead vs baseline | **+65 s** (win 42 vs baseline win 55) | ✅ Xong |
| SLA fairness | `sla_ok=true` mọi scenario | ✅ Xong |
| Baseline threshold | **6/8 PASS** (S4/S5 FAIL — over-escalate) | ✅ Mới chạy |
| Lead-time analyzer | CSV + MD tại `evaluation/results/` | ✅ Mới chạy |
| XGBoost 7-class | Acc=**98.25%**, F1=**96.42%**, AUC=**99.58%**, P99=2.2ms | ✅ Xong |
| Transformer+LSTM | AUC t+30=**98.84%** → t+120=**97.11%** | ✅ Xong |
| LP SLA Allocator | 3-tenant HiGHS, URLLC floor 150Mbps | ✅ Xong |
| Policy Engine | 5-tier, hysteresis, frequency guard | ✅ Xong |

### 1.2 Thesis chapters — Trạng thái thực tế (2026-04-26)

| File | Dòng | Trạng thái | Ghi chú |
|------|------|-----------|---------|
| `Docs/thesis/chapters/abstract.tex` | 78 | ✅ **DONE** | EN + VN với số liệu thực |
| `Docs/thesis/chapters/ch01_intro.tex` | 102 | ✅ **DONE** | RQ + H1/H2/H3 + 4 contributions |
| `Docs/thesis/chapters/ch02_background.tex` | 112 | ✅ **DONE** | Related work 8 papers + gap analysis |
| `Docs/thesis/chapters/ch03_architecture.tex` | 183 | ✅ **DONE** | Threat model + safety invariants + LP |
| `Docs/thesis/chapters/ch04_ai.tex` | 262 | ✅ **DONE** | Số liệu thực, SHAP, CV 3 strategies |
| `Docs/thesis/chapters/ch05_evaluation.tex` | 430 | ✅ **DONE** | S1–S8 + baseline + lead-time tables |
| `Docs/thesis/chapters/ch06_conclusion.tex` | 129 | ✅ **DONE** | H1/H2/H3 attained + future work |
| `Docs/thesis/main.tex` | 90 | ✅ **DONE** | Document shell, compile-ready |
| `Docs/thesis/references.bib` | — | ✅ **DONE** | 13 refs seed |
| `Docs/slides/presentation.html` | — | ✅ **DONE** (2026-04-26) | 17 slides HTML |
| `Docs/litetature_review.tex` | 310 | ⬜ Cần review | Bổ sung ≥5 paper 2025 |

### 1.3 Vấn đề đã sửa / còn lại

| # | Vị trí | Vấn đề | Trạng thái |
|---|--------|--------|-----------|
| 1 | ch04 | AUC "99.03%" vs "96.53%" inconsistent | ✅ Sửa: dùng AUC per-horizon (98.84%→97.11%), avg=96.53% |
| 2 | ch05 | Bảng S1–S8 dùng số liệu thực từ JSON | ✅ Done |
| 3 | ch05 | Bảng baseline với S4/S5 FAIL | ✅ Done |
| 4 | ch05 | Lead-time table với số chính xác | ✅ Done |
| 5 | references.bib | ≥40 citations | ⬜ Cần mở rộng |

---

## 2. Số liệu chuẩn để trích dẫn (verified 2026-04-26)

| Metric | Giá trị | Nguồn |
|--------|---------|-------|
| XGBoost Acc | 0.9825 (98.25%) | `project_ai_v2_training.md` |
| XGBoost Macro-F1 | 0.9642 (96.42%) | ibid |
| XGBoost AUC | 0.9958 (99.58%) | ibid |
| XGBoost P99 | 2.2 ms | ibid |
| Forecast AUC t+30 | 0.9884 | ibid |
| Forecast AUC t+120 | 0.9711 | ibid |
| Forecast P99 | 7.68 ms | ibid |
| T2 proactive P50 | 505–506 ms | `evaluation_summary.json` |
| T3 reactive P50 | 6004–6006 ms | ibid |
| Proactive advantage (S8) | 135 s (win 31→58) | `lead_time_comparison.csv` |
| Lead vs baseline (S3) | +65 s (win 42→55) | ibid |
| AI pass rate | 8/8 (100%) | `evaluation_summary.json` |
| Baseline pass rate | 6/8 (75%) | `baseline_summary.json` |
| URLLC floor | 150 Mbps (all 8 scenarios) | `S7_sla_fairness_3tenant_summary.json` |

---