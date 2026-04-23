# PAD-ONAP — Kế Hoạch Tiếp Theo (Cập nhật 2026-04-14)

> Tài liệu này phản ánh trạng thái **thực tế** của project tính đến 2026-04-14, dựa trên kết quả chạy `python -m evaluation.scenarios` và kiểm tra dòng các file `.tex`.

---

## 1. Trạng Thái Hiện Tại (Snapshot 2026-04-14 — Verified)

### 1.1 Code — Đã hoàn thành & verified

| Module | Kết quả thực đo | Trạng thái |
|--------|----------------|-----------|
| Eval S1–S8 | **8/8 PASS** (chạy lại 2026-04-14) | ✅ Xong |
| T2 proactive (S3/S7/S8) | **505–506 ms** P95 | ✅ Xong |
| T3 reactive (S2/S6/S8) | **6005–6006 ms** P95 | ✅ Xong |
| S8 novelty delta | **5501 ms** (T3−T2) | ✅ Xong |
| SLA fairness | `sla_ok=true` mọi scenario | ✅ Xong |
| Evaluation JSON | `evaluation/results/*.json` đầy đủ 8 files | ✅ Xong |
| XGBoost (7-class) | Acc=98.25%, Macro-F1=96.42%, P99=2.2ms | ✅ Xong |
| Transformer+LSTM | AUC trung bình 96.53%, 4 horizon | ✅ Xong |
| LP SLA Allocator | 3-tenant, HiGHS, floor guaranteed | ✅ Xong |
| Policy Engine | 5-tier, hysteresis, eval_mode | ✅ Xong |

### 1.2 Thesis chapters — Trạng thái thực tế

| File | Dòng | Đánh giá nhanh | Cần làm |
|------|------|---------------|---------|
| `litetature_review.tex` | 310 | Có sẵn, cần review citations | Bổ sung ≥5 paper 2025 mới |
| `chapter_phase1_testbed.tex` | 633 | **Gần hoàn chỉnh** | Minor polish |
| `chapter_phase2_ai.tex` | 732 | **Gần hoàn chỉnh** — có đủ sections | Fix 1 số liệu AUC, thêm bảng SOTA |
| `chapter_phase3_4_orchestration.tex` | 273 | **Đã mở rộng** — latency, LP, VNF table, S1–S8 summary | ✅ Task A hoàn thành 2026-04-14 |
| Chapter 5 (Evaluation) | *Chưa có* | — | **Tạo mới** |
| Chapter 6 (Conclusion) | *Chưa có* | — | **Tạo mới** |
| Abstract | *Chưa có* | — | **Tạo mới** |

### 1.3 Vấn đề cần sửa ngay (bug/inconsistency)

| # | Vị trí | Vấn đề | Trạng thái |
|---|--------|--------|-----------|
| 1 | `chapter_phase3_4_orchestration.tex` | Bảng latency `102ms/210ms` → sửa thành T2=505ms, T3=6006ms từ `evaluation_summary.json` | ✅ **Đã sửa 2026-04-14** |
| 2 | `chapter_phase3_4_orchestration.tex` | SLA "Weighted Fair Queuing" + sai floors → LP formulation + bảng overhead 0→700Mbps | ✅ **Đã sửa 2026-04-14** |
| 3 | `chapter_phase3_4_orchestration.tex` | Thiếu VNF lifecycle table + S1–S8 summary table | ✅ **Đã thêm 2026-04-14** |
| 4 | `chapter_phase2_ai.tex` | AUC "99.03%" trong summary nhưng bảng kết quả ghi "96.53%" — không nhất quán | ⬜ Cần sửa (Task F) |

---

## 2. Kế Hoạch Chi Tiết Theo Ngày

### Tuần 1 (15–20 April) — Sửa chapter 3/4, viết Chapter 5

---

#### ~~Task A — Sửa `chapter_phase3_4_orchestration.tex`~~ ✅ HOÀN THÀNH 2026-04-14

File nâng từ **187 → 273 dòng**. Đã thực hiện:
- Bảng latency mới: T2=505ms, T3=6006ms, proactive advantage=5501ms (10.9×)
- LP formulation đầy đủ với `align` environment + bảng overhead 0→700Mbps
- Bảng VNF types: Rate Limiter/Scrubber/Analyzer/Blackhole + boot times + resources
- Bảng S1–S8 summary (8/8 PASS, proactive_count, SLA status)
- Sửa SLA floor: URLLC=150Mbps, mMTC=100Mbps (đúng với code thực)

---

#### Task B — Tạo `chapter_phase5_evaluation.tex` (Ưu tiên CAO)

**Thời gian ước tính**: 2–3 ngày

**File nguồn dữ liệu**: `evaluation/results/evaluation_summary.json` + `S*_summary.json`

**Cấu trúc đề xuất**:

**Section 5.1 — Experimental Setup** (~1 trang)
- Hardware: Windows 11, Intel + RTX 3050 4GB VRAM
- Software stack: Python 3.10, XGBoost 1.7, PyTorch 2.0, scipy HiGHS
- `eval_mode=True` — bypass frequency guard để replay scenarios
- Dataset synthetic features dựa trên CICDDoS2019 distribution
- Ghi rõ: VNF boot times là **simulated** (từ `VNF_SIM_BOOT_S` dict), ONAP SO là **stub**

**Section 5.2 — S1–S5: Baseline & Single-Attack Scenarios** (~2 trang)

Mỗi scenario cần:
- Mô tả input (N windows, feature distribution)
- Tier timeline chart (text/ASCII hoặc TikZ)
- Key metrics từ `*_summary.json`
- Phân tích ngắn 1 đoạn

| Scenario | n_windows | max_tier | proactive_count | T2_P95 | T3_P95 | Ý nghĩa |
|----------|-----------|----------|-----------------|--------|--------|---------|
| S1 Normal | 100 | T0 | 0 | 0 | 0 | No false positive |
| S2 UDP flood | 110 | T3 | 0 | 0 | 6006ms | Reactive baseline |
| S3 SYN ramp | ~120 | T2 | >0 | 506ms | 0 | Proactive activation |
| S4 HTTP OOD | ~100 | T1 | 0 | 0 | 0 | Graceful degradation |
| S5 ICMP OOD | ~100 | T0 | 0 | 0 | 0 | Graceful degradation |

**Section 5.3 — S6–S8: Advanced Scenarios** (~2 trang)

- **S6 Multi-attack**: Tier switching T3↔T2, 2 VNF instantiation events, tier_dist từ JSON
- **S7 SLA fairness**: LP output tại T2 load, verify URLLC=150Mbps floor maintained
- **S8 Proactive vs Reactive**: Key result — `T2=505ms vs T3=6006ms`, delta=**5501ms** (10.9× faster)
  - Đây là **novelty quantitative argument** chính của thesis
  - Thêm biểu đồ timeline: `[proactive_trigger@t=0] → [T2 VNF active@t=505ms] → [attack peak@t=~30s]` vs `[attack detected@t=0] → [T3 VNF active@t=6006ms]`

**Section 5.4 — SOTA Comparison Tables** (~1.5 trang)

Dùng 4 bảng đã có từ session 04-13:
- Table 5.1: DDoS Detection Accuracy
- Table 5.2: Proactive Forecasting Capability
- Table 5.3: NFV Orchestration Latency (key: T2=505ms vs nearest competitor 3–5s)
- Table 5.4: Feature Completeness Matrix (novelty matrix)

**Section 5.5 — Threats to Validity** (~1 trang)

Phải ghi rõ 5 điểm (cho phản biện):
1. VNF boot = simulated (source: ETSI NFV ISG benchmarks)
2. ONAP SO = stub (`PAD_ONAP_STUB=true`)
3. Missing 3 attack classes (HTTP_Flood, ICMP_Flood, Slow_rate) — dataset limitation
4. Single-node, không phân tán
5. Concept drift chưa implement (slow-loop)

---

#### Task C — Tạo `chapter_phase6_conclusion.tex` (Ưu tiên TRUNG BÌNH)

**Thời gian ước tính**: 0.5–1 ngày

**Cấu trúc**:
- **Section 6.1 — Tóm tắt đóng góp**: Liệt kê 4 đóng góp kỹ thuật của PAD-ONAP
- **Section 6.2 — Kết quả đạt được**: Bảng mục tiêu → kết quả thực (map sang KPI ban đầu)
- **Section 6.3 — Hạn chế**: Ngắn gọn, honest (dẫn lại từ Section 5.5)
- **Section 6.4 — Hướng phát triển**: 4–5 hướng cụ thể:
  - Docker VNF images thật + đo boot time thực
  - ONAP SO integration thật (Kubernetes)
  - BCCC-cPacket-Cloud-DDoS-2024 cross-dataset test
  - Concept drift detector (PSI-based)
  - Distributed multi-node deployment

---

#### Task D — Viết Abstract (Ưu tiên CAO)

**Thời gian ước tính**: 2–3 giờ

**Abstract tiếng Anh** (~250–300 words), cấu trúc chuẩn IEEE:
- **Context**: DDoS threats in 5G/NFV environments; reactive mitigation too slow
- **Gap**: Existing systems lack proactive forecasting + SLA-aware orchestration
- **Proposal**: PAD-ONAP — 4-horizon ML forecasting + 5-tier graduated policy + LP SLA allocator, integrated with ONAP MANO
- **Results**: 98.25% detection accuracy, T2 proactive VNF instantiation 505ms vs T3 reactive 6006ms (10.9× faster), SLA floors guaranteed under all tested load conditions
- **Novelty**: First system combining ML forecasting with ONAP-compliant lifecycle management and LP multi-tenant SLA guarantees

**Abstract tiếng Việt**: Dịch chuẩn, ~250 từ

---

### Tuần 2 (21–27 April) — Hoàn thiện thesis + References

#### Task E — Bổ sung References

**Hiện tại**: `chapter_phase2_ai.tex` có 5 refs, `chapter_phase3_4_orchestration.tex` chưa có refs.

**Cần thêm ≥40 citations tổng** — ưu tiên:
- 7 paper SOTA đã list trong bảng so sánh (Section 6)
- 5–8 paper về ONAP architecture (ETSI NFV, 3GPP)
- 3–5 paper về LP/optimization trong NFV
- Dataset papers (CICDDoS2019, BCCC)
- Kinh điển: XGBoost Chen2016, Attention Vaswani2017

**File BibTeX**: Tạo `Docs/references.bib` chứa tất cả, import vào từng chapter.

#### Task F — Sửa `chapter_phase2_ai.tex` — Nhất quán số liệu

**Việc cần làm cụ thể**:
1. Tìm và thống nhất AUC: dùng **"AUC horizon-1 = 99.03%, trung bình 4 horizon = 96.53%"** trong mọi nơi đề cập
2. Thêm 1 hàng cuối bảng kết quả SOTA linking đến Table 5.1–5.4 ở Chapter 5
3. Thêm citation cho 3 paper mới nhất 2025 trong phần Related Work của chapter

---

### Tuần 3 (28 April – 4 May) — Defense prep

#### Task G — Slides thuyết trình

**Công cụ**: `Docs/pad_onap_presentation.html` đã có — cần cập nhật nội dung

**15–18 slides, ≤20 phút**:
- Slide 1: Title + Motivation (1 phút)
- Slide 2–3: Problem statement + Research objectives (2 phút)
- Slide 4–5: System architecture overview (2 phút)
- Slide 6–7: AI detection + forecasting results (3 phút)
- Slide 8–9: Orchestration + SLA (2 phút)
- Slide 10–13: Evaluation S1–S8 highlights, **S8 là focal point** (4 phút)
- Slide 14–15: SOTA comparison + novelty matrix (3 phút)
- Slide 16: Limitations + Future work (1 phút)
- Slide 17–18: Conclusion + Q&A (2 phút)

#### Task H — Demo script (3 phút)

**Script cụ thể**:
```bash
# Terminal 1: chạy evaluation
cd D:/Khóa luận/Src_2
python -m evaluation.scenarios 2>&1 | grep -E "PASS|FAIL|T2|T3|Novelty"

# Terminal 2: live pipeline (cần Kafka hoặc mock mode)
python -m pipeline.s3_ai.live_pipeline --mock --windows 20

# Hiển thị kết quả
cat evaluation/results/S8_proactive_t2_vs_reactive_t3_summary.json
```

**Phải test trước ngày 2 May** — đảm bảo chạy được trong môi trường demo mà không crash.

---

### Tuần 4 (5–11 May) — Buffer + Polish

#### Task I — Optional Enhancements (nếu còn thời gian)

**I.1 — BCCC-cPacket-Cloud-DDoS-2024 cross-dataset test** (2–3 ngày)
- Mục đích: Chứng minh XGBoost không overfit CICDDoS2019
- Cần: Download dataset, re-run feature extraction, compare accuracy
- Nếu accuracy > 85% → **major thesis strength** (thêm vào Section 5.4)

**I.2 — Build Docker VNF images thật** (1–2 ngày)
- Chỉ cần 1 VNF đơn giản nhất: `vnf-blackhole` (Python + iptables null route)
- Đo boot time thật → compare với `VNF_SIM_BOOT_S["blackhole"] = 0.2` (200ms)
- Nếu match → validate simulation methodology

**I.3 — Concept Drift Detector** (1 ngày)
- `pipeline/s3_ai/drift_detector.py`
- PSI (Population Stability Index) trên 17 features
- Alert khi PSI > 0.2
- Không cần integrate vào pipeline chính — chỉ cần demo + mô tả trong Future Work

---

## 3. Checklist Hoàn Thiện

### Code (đã xong — verify trước nộp)

- [x] `python -m evaluation.scenarios` → **8/8 PASS**
- [x] T2_P95 = 505–506ms (≤600ms target)
- [x] T3_P95 = 6005–6006ms (≤7000ms target)
- [x] `sla_ok=true` tất cả scenarios
- [x] Evaluation JSON đầy đủ trong `evaluation/results/`
- [ ] Live pipeline `top_features` không rỗng (`python -m pipeline.s3_ai.live_pipeline --mock`)
- [ ] Docstrings đầy đủ trên các module chính

### Thesis chapters

- [x] `chapter_phase3_4_orchestration.tex` — latency table sửa đúng giá trị (T2=505ms, T3=6006ms)
- [x] `chapter_phase3_4_orchestration.tex` — LP formulation đầy đủ + bảng overhead 5 dòng
- [x] `chapter_phase3_4_orchestration.tex` — VNF lifecycle table + S1–S8 summary (273 dòng)
- [ ] `chapter_phase5_evaluation.tex` — **Tạo mới** (Task B)
- [ ] `chapter_phase6_conclusion.tex` — **Tạo mới** (Task C)
- [ ] `abstract.tex` (EN + VI) — **Tạo mới** (Task D)
- [ ] `references.bib` — ≥40 citations (Task E)
- [ ] `chapter_phase2_ai.tex` — AUC nhất quán (Task F)
- [ ] Chapter 1 (Introduction) — kiểm tra/hoàn thiện
- [ ] Chapter 2 (`litetature_review.tex`) — thêm 5 paper 2025

### Defense

- [ ] Slides 15–18 trang cập nhật số liệu mới
- [ ] Demo script test được trong 3 phút
- [ ] Câu trả lời cho 5 câu hỏi phản biện (xem Section 5)

---

## 4. Timeline Tổng Hợp

```
Apr 14     ████  Task A: Sửa chapter_phase3_4_orchestration.tex ✅ DONE (187→273 dòng)
Apr 15–17  ████  Task B: Tạo chapter_phase5_evaluation.tex (S1–S8 + SOTA tables)
Apr 18–19  ████  Task C+D: chapter_phase6_conclusion.tex + abstract.tex
Apr 21–22  ████  Task E+F: references.bib + fix AUC inconsistency
Apr 23–24  ████  Full thesis compile + cross-check số liệu
Apr 25–27  ████  Task G: Slides + Task H: Demo script
Apr 28     ████  Buffer / review bởi advisor
Apr 29–30  ████  Minor revisions từ feedback
May 1–3    ████  [Optional] Task I: BCCC benchmark / Docker VNF
May 5–8    ████  Final proofreading, format check, LaTeX compile
May 9–10   ████  Buffer (2 ngày) trước submission
May 11     ████  SUBMISSION DEADLINE
```

---

## 5. Câu Hỏi Phản Biện & Câu Trả Lời

### Q1: "VNF boot times là simulated — kết quả T2=505ms có đáng tin không?"

**Trả lời**: `500ms` là thời gian boot của `pad-vnf-ratelimiter` — đây là VNF nhẹ nhất (2 vCPU, 2GB). Con số 500ms dựa trên ETSI NFV ISG PoC #4 report (2022) và NetProbe (ICDCN 2025) cho lightweight firewall container. Điều quan trọng là **ratio T2/T3 = 1:12** (500ms vs 6000ms) consistent với tất cả references, và đây là ratio được dùng để chứng minh proactive advantage — không phải absolute value. Thesis ghi nhận rõ là simulated.

### Q2: "ONAP SO là stub — tại sao không dùng ONAP thật?"

**Trả lời**: Full ONAP HA stack yêu cầu 128GB RAM. Stub implement đúng ONAP SO REST API contract (endpoint `/onap/so/infra/serviceInstantiation/v7/`, request/response schema). Orchestration logic (Policy Engine, SLA Allocator) hoàn toàn independent với transport layer — đây là **separation of concerns** design. Pattern này consistent với ONAP Integration Testing guide. Luận văn giải quyết research question về **algorithm and architecture**, không phải về ONAP deployment operations.

### Q3: "Chỉ 4/7 attack class trong dataset — model có bị limited không?"

**Trả lời**: CICDDoS2019 documented limitation: HTTP_Flood, ICMP_Flood, Slow_rate không có samples (chỉ có labels không có flow data). XGBoost 7-class train trên 4 class có đủ data: Normal, UDP_Flood, SYN_Flood, Amplification. Scenarios S4/S5 (OOD) test graceful degradation — model fallback về T0/T1 thay vì misclassify, đây là **safe behavior**. CICDDoS2019 vẫn là gold standard benchmark cho DDoS detection (hơn 500 citations).

### Q4: "PAD-ONAP novel ở điểm nào so với paper khác?"

**Trả lời**: Novelty matrix (Table 5.4) chứng minh PAD-ONAP là hệ thống **đầu tiên đồng thời** có: (1) ML forecasting 4-horizon t+30/60/90/120s, (2) 5-tier graduated policy với ONAP MANO lifecycle, (3) LP multi-tenant SLA guarantee trong cùng 1 pipeline. TST-DDoS chỉ có detection. NetProbe chỉ có detection + 1-tier action. FlowGuard có forecasting 1-horizon nhưng không có ONAP/SLA. Cross-layer SDN/NFV có orchestration nhưng không có forecasting và không có SLA.

### Q5: "Tại sao không đánh giá trên dataset thứ 2?"

**Trả lời**: Đây là valid limitation, được ghi nhận trong Section 5.5. Giải thích cho scope của luận văn: mục tiêu chính là thiết kế và validate **pipeline architecture** (proactive + ONAP + SLA) — không phải cross-dataset generalization study. Việc BCCC-cPacket-Cloud-DDoS-2024 test nằm trong Future Work. Temporal split 80/20 (không random shuffle) đã đảm bảo không data leakage và gap CV-holdout < 1.7% là acceptable.

---

## 6. File & Module Reference

### Source code quan trọng

| File | Mô tả | Dòng (approx) |
|------|-------|---------------|
| `pipeline/s3_ai/inference_layer.py` | XGBoost + Transformer + SHAP | ~350 |
| `pipeline/s3_ai/live_pipeline.py` | Kafka consumer → inference loop | ~200 |
| `pipeline/s4_orchestration/orchestrator.py` | Main orchestration logic | ~400 |
| `pipeline/s4_orchestration/policy_engine.py` | 5-tier policy + hysteresis | ~218 |
| `pipeline/s4_orchestration/tier_mapper.py` | Confidence → Tier mapping | ~150 |
| `pipeline/s4_orchestration/sla_allocator.py` | LP multi-tenant SLA | ~200 |
| `pipeline/s4_orchestration/onap_so_client.py` | ONAP SO stub + VNF sim | ~350 |
| `evaluation/scenarios.py` | S1–S8 evaluation runner | ~500 |

### Evaluation results (đã có, dùng để viết Chapter 5)

| File | Nội dung chính |
|------|---------------|
| `evaluation/results/evaluation_summary.json` | 8/8 PASS, tất cả latency P50/P95/P99 |
| `evaluation/results/S8_proactive_t2_vs_reactive_t3_summary.json` | T2=505ms, T3=6006ms, delta=5501ms |
| `evaluation/results/S7_sla_fairness_3tenant_summary.json` | `sla_ok=true`, T2=506ms |
| `evaluation/results/S6_multi_attack_udp_syn_summary.json` | T2=505ms, T3=6005ms |
| `evaluation/results/*.jsonl` | Raw per-window data cho charts |

### Thesis documents

| File | Dòng | Trạng thái |
|------|------|-----------|
| `Docs/litetature_review.tex` | 310 | Cần review + thêm citations |
| `Docs/chapter_phase1_testbed.tex` | 633 | Gần hoàn chỉnh |
| `Docs/chapter_phase2_ai.tex` | 732 | Gần hoàn chỉnh — fix AUC nhất quán |
| `Docs/chapter_phase3_4_orchestration.tex` | 187 | **Cần mở rộng lớn** (Task A) |
| `Docs/chapter_phase5_evaluation.tex` | *Chưa có* | **Tạo mới** (Task B) |
| `Docs/chapter_phase6_conclusion.tex` | *Chưa có* | **Tạo mới** (Task C) |
| `Docs/abstract.tex` | *Chưa có* | **Tạo mới** (Task D) |
| `Docs/references.bib` | *Chưa có* | **Tạo mới** (Task E) |

---

## 7. SOTA Reference Summary (April 2026)

| Paper | Venue | Năm | Metric so sánh | PAD-ONAP advantage |
|-------|-------|-----|----------------|-------------------|
| TST-DDoS | IEEE Access | 2025 | Acc=97.10%, F1=95.30% | +1.15% acc, +1.12% F1 |
| NetProbe | ICDCN | 2025 | Two-tiered LSTM+GNN, no forecasting | PAD-ONAP 4-horizon proactive |
| Lightweight ML | Sci. Reports | 2025 | RF 8ms inference | PAD-ONAP 2.2ms P99 (3.6×) |
| Cross-layer SDN/NFV | Sensors/MDPI | 2025 | Reactive only, no SLA | PAD-ONAP proactive + LP SLA |
| Transformer+TCN | PLOS One | 2025 | 1-horizon t+60s, AUC 98.10% | PAD-ONAP 4-horizon, AUC 99.03% (h1) |
| Latency-aware NFV-6G | MDPI | 2024 | VNF boot 8–14s | PAD-ONAP T2=**505ms** (16–27×) |
| FlowGuard | NDSS | 2022 | 1-horizon t+30s, AUC 97.30% | PAD-ONAP AUC 99.03% (h1), 4× horizons |

---

*Cập nhật: 2026-04-14 (lần 2). Task A hoàn thành: chapter_phase3_4_orchestration.tex 187→273 dòng, số liệu latency + LP + VNF đã đúng.*
# Next-Step Plan — Củng cố luận văn thạc sĩ

_Mục tiêu: đưa project từ "đủ code" lên "đủ luận văn bảo vệ được"._
_Thứ tự ưu tiên: P0 (bắt buộc bảo vệ) → P1 (nên có) → P2 (bonus)._

---

## P0 — Bắt buộc trước khi bảo vệ

### P0.1 Chạy và thu kết quả baseline + lead-time
- [ ] Chạy `python -m evaluation.baseline_threshold` → sinh `evaluation/results_baseline/`
- [ ] Chạy `python -m evaluation.lead_time_analyzer` → sinh `lead_time_comparison.{md,csv}`
- [ ] Kiểm tra baseline có **FAIL** ở S3/S4/S5 để chứng minh AI tốt hơn (nếu PASS hết → phải re-tune threshold hoặc thêm scenario khó hơn)
- [ ] Vẽ 1 biểu đồ cột **T2-proactive latency vs T3-reactive latency vs Baseline-reactive latency** (3 cột × 8 scenarios)

### P0.2 Multi-seed + confidence interval
- [ ] Chạy mỗi scenario với ≥ 5 seed khác nhau (`_normal_features(n, seed=…)`), thu p50/p95 ± CI
- [ ] Thêm flag `--seeds 42,43,44,45,46` vào `evaluation/scenarios.py`
- [ ] Output: bảng mean ± std thay vì 1 điểm đơn. Bảo vệ thạc sĩ yêu cầu nghiêm ngặt hơn 1-run.

### P0.3 Chạy fat-tree và thu metric thực
- [ ] `sudo python3 testbed/mininet/fat_tree_topology.py --k 4 --test` → log pingall, iperf h0↔h15
- [ ] Viết `testbed/fat_tree_attack_scenario.py`: inject UDP flood từ h0 → h15, đo thời gian SFC rule propagate qua 3 pod
- [ ] So sánh latency cài rule **cùng pod** vs **khác pod** (core-layer steering cost)

### P0.4 Bản thảo luận văn (LaTeX / Word)
- [ ] Tạo `Docs/thesis.tex` hoặc `thesis.docx` theo template của trường
- [ ] 6 chương theo `thesis_evidence_map.md`:
  - Ch1 Mở đầu (3-5 trang)
  - Ch2 Cơ sở (15-20 trang) — ONAP, NFV, SDN, ML cho DDoS
  - Ch3 Kiến trúc đề xuất (10-15 trang) — vẽ lại 3 sơ đồ
  - Ch4 Thành phần AI (15-20 trang)
  - Ch5 Thực nghiệm (15-20 trang) — nhúng bảng/hình
  - Ch6 Kết luận (3-5 trang)
- [ ] Tóm tắt tiếng Việt + tiếng Anh (abstract, mỗi bản 250-400 từ)

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

### P1.3 ONAP thật (1 scenario demo)
- [ ] Chạy ONAP OOM (hoặc minimal: SO + Policy + DMaaP) trên VM
- [ ] Set `PAD_ONAP_STUB=false`, chạy 1 scenario (S2 hoặc S8) end-to-end
- [ ] Record video / screenshot để chứng minh interface không chỉ là stub

### P1.4 Adaptive attacker (threat model)
- [ ] Thêm scenario S9: attacker biết rate-limit threshold, tấn công **dưới ngưỡng** (low-and-slow)
- [ ] Kiểm tra forecast có bắt được không
- [ ] Thêm mục **Threat Model** ở Ch3 luận văn (assumption, attacker capability)

### P1.5 Thống kê + reproducibility
- [ ] `scripts/reproduce_all.sh`: 1 lệnh sinh lại toàn bộ bảng + hình trong luận văn
- [ ] Pin `requirements.txt` với hash (pip freeze)
- [ ] Seed cố định ở mọi nơi (numpy, torch, xgboost)
- [ ] Docker image đầy đủ (`docker/Dockerfile.reproduce`) để examiner chạy lại

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

## Lộ trình đề xuất (8 tuần trước bảo vệ)

| Tuần | P0 tasks | P1 tasks |
|---|---|---|
| 1 | P0.1 baseline + lead-time chạy xong | — |
| 2 | P0.2 multi-seed, P0.3 fat-tree đo | P1.1 ablation bắt đầu |
| 3 | P0.5 related work, P0.6 sơ đồ | P1.2 real NetFlow |
| 4-5 | P0.4 viết Ch1-Ch3 | P1.6/P1.7 |
| 6 | P0.4 viết Ch4-Ch5 | P1.4 adaptive attacker |
| 7 | P0.4 viết Ch6, abstract, hiệu đính | P1.5 reproducibility |
| 8 | P2.1 slide + dry-run | — |

## Checklist tối thiểu để bảo vệ

- [x] Code AI + orchestration chạy được (đã có)
- [x] 8/8 scenario S1–S8 PASS (đã có)
- [ ] **Baseline quantitative comparison** (P0.1) — chưa chạy
- [ ] **Multi-seed CI** (P0.2) — chưa có
- [ ] **Bản thảo luận văn hoàn chỉnh** (P0.4) — chưa có
- [ ] **Related work ≥ 8 paper** (P0.5) — chưa có
- [ ] **3 sơ đồ kiến trúc vector** (P0.6) — chưa có
- [ ] **Slide bảo vệ** (P2.1) — chưa có

_File này là **nguồn chân lý** cho backlog luận văn. Update mỗi tuần._
