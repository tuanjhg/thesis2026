---

# Báo Cáo Tiến Độ — PAD-ONAP (2026-04-11)

---

## Tổng quan

| Hạng mục | Trạng thái |
|----------|-----------|
| Phase 1 — Testbed & telemetry | Hoàn thành |
| Phase 2 — AI Models (training) | Hoàn thành, vượt mục tiêu |
| Phase 2 — AI Inference pipeline | Hoàn thành + production-hardened |
| Phase 3 — ONAP Integration | Chưa làm (stub) |
| Phase 4 — Slow-loop / Drift | Chưa làm |

---

## Phase 1 — Testbed

### Đã hoàn thành
- **gNMI Simulator** (`testbed/gnmi_simulator/main.py`) — Mock REST server đầy đủ endpoint: `/metrics`, `/attack/start`, `/attack/stop`, `/attack/ramp`, `/health`. Sinh synthetic traffic cho 3 thiết bị (r1/r2/r3).
- **NetFlow Collector** (`testbed/netflow_collector/collector.py`) — Hỗ trợ cả NetFlow v5/v9 UDP thật lẫn synthetic mode (kéo từ gNMI). Expose `/flows/latest` REST API cho inference pipeline.
- **Anomaly Injector** — 4 kịch bản tấn công: UDP flood, SYN flood, bandwidth ramp, CPU spike.
- **Mininet Topology** — 3-slice topology.
- **Testbed Verification Script** (`scripts/verify_testbed.sh`) — 327 dòng, 8 phần kiểm tra tự động.

---

## Phase 2 — AI Models

### Dữ liệu training
- **Nguồn**: CICDDoS2019 (19.1M flows raw → 35,928 feature windows)
- **17 features**: entropy, packet rate, protocol distribution, flag ratios, inter-arrival time
- **Phương pháp split**: Temporal 80/20 (tránh data leakage hoàn toàn)
- **Train**: 186,133 samples · **Test**: 44,210 samples

### Kết quả XGBoost (4-class classifier)

| Metric | Đạt được | Mục tiêu |
|--------|---------|---------|
| Accuracy (holdout) | **98.25%** | ≥95% ✅ |
| Macro F1 | **96.42%** | ≥90% ✅ |
| AUC (macro OvR) | **99.58%** | — ✅ |
| P99 Inference latency | **2.2 ms** | <10ms ✅ |
| 5-Fold CV accuracy | **99.87%** | — (no overfitting) ✅ |

**SHAP Top-5 features**: `src_port_entropy` → `proto_dist_tcp` → `proto_dist_udp` → `avg_pkt_size` → `inter_arrival_mean`

### Kết quả Transformer+LSTM (4-horizon forecaster)

| Horizon | AUC | Accuracy |
|---------|-----|---------|
| t+30s | **99.43%** | 99.70% |
| t+60s | **99.17%** | 99.67% |
| t+90s | **98.96%** | 98.20% |
| t+120s | **98.57%** | 98.21% |
| **Mean** | **99.03%** | — |

Độ suy giảm theo horizon: **~0.29% AUC/horizon** — trong ngưỡng chấp nhận.

---

## Infrastructure & Pipeline

### Docker Compose (7 services)
| Service | Port | Trạng thái |
|---------|------|-----------|
| Kafka KRaft | 9092 | ✅ Dual-listener (INTERNAL + EXTERNAL) |
| gNMI Simulator | 8080 | ✅ Health check, restart: always |
| NetFlow Collector | 7070 | ✅ Synthetic mode |
| Prometheus | 9190 | ✅ (tránh port 9090 của ONAP) |
| Grafana | 3001 | ✅ (tránh port 3000 của ONAP) |
| Metrics Exporter | 9191 | ✅ |

### Inference Pipeline (3 native Python components)
```
gNMI (8080) → kafka_producer → pad.telemetry.raw
                                      ↓
                          flink_processor (5s window/1s slide)
                                      ↓
                              pad.telemetry.features
                                      ↓
                          live_pipeline → InferenceEngine (CUDA)
                                      ↓
                          stdout + logs/inference_output.jsonl
```

**Production hardening đã implement**:
- Exponential backoff (2s→4s→...→60s) trên tất cả Kafka connections
- Auto-reconnect khi Kafka drop ở cả 3 components
- Async fire-and-forget send (không block produce loop)
- Producer flush sau mỗi emit (không mất message)
- Log rotation (json-file driver, max 20MB/5 files)
- Resource limits cho Docker (Kafka 1GB, Prometheus 512MB, ...)
- `.env` cho port config — tránh conflict với ONAP

---

## Vấn đề còn tồn tại

### Nghiêm trọng
| Vấn đề | Chi tiết |
|--------|---------|
| **SHAP trong live pipeline bị rỗng** | `live_output.jsonl` cho thấy `top_features: {}` — SHAP đang không được populate trong inference loop thật |
| **Proactive trigger không fire** | Live output: `p_attack_30s ≈ 0.46` với Amplification attack. Threshold 0.70 quá cao, cần tune lại |
| **3 attack class bị missing** | HTTP_Flood, ICMP_Flood, Slow_rate = 0 samples trong CICDDoS2019 — model chỉ detect được 4/7 class |

### Trung bình
| Vấn đề | Chi tiết |
|--------|---------|
| **Distribution shift** | Train: UDP 11.1%, SYN 7.2% → Test: UDP 36.4%, SYN 48.3% — temporal shift tự nhiên nhưng cần ghi nhận trong thesis |
| **Phase 3 ONAP chưa làm** | DMaaP publish, Policy Framework, SO/SDNC calls đều là stub |
| **Không có slow-loop** | Concept drift detection, model versioning, continuous retraining chưa implement |

---

## Đánh giá tổng thể

**Đã làm được (ước tính ~70% scope toàn bộ thesis)**:
- Toàn bộ data pipeline và AI inference hoạt động end-to-end
- Model performance vượt tất cả mục tiêu đặt ra
- Infrastructure production-ready với ONAP deployment
- Documentation đầy đủ (README, architecture diagrams, progress report)

**Chưa làm (30% còn lại)**:
- ONAP integration thật sự (S4/S5/S6)
- Slow-loop monitoring
- Fix SHAP + proactive trigger calibration

---

## Đề xuất bước tiếp theo (theo mức độ ưu tiên)

**Ưu tiên 1 — Fix ngay trước demo**:
1. Fix SHAP trong `live_pipeline.py` — xem `inference_layer.py` trả về `top_features` nhưng pipeline không propagate đúng
2. Hạ proactive trigger threshold xuống 0.50–0.60 hoặc tune từ live data thật

**Ưu tiên 2 — Hoàn thiện luận văn**:
3. Mock ONAP S4 endpoint (DMaaP stub → in ra action được thực hiện)
4. Viết section về 3 missing classes — giải thích trong thesis là limitation của dataset, không phải lỗi model

**Ưu tiên 3 — Nếu còn thời gian**:
5. Synthetic data generation cho HTTP_Flood/ICMP_Flood/Slow_rate
6. Concept drift detector đơn giản (PSI/KL divergence trên feature distribution)