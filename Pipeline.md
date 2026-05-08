# PAD-ONAP: Proactive AI-Driven DDoS Defense Pipeline
## Full Technical Specification — Publication & Implementation Ready

**Update note (May 2026):** Track A now uses a deployment-oriented grouped-label configuration for production training while preserving the original 12-class CICDDoS2019 taxonomy for audit and fine-grained reporting. This change is aligned with the notebook `ddos-train-new-grouped.ipynb`.

## 1. Overview and Motivation

### 1.1 Problem Statement

Distributed Denial-of-Service (DDoS) attacks in cloud data centers present a unique challenge at the intersection of attack speed and infrastructure complexity. Volumetric floods can saturate uplinks within **3–5 seconds** [RFC 8612], yet the most advanced published closed-loop defense system (RIGOUROUS, JNSM 2026) requires **15–51 seconds** to react end-to-end — an order-of-magnitude mismatch. The root causes of this gap are threefold:

1. **Reactive-only detection:** All existing AI-based systems wait for attack traffic to be present before triggering mitigation. By the time a scrubbing VNF is provisioned, the attack has already caused damage.
2. **Siloed pipelines:** Detection, orchestration, and enforcement are designed independently and never measured end-to-end. Each stage adds latency; no published work reports the aggregate.
3. **No real MANO integration:** Academic work uses toy SDN controllers (Ryu, Floodlight) instead of production MANO frameworks (ONAP, OSM), rendering results non-deployable.

### 1.2 Core Contribution

PAD-ONAP (Proactive AI-Driven DDoS Defense using ONAP) is a **four-stage closed-loop pipeline** that:

- **Detects** DDoS attacks via a Feature-Driven Supervised Learning classifier (XGBoost with Extra Trees Gini-based feature selection, per IJSRA 2021) and **predicts** attack onset at three lead times (1, 5, 15 minutes) via a Multivariate LSTM multi-horizon forecaster.
- **Orchestrates** graduated NFV responses via ONAP's Policy Framework, mapping probabilistic AI outputs directly to SO (Service Orchestrator) instantiation workflows.
- **Enforces** mitigation through dynamically scheduled and scaled scrubbing CNFs (Cloud-native Network Functions), with full container lifecycle metrics tracked.
- **Explains** every automated decision via SHAP values (TreeExplainer for XGBoost) surfaced as policy metadata in ONAP.

### 1.3 Novelty Claims (vs. Prior Work)

| Novelty Dimension | PAD-ONAP | Best Prior Work |
|---|---|---|
| Proactive pre-attack VNF pre-positioning | **Yes (multi-horizon LSTM, 1/5/15 min lead times)** | No (all reactive) |
| Full ONAP integration (DCAE→Policy→SO) | **Yes** | No (toy SDN controllers) |
| End-to-end latency measurement (all 4 stages) | **Yes** | No (siloed measurement) |
| Probabilistic AI → graduated policy mapping | **Yes (5-tier graduated)** | No (binary thresholds) |
| SHAP-based XAI in ONAP policy metadata | **Yes (TreeExplainer for XGBoost)** | No |
| Lightweight AI suitable for production NFV | **Yes (XGBoost + Stacked LSTM)** | No (heavy ensembles) |
| CNF deployment metrics reported (Startup/CPU/RAM) | **Yes** | Only de Oliveira 2023 (placement only) |
| Multi-tenant SLA preservation during attack | **Yes** | Partial (RIGOUROUS) |

**Design philosophy:** PAD-ONAP intentionally trades *peak detection accuracy* for *deployability* — using lightweight classical/recurrent models that fit production NFV constraints (sub-second inference on commodity worker nodes, no GPU requirement).

---

## 2. System Architecture

### 2.1 High-Level Pipeline

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          PAD-ONAP PIPELINE (v2)                               ║
╠═══════════════╦═══════════════╦═══════════════════════╦═══════════════════════╣
║  STREAMING    ║  AI DETECTION ║  ONAP ORCHESTRATION   ║  CLOUD-NATIVE         ║
║  TELEMETRY    ║  & FORECAST   ║  DECISION ENGINE      ║  ENFORCEMENT          ║
║               ║               ║                       ║  LAYER                ║
╠═══════════════╬═══════════════╬═══════════════════════╬═══════════════════════╣
║ gNMI/gRPC     ║ XGBoost +     ║ DCAE (event ingestion)║ CNF Scrubber          ║
║ YANG models   ║ SHAP (Track A)║ Policy Framework      ║ CNF Rate-Limiter      ║
║ sFlow/IPFIX   ║ Multivariate  ║ Direct SO triggers    ║ SFC chain update      ║
║ Apache Kafka  ║ LSTM (Track B)║ SO (K8s lifecycle)    ║ OVS/eBPF data plane   ║
║               ║ Extra Trees   ║                       ║                       ║
║               ║ Feature Select║                       ║                       ║
╚═══════════════╩═══════════════╩═══════════════════════╩═══════════════════════╝
```

### 2.2 Component Topology

```
                         ┌─────────────────────────────────┐
                         │       ONAP Platform             │
                         │  ┌──────────┐  ┌─────────────┐  │
         AI Scores ─────▶│  │  DCAE    │─▶│   Policy    │  │
         (REST/Kafka)    │  │ (event   │  │  Framework  │  │
                         │  │  ingest) │  │  (PAP/PDP)  │  │
                         │  └──────────┘  └──────┬──────┘  │
                         │                       │Policy   │
                         │              ┌────────▼───────┐ │
                         │              │      SO        │ │
                         │              │ (Service Orch) │ │
                         └──────────────┴────────┬───────┘─┘
                                                 │ REST/TOSCA
                           ┌─────────────────────────────────┐
                           │      Kubernetes Cluster         │
                           │  CNF-Scrubber  CNF-RateLimit    │
                           │  CNF-Analyzer  CNF-Classifier   │
                           └─────────────────────────────────┘
                                         │
                          ┌──────────────▼───────┐
                          │   Data Plane (OVS)   │
                          │   SFC steering rules │
                          └──────────────────────┘
```

---

## 3. Module M1 — Streaming Telemetry Collection

### 3.1 Design Rationale

Traditional NetFlow/sFlow export intervals are 60 seconds — far too slow for sub-second attack detection. M1 replaces passive flow export with **streaming telemetry** using the gNMI/gRPC protocol with YANG data models, achieving sub-second sampling. M1 produces two parallel feature streams:

- **Flow-level feature stream** (per 5-second window) — input for Track A (Random Forest classifier)
- **Aggregated time-series stream** (per 1-minute interval) — input for Track B (Multivariate LSTM forecaster)

### 3.2 Technical Specification

**Protocol stack:**
```
Physical switch/router
        │
        ▼
gNMI (gRPC Network Management Interface)
  - Subscription mode: SAMPLE (period = 500ms) or ON_CHANGE
  - Path: /interfaces/interface/statistics
  - Authentication: mTLS certificates
        │
        ▼
Apache Kafka (message broker)
  - Topic: telemetry.raw
  - Partition key: source_device_id
  - Retention: 30 minutes (rolling window for Track B history)
        │
        ▼
Apache Flink (stream processor)
  - Branch 1 (flow features): 5-second sliding window, 1-second slide
                              → telemetry.features.flow
  - Branch 2 (aggregated TS): 1-minute tumbling window
                              → telemetry.features.timeseries
```

### 3.3 Track A Feature Set — Flow-Level (Feature-Driven SL per IJSRA 2021)

Following Hossain et al. (IJSRA 2021), M1 extracts the standard CICFlowMeter feature set (88 features per flow) from CICDDoS2019, then performs the following **pre-processing pipeline** identical to the reference paper:

**Stage 1 — Data cleaning:**
- **Eliminate socket-level features** (Flow ID, Src IP, Src Port, Dst IP, Dst Port, Timestamp) due to high variability across networks (cause overfitting). Retains **80 features**.
- Remove duplicate rows.
- Impute missing, infinite, and negative values using **median imputation**.

**Stage 2 — Feature scaling and encoding:**
- **StandardScaler** normalization on all numerical features:  z = (x − μ) / σ
- **Label Encoding** for categorical attributes (each category → unique integer starting from 0).

**Stage 3 — Feature selection via Extra Trees Classifier (Gini importance):**
- Train an Extra Trees Classifier on the 80-feature pre-processed data.
- At each test node, k random features are sampled; the best split is chosen based on Gini importance.
- Compute the standardized total decrease in Gini criterion per attribute → rank features.
- Select **top features by Gini importance** (paper retains the highest-ranked subset; PAD-ONAP uses **top-22 features**, aligned with Track B's input dimensionality for unified telemetry).

**Final Track A feature subset (top-22 by Extra Trees Gini importance on CICDDoS2019):**

| # | Feature | CICFlowMeter Name |
|---|---|---|
| 1 | `flow_duration` | Flow Duration |
| 2 | `total_fwd_packets` | Total Fwd Packets |
| 3 | `total_bwd_packets` | Total Backward Packets |
| 4 | `total_length_fwd_packets` | Total Length of Fwd Packets |
| 5 | `total_length_bwd_packets` | Total Length of Bwd Packets |
| 6 | `fwd_packet_length_max` | Fwd Packet Length Max |
| 7 | `fwd_packet_length_mean` | Fwd Packet Length Mean |
| 8 | `bwd_packet_length_mean` | Bwd Packet Length Mean |
| 9 | `flow_bytes_per_sec` | Flow Bytes/s |
| 10 | `flow_packets_per_sec` | Flow Packets/s |
| 11 | `flow_iat_mean` | Flow IAT Mean |
| 12 | `flow_iat_std` | Flow IAT Std |
| 13 | `fwd_iat_total` | Fwd IAT Total |
| 14 | `fwd_iat_mean` | Fwd IAT Mean |
| 15 | `bwd_iat_total` | Bwd IAT Total |
| 16 | `syn_flag_count` | SYN Flag Count |
| 17 | `ack_flag_count` | ACK Flag Count |
| 18 | `fwd_psh_flags` | Fwd PSH Flags |
| 19 | `init_win_bytes_fwd` | Init_Win_bytes_forward |
| 20 | `init_win_bytes_bwd` | Init_Win_bytes_backward |
| 21 | `min_seg_size_fwd` | min_seg_size_forward |
| 22 | `protocol` | Protocol |

These 22 features are reproducible directly from CICDDoS2019 ground-truth labels and standard `CICFlowMeter` extraction. The exact ranking depends on the random seed of the Extra Trees Classifier; PAD-ONAP fixes `random_state=42` for reproducibility.

### 3.4 Track B Feature Set — Aggregated Multivariate Time-Series

Following the Multivariate LSTM paper, M1 computes 6 aggregated network-state variables per **1-minute** interval (tumbling window). The forecaster operates on a 60-minute rolling history (look-back window = 60).

| # | Variable | Description |
|---|---|---|
| 1 | `pkt_count_total` | Total packets observed in the minute |
| 2 | `byte_count_total` | Total bytes observed in the minute |
| 3 | `unique_src_ip_count` | Cardinality of source IPs |
| 4 | `unique_dst_ip_count` | Cardinality of destination IPs |
| 5 | `avg_pkt_size` | Mean packet size (bytes) |
| 6 | `syn_count` | Count of TCP SYN packets |

These six variables are the same ones reported in the Multivariate LSTM reference paper to be most predictive of impending volumetric attacks.

### 3.5 Testbed Configuration

Configuration values: sampling_interval_ms=500; kafka_broker=kafka:9092; topics telemetry.raw, telemetry.features.flow, telemetry.features.timeseries; Flink flow_window=5s slide=1s parallelism=4; Flink aggregate_window=60s parallelism=2.

---

## 4. Module M2 — AI Detection and Proactive Forecasting

### 4.1 Architecture Overview

M2 implements a **two-track hybrid inference system**:

- **Track A (Real-time detection):** XGBoost classifier with Extra Trees Gini-based feature selection (per IJSRA 2021) — low-latency (<50ms), targets ≥98.87% validation accuracy on CICDDoS2019 — fires on each 5-second flow feature vector.
- **Track B (Proactive forecasting):** Multi-horizon Stacked Multivariate LSTM — analyzes 60-minute multivariate history to predict attack onset at t+1, t+5, and t+15 minutes.
- **XAI Layer:** SHAP TreeExplainer (Track A) and Permutation Importance (Track B) generate explainability payloads for M3.

```
Flow features (22-dim, 5s)         Aggregate features (6-dim, 1-min)
          │                                      │
          ▼                                      ▼
  ┌─────────────┐                    ┌──────────────────┐
  │  XGBoost    │                    │ Sliding History  │
  │ Classifier  │                    │ Buffer (60 min)  │
  │ (Track A)   │                    └────────┬─────────┘
  └─────┬───────┘                             │
          │                            ┌────────▼─────────┐
          │ Attack class + P(attack)   │ Multi-Horizon    │
          │                            │ Stacked LSTM     │
          ▼                            │ (Track B)        │
  ┌─────────────┐                    └───┬─────┬─────┬───┘
  │   SHAP      │                        │     │     │
  │TreeExplainer│                        │     │     │
  └─────┬───────┘                        │     │     │
          │                         P(t+1) P(t+5) P(t+15)
          └──────────────┬────────────────┴─────┴─────┘
                             ▼
                  ┌────────────────┐
                  │ AI Output Msg  │
                  │ (JSON payload) │
                  └────────┬───────┘
                             │ Kafka: ai.detections
                             ▼ (to M3)
```

### 4.2 Track A — XGBoost + SHAP (Feature-Driven SL per IJSRA 2021)

PAD-ONAP adopts the Feature-Driven Supervised Learning pipeline of Hossain et al. (IJSRA 2021), with **XGBoost** as the production classifier (the paper reports XGBoost as the best-performing model with feature selection at **98.87% validation accuracy** on CICDDoS2019).

**Implementation update:** The production classifier now trains on `GROUPING_STRATEGY = "deployment_action"` labels. The original labels are preserved as audit labels so weak subtype-level classes such as `DrDoS_SSDP`, `DrDoS_UDP`, and `UDP-lag` no longer dominate the operational objective while still remaining visible in diagnostics.

**Pipeline (matching IJSRA 2021):**
```
Raw flow records (CICFlowMeter, 88 features)
        ↓
Stage 1: Eliminate socket-level features  → 80 features
        ↓
Stage 2: Drop duplicates + median-impute missing/inf/negative values
        ↓
Stage 3: Label Encoding (categorical) + StandardScaler (numerical)
        ↓
Stage 4: Extra Trees Classifier (Gini importance) → top-22 features
        ↓
XGBoost classifier (sequential tree boosting)
        ↓
Deployment-action softmax (5 grouped classes)
        ↓
Fine-grained audit mapping back to original 12-class taxonomy
        ↓
SHAP TreeExplainer → top-3 contributing features
```

**XGBoost hyperparameters:**

| Parameter | Value | Rationale |
|---|---|---|
| `objective` | multi:softprob | grouped multi-class probabilistic output |
| `num_class` | 5 | deployment-action taxonomy used by the production model |
| `n_estimators` | 200 | sequential boosting rounds |
| `max_depth` | 6 | XGBoost default; controls overfitting |
| `learning_rate` (eta) | 0.1 | standard for medium n_estimators |
| `subsample` | 0.8 | row sampling per tree |
| `colsample_bytree` | 0.8 | column sampling per tree |
| `min_child_weight` | 1 | minimum hessian per leaf |
| `gamma` | 0 | minimum loss reduction for split |
| `reg_alpha` (L1) | 0 | L1 regularization |
| `reg_lambda` (L2) | 1 | L2 regularization |
| `eval_metric` | mlogloss | multi-class log-loss |
| `tree_method` | hist | fast histogram algorithm |
| `n_jobs` | -1 | parallel tree construction |
| `random_state` | 42 | reproducibility |

**Production target classes — deployment-action grouped taxonomy:**

The production Track A model is trained with a **5-class grouped taxonomy** rather than forcing the classifier to separate visually and statistically similar DDoS subtypes. This improves operational robustness because ONAP needs to choose the correct mitigation action/CNF profile, not necessarily the exact wire-protocol subtype for every packet burst.

| Group ID | Production Class | Original CICDDoS2019 Labels | Primary CNF / Policy Action |
|---|---|---|---|
| 0 | BENIGN | BENIGN | No mitigation; baseline monitoring |
| 1 | DrDoS_Reflection | DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS, DrDoS_NTP, DrDoS_SNMP | CNF-Scrubber with reflection-mode profile |
| 2 | Syn | Syn | SYN-proxy mode + rate limiting |
| 3 | UDP_based_attack | DrDoS_SSDP, DrDoS_UDP, UDP-lag | CNF-Scrubber + adaptive token-bucket profile |
| 4 | WebDDoS | WebDDoS | Application-layer rate-limiter |

**Original 12-class taxonomy retained for audit/reporting:**

| Original ID | Fine-Grained Class | Type | Production Group |
|---|---|---|---|
| 0 | BENIGN | Normal traffic | BENIGN |
| 1 | DrDoS_DNS | Reflection — DNS amplification | DrDoS_Reflection |
| 2 | DrDoS_LDAP | Reflection — LDAP amplification | DrDoS_Reflection |
| 3 | DrDoS_MSSQL | Reflection — MSSQL amplification | DrDoS_Reflection |
| 4 | DrDoS_NetBIOS | Reflection — NetBIOS amplification | DrDoS_Reflection |
| 5 | DrDoS_NTP | Reflection — NTP amplification | DrDoS_Reflection |
| 6 | DrDoS_SNMP | Reflection — SNMP amplification | DrDoS_Reflection |
| 7 | DrDoS_SSDP | Reflection — SSDP amplification | UDP_based_attack |
| 8 | DrDoS_UDP | Reflection — Generic UDP-based | UDP_based_attack |
| 9 | Syn | Exploitation — TCP SYN flood | Syn |
| 10 | UDP-lag | Exploitation — UDP-Lag | UDP_based_attack |
| 11 | WebDDoS | Application-layer — HTTP flood | WebDDoS |

This keeps compatibility with the CICDDoS2019 / IJSRA 2021 12-label taxonomy while making the deployed classifier match the PAD-ONAP enforcement layer. The notebook stores fine-grained labels for audit (`*_fine`) and grouped production labels for model training/evaluation (`*_model`).

**Mapping grouped output → 5 graduated tiers (M3):**
The grouped XGBoost probabilities are aggregated to a single P(attack) = 1 − P(BENIGN) for tier dispatch, while the predicted production group is forwarded as `attack_type` for tier-specific CNF action selection. Fine-grained labels are retained only for offline error analysis and reporting.

### 4.3 Track B — Multivariate LSTM Multi-Horizon Forecaster

**Design principle — horizon spacing:**
PAD-ONAP uses **3 forecast horizons with geometric spacing (1:5:15 minutes)**, each mapped 1-to-1 to a specific orchestration action whose execution time matches the available lead time. Geometric spacing (~5× ratio) ensures sufficient temporal decorrelation between sigmoid heads, avoiding training instability from over-correlated outputs. Horizons beyond 15 minutes are excluded because LSTM forecast AUC-ROC on network traffic degrades sharply past this point in single-domain testbeds; horizons shorter than 1 minute overlap the response time of Track A (5-second flow window) without providing additional lead-time value.

**Action–horizon alignment rationale:**

| Action | Execution Time | Required Lead Time | Mapped Horizon |
|---|---|---|---|
| Boost telemetry sampling | ~100 ms | any (cheap) | — (always-on for Tier 1) |
| Pre-position CNF-Scrubber Pod (standby) | ~4 s startup + ~5 s scheduling | ≥ 1 min (safety buffer) | **t+5 min** |
| Insert CNF into SFC + rate-limit | ~10 s (Pod ready + OpenFlow) | ≥ 1 min | **t+1 min** |
| Capacity expansion (extra worker / BW reservation) | ~2 min | ≥ 15 min | **t+15 min** |

**Input shape:** `(batch, look_back=60, n_features=6)` — 60 one-minute timesteps × 6 aggregated variables (Section 3.4).

**Output:** Probability of attack onset at three forecast horizons (t+1, t+5, t+15 minutes), independent sigmoid heads.

**Model architecture (stacked LSTM, per the reference paper):**

```
Input: (batch, 60, 6)
        │
        ▼
LSTM layer 1: hidden_size=100, return_sequences=True, activation=tanh, dropout=0.2
        │
        ▼
LSTM layer 2: hidden_size=100, return_sequences=True, activation=tanh, dropout=0.2
        │
        ▼
LSTM layer 3: hidden_size=50, return_sequences=False, activation=tanh, dropout=0.2
        │
        ▼
Dense: 50 → 25 (ReLU)
        │
        ▼
Dense: 25 → 3 (sigmoid, independent heads)
        │
        ▼
Output: (batch, 3)   # P(attack) at t+1min, t+5min, t+15min
```

**Training hyperparameters (per reference paper):**

| Parameter | Value |
|---|---|
| Optimizer | Adam |
| Learning rate | 0.001 |
| Loss | Binary cross-entropy (averaged over 3 horizons) |
| Batch size | 64 |
| Epochs | 100 (with early stopping, patience=10 on val_loss) |
| Class weighting | attack:normal = 5:1 (calibrated to dataset imbalance) |
| Validation split | 20% of training (chronological, no leakage) |
| Look-back window | 60 timesteps (60 minutes) |
| Forecast horizons | **1, 5, 15 minutes ahead** (geometric spacing) |

**Per-horizon loss weighting:**
Because shorter horizons are inherently easier to predict (less uncertainty), the total loss is weighted to balance training signal across heads:
```
L_total = w_1 · BCE(P(t+1), y(t+1))
        + w_5 · BCE(P(t+5), y(t+5))
        + w_15 · BCE(P(t+15), y(t+15))
where w_1 = 0.5, w_5 = 1.0, w_15 = 1.5
```
Higher weight on the harder long-horizon head prevents the LSTM from collapsing to a near-term oracle.

**Data preparation:**
- Min-Max normalization per feature (fit on training partition only)
- Sliding-window construction: each training sample is a 60-minute history paired with binary attack labels at t+1, t+5, t+15
- Dataset partition is **chronological** (not random shuffle) to prevent temporal leakage — first 70% train, next 15% validation, last 15% test

**Tier-aware operating thresholds (per horizon, calibrated on validation set):**

| Horizon | Threshold | Triggered Tier | Rationale |
|---|---|---|---|
| t+15 min | **0.50** | Tier 1 ALERT | Long horizon → low confidence acceptable; cheap action |
| t+5 min | **0.70** | Tier 2 PREEMPT | Medium horizon → moderate confidence; pre-positioning is reversible |
| t+1 min | **0.85** | Tier 3 MITIGATE (forecast-driven) | Short horizon → high confidence required before SFC reconfiguration |

Threshold values are inversely related to horizon length: longer horizon ⇒ accept more false alarms in exchange for more lead time; shorter horizon ⇒ act only on high-confidence predictions because the corresponding action is more invasive.

**Inference latency target:** ≤200 ms per forecast on a 4-vCPU worker node (no GPU required).

### 4.4 Online Incremental Learning (Concept Drift Adaptation)

For Track A (XGBoost), drift detection uses ADWIN (delta=0.002) on a 10,000-sample sliding buffer of class-probability outputs. When drift is flagged after at least 1,000 samples, a fresh XGBoost booster is retrained on the buffered window using `xgb.train(..., xgb_model=current_model)` for warm-start incremental learning, then atomically swapped in.

For Track B (LSTM), monthly offline retraining is scheduled by default; if validation AUC-ROC drops by >5% from baseline on a rolling 7-day evaluation, an unscheduled retraining is triggered.

### 4.5 Explainability Layer

**Track A — SHAP TreeExplainer (XGBoost):**
Per-prediction explanation uses `shap.TreeExplainer(xgb_model)` which computes exact Shapley values in O(TLD²) time (T=trees, L=leaves, D=depth). For each prediction, SHAP returns:
- 22-dim Shapley value vector (signed contribution of each feature to the predicted class)
- Top-3 features by |Shapley value| with their direction of impact (positive/negative toward attack)
- Auto-generated `explanation_text` (e.g., *"Predicted UDP_based_attack because high `flow_packets_per_sec` (+0.43), high `flow_bytes_per_sec` (+0.31), and low `flow_iat_mean` (+0.18) indicate a UDP-heavy attack pattern"*)

SHAP overhead: ≤20 ms per prediction with `tree_method=hist` and pre-built explainer cache.

**Track B — Permutation Importance:**
For each forecast, a fast permutation-importance pass over the 6 input variables (1 epoch of shuffled inference) gives a relative contribution score per variable. Top-3 variables and a forecast-justification string are exported to M3.

### 4.6 AI Output Message Schema

AI output message fields include event_id, timestamp_utc, source_ip_prefix, target_ip_prefix, detection (track="A_XGB", attack_type ∈ {BENIGN, DrDoS_Reflection, Syn, UDP_based_attack, WebDDoS}, attack_class_id ∈ [0,4], fine_grained_source_labels ∈ optional {BENIGN, DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS, DrDoS_NTP, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP, Syn, UDP-lag, WebDDoS}, confidence, is_attack), forecast (p_attack_1min, p_attack_5min, p_attack_15min, pre_position_recommended, triggered_horizon), xai (shap_top_features, shap_values, explanation_text), tenant_id, severity_estimate.

---

## 5. Module M3 — ONAP Orchestration Decision Engine

### 5.1 ONAP Component Mapping

PAD-ONAP integrates with the following ONAP subsystems:

| ONAP Component | Role in PAD-ONAP |
|---|---|
| **DCAE** (Data Collection Analytics & Events) | Ingests AI output messages from Kafka `ai.detections` topic |
| **Policy Framework** (PAP + PDP) | Stores and evaluates PAD-ONAP policies; maps AI confidence scores to action tiers and triggers SO directly |
| **SO** (Service Orchestrator) | Executes CNF instantiation (via Helm/K8s Plugin), scaling, and termination workflows |
| **A&AI** (Active & Available Inventory) | Provides real-time CNF topology and tenant SLA records |
| **SDC** (Service Design Center) | Houses CNF/NS descriptors (Helm Charts) for all four PAD-ONAP CNF types |

### 5.2 DCAE Microservice: PAD-ONAP Event Collector

A custom DCAE microservice subscribes to the `ai.detections` Kafka topic and publishes normalized VES (Virtual Event Streaming) events to the ONAP event bus. Severity bands are derived from confidence; the VES payload carries XAI text plus forecast and tenant fields in additionalFields. Both Track A (immediate detection) and Track B (forecast) events route through the same VES schema with a `track` discriminator.

### 5.3 Policy Framework — Graduated Response Tiers

PAD-ONAP defines **5 response tiers** driven by AI confidence scores from both tracks. Each tier is tied to a specific forecast horizon (Track B) or detection signal (Track A) whose lead time matches the action's execution cost.

```
Trigger Source → Threshold → Response Tier → Lead Time → CNF Action
────────────────────────────────────────────────────────────────────────────────
 All scores < 0.50          Tier 0 – NORMAL      —          No action; baseline
                                                              monitoring at 500ms

 Track B P(t+15) ≥ 0.50     Tier 1 – ALERT      ~15 min     Increase telemetry
                                                              sampling 500→200ms
                                                              Log event + A&AI update
                                                              Capacity-expansion hint

 Track B P(t+5) ≥ 0.70      Tier 2 – PREEMPT    ~5 min      Pre-position CNF-Scrubber
                                                              to target worker node
                                                              (standby Pod, ready-warm)
                                                              Reserve BW quota
                                                              [PROACTIVE NOVELTY]

 Track B P(t+1) ≥ 0.85      Tier 3 – MITIGATE   ~1 min      Insert CNF-Scrubber into
   OR                                            (forecast)   SFC path
 Track A confidence ≥ 0.85                       instant     Apply rate-limiting
                                                  (reactive)  Throttle tenant BW to
                                                              SLA floor

 Track A confidence ≥ 0.95  Tier 4 – ISOLATE    instant     Full scrubbing + blackhole
                                                              of attack source prefixes
                                                              Activate CNF-RateLimit
                                                              on all ingress prefixes
                                                              NOC alarm + cross-domain
                                                              coordination
```

**Trigger logic — disjunctive Tier 3:** Tier 3 fires from either (a) Track B's short-horizon forecast crossing 0.85 (proactive — Pod started warming during prior Tier 2) or (b) Track A's reactive detection crossing 0.85 (covers volumetric attacks too fast for Track B). The two paths converge on the same SFC insertion action; A&AI deduplicates by `target_ip_prefix + 30s window`.

**Tier escalation:** Tiers are strictly monotonic — once Tier 2 fires, the standby Pod remains warm even if subsequent forecasts dip below 0.70 (within the 60s abatement cooldown), eliminating thrashing. Demotion only occurs after sustained P(attack) < 0.30 for 60s.

**XACML policy fragment (Tier 3):**
Tier 3 policy triggers when 0.85 <= confidence < 0.95 AND track="A_XGB" AND obligates INSERT_CNF_SCRUBBER with sla_floor_mbps and xai_justification (SHAP top-3 features + explanation_text). The `attack_type` field selects the CNF scrubbing profile: DrDoS_* → reflection-mode, Syn → SYN-proxy mode, WebDDoS → application-layer rate-limiter, UDP-lag → adaptive token-bucket.

### 5.4 SO Closed-Loop Integration

```
ONAP SO Direct Loop: PAD-DDoS-Response-Loop
  ┌────────────────────────────────────────────────────────────┐
  │  [ONSET Event from DCAE]                                   │
  │         │                                                  │
  │         ▼                                                  │
  │  [Guard Policy Check]  ──── Frequency guard:               │
  │  (prevent thrashing)        max 1 Pod instantiation/30s    │
  │         │                                                  │
  │         ▼                                                  │
  │  [Policy Decision]     ──── PAD-ONAP-Tier Policy           │
  │                              returns action + params       │
  │         │                                                  │
  │         ▼                                                  │
  │  [SO Operation]        ──── SO Helm/K8s Adapter            │
  │    INSTANTIATE / SCALE      (CNF Helm Chart from SDC)      │
  │    TERMINATE                Returns: operation_id          │
  │         │                                                  │
  │         ▼                                                  │
  │  [Confirmation Event]  ──── K8s callback → DCAE            │
  │  (Pod is RUNNING)            Update A&AI inventory         │
  │         │                                                  │
  │         ▼                                                  │
  │  [Abatement Check]     ──── If P(attack) < 0.30 for 60s:   │
  │  (cooldown period)           terminate CNF + restore SFC   │
  └────────────────────────────────────────────────────────────┘
```

### 5.5 SLA-Aware Scheduling
Scheduling ranks candidate nodes using features (hops_to_ingress, cpu_availability, mem_availability, pod_density, sfc_path_length) and selects the highest scored feasible node.

**Objective:** Minimize SLA violations while maximizing scrubbing capacity.

```
Minimize:   sum_i  w_i * max(0, SLA_i - BW_i)    [SLA violation cost]
            + lambda * CNF_scrub_cost              [resource cost]

Subject to:
  BW_i >= SLA_floor_i              for all legitimate tenants i
  sum_i BW_i + BW_scrub <= C_total  [total link capacity]
  CNF_scrub_vCPUs <= C_vcpu_avail
  CNF_scrub_vRAM  <= C_vram_avail

Where:
  w_i        = tenant priority weight (Gold=3, Silver=2, Bronze=1)
  SLA_floor  = 50% of contracted BW for Gold, 30% for Silver, 20% Bronze
  lambda     = resource cost penalty (tuning parameter)
```

Solved with `scipy.optimize.linprog` or CVXPY; typical solve time <5ms.

---

## 6. Module M4 — Cloud-Native Enforcement Layer

### 6.1 CNF Catalog

Minimal evaluation instantiates two CNF types (Docker images), each described as a Helm Chart in ONAP SDC:

| CNF | Function | CPU Request | RAM Request | Typical Startup Time |
|---|---|---|---|---|
| `cnf-rate-limiter` | Token bucket rate limiting | 0.5 | 1 Gi | ~1.0s |
| `cnf-scrubber` | Stateful scrubbing (SYN proxy, etc.) | 4.0 | 8 Gi | ~4.0s |

Full deployment can additionally include `cnf-traffic-analyzer` and `cnf-blackhole`, but they are outside the minimal test scope.

**TOSCA descriptor fragment (vnf-scrubber):**
TOSCA descriptor specifies VNF scrubber properties (max_throughput_gbps, scrubbing_modes, sla_preservation) and lifecycle operations for instantiate and scale.

### 6.2 VNF Placement Algorithm

Placement follows the **proximity-to-attacker principle** (de Oliveira et al. 2023): scrubbing VNFs placed near the attack ingress minimize malicious traffic traversal of internal links. Placement ranks hosts using hops_to_ingress, vcpu_availability, vram_availability, load_complement, and sfc_path_length, then selects the highest scored host meeting resource constraints.

### 6.3 Service Function Chaining (SFC) Update

```
Before attack:
  Ingress Router ──→ [OVS] ──→ Tenant VMs

Tier 3 mitigation (if SFC enabled):
        Ingress Router ──→ [OVS] ──→ CNF-RateLimiter ──→ CNF-Scrubber ──→ Tenant VMs
```

**OpenFlow rule injection (via ONAP CDS / SDN-C):**
OpenFlow rules match tenant_subnet traffic, set tunnel_id to the scrubber port, and output to NORMAL with idle_timeout=300 and hard_timeout=3600. In minimal scope, SFC is optional and only applied if enabled in the testbed.

### 6.4 NFV Deployment Metrics Collection

This addresses the primary methodological gap: 80% of prior papers (de Oliveira et al. 2023) never measure NFV deployment overhead.

Metrics include timestamps for detection, policy decision, SO request, CNF running, and optional SFC update (if enabled); derived E2E latencies; CPU and memory peaks plus node load overhead; and effectiveness metrics (attack dropped, legitimate passed, SLA violations).

---

## 7. Evaluation Design

### 7.1 Testbed Configuration

```
Simulation testbed (Mininet + Open vSwitch + Docker/ONAP SO):

  Attack traffic generator              Legitimate traffic generator
  (Scapy + hping3)                      (iperf3 + wrk HTTP benchmark)
         │                                      │
         ▼                                      ▼
  ┌─────────────────────────────────────────────────────────┐
  │               Mininet Virtual Network Topology (OVS)    │
  │  ISP-Edge-Router ──── Core-Switch ──── Tenant VMs       │
  │  (attack ingress)          │                            │
  │                    PAD-ONAP Orchestrator + SO Client    │
  │                    (Cloud-Native CNFs on K8s)           │
  └─────────────────────────────────────────────────────────┘

Kubernetes Cluster configuration:
  - Master Node: 1 node  (8 CPU, 16 GB RAM)
  - Worker Nodes: 3 nodes (16 CPU, 32 GB RAM each)
  - CNI: Multus + Open vSwitch (OVS) for multi-interface Pods
  - Container Runtime: containerd / Docker

ONAP deployment (Docker Compose, research-scale):
  Services: DCAE, Policy Framework, SO, A&AI, SDC
  Message bus: Kafka 3.x
  Persistence: MariaDB + Cassandra
```

**Evaluation scope (minimal CNF instantiation):** The onap-on-k8s testbed instantiates only `cnf-rate-limiter` and a lightweight `cnf-scrubber` profile to measure SO → K8s latency, Pod startup, and end-to-end mitigation timing. Other CNFs are not deployed; metrics tied to them are excluded from this evaluation.

### 7.2 Attack Scenarios

| Scenario | Attack Type | Intensity | Duration | Primary Goal |
|---|---|---|---|---|
| S1 | DrDoS suite: DrDoS_DNS, DrDoS_LDAP, DrDoS_MSSQL, DrDoS_NetBIOS, DrDoS_NTP, DrDoS_SNMP, DrDoS_SSDP, DrDoS_UDP (run each class separately, reported as grouped deployment classes plus fine-grained audit) | 1 Gbps | 5 min | Track A coverage for `DrDoS_Reflection` and `UDP_based_attack`, with subtype audit for original DrDoS_* labels |
| S2 | SYN Flood (Syn) + UDP-lag (run separately, A/B; UDP-lag routed to `UDP_based_attack`) | Syn: 500k pps; UDP-lag: 200k pps | 5 min | AI disabled vs AI enabled comparison for exploitation/UDP-based classes |
| S3 | HTTP Flood (WebDDoS) | 100k rps | 5 min | Application-layer detection |
| S4 | Volumetric ramp (A/B) | 100M → 10G over 20 min | 40 min | AI disabled vs AI enabled comparison for forecast pre-positioning |
| S5 | Multi-tenant | 3 tenants, 1 under attack | 5 min | SLA isolation |

**A/B definition (AI disabled vs AI enabled):**
AI enabled uses Track A/B outputs to drive tiered policies and forecast-triggered pre-positioning. AI disabled removes M2 and replaces it with static threshold rules (e.g., pkt/byte rate and SYN rate) plus manual policy triggers; no forecasting and no SHAP/XAI metadata. Enforcement actions and CNF catalog remain identical to isolate the decision-logic effect.


### 7.3 Evaluation Metrics

**Track A — XGBoost + SHAP detection quality:**
- Training accuracy & validation accuracy for the 5-class deployment-action taxonomy
- Precision, Recall, F1-score per deployment class: BENIGN, DrDoS_Reflection, Syn, UDP_based_attack, WebDDoS
- Macro-averaged and weighted-averaged Precision/Recall/F1 for grouped production labels
- Fine-grained audit table showing how original 12-class labels are routed into the 5 production groups
- Optional fine-grained 12-class confusion matrix for diagnosis only; not used as the production decision objective
- False Positive Rate (FPR) — target: <1% for BENIGN vs ATTACK
- Confusion matrix on CICDDoS2019 Day-1 validation partition using grouped production labels
- Inference latency: per-flow prediction time (ms)
- SHAP-attribution stability: Jaccard similarity of top-3 features across 1,000 perturbed samples (target: >0.85)
- Probability calibration quality for tier mapping: Brier score and Expected Calibration Error (ECE) on P(attack) = 1 − P(BENIGN)
- Ablation: XGBoost with vs. without Extra Trees feature selection, plus 12-class fine-grained vs. 5-class deployment-action grouping

**Track B — Multivariate LSTM forecast quality:**
- AUC-ROC at horizons Δ ∈ {1, 5, 15} minutes (per-head evaluation)
- AUPRC at horizons Δ ∈ {1, 5, 15} minutes (attack imbalance sensitivity)
- Per-horizon Precision/Recall at the tier-mapped operating thresholds (0.85 / 0.70 / 0.50 respectively)
- **Mean lead time per tier:** minutes between first crossing of the tier threshold and actual attack onset; must satisfy Tier 1 ≥ 10 min, Tier 2 ≥ 3 min, Tier 3 (forecast path) ≥ 30 s
- **Lead-time vs. accuracy trade-off** (vs. baseline B4 classification variant): plot AUC-ROC degradation per minute of lead time across the 3 horizons
- RMSE on calibrated probability vs. ground-truth labels per horizon
- False alarm rate per 24-hour benign baseline (per tier)
- Permutation-importance stability: Jaccard similarity of top-3 variables across 1,000 perturbed windows
- **Tier-specific trigger precision:**
  - Tier 1 ALERT: fraction of `P(t+15)>0.50` followed by an attack within 30 min
  - Tier 2 PREEMPT: fraction of `P(t+5)>0.70` followed by an attack within 10 min
  - Tier 3 (forecast path): fraction of `P(t+1)>0.85` followed by an attack within 3 min
- Inter-horizon correlation: Pearson ρ between sigmoid heads (target: ρ ∈ [0.4, 0.8] — too low = independent collapse; too high = redundant heads)

**Orchestration quality (M3):**
- Policy evaluation latency (ms)
- Tier assignment accuracy (correct tier for given attack intensity)
- Guard effectiveness: Pod/CNF thrashing rate (oscillations per hour)

**Cloud-Native deployment quality (M4):**
- CNF startup time: mean, p50, p95, p99 (seconds)
- Node CPU overhead during startup (%)
- Node RAM consumption during startup (GB)
- SFC update latency (ms)
- CNF sustained throughput under load (Gbps)

**End-to-end effectiveness (minimal CNF scope):**
- E2E mitigation latency (rate-limiter): detection → `cnf-rate-limiter` Pod ready + policy applied (ms)
- E2E mitigation latency (scrubber): detection → `cnf-scrubber` Pod ready (+ traffic redirection if SFC enabled) (ms)
- Attack traffic blocked (%)
- Legitimate traffic preserved during mitigation (%)
- SLA violations per tenant per minute during attack
- Proactive benefit: latency delta between Tier 2 (Track B pre-positioned) and Tier 3 (Track A reactive)
- Budget compliance: measured Tier 1–3 latencies vs. targets in Section 7 (Tier 4 excluded)

**AI vs. no-AI comparative metrics (A/B scenarios S2 and S4):**
- Time-to-first-action: attack onset → first mitigation action (ms)
- Time-to-clean-traffic: attack onset → legitimate throughput ≥ 95% of pre-attack baseline sustained for 60s (ms)
- Mitigation effectiveness delta: blocked attack traffic (%) and preserved legitimate traffic (%)
- SLA impact delta: total SLA-violation minutes and worst-case throughput drop
- Operational overhead delta: number of CNF instantiations, average CNF CPU/RAM, and policy action count


## 8. Appendix: Terminology

| Term | Definition |
|---|---|
| **CNF** | Cloud-native Network Function — Network function running in containers (Docker/K8s) |
| **Helm** | Kubernetes package manager used by ONAP SO for CNF orchestration |
| **Pod** | Basic execution unit in Kubernetes, hosting one or more containers |
| **Multus** | K8s CNI enabling multiple network interfaces per Pod (required for SFC) |
| **ONAP** | Open Network Automation Platform — Linux Foundation project for CNF/VNF lifecycle |
| **DCAE** | Data Collection, Analytics & Events — ONAP's telemetry ingestion and analytics subsystem |
| **SO** | Service Orchestrator — ONAP component for CNF/VNF lifecycle |
| **VES** | Virtual Event Streaming — ONAP's standardized telemetry event schema |
| **TOSCA / Helm** | Descriptor languages for defining network services and container apps |
| **SFC** | Service Function Chaining — traffic steering through ordered CNF sequence |
| **gNMI** | gRPC Network Management Interface — streaming telemetry protocol |
| **XGBoost** | eXtreme Gradient Boosting — sequential tree-boosting classifier used in Track A |
| **Extra Trees** | Extremely Randomized Trees — ensemble used for Gini-importance feature selection |
| **Gini Importance** | Standardized total decrease in Gini criterion per attribute, used for feature ranking |
| **SHAP** | SHapley Additive exPlanations — model explainability framework (TreeExplainer for Track A) |
| **LSTM** | Long Short-Term Memory — recurrent network used in Track B |
| **CICDDoS2019** | Canadian Cyber Security Institute DDoS 2019 benchmark dataset (88 features, 12 attack classes) |
| **ADWIN** | ADaptive WINdowing — online concept drift detection algorithm |
| **FPR** | False Positive Rate — fraction of normal traffic misclassified as attack |
| **XACML** | eXtensible Access Control Markup Language — ONAP Policy Framework rule language |
| **PAP/PDP** | Policy Administration/Decision Point — ONAP Policy Framework components |
| **LP** | Linear Program — optimization formulation used in SLA-aware resource allocation |

---
