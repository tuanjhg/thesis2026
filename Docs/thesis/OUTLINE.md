# Thesis Outline — PAD-ONAP

**Title:** AI-Augmented NFV Orchestration for Proactive DDoS Mitigation in Data Center Networks

**Working title (VN):** Điều phối NFV tăng cường AI cho giảm thiểu DDoS chủ động trong mạng trung tâm dữ liệu

## Abstract (EN + VN, ~250–300 words)
Context → Gap → Proposal (PAD-ONAP: forecast + 5-tier + LP SLA + ONAP MANO) → Results (XGB Acc=98.25%, AUC=0.9958; forecast AUC 0.988→0.971 over t+30…120s; T2 pre-position 505 ms vs T3 reactive 6006 ms; lead-time vs threshold baseline +65 s on S3, +5 s on S7/S8; baseline FAIL on S4/S5 OOD) → Novelty (first system combining all four pillars).

## Chapter 1 — Introduction (5–7 pp.)
- 1.1 Motivation: DDoS trends in DCN, cost of reactive defense
- 1.2 Problem statement: reactive latency, OOD brittleness, SLA violation
- 1.3 **Research questions & hypotheses** (formal):
  - RQ1: Can ML forecast reduce mitigation latency vs threshold baseline at FPR ≤ 1%?
  - RQ2: Does graduated 5-tier policy preserve tenant SLA under active mitigation?
  - RQ3: Is pre-positioning at T2 safe (no harm to benign tenants)?
  - H1: Lead-time advantage ≥ 30 s on gradual attacks (S3).
  - H2: Binary detection Acc ≥ 98% with AUC ≥ 0.99 under temporal split.
  - H3: URLLC floor holds under all tier loads.
- 1.4 Contributions (4): architecture, forecasting, LP SLA, quantitative evaluation.
- 1.5 Thesis outline.

## Chapter 2 — Background and Related Work (15–20 pp.)
- 2.1 DDoS taxonomy and DCN threat surface
- 2.2 NFV/SFC/OpenFlow fundamentals
- 2.3 ONAP MANO (SO, CLAMP, Policy, DMaaP)
- 2.4 ML for DDoS: tree-based, deep, sequence models
- 2.5 Forecasting architectures (Transformer, LSTM)
- 2.6 Fat-tree DCN topology
- 2.7 **Related work comparison** (≥8 papers, 6-axis matrix)
- 2.8 Research gap

## Chapter 3 — Proposed Architecture (10–15 pp.)
- 3.1 System overview (4-tier S1→S4 + closed-loop ONAP)
- 3.2 **Threat model** (NEW):
  - Attacker capability (volumetric, spoofed, ramping, adaptive low-and-slow)
  - Assumptions (telemetry integrity, control-plane trust)
  - Out-of-scope (insider, crypto attacks)
- 3.3 **Safety definition** (NEW):
  - FP-cost ceiling: pre-positioning SHALL NOT reduce benign tenant allocation below SLA floor
  - Invariant: for every tier t, URLLC_alloc ≥ URLLC_floor
  - Rollback guarantee: tier de-escalation within ≤ 1 hysteresis window
- 3.4 5-tier state machine (T0…T4) — formal definition + hysteresis + frequency guard
- 3.5 AI output schema (AIOutputPayload) and DMaaP contract
- 3.6 LP SLA allocator (primal formulation + fallback)

## Chapter 4 — AI Components (15–20 pp.)
- 4.1 Feature engineering — 17 entropy/rate features
- 4.2 Dataset: CICDDoS2019 with real BENIGN oversampling, temporal 80/20
- 4.3 XGBoost 7-class: training, CV, SHAP top features
- 4.4 Transformer+LSTM 4-horizon: architecture, loss, training
- 4.5 Cross-validation: stratified + time-series + attack-only
- 4.6 Adversarial robustness: FGSM (implemented) + PGD (§ Future Work)
- 4.7 Calibration (Platt) + OOD gate (NEW)
- 4.8 SHAP interpretability
- 4.9 **Data limitations (honest)**: binary AUC=1.0 root-cause analysis, BENIGN oversampling ×27.8, missing 3 attack classes.

## Chapter 5 — Experimental Evaluation (15–20 pp.)
- 5.1 Experimental setup, reproducibility
- 5.2 AI metrics (per-class, per-horizon, CV variance)
- 5.3 Scenarios S1–S8 — AI orchestrator (8/8 PASS)
- 5.4 **Threshold baseline comparison** (FRESH DATA):
  - 6/8 PASS, **S4/S5 OOD FAIL** (over-escalate to T2)
  - Baseline T3 P50 ≈ 6000 ms (no advantage over AI reactive)
- 5.5 **Lead-time analysis** (FRESH DATA):
  - S3 gradual ramp: +65 s lead vs baseline
  - S8 novelty: +135 s lead vs AI-reactive, +5 s vs baseline
  - S7 SLA: +5 s lead with SLA maintained
- 5.6 SLA fairness deep-dive (URLLC floor 150 Mbps preserved)
- 5.7 Hysteresis micro-benchmark
- 5.8 Fat-tree testbed (k=4): connectivity + SFC path latency
- 5.9 SOTA comparison (TST-DDoS, NetProbe, FlowGuard, DAWN)
- 5.10 Threats to validity (VNF sim, ONAP stub, dataset scope)

## Chapter 6 — Conclusion (3–5 pp.)
- 6.1 Summary of contributions
- 6.2 KPI attainment table
- 6.3 Limitations
- 6.4 Future work (ONAP OOM real, k≥8 fat-tree, PGD/BIM, concept drift PSI, cross-dataset BCCC)
