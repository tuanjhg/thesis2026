# PAD-ONAP vs Threshold Baseline — Comparison Report

> Generated from `evaluation_summary.json`, `baseline_summary.json`, `lead_time_comparison.csv`

## Table 1: Scenario Results — PAD-ONAP AI (Proactive) vs Threshold Baseline (Reactive)

| ID | Scenario | AI Verdict | AI MaxTier | AI Proact# | AI T2 P50 (ms) | AI T3 P50 (ms) | Base Verdict | Base MaxTier | Base T2 P50 (ms) | Base T3 P50 (ms) | SLA |
|:---|:---------|:----------:|:----------:|:----------:|:--------------:|:--------------:|:------------:|:------------:|:----------------:|:----------------:|:---:|
| S1 | Normal traffic (benign) | **PASS** | T0 | 0 | --- | --- | **PASS** | T0 | --- | --- | YES |
| S2 | Sudden UDP flood | **PASS** | T3 | 0 | --- | 6,006.0 | **PASS** | T3 | --- | 6,009.3 | YES |
| S3 | Gradual SYN ramp | **PASS** | T2 | 67 | 505.5 | --- | **PASS** | T3 | 501.0 | 6,001.0 | YES |
| S4 | HTTP flood (OOD) | **PASS** | T1 | 0 | --- | --- | **⚠ FAIL** | T2 | 501.0 | --- | YES |
| S5 | ICMP burst (OOD) | **PASS** | T0 | 0 | --- | --- | **⚠ FAIL** | T2 | 504.3 | --- | YES |
| S6 | Multi-attack UDP+SYN | **PASS** | T3 | 48 | 505.0 | 6,004.5 | **PASS** | T3 | --- | 6,002.4 | YES |
| S7 | SLA fairness (3-tenant) | **PASS** | T2 | 78 | 505.7 | --- | **PASS** | T3 | --- | 6,004.0 | YES |
| S8 | Proactive vs reactive | **PASS** | T3 | 30 | 505.2 | 6,006.1 | **PASS** | T3 | --- | 6,007.0 | YES |

**AI total: 8/8 PASS** | **Baseline total: 6/8 PASS**

---

## Table 2: Lead-Time Analysis (proactive AI vs reactive paths)

Window = 5 s. Positive lead = AI proactive fired earlier. Negative = reactive fired earlier (expected for sudden attacks).

| ID | Scenario | First Proact. Win | First React. AI Win | First React. Base Win | Lead vs AI-React (s) | Lead vs Baseline (s) | # Proact. Wins |
|:---|:---------|:-----------------:|:-------------------:|:---------------------:|:--------------------:|:--------------------:|:--------------:|
| S1 | Normal traffic (benign) | --- | --- | --- | --- | --- | 0 |
| S2 | Sudden UDP flood | --- | 37 | 32 | --- | --- | 0 |
| S3 | Gradual SYN ramp | 42 | --- | 55 | --- | +65 s | 67 |
| S4 | HTTP flood (OOD) | --- | --- | --- | --- | --- | 0 |
| S5 | ICMP burst (OOD) | --- | --- | --- | --- | --- | 0 |
| S6 | Multi-attack UDP+SYN | 71 | 32 | 32 | -195 s | -195 s | 48 |
| S7 | SLA fairness (3-tenant) | 31 | --- | 32 | --- | +5 s | 78 |
| S8 | Proactive vs reactive | 31 | 58 | 32 | +135 s | +5 s | 30 |

---

## Table 3: Proactive Speed-Up Summary

| ID | Scenario | Proactive T2 P50 (ms) | Reactive T3 P50 (ms) | Speed-up Ratio |
|:---|:---------|:---------------------:|:--------------------:|:--------------:|
| S2 | Sudden UDP flood | --- | 6,006.0 | (no T2 preempt) |
| S3 | Gradual SYN ramp | 505.5 | --- | (no T3) |
| S6 | Multi-attack UDP+SYN | 505.0 | 6,004.5 | **11.9x** |
| S7 | SLA fairness (3-tenant) | 505.7 | --- | (no T3) |
| S8 | Proactive vs reactive | 505.2 | 6,006.1 | **11.9x** |

---

## Key Findings

| Metric | PAD-ONAP AI | Threshold Baseline | Delta |
|:-------|:-----------:|:-----------------:|:-----:|
| Pass rate | **8/8** | **6/8** | AI +2 |
| OOD handling (S4/S5) | **PASS** (graceful under-respond) | **FAIL** (over-escalate to T2) | AI avoids false VNF boot |
| Proactive capability | **YES** (T2 pre-position) | NO | AI only |
| T2 activation latency | **505 ms** | 501–504 ms (reactive) | AI pre-positioned earlier |
| S3 lead-time vs baseline | **+65 s** | baseline (ref) | H1 confirmed (target ≥30 s) |
| S8 proactive advantage | **+135 s** vs AI-reactive | --- | 10.9x speed-up |
| SLA preserved (all scenarios) | **YES** (8/8) | YES (8/8)* | *baseline FAIL scenarios still sla_ok |

> \* Baseline sla_ok=true on S4/S5 because VNF overhead does not violate floor, but the escalation itself is a false positive (wrong tier for OOD traffic).