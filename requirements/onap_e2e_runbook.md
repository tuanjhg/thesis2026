# ONAP OOM Real E2E Runbook — S2 & S8

> **Audience**: Thesis evaluators and lab operators running PAD-ONAP with a live ONAP OOM cluster.  
> **Scenarios**: S2 (UDP Flood → T3 Reactive Mitigate) and S8 (SYN Flood → T2 Proactive + UDP Flood → T3 Reactive).  
> **Scripts**: `onap/scripts/run_s2_real.py` | `onap/scripts/run_s8_real.py`

---

## 1. Prerequisites

### 1.1 Kubernetes Cluster

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 48 GB | 64 GB |
| CPU | 12 cores | 16 cores |
| Disk | 100 GB SSD | 200 GB SSD |
| K8s version | 1.24+ | 1.27+ |

```bash
kubectl version --short
# Server Version: v1.27.x
```

### 1.2 ONAP OOM Components (must be Running)

```bash
# Deploy only the needed subset (saves ~30 GB RAM vs full ONAP)
helm install onap onap/onap -n onap \
  -f onap/values-override.yaml \
  --set so.enabled=true \
  --set message-router.enabled=true \
  --set policy.enabled=true \
  --set clamp.enabled=true

# Verify all pods Ready
kubectl get pods -n onap | grep -E 'so|message-router|policy|clamp'
```

Expected output (all `1/1 Running`):
```
so-0                          1/1     Running   0   8m
message-router-0              1/1     Running   0   6m
policy-pap-xxx                1/1     Running   0   5m
policy-pdp-xxx                1/1     Running   0   5m
clamp-backend-xxx             1/1     Running   0   4m
```

### 1.3 ONAP Service Endpoints

```bash
# Port-forward all needed services (run each in a separate terminal)
kubectl port-forward -n onap svc/so                8080:8080
kubectl port-forward -n onap svc/message-router    3904:3904
kubectl port-forward -n onap svc/policy-pap        6969:6969
```

Or use `NodePort` / `Ingress` as configured in your cluster — update `SO_URL`, `DMAAP_URL`, `PAP_URL` env vars accordingly.

### 1.4 OVS Bridge

```bash
# Verify OVS bridge exists on the test host
sudo ovs-vsctl show
# Should list: Bridge "br-pad"
```

If missing:
```bash
sudo ovs-vsctl add-br br-pad
sudo ovs-vsctl add-port br-pad eth1   # victim-facing NIC
```

### 1.5 Python Dependencies

```bash
cd D:\Khóa luận\Src_2   # project root
pip install requests docker    # only new deps; others already installed
python -c "import requests, docker; print('OK')"
```

### 1.6 Trained AI artifacts (REQUIRED)

The S2 / S8 runners drive **all** ONAP triggers from the live trained model
(`InferenceEngine` in `pipeline/s3_ai/`). They no longer use simulated
payloads. The following files must exist before any run:

```
pad_onap_v3/models/
├── xgboost_v3.json         # 7-class XGBoost classifier
├── transformer_v3.pt       # 4-horizon Transformer+LSTM forecaster
├── scaler.pkl              # StandardScaler fit on training data
├── xgb_label_map.json
├── xgb_tuned_configs.json
├── tf_best_config.json
└── transformer_metrics.json
```

Verify:
```bash
ls pad_onap_v3/models/{xgboost_v3.json,transformer_v3.pt,scaler.pkl}
```

### 1.7 NetFlow feature collector (REQUIRED)

The runner polls features from a collector HTTP endpoint (default
`http://localhost:7070`). Start it before launching S2 / S8:

```bash
# Synthetic feed driven by gNMI simulator (lab default)
python testbed/netflow_collector/collector.py \
  --mode synthetic --gnmi http://localhost:8888 --api-port 7070 &

# Real NetFlow v5 from OVS / softflowd
python testbed/netflow_collector/collector.py \
  --mode netflow --port 6343 --api-port 7070 &

# Verify
curl -s http://localhost:7070/flows/latest | jq .timestamp
```

---

## 2. Environment Variables

Set these before running any scenario script:

```bash
# --- ONAP mode switch (CRITICAL) ---
export PAD_ONAP_STUB=false          # enables real ONAP calls

# --- Service URLs (adjust to your cluster) ---
export SO_URL=http://localhost:8080
export DMAAP_URL=http://localhost:3904
export PAP_URL=http://localhost:6969

# --- ONAP credentials (from onap/values-override.yaml) ---
export SO_USER=so_user
export SO_PASS=so_pass
export PAP_USER=healthcheck
export PAP_PASS=zb!XztG34

# --- Testbed ---
export OVS_BRIDGE=br-pad
export ATTACK_SRC_IP=10.0.0.1      # attacker IP (h0 in fat-tree)
export VNF_DOCKER_HOST=unix:///var/run/docker.sock

# --- Optional gNMI simulator ---
export GNMI_URL=http://localhost:8888

# --- Trained AI (overridable via CLI flags too) ---
export PAD_COLLECTOR_URL=http://localhost:7070
export PAD_MODEL_DIR=pad_onap_v3/models
export PAD_DATA_DIR=pad_onap_v3/processed
export PAD_DEVICE=cpu        # or cuda
```

Verify with:
```bash
env | grep -E 'PAD_ONAP|SO_URL|DMAAP|PAP_URL'
```

---

## 3. Preflight Check

Always run before a real scenario:

```bash
cd D:\Khóa luận\Src_2
python onap/scripts/preflight_check.py
```

Expected output:
```
[OK] SO        http://localhost:8080/actuator/health → 200
[OK] DMaaP     http://localhost:3904/topics → 200
[OK] Policy PAP http://localhost:6969/policy/pap/v1/healthcheck → 200
All services reachable. Safe to set PAD_ONAP_STUB=false.
```

If any check fails → do NOT proceed; fix connectivity first (see §7 Troubleshooting).

---

## 4. Scenario S2 — UDP Flood → T3 Reactive Mitigate

### 4.1 What S2 Tests

| Phase | Action | Expected Outcome |
|-------|--------|-----------------|
| Normal (0–30 s) | Baseline traffic | Tier 0, no VNF |
| Detect (30–35 s) | AI sees UDP flood features | Conf ≥ 0.92 → Tier 3 decision |
| Policy (≈35 s) | CLAMP pushes to PAP | HTTP 200 from PAP |
| Instantiate (≈35 s) | SO creates scrubber VNF | instance_id returned |
| VNF Active (≈41 s) | SO polls until ACTIVE | boot ~6 000 ms |
| SFC (≈41 s) | OVS rule diverts traffic | `ovs-ofctl` exit 0 |
| Cleanup | Scrubber terminated | SO DELETE 200 |

### 4.2 Run Command

The runner loads `pad_onap_v3/models/*` once at startup and polls features
from `--collector-url` every 5 s. Triggers fire only when the **trained
model** raises `tier ≥ 3` (no simulated payload).

```bash
# gNMI mode (recommended for lab without real attack traffic)
python onap/scripts/run_s2_real.py \
  --attack-mode gnmi \
  --gnmi-url http://localhost:8888 \
  --bridge br-pad \
  --src-ip 10.0.0.1 \
  --vnf-port 9001 \
  --collector-url http://localhost:7070 \
  --model-dir pad_onap_v3/models \
  --device cpu

# Mininet mode (real hping3 attack)
python onap/scripts/run_s2_real.py \
  --attack-mode mininet \
  --bridge br-pad \
  --src-ip 10.0.0.1 \
  --vnf-port 9001
```

**Dry-run** (validates logic without calling SO/CLAMP):
```bash
python onap/scripts/run_s2_real.py --dry-run
```

### 4.3 Expected Console Output

```
[S2] Phase 1 — Preflight check ...
[S2]   SO health: OK
[S2]   CLAMP health: OK
[S2] Phase 2 — Normal baseline 30s ...
[S2] Phase 3 — Injecting UDP flood (gnmi) ...
[S2]   POST http://localhost:8888/attack/start → 200
[S2] Phase 4 — Waiting 5s for AI window ...
[S2]   t_trigger = 1746000035.123
[S2] Phase 5 — Pushing CLAMP policy (T3 UDP_Flood conf=0.92) ...
[S2]   PAP response: 200 OK
[S2]   t_policy_push = 1746000035.234  (Δ 111 ms)
[S2] Phase 6 — SO instantiate vnfd-scrubber-v1 ...
[S2]   instance_id = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
[S2]   t_so_request = 1746000035.356  (Δ 233 ms)
[S2] Phase 7 — Waiting VNF ACTIVE (timeout 120s) ...
[S2]   VNF ACTIVE after 6134 ms
[S2]   t_vnf_active = 1746000041.490  (Δ 6367 ms)
[S2] Phase 8 — Installing OVS SFC rule ...
[S2]   ovs-ofctl: rule installed on br-pad
[S2]   t_sfc_rule = 1746000041.521  (Δ 6398 ms)
[S2] Phase 9 — Holding attack for 30s ...
[S2] Phase 10 — Cleanup ...
[S2]   SO terminate: True
[S2]   CLAMP revoke: True
[S2]   SFC rule removed: True

══════════════════════════════════════════════════════
  S2 E2E Latency Report
══════════════════════════════════════════════════════
  Detection → Policy push    :    111 ms
  Policy push → SO request   :    122 ms
  SO request → VNF active    :  6 134 ms   ← boot time
  VNF active → SFC rule      :     31 ms
  ─────────────────────────────────────────────────
  End-to-end (trigger→SFC)   :  6 398 ms
══════════════════════════════════════════════════════
[S2] Results saved → evaluation/results/s2_real_onap.json
```

### 4.4 Key Metrics to Record

| Metric | Target | Typical |
|--------|--------|---------|
| `detection_to_policy_ms` | < 200 ms | ~110 ms |
| `so_to_vnf_ms` | ~6 000 ms | 5 800–6 500 ms |
| `end_to_end_ms` | < 7 000 ms | ~6 400 ms |

---

## 5. Scenario S8 — Proactive T2 + Reactive T3 (Lead-Time Proof)

### 5.1 What S8 Tests

S8 is the **key novelty demonstration**: the forecaster predicts an attack 30 s ahead, pre-positions a lightweight ratelimiter VNF (T2), and when the real attack arrives the T3 scrubber fires with a measured **lead-time advantage**.

| Phase | Time (s) | Action |
|-------|----------|--------|
| Normal | 0–30 | Baseline |
| SYN ramp | 30–35 | gNMI injects syn_flood on r1 |
| T2 Proactive | 35 | AI: conf=0.74, P30s=0.71 → T2 fires |
| Ratelimiter VNF | 35–35.5 | SO instantiates vnfd-ratelimiter-v1 (~500 ms) |
| Escalation hold | 35–65 | ratelimiter active, monitoring |
| UDP Flood | 65 | gNMI switches to udp_flood on r1 |
| T3 Reactive | 65–71 | AI: conf=0.92 → T3 fires |
| T2→T3 handoff | 65 | Terminate ratelimiter, instantiate scrubber (~6 s) |
| Scrubber active | ~71 | SFC rule updated to scrubber port |
| Cleanup | 71+ | All VNFs terminated |

**Lead time** = `t3_trigger − t2_trigger` ≈ 25–35 s (proof of proactive advantage)

### 5.2 Run Command

Same trained AI requirement as S2. Two triggers come from the live model:
proactive (Transformer P30 ≥ 0.70 OR XGBoost conf > 0.80) → T2, then
reactive (conf > 0.90 + P30 > 0.90) → T3.

```bash
python onap/scripts/run_s8_real.py \
  --gnmi-url http://localhost:8888 \
  --bridge br-pad \
  --vnf-port 9001 \
  --collector-url http://localhost:7070 \
  --model-dir pad_onap_v3/models \
  --device cpu

# With custom hold duration between T2 and T3
python onap/scripts/run_s8_real.py \
  --gnmi-url http://localhost:8888 \
  --bridge br-pad \
  --vnf-port 9001 \
  --hold-seconds 30
```

### 5.3 Expected Console Output

```
[S8] Phase 1 — Normal baseline 30s ...
[S8] Phase 2 — Inject SYN flood (gNMI) ...
[S8]   POST /attack/start {type: syn_flood, target: r1} → 200
[S8] ── T2 Proactive Branch ──
[S8]   Payload: SYN_Flood conf=0.74 P30s=0.71 proactive_trigger=True
[S8]   CLAMP push T2 → PAP 200  (Δ 98 ms)
[S8]   SO instantiate vnfd-ratelimiter-v1 ...
[S8]   VNF ACTIVE after 487 ms
[S8]   OVS rule installed (ratelimiter port 9001)
[S8]   t2_end_to_end_ms = 612 ms
[S8] Holding 30s with ratelimiter active ...
[S8] Phase 3 — Escalate to UDP flood (gNMI) ...
[S8]   POST /attack/start {type: udp_flood, target: r1} → 200
[S8] ── T3 Reactive Branch ──
[S8]   Payload: UDP_Flood conf=0.92 proactive_trigger=False
[S8]   Terminate T2 VNF (ratelimiter) ...
[S8]   CLAMP push T3 → PAP 200  (Δ 104 ms)
[S8]   SO instantiate vnfd-scrubber-v1 ...
[S8]   VNF ACTIVE after 6201 ms
[S8]   OVS rule updated (scrubber port 9001)
[S8]   t3_end_to_end_ms = 6389 ms

══════════════════════════════════════════════════════
  S8 E2E Latency Report
══════════════════════════════════════════════════════
  T2 Proactive
    Detection → Policy      :     98 ms
    SO request → VNF active :    487 ms
    End-to-end              :    612 ms
  T3 Reactive
    Detection → Policy      :    104 ms
    SO request → VNF active :  6 201 ms
    End-to-end              :  6 389 ms
  ─────────────────────────────────────────────────
  Lead time (t3 - t2 trigger):  30.1 s   ★ KEY METRIC
══════════════════════════════════════════════════════
[S8] Results saved → evaluation/results/s8_real_onap.json
```

### 5.4 Key Metrics to Record

| Metric | Target | Typical |
|--------|--------|---------|
| `t2_end_to_end_ms` | < 700 ms | ~612 ms |
| `t3_end_to_end_ms` | < 7 000 ms | ~6 400 ms |
| `lead_time_s` | ≥ 25 s | 25–35 s |

---

## 5b. ONAP rule-based baseline (no AI)

The **honest baseline** for the thesis is what stock ONAP DCAE/Holmes
would do on the same traffic without any ML — pure threshold rules
on raw counters. Implemented in `onap/scripts/run_baseline_real.py`:

- Polls the **same** `/flows/latest` collector endpoint that
  `LiveInferenceRunner` uses (identical 17-feature stream).
- Per window, applies `evaluation.baseline_threshold.threshold_decide()`
  (rules: `pkt_rate > 10k → T3`, `udp_frac > 0.85 → T3`,
  `syn_ratio > 0.60 → T3`, etc.). NO ML, NO forecast.
- Requires `--sustain-windows` consecutive trips before firing
  (default 3, ≈ 15 s of evidence) — emulates DCAE-TCAGen2 / Holmes
  CEP correlation behaviour.
- When the rule trips T3, fires the **same** real `CLAMPReal /
  ONAPSOReal / OVSSFCReal` chain → scrubber VNF.

```bash
python onap/scripts/run_baseline_real.py \
  --attack-mode gnmi --gnmi-url http://localhost:8888 \
  --bridge br-pad --src-ip 10.0.0.1 --vnf-port 9001 \
  --collector-url http://localhost:7070 \
  --sustain-windows 3 \
  --out evaluation/results/s2_baseline_real_onap.json
```

> The `--no-proactive` flag on `run_s8_real.py` is **not** a baseline —
> it only disables the T2 firing inside the AI run. Use this script
> for the real "ONAP without AI" baseline.

---

## 5c. Three-way comparison: AI reactive vs AI proactive vs ONAP rule-based

### One-shot harness

```bash
export PAD_ONAP_STUB=false
export SO_URL=http://localhost:8080
export DMAAP_URL=http://localhost:3904
export PAP_URL=http://localhost:6969

bash onap/scripts/run_compare_all.sh \
  --gnmi-url      http://localhost:8888 \
  --collector-url http://localhost:7070 \
  --bridge        br-pad \
  --src-ip        10.0.0.1 \
  --vnf-port      9001 \
  --vnf-port-t2   3 \
  --vnf-port-t3   4 \
  --sustain       3
```

Produces:

| File | Run |
|------|-----|
| `evaluation/results/s2_real_onap.json`          | AI reactive (XGBoost)                |
| `evaluation/results/s8_real_onap.json`          | AI proactive + reactive (Transformer)|
| `evaluation/results/s2_baseline_real_onap.json` | ONAP rule-based (no AI)              |
| `evaluation/results/ai_vs_baseline.md`          | Side-by-side latency report          |

### Metrics measured (defined identically across all three runs)

| Metric                  | Formula                                   | Meaning                                                                                  |
|-------------------------|-------------------------------------------|------------------------------------------------------------------------------------------|
| `detection_lat_ms`      | `t_trigger − t_attack_start`              | Detector cost only (AI inference vs threshold sustain). Quantifies what the model buys you. |
| `detection_to_policy_ms`| `t_policy_push − t_trigger`               | CLAMP push to PAP (network round-trip; same code in all runs).                           |
| `policy_to_so_ms`       | `t_so_request − t_policy_push`            | Time to POST the SO instantiate (same code in all runs).                                 |
| `so_to_vnf_ms`          | `t_vnf_active − t_so_request`             | VNF boot — depends on **VNF profile**: ratelimiter ≈ 500 ms, scrubber ≈ 6 000 ms.        |
| `vnf_to_sfc_ms`         | `t_sfc_rule − t_vnf_active`               | OVS rule install (same code in all runs).                                                |
| `pipeline_e2e_ms`       | `t_sfc_rule − t_trigger`                  | ONAP downstream cost: detector boundary → packets diverted.                              |
| `time_to_mitigation_ms` | `t_sfc_rule − t_attack_start`             | **User-visible quantity**: how long until the victim stops receiving attack packets. ★    |

Cross-run quantities (computed by `compare_ai_vs_baseline.py`):

| Quantity                  | Definition                                                                  |
|---------------------------|-----------------------------------------------------------------------------|
| `proactive_advantage_ms`  | `baseline.time_to_mitigation_ms − ai_proactive.t2_time_to_mitigation_ms`    |
| `reactive_advantage_ms`   | `baseline.time_to_mitigation_ms − ai_reactive.time_to_mitigation_ms`        |
| `forecast_lead_time_s`    | `s8.t3_t_trigger − s8.t2_t_trigger` (intra-S8; no baseline equivalent)      |

### Expected ranges (lab numbers)

| Detector              | `detection_lat_ms` | `pipeline_e2e_ms` | `time_to_mitigation_ms` |
|-----------------------|--------------------|-------------------|-------------------------|
| AI proactive (T2)     | 0–5 s (forecast)   | ~600              | ~5 000–10 000 (often **before** attack peak) |
| AI reactive (S2)      | 5–10 s (1 window)  | ~6 400            | ~11 000–16 000          |
| ONAP rule-based       | 15–60 s (sustain)  | ~6 400            | ~21 000–66 000          |

The thesis claim is `proactive_advantage_ms ≥ 15 000 ms` and a
non-negative `forecast_lead_time_s` — both directly readable from
`ai_vs_baseline.md`.

---

## 6. Interpreting Results

### 6.1 JSON Output Structure

**`evaluation/results/s2_real_onap.json`**:
```json
{
  "scenario": "S2",
  "t_trigger": 1746000035.123,
  "t_policy_push": 1746000035.234,
  "t_so_request": 1746000035.356,
  "t_vnf_active": 1746000041.490,
  "t_sfc_rule": 1746000041.521,
  "detection_to_policy_ms": 111,
  "so_to_vnf_ms": 6134,
  "end_to_end_ms": 6398,
  "vnf_profile": "vnfd-scrubber-v1",
  "instance_id": "...",
  "cleanup_ok": true
}
```

**`evaluation/results/s8_real_onap.json`**:
```json
{
  "scenario": "S8",
  "t2": { "t_trigger": ..., "end_to_end_ms": 612, ... },
  "t3": { "t_trigger": ..., "end_to_end_ms": 6389, ... },
  "lead_time_s": 30.1
}
```

### 6.2 Using Lead-Time Analyzer

After running both scenarios, generate the comparison report:

```bash
python -m evaluation.lead_time_analyzer \
  --ai-results evaluation/results/evaluation_summary.json \
  --baseline-results evaluation/results_baseline/baseline_summary.json \
  --output-dir evaluation/results
```

Outputs:
- `evaluation/results/lead_time_comparison.md` — markdown table
- `evaluation/results/lead_time_comparison.csv` — for LaTeX `pgfplots`

---

## 7. Troubleshooting

### 7.1 SO returns 503

```
requests.exceptions.HTTPError: 503 Service Unavailable
```

**Cause**: SO pod not ready or port-forward dropped.  
**Fix**:
```bash
kubectl get pods -n onap | grep so
# If CrashLoopBackOff:
kubectl logs -n onap so-0 --tail=50
# Restart port-forward:
kubectl port-forward -n onap svc/so 8080:8080
```

### 7.2 Policy PAP returns 401

```
CLAMPReal: PAP returned 401
```

**Cause**: Wrong credentials in env vars.  
**Fix**:
```bash
# Get actual creds from secret
kubectl get secret -n onap policy-secret -o jsonpath='{.data.password}' | base64 -d
export PAP_PASS=<decoded>
```

### 7.3 OVS bridge not found

```
OVSSFCReal: ovs-ofctl failed — bridge br-pad not found
```

**Fix**:
```bash
sudo ovs-vsctl add-br br-pad
# Re-run scenario
```

### 7.4 VNF never reaches ACTIVE (timeout)

```
wait_vnf_active: TIMEOUT after 120s — last status=IN_PROGRESS
```

**Cause**: Docker image `pad-vnf-scrubber:latest` not pulled or Docker daemon unreachable.  
**Fix**:
```bash
docker pull pad-vnf-scrubber:latest
# Or build locally:
docker build -t pad-vnf-scrubber:latest onap/docker/scrubber/
# Verify Docker socket:
export VNF_DOCKER_HOST=unix:///var/run/docker.sock
docker info
```

### 7.5 gNMI simulator not responding

```
requests.ConnectionError: http://localhost:8888/attack/start
```

**Fix**:
```bash
# Start simulator
python testbed/gnmi_simulator/main.py --port 8888 &
# Verify
curl http://localhost:8888/health
```

### 7.6 Running in stub mode accidentally

If results show `so_to_vnf_ms ≈ 200` (too fast), real ONAP is **not** being called.

**Check**:
```bash
echo $PAD_ONAP_STUB   # must be "false"
python -c "
from pipeline.s4_orchestration.onap_so_client import ONAPSOClient
c = ONAPSOClient()
print('stub:', c._stub)   # must be False
"
```

---

## 8. Quick Reference

```bash
# Full S2 run (real ONAP, gNMI attack)
PAD_ONAP_STUB=false \
SO_URL=http://localhost:8080 \
DMAAP_URL=http://localhost:3904 \
PAP_URL=http://localhost:6969 \
  python onap/scripts/run_s2_real.py \
    --attack-mode gnmi \
    --gnmi-url http://localhost:8888 \
    --bridge br-pad \
    --src-ip 10.0.0.1 \
    --vnf-port 9001

# Full S8 run (real ONAP, proactive + reactive)
PAD_ONAP_STUB=false \
SO_URL=http://localhost:8080 \
DMAAP_URL=http://localhost:3904 \
PAP_URL=http://localhost:6969 \
  python onap/scripts/run_s8_real.py \
    --gnmi-url http://localhost:8888 \
    --bridge br-pad \
    --vnf-port 9001

# Dry-run (no real calls, validates code paths)
python onap/scripts/run_s2_real.py --dry-run
python onap/scripts/run_s8_real.py --dry-run

# View results
cat evaluation/results/s2_real_onap.json | python -m json.tool
cat evaluation/results/s8_real_onap.json | python -m json.tool
```

---

## 9. Thesis Evidence Checklist

After a successful run, these artifacts constitute real ONAP evidence:

- [ ] `evaluation/results/s2_real_onap.json` — S2 latency breakdown
- [ ] `evaluation/results/s8_real_onap.json` — S8 lead-time proof
- [ ] `evaluation/results/lead_time_comparison.md` — AI vs baseline comparison
- [ ] Console log (saved via `tee`): `python ... | tee logs/s8_run_$(date +%Y%m%d).log`
- [ ] Screenshot of `kubectl get pods -n onap` during run (show scrubber pod spinning up)
- [ ] `ovs-ofctl dump-flows br-pad` output showing divert rule active

These map to thesis claims:
- **Chapter 4.3** (Instantiation latency): `so_to_vnf_ms` ≈ 6 000 ms for scrubber
- **Chapter 4.4** (Proactive advantage): `lead_time_s` ≥ 25 s
- **Chapter 5** (System integration): real SO + CLAMP + OVS pipeline working end-to-end
