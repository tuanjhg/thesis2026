# Remote-Pipeline Testbed — Local Mininet ↔ Remote K8s + ONAP

End-to-end guide for running the PAD-ONAP testbed with Mininet on your
**local machine** and the AI pipeline + ONAP closed-loop on a **remote
K8s server**. Matches the topology proposed in the architecture
discussion: only telemetry (Kafka) and metrics (Prometheus) cross the
local↔server boundary; AI inference, DCAE, Policy, SO, and CNF
instantiation all stay in the cluster.

```
LOCAL machine (laptop / dev box)              REMOTE server (K8s + ONAP)
┌──────────────────────────────────┐         ┌────────────────────────────────────────┐
│ Ubuntu / WSL2                    │         │ K8s node                               │
│                                  │         │                                        │
│ Mininet fat-tree k=4             │         │ ns: pad-onap                           │
│  h0 hping3  →  h15 iperf3 -s     │         │   StatefulSet kafka  (KRaft)           │
│  softflowd ─NetFlow─►  collector │         │   Svc kafka (ClusterIP :9092)          │
│    │                             │         │   Svc kafka-external (NodePort 30992)  │
│    └─Kafka producer──────────────┼─TCP────►│                                        │
│         pad.telemetry.raw  30992 │         │   Deployment pad-onap-pipeline         │
│                                  │         │     consume → Flink (in-pod) → s3_ai   │
│ RemoteTierPoller ◄───HTTP 30292──┼─────────┤     → DMaaP → CLAMP → Policy → SO      │
│ (samples pad_current_tier 1Hz)   │         │   Svc pad-onap-metrics-external        │
│                                  │         │     NodePort 30292 :metrics, 30293 :hz │
│ → generate_report() local        │         │                                        │
│   evaluation/results/*.{png,json}│         │ ns: onap (or onap-cnf)                 │
│                                  │         │   message-router, so, policy-pap …     │
└──────────────────────────────────┘         └────────────────────────────────────────┘
```

---

## 0. Prereqs

**Remote server:**
- Kubernetes cluster up, `kubectl` works.
- ONAP OOM installed in `onap` (or `onap-cnf`) namespace and healthy.
- PAD-ONAP pipeline applied: `kubectl apply -f onap/k8s/pad-onap-deployment.yaml`.
- Pipeline image built and pushed/loaded: `pad-onap/pipeline:1.0.0`.
- Outbound port `30992` (Kafka) and `30292` (metrics) open to the
  Mininet VM's IP.

**Local machine:**
- Ubuntu 22.04 (native or WSL2). Root access via `sudo`.
- Can reach the remote node IP on TCP/30992 and TCP/30292.

---

## 1. One-shot setup on the SERVER

```bash
# On the K8s server, from the repo root
chmod +x onap/scripts/setup_remote_testbed.sh

# Auto-detect node IP, or override (e.g. when fronted by VPN/NAT):
PAD_NODE_PUBLIC_IP=10.50.0.1 ./onap/scripts/setup_remote_testbed.sh
```

What it does:
1. Detects the node IP the Mininet VM will reach (or honours
   `PAD_NODE_PUBLIC_IP`).
2. Renders [`onap/k8s/kafka-pad-onap.yaml`](../onap/k8s/kafka-pad-onap.yaml)
   with `KAFKA_ADVERTISED_LISTENERS=EXTERNAL://<that-ip>:30992` — **this
   is the #1 cause of remote Kafka failures, do not skip it.**
3. Applies Kafka StatefulSet + 3 Services (ClusterIP `kafka:9092`,
   headless `kafka-headless`, NodePort `kafka-external:30992`).
4. Applies [`pad-onap-metrics-nodeport.yaml`](../onap/k8s/pad-onap-metrics-nodeport.yaml)
   exposing `:9292` metrics and `:9293` health probes via NodePort
   `30292` / `30293`.
5. `kubectl rollout restart deploy/pad-onap-pipeline` so the pipeline
   re-reads the new in-cluster Kafka.
6. Smoke-tests the broker from inside the cluster and prints the
   endpoints to use from the Mininet VM.

> **Re-run safely**: the script is idempotent. Run again whenever the
> node IP changes (e.g. you switch VPN gateways).

Expected output tail:

```
From the Mininet VM, use these endpoints:

  export PAD_REMOTE_KAFKA=10.50.0.1:30992
  export PAD_REMOTE_METRICS=http://10.50.0.1:30292/metrics
```

---

## 2. Health-check the remote pipeline

Still on the server:

```bash
# All pods Running
kubectl -n pad-onap get pods

# pad-onap-pipeline ConfigMap in real ONAP mode (not stub, not helm)
kubectl -n pad-onap get cm pad-onap-config \
  -o jsonpath='{.data.PAD_DEPLOY_MODE}'   # → onap

# Pipeline can publish to ONAP DMaaP
kubectl -n pad-onap logs deploy/pad-onap-pipeline --tail=50 \
  | grep -E 'DMaaP|tier|attack_type'

# Run the existing preflight (probes SO, DMaaP, Policy, model files)
python3 onap/scripts/preflight_check.py --host "$(hostname -I | awk '{print $1}')"
```

If `PAD_DEPLOY_MODE` is not `onap`, patch it:

```bash
kubectl -n pad-onap patch cm pad-onap-config --type merge \
  -p '{"data": {"PAD_DEPLOY_MODE": "onap", "PAD_ONAP_STUB": "false"}}'
kubectl -n pad-onap rollout restart deploy/pad-onap-pipeline
```

---

## 3. One-shot setup on the LOCAL Mininet VM

Copy the repo to your local machine (or use a VPN-mounted share), then:

```bash
cd /path/to/Src_2
chmod +x testbed/setup_mininet_vm.sh

# IP of the remote server as your laptop reaches it (public IP or VPN endpoint)
PAD_NODE_PUBLIC_IP=10.50.0.1 ./testbed/setup_mininet_vm.sh
```

What it does:
1. `apt install` Mininet, OVS, softflowd, iperf3, hping3, chrony.
2. `service openvswitch-switch start` + `chronyc makestep` (clock sync —
   critical for end-to-end latency measurement).
3. Sysctl + iptables hardening: `rp_filter=1`, drop any
   `10.0.0.0/16`-sourced packet on real NICs (prevents attack traffic
   from leaking onto the upstream network).
4. Installs `kafka-python`, `numpy`, `matplotlib` into the **system**
   Python (because Mininet runs under `sudo` which doesn't use venv).
5. Probes the remote endpoints — TCP/30992, HTTP/30292, and a real
   Kafka protocol handshake to catch advertised-listener
   misconfiguration immediately.
6. Writes `testbed/.env.remote` with the exports you'll need.

Expected verification:

```
✓ Kafka TCP 10.50.0.1:30992 reachable
✓ Metrics endpoint http://10.50.0.1:30292/metrics reachable
✓ Kafka protocol-level OK; partitions = {0}
```

---

## 4. Run a scenario

```bash
cd /path/to/Src_2
source testbed/.env.remote

sudo -E python3 testbed/netflow_e2e_pipeline.py \
     --mode ai \
     --remote-pipeline \
     --broker          "$PAD_REMOTE_KAFKA" \
     --collector-kafka "$PAD_REMOTE_KAFKA" \
     --remote-metrics-url "$PAD_REMOTE_METRICS" \
     --skip-kafka-setup \
     --k 4 \
     --duration 60
```

Flag-by-flag:

| Flag | Purpose |
|---|---|
| `--mode ai` | Selects AI path. Re-run with `--mode baseline` for A/B. |
| `--remote-pipeline` | Skip local Flink + local Orchestrator. Local does only Mininet + softflowd + collector. |
| `--broker` | Kafka bootstrap server **as seen from the host root namespace** (where Python runs). Same as collector address. |
| `--collector-kafka` | Kafka bootstrap server **as seen from the Mininet host netns**. Same value in remote mode because both addresses resolve to the remote NodePort. |
| `--remote-metrics-url` | Where the local poller scrapes `pad_current_tier` (and `pad_tier_decisions_total` as fallback) at 1 Hz. |
| `--skip-kafka-setup` | **Required** — prevents the script from trying `docker compose up kafka` locally. |
| `--k 4` | Fat-tree k-factor (16 hosts, h0=attacker, h15=victim). |
| `--duration 60` | Attack phase length in seconds. |

What happens during the run:
- Phase 1 (30 s): baseline traffic only — `iperf3` background flows.
- Phase 2 (`--duration` s): `hping3 --udp --flood` from h0 to h15.
- Phase 3 (20 s): recovery.
- Throughout: softflowd on each Mininet host exports NetFlow v5 to h0;
  collector aggregates 5-s feature windows and publishes
  `pad.telemetry.raw` to the **remote** Kafka.
- Remote `pad-onap-pipeline` consumes, runs XGBoost + LSTM, emits VES
  to ONAP DMaaP, Policy + SO triggers Helm install of the CNFs.
- Local `RemoteTierPoller` samples `pad_current_tier` once per second
  and assembles the tier time series for the report.

Re-run with `--mode baseline` to get the AI-vs-baseline pair.

---

## 5. Read back results

### 5.1 Local report (auto-generated)

```
evaluation/results/real_e2e_ai_<ts>.png
evaluation/results/real_e2e_ai_<ts>.json
evaluation/results/real_e2e_baseline_<ts>.png
evaluation/results/real_e2e_baseline_<ts>.json
```

These now reflect **remote tier decisions** (via `RemoteTierPoller`) plus
**local iperf3 throughput** (which is the only ground truth for SLA
preservation in remote mode).

Compare AI vs baseline:

```python
import json, glob, matplotlib.pyplot as plt
ai = json.load(open(sorted(glob.glob('evaluation/results/real_e2e_ai_*.json'))[-1]))
bs = json.load(open(sorted(glob.glob('evaluation/results/real_e2e_baseline_*.json'))[-1]))
plt.step(ai['series']['time_axis_rel_s'], ai['series']['tiers'],
         label='AI (remote)', where='post')
plt.step(bs['series']['time_axis_rel_s'], bs['series']['tiers'],
         label='Baseline (remote)', where='post', linestyle='--')
plt.axvline(0, color='gray'); plt.legend(); plt.grid()
plt.savefig('evaluation/results/compare_remote_ai_vs_baseline.png', dpi=200)
```

### 5.2 Remote-side artifacts (cluster events + SO operations)

These don't fit in the local JSON — fetch separately for the C2/C7
chapters of the thesis:

```bash
# CNF Pod startup timeline (raw kubectl events, with creationTimestamp)
kubectl get events -n pad-onap --sort-by='.lastTimestamp' \
  --field-selector type=Normal \
  -o jsonpath='{range .items[*]}{.lastTimestamp}{"\t"}{.reason}{"\t"}{.involvedObject.name}{"\n"}{end}' \
  | grep -iE 'cnf-|scrubber|ratelimit' \
  > evaluation/results/cnf_events_$(date +%Y%m%d_%H%M%S).tsv

# Pipeline log including SHAP top-3 features per tier transition
kubectl logs -n pad-onap deploy/pad-onap-pipeline --since=10m \
  > evaluation/results/pipeline_log_$(date +%Y%m%d_%H%M%S).log

# ONAP SO operations (in case CLAMP triggered VNF instantiation)
kubectl logs -n onap deploy/so --since=10m \
  | grep -iE 'instantiate|vnfd-(scrubber|ratelimiter)' \
  > evaluation/results/so_ops_$(date +%Y%m%d_%H%M%S).log
```

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Kafka protocol-level FAILED: NoBrokersAvailable` from `setup_mininet_vm.sh` | EXTERNAL advertised listener points to an unreachable IP | Re-run `setup_remote_testbed.sh` on the server with the correct `PAD_NODE_PUBLIC_IP`. |
| Kafka TCP probe `nc -zv 30992` succeeds, but produce times out | EXTERNAL advertised IP is in-cluster only (e.g. `10.42.x.x`) | Same as above — the metadata exchange returns an IP your laptop can't route to. |
| `RemoteTierPoller: 0 samples collected` | Pipeline Pod metrics endpoint not exposing `pad_current_tier` or NodePort 30292 unreachable | `curl http://<NODE_IP>:30292/metrics | head` — must start with `#`. If empty, `kubectl -n pad-onap get svc pad-onap-metrics-external`. |
| All tier samples = 0 | Pipeline is in `stub` mode, or features never reach the Pod | Check `PAD_DEPLOY_MODE=onap`; check `kubectl -n pad-onap logs deploy/pad-onap-pipeline` for "consumed from pad.telemetry.raw" lines. |
| Mininet hosts can't reach the remote Kafka | Mininet host netns isolated from host eth0 | The Mininet host h0 runs `softflowd` and `collector` — collector is the one talking to Kafka. Verify with `mn> h0 ip route`. |
| `n_windows=0` in the JSON | softflowd flushed nothing during the run (default 60-s active flow expiry) | Already mitigated in script: `softflowd ... -t maxlife=10 -t expint=5`. Bump `--duration` to ≥ 60s if the attack is short. |
| Time-zero mismatch between iperf3 and tier series | Local and remote clocks drift | `chronyc tracking` on **both** sides. Offset must be < 50 ms for E2E latency claims to hold. |
| `pad-onap-pipeline` Pod restarts mid-run | OOMKilled or `wait-so` initContainer timed out | `kubectl -n pad-onap describe pod -l app=pad-onap-pipeline`. Increase memory limit in the Deployment if OOM, or check `kubectl -n onap get pods` for ONAP outage. |

---

## 7. Contribution mapping

Which thesis contributions this remote-mode setup proves:

| # | Contribution | Measured by |
|---|---|---|
| C1 | Proactive forecasting (Track B 1/5/15 min) | `series.tiers` first crossing T2/T3 relative to `phase_t.attack` |
| C2 | Real ONAP closed loop (DCAE → Policy → SO → Helm) | `cnf_events_*.tsv` + `so_ops_*.log` from §5.2 |
| C3 | E2E latency 4 stages | `kubectl get events` timestamps minus iperf3 attack-start, **NTP-synced** |
| C4 | 5-tier graduated policy | `series.tiers` value transitions under volumetric ramp |
| C5 | SHAP in ONAP VES metadata | `pipeline_log_*.log` filtered for `shap_top_features` |
| C6 | Lightweight AI on CPU-only Pod | Pod resource usage (`kubectl top pod -n pad-onap`) during inference |

C7 (CNF startup p50/p95/p99) and C8 (multi-tenant SLA isolation) are
best measured with `--source replay` inside the cluster, not via this
remote Mininet driver — Mininet hosts are not real tenants and don't
trigger SO at scale.
