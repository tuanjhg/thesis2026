# PAD-ONAP — Production Deploy Runbook (ONAP + Kubernetes)

This runbook walks through deploying the **PAD-ONAP v3 pipeline** on a server
that already runs ONAP and Kubernetes.  It complements
`onap/DEPLOY.md` (legacy v2 instructions) and `Pipeline.md` (spec).

---

## 1. Pre-deploy checklist

Run from the project root on the ONAP server:

```bash
# Sanity checks (Python deps, ONAP endpoints, model files)
export PAD_DEPLOY_MODE=onap
export ONAP_HOST=$(kubectl get nodes -o wide --no-headers | head -1 | awk '{print $6}')
export PAD_MODEL_DIR=$(pwd)/pad_onap_v3/models

python3 onap/scripts/preflight_check.py --host "$ONAP_HOST"
```

All FAIL items must be addressed before continuing.

Required artefacts under `pad_onap_v3/models/` (one Track A + one Track B + scaler):

| File | Purpose | Schema |
|---|---|---|
| `xgboost_track_a.json` | Track A classifier | Spec mode (22-dim, 12-class) |
| `xgboost_v3.json` | Track A classifier | Legacy mode (17-dim, 7-class) |
| `lstm_track_b.pt` | Track B forecaster | Spec mode (60×6, 3 horizons) |
| `transformer_v3.pt` | Track B forecaster | Legacy mode (12×17, 4 horizons) |
| `scaler_track_a.pkl` | StandardScaler | Track A inputs |
| `scaler_track_b_minmax.pkl` | MinMaxScaler | Track B inputs (spec only) |
| `xgb_label_map.json` | Class id remap | both |

Inference mode is chosen at startup via `--mode {spec, legacy}`.

---

## 2. Build pipeline image

```bash
# At project root
docker build -t pad-onap/pipeline:1.0.0 -f Dockerfile.pipeline .

# Push to a registry the K8s nodes can pull from
docker tag pad-onap/pipeline:1.0.0 <registry>/pad-onap/pipeline:1.0.0
docker push <registry>/pad-onap/pipeline:1.0.0
```

If you don't have a private registry, load directly on each K8s node:

```bash
docker save pad-onap/pipeline:1.0.0 | ssh <node> 'docker load'
```

For K3s use `k3s ctr images import` instead of `docker load`.

---

## 3. Onboard CNF descriptors into ONAP SDC

The orchestrator's SO REST client (`pipeline/s4_orchestration/onap_so_client.py`)
references the following `modelName` values:

| CNF profile | ONAP SO model | TOSCA file |
|---|---|---|
| `cnf-scrubber-reflection` | `vnfd-scrubber-v1` | `onap/vnfd/vnfd-scrubber-v1.yaml` |
| `cnf-scrubber-syn-proxy` | `vnfd-scrubber-v1` | same — runtime mode selection |
| `cnf-rate-limiter-app-layer` | `vnfd-ratelimiter-v1` | `onap/vnfd/vnfd-ratelimiter-v1.yaml` |
| `cnf-rate-limiter-token-bucket` | `vnfd-ratelimiter-v1` | same |
| `cnf-scrubber-warm-standby` | `vnfd-ratelimiter-v1` | same |
| `cnf-scrubber-blackhole` | `vnfd-blackhole-v1` | `onap/vnfd/vnfd-blackhole-v1.yaml` |

Onboard each YAML into SDC (UI or REST) before activating policy push.

---

## 4. Deploy

```bash
# Create namespace + RBAC + ConfigMap + Secret + Deployment
kubectl apply -f onap/k8s/pad-onap-deployment.yaml

# Verify
kubectl -n pad-onap get pods,svc
kubectl -n pad-onap logs -f deploy/pad-onap-pipeline -c pad-pipeline
```

The pod stays in `Init` until both `wait-dmaap` and `wait-so` see their ONAP
counterparts.  Once running, `readinessProbe` requires at least one processed
window before `Ready=True`.

Health endpoints exposed by the pod:

```bash
kubectl -n pad-onap port-forward svc/pad-onap-metrics 9293:9293 9292:9292
curl -s http://localhost:9293/healthz   # liveness
curl -s http://localhost:9293/readyz    # readiness + last metrics
curl -s http://localhost:9292/metrics   # Prometheus exposition
```

---

## 5. Mode switch (legacy vs spec)

Edit the ConfigMap if the on-disk models are the legacy v3 (17-dim) artefacts:

```bash
kubectl -n pad-onap edit configmap pad-onap-config
# Change PAD_DEPLOY_MODE or add --mode legacy to the Deployment args
```

Then `rollout restart`:

```bash
kubectl -n pad-onap rollout restart deploy/pad-onap-pipeline
```

---

## 6. Common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `wait-so` initContainer loops forever | `so.onap.svc.cluster.local:8080` unreachable | check ONAP `kubectl -n onap get svc so` |
| Pod is `Running` but never `Ready` | No telemetry on `telemetry.features.flow` | check `pad-kafka` topic; `kafka-console-consumer` to verify |
| `infer_track_a` raises `shape != 22` | Mode `spec` selected but legacy XGBoost loaded | switch to `--mode legacy` or upload spec-mode model |
| `instantiate` falls back to `_sim_start` | SO REST 4xx/5xx | check SDC onboarding; check `PAD_ONAP_SO_USER/PASS` secret |
| `helm install` rejects with `error: failed to download` | Chart repo path inside container is wrong | mount `onap/k8s/helm/` and set `PAD_HELM_CHART_REPO` |
| ONAP SO instantiation latency 20–30 s | Normal — see Spec §6.4 and thesis §5.7 | none (this is the real ONAP overhead) |

---

## 7. Rollback

```bash
kubectl -n pad-onap delete deploy/pad-onap-pipeline
# Optional: also remove ConfigMap/Secret to reset config
kubectl -n pad-onap delete configmap pad-onap-config
kubectl -n pad-onap delete secret    pad-onap-secrets
```

The ONAP services are not touched.

---

## 8. Cohabitation with the Mininet testbed

**Do not run `testbed/mininet/*.py` on the same host as the ONAP K8s cluster
unless you have read `onap/TESTBED_ISOLATION.md`.**  Mininet manipulates the
system-wide Open vSwitch and Linux network namespaces, both of which the K8s
CNI also uses for production traffic.
