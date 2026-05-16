# PAD-ONAP — Testbed Isolation Guide

**Audience:** anyone running `testbed/mininet/*.py` against a Kubernetes
cluster that already hosts **ONAP** (namespace `onap`, sometimes `onap-cnf`)
and the **PAD-ONAP pipeline** (namespace `pad-onap`, see
[onap/k8s/pad-onap-deployment.yaml](k8s/pad-onap-deployment.yaml)).

**Short answer:** put Mininet on a dedicated VM, push telemetry into the
`pad-onap` namespace's own Kafka broker (NOT directly into ONAP DMaaP), and
keep the attack data plane isolated from the cluster CNI. The reason is
unchanged from earlier drafts — Mininet manipulates kernel objects (OVS
bridges, netns, qdisc, conntrack, iptables) that K8s/CNI/ONAP all share.
What *has* changed is that this guide now references the concrete
services, DNS names, NodePorts, and config knobs the cluster actually
exposes.

---

## 0. What the deployed system looks like

The PAD-ONAP pipeline runs as a regular Kubernetes Deployment alongside
ONAP. Two namespaces are in play:

| Namespace | Owner | Key services |
|---|---|---|
| `onap` (or `onap-cnf`) | ONAP OOM | `so`, `message-router`, `policy-pap`, `aai`, `sdc`, `sdnr` |
| `pad-onap` | PAD-ONAP | `pad-onap-pipeline` (Deployment), `pad-onap-metrics` (Service), `kafka.pad-onap.svc.cluster.local:9092` |

The pipeline talks to ONAP via in-cluster DNS, configured in
[`pad-onap-config` ConfigMap](k8s/pad-onap-deployment.yaml):

```
PAD_ONAP_SO_URL        = http://so.onap.svc.cluster.local:8080
PAD_ONAP_POLICY_URL    = http://policy-pap.onap.svc.cluster.local:6969
PAD_DMAAP_HOST         = message-router.onap.svc.cluster.local
PAD_KAFKA_BROKER       = kafka.pad-onap.svc.cluster.local:9092
PAD_DEPLOY_MODE        = onap        # stub | helm | onap
```

External clients (the Mininet VM) reach ONAP through NodePorts published
by [`onap/scripts/detect_onap_env.sh`](scripts/detect_onap_env.sh):

| Service | In-cluster | NodePort (default) |
|---|---|---|
| ONAP SO | `so.onap.svc.cluster.local:8080` | `30080` |
| DMaaP MR | `message-router.onap.svc.cluster.local:3904` | `30904` |
| Policy PAP | `policy-pap.onap.svc.cluster.local:6969` | `30969` |
| A&AI | `aai.onap.svc.cluster.local:8443` | `30232` |
| PAD metrics | `pad-onap-metrics.pad-onap.svc:9292` | (port-forward) |

The Mininet VM publishes telemetry to **PAD's own Kafka in `pad-onap`**,
not into ONAP DMaaP. The pipeline (s3_ai) consumes from that Kafka,
classifies/forecasts, then writes VES events to ONAP DMaaP, which Policy
+ SO turn into Helm/K8s actions in the same cluster. Mininet is therefore
a **producer-only** edge — it never reaches ONAP control plane directly.

---

## 1. Concrete risks (in this specific deployment)

### 1.1 Shared Open vSwitch daemon
- Mininet adds bridges (`s1`, `s2`, … or `r1`, `r2`, …) through `ovs-vsctl`
  on the host kernel.
- If the cluster CNI is **Antrea**, **OVN-Kubernetes**, or **Multus +
  OVS-CNI** (the pipeline Pod uses Multus when SFC is enabled — see
  `PAD_OVS_BRIDGE=br-pad` in ConfigMap), pod interfaces live on the same
  `ovs-vswitchd` instance.
- Risk: `sudo mn -c` deletes **all** bridges with names starting in `s`,
  which includes pod-facing bridges. The `br-pad` bridge used by SFC
  doesn't match that prefix but is still on the same daemon — a misfire
  on `ovs-vsctl del-br` is one typo away from disconnecting CNF Pods.

### 1.2 Network namespaces
- Mininet creates `mn-h0`, `mn-r1`, … via `ip netns add`.
- Cluster CNI manages pod netns under `/var/run/netns/cni-*` (or under
  `/proc/<pid>/ns/net` for runtime-managed namespaces). Prefix collision
  is unlikely, but any cleanup script doing `ip netns list | xargs ip
  netns del` is unsafe.

### 1.3 Linux Traffic Control (TC) and HTB
- Mininet `TCLink` attaches HTB qdiscs to virtual interfaces.
- Cilium/Calico/Antrea apply their own qdisc/eBPF programs on the
  physical NICs and on cluster veth pairs. A stray
  `tc qdisc del dev <real-nic>` from a Mininet wrapper script disrupts
  CNF egress and ONAP traffic.

### 1.4 iptables / nftables / conntrack
- Attack generators (`hping3 --flood`, `iperf3 -u`) push millions of pps.
  Even when destined to a Mininet host, the host kernel sees them:
  - `nf_conntrack` table fills → drops on legitimate cluster traffic.
  - `kube-proxy` iptables rules slow down (linear chain traversal).
  - The kubelet may mark the node `NotReady` if the API watch stalls,
    which will evict `pad-onap-pipeline` and ONAP Pods alike.

### 1.5 Reverse-path filtering and source spoofing
- `hping3 --rand-source -S` emits TCP SYN with random source IPs.
- If `net.ipv4.conf.all.rp_filter=0` (Mininet default), packets exit the
  Mininet bridge onto the upstream NIC. Your firewall and ISP see DDoS
  traffic from the K8s node's IP — and so does Calico's
  `cali-from-host-endpoint` chain, which can panic-log and slow the
  control plane.

### 1.6 Resource contention with ONAP OOM
- The deployment guide ([onap/DEPLOY.md](DEPLOY.md)) lists 64+ GB RAM and
  16+ cores just for ONAP OOM (minimal profile). Mininet plus 3 attacker
  hosts and 3 victim hosts adds 2-4 GB and 4-8 vCPU.
- `hping3 --flood` saturates one CPU core. If pinned to the same NUMA
  node as `kube-apiserver` or `so` (ONAP SO is heavy), API latency
  spikes and the closed-loop measurement becomes meaningless — you
  would be measuring CPU contention, not pipeline latency.

### 1.7 Pod-network leakage
- Mininet's `fat_tree_topology.py` uses `10.0.0.0/16` by default.
- Cluster Pod CIDR varies by CNI:

```bash
# Find Pod CIDR on this cluster:
kubectl cluster-info dump | grep -m1 -i 'cluster-cidr'
# Common defaults:
#   K3s (Flannel)       10.42.0.0/16
#   Calico              192.168.0.0/16
#   Cilium              10.0.0.0/8       ← OVERLAPS Mininet!
#   OVN-Kubernetes      10.128.0.0/14    ← OVERLAPS Mininet!
```

Overlap with Cilium or OVN-Kubernetes is the most common production foot-
gun: Mininet's hosts will be routed into pod IP space by the kernel and
vice versa. **Verify before every run.**

### 1.8 Pipeline Pod Kafka exposure
- `pad-onap-pipeline` consumes `kafka.pad-onap.svc.cluster.local:9092`.
  That Service is ClusterIP by default — the Mininet VM **cannot** reach
  it without one of:
  - `kubectl port-forward svc/kafka 9092:9092 -n pad-onap` (dev only,
    single-flow bottleneck), or
  - a NodePort/LoadBalancer override on the Kafka Service, or
  - a dedicated `kafka-external` Service of type NodePort.

Exposing Kafka via NodePort is the recommended path for the testbed;
see §2 below.

---

## 2. Recommended deployment topology

```
                    Mininet VM (Ubuntu 22.04)
                    ┌─────────────────────────────────────┐
                    │  Fat-Tree k=4 (OVS)                  │
                    │   attacker × 3   victim × 3          │
                    │   legit    × 6   tenant Gold/Silver/Bronze
                    │                                       │
                    │  softflowd → netflow_collector ──┐   │
                    │                                  │   │
                    │  net.ipv4.ip_forward = 0         │   │
                    │  rp_filter = 1                   │   │
                    │  iptables FORWARD -s 10.0/16 -j DROP │
                    └──────────────────────────────────┼───┘
                                                       │ host-only / VXLAN
                                                       │ 10.50.0.0/30
                                                       ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │   Bare-metal / production K8s server                                │
   │                                                                     │
   │   ┌─────────────────────────────┐    ┌─────────────────────────┐   │
   │   │  ns: pad-onap               │    │  ns: onap (or onap-cnf) │   │
   │   │                             │    │                         │   │
   │   │  kafka-external (NodePort)  │◄───┤                         │   │
   │   │   30992 → kafka:9092        │    │                         │   │
   │   │              │              │    │                         │   │
   │   │              ▼              │    │   ┌─────────────────┐   │   │
   │   │  pad-onap-pipeline Pod      │───►│   │ message-router  │   │   │
   │   │   (XGBoost + LSTM + SHAP)   │    │   │  (DMaaP MR)     │   │   │
   │   │   PAD_DEPLOY_MODE=onap      │    │   │  topic: PAD_ONAP_AI_SIGNALS
   │   │                             │    │   └────────┬────────┘   │   │
   │   │  cnf-rate-limiter (when SO  │    │            │            │   │
   │   │   triggers Helm install)    │    │   ┌────────▼────────┐   │   │
   │   │  cnf-scrubber               │◄───┤   │  policy-pap     │   │   │
   │   │                             │    │   │  → so           │   │   │
   │   └─────────────────────────────┘    │   └─────────────────┘   │   │
   │                                       └─────────────────────────┘   │
   │   Prometheus + Grafana scrape `pad-onap-metrics:9292`              │
   └─────────────────────────────────────────────────────────────────────┘
```

The Mininet VM only ever talks to **one** endpoint outside itself: the
NodePort exposing the `pad-onap` Kafka. From there, all closed-loop
signaling stays inside the cluster via in-cluster DNS.

### 2.1 Expose `pad-onap` Kafka to the Mininet VM

Add this Service (do **not** modify the cluster-internal `kafka`
Service — keep ClusterIP for the Pod-to-Pod path):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kafka-external
  namespace: pad-onap
spec:
  type: NodePort
  selector:
    app: kafka
  ports:
    - name: external
      port: 9092
      targetPort: 9094       # configure a second listener on the broker
      nodePort: 30992
```

> **Kafka listener note:** clients reaching the broker via NodePort see
> advertised host = the K8s node IP, not the in-cluster DNS. Configure
> the broker with two listeners (`INTERNAL` on `9092` advertising
> `kafka.pad-onap.svc.cluster.local`, `EXTERNAL` on `9094` advertising
> `<node-ip>:30992`). The pattern is identical to the dual-listener
> setup in [testbed/docker-compose.yml](../testbed/docker-compose.yml).

Then from the Mininet VM:

```bash
# Sanity check
nc -zv <NODE_IP> 30992

# Collector pushes raw NetFlow features to pad-onap Kafka
sudo -E python3 testbed/netflow_e2e_pipeline.py \
    --mode ai \
    --broker localhost:9092 \
    --collector-kafka <NODE_IP>:30992 \
    --kafka-topic pad.telemetry.raw \
    --duration 60
```

### 2.2 Hard-wire the Mininet VM

```bash
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.netfilter.nf_conntrack_max=2000000   # absorb floods locally
# Block any Mininet-sourced packet from leaving non-VXLAN NICs
for nic in $(ls /sys/class/net | grep -vE '^(lo|veth|ovs|tun|docker|cni|wg)'); do
    sudo iptables -I OUTPUT -s 10.0.0.0/16 -o "$nic" -j DROP
    sudo iptables -I FORWARD -s 10.0.0.0/16 -o "$nic" -j DROP
done
```

### 2.3 Verify cluster Pod CIDR ≠ Mininet subnet

```bash
kubectl cluster-info dump | grep -m1 -i 'cluster-cidr'
kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'
```

If either prints something inside `10.0.0.0/16`, change Mininet's
`--ipBase` in [testbed/mininet/fat_tree_topology.py](../testbed/mininet/fat_tree_topology.py)
(e.g. to `192.168.99.0/24`).

---

## 3. If you must co-locate Mininet on the K8s node

A minimum isolation profile, in order of importance. Each step assumes
ONAP is already running in the `onap` namespace and PAD pipeline in
`pad-onap` — do not stop them while applying these.

### 3.1 Dedicated Linux network namespace

```bash
sudo ip netns add mn-sandbox
sudo ip link add veth-mn-in type veth peer name veth-mn-out
sudo ip link set veth-mn-out netns mn-sandbox
sudo ip addr add 10.99.99.1/30 dev veth-mn-in
sudo ip link set veth-mn-in up
sudo ip netns exec mn-sandbox ip addr add 10.99.99.2/30 dev veth-mn-out
sudo ip netns exec mn-sandbox ip link set veth-mn-out up
sudo ip netns exec mn-sandbox ip link set lo up
# Route only to the pad-onap Kafka NodePort, nothing else
sudo ip netns exec mn-sandbox ip route add <NODE_IP>/32 via 10.99.99.1
# Enter the namespace before running Mininet
sudo ip netns exec mn-sandbox sudo python3 testbed/mininet/topology.py
```
Prevents `mn -c` from touching CNI OVS bridges in the root namespace.

### 3.2 Private OVS daemon (separate from the one CNI uses)

```bash
sudo mkdir -p /var/run/openvswitch-mn /etc/openvswitch-mn
sudo ovsdb-tool create /etc/openvswitch-mn/conf.db \
    /usr/share/openvswitch/vswitch.ovsschema
sudo ovsdb-server /etc/openvswitch-mn/conf.db \
    --remote=punix:/var/run/openvswitch-mn/db.sock \
    --pidfile=/var/run/openvswitch-mn/ovsdb.pid --detach
sudo ovs-vswitchd unix:/var/run/openvswitch-mn/db.sock \
    --pidfile=/var/run/openvswitch-mn/vswitchd.pid --detach
export OVS_RUNDIR=/var/run/openvswitch-mn
```
Verify isolation: `ovs-vsctl --db=unix:/var/run/openvswitch/db.sock list-br`
(the CNI's daemon) **must not** show Mininet bridges, and the reverse.

### 3.3 cgroup CPU + memory cap

```bash
sudo systemd-run --slice=mn.slice \
    -p CPUQuota=400% -p MemoryMax=8G -p MemorySwapMax=0 \
    -p AllowedCPUs=0-3 \
    sudo python3 testbed/mininet/topology.py
```

Pinning to `AllowedCPUs=0-3` keeps the flood off the cores running
`kube-apiserver`, `so`, and `pad-onap-pipeline`. Identify safe cores:

```bash
# Cores actually used by ONAP SO and PAD pipeline
crictl inspect $(crictl ps -q --name so) | jq '.info.runtimeSpec.linux.resources.cpu.cpus'
crictl inspect $(crictl ps -q --name pad-pipeline) | jq '.info.runtimeSpec.linux.resources.cpu.cpus'
```

### 3.4 Block attack-traffic egress at the host

Same as §2.2 but on the cluster node itself, with extra care to skip
CNI interfaces (`flannel.1`, `cilium_*`, `cali*`, `ovn-k8s-mp*`):

```bash
for nic in $(ls /sys/class/net \
    | grep -vE '^(lo|veth|ovs|tun|docker|cni|flannel|cilium|cali|ovn|kube|wg)'); do
    sudo iptables -I FORWARD -s 10.0.0.0/8 -o "$nic" -j DROP
done
```

### 3.5 Distinct Pod CIDR (see §1.7)

Identify and resolve overlap **before** the first `mn` invocation.

### 3.6 Disable Mininet during real ONAP closed-loop runs

The orchestrator supports a synthetic replay path that exercises the
exact same M2 → M3 → M4 chain (DMaaP → Policy → SO → Helm/K8s) without
Mininet:

```bash
# Inside the cluster (or via kubectl exec into pad-onap-pipeline)
python -m pipeline.s4_orchestration.orchestrator \
    --source replay \
    --replay-trace evaluation/traces/cicddos2019_drdos_dns.jsonl
```

This is the right harness for **C2** (ONAP closed-loop), **C5** (SHAP
in policy metadata), and **C7** (CNF startup metrics) measurements,
because those don't need the Mininet data plane — only AI scores hitting
DMaaP. Reserve Mininet for **C1** (forecast lead time), **C3** (E2E
latency including telemetry stage), **C4** (5-tier transitions under
attack ramp), and **C8** (multi-tenant SLA).

---

## 4. Pre-flight script

[`scripts/verify_testbed.sh`](../scripts/verify_testbed.sh) covers the
Mininet side. For the cluster side, add this block before every run:

```bash
# 0. Detect ONAP namespace (may be "onap" or "onap-cnf")
source onap/scripts/detect_onap_env.sh onap || \
    source onap/scripts/detect_onap_env.sh onap-cnf

# 1. ONAP control plane health
kubectl -n $ONAP_NS get pods --no-headers \
    | grep -vE '(Running|Completed)' && { echo "ONAP not healthy — abort"; exit 1; }

# 2. PAD-ONAP pipeline ready
kubectl -n pad-onap rollout status deploy/pad-onap-pipeline --timeout=60s

# 3. PAD pipeline is in real mode (not stub)
kubectl -n pad-onap get cm pad-onap-config -o jsonpath='{.data.PAD_DEPLOY_MODE}'
# Expect: onap   (not stub, not helm)

# 4. Kafka NodePort reachable from Mininet VM side
nc -zv $NODE_IP 30992

# 5. DMaaP topic exists
curl -s "http://$NODE_IP:$ONAP_DMAAP_PORT/topics" | grep PAD_ONAP_AI_SIGNALS

# 6. Pod CIDR does not overlap Mininet
PCIDR=$(kubectl cluster-info dump | grep -m1 'cluster-cidr' | tr -d '",' | awk '{print $NF}')
echo "Pod CIDR = $PCIDR"
case "$PCIDR" in 10.0.*) echo "OVERLAPS Mininet 10.0.0.0/16 — change --ipBase"; exit 1;; esac
```

If any check fails, **do not start Mininet**.

---

## 5. Cleanup (in this order, every session)

```bash
# 1. Stop attack/legit traffic generators
sudo pkill -f 'hping3|iperf3|wrk' 2>/dev/null || true

# 2. Drain Mininet sandbox if you used §3.1
sudo ip netns exec mn-sandbox ip link del veth-mn-out 2>/dev/null || true
sudo ip link del veth-mn-in 2>/dev/null || true

# 3. Mininet cleanup — only touches bridges starting with `s` and netns `mn-*`
sudo mn -c

# 4. Verify CNI/ONAP OVS bridges are still alive
sudo ovs-vsctl list-br | grep -E '(br-int|br-ex|br-pad|antrea-|ovn-)' || \
    echo "WARN: expected CNI bridges missing — investigate before re-running"

# 5. Reset conntrack only inside the sandbox netns (root conntrack belongs to K8s)
sudo ip netns exec mn-sandbox conntrack -F 2>/dev/null || true

# 6. Cluster sanity
kubectl -n $ONAP_NS get pods --no-headers | grep -v Running
kubectl -n pad-onap get pods --no-headers | grep -v Running
# Both must be empty before the next run.
```

If `mn -c` reports unknown bridges, **stop**. Investigate before re-running.

---

## 6. TL;DR

* Best path: separate Mininet VM, single host-only/VXLAN link to a
  NodePort-exposed Kafka in `pad-onap`. ONAP DMaaP, Policy, SO, and the
  pipeline Pod stay inside the cluster on their own DNS.
* The pipeline Pod must run with `PAD_DEPLOY_MODE=onap` (not `stub`,
  not `helm`) for real closed-loop measurements.
* Co-location on the cluster node is possible but requires the 6
  hardening steps in §3.
* For C2/C5/C7 measurements (ONAP loop + SHAP + CNF startup), prefer the
  `--source replay` harness — it does not need Mininet at all and gives
  the cleanest cluster-side numbers.
