# PAD-ONAP — Testbed Isolation Guide

**Audience:** anyone considering running `testbed/mininet/*.py` on the same
host that runs ONAP + Kubernetes.

**Short answer:** don't.  Use a dedicated VM, or isolate via network/CPU
namespaces as described below.  Mininet's blast radius extends beyond the
process tree because it manipulates the system-wide kernel objects that K8s
also uses for production traffic.

---

## 1. Concrete risks

### 1.1 Shared Open vSwitch daemon
- Mininet adds bridges (`s1`, `s2`, … or `r1`, `r2`, …) through `ovs-vsctl`,
  which talks to the host's `ovs-vswitchd` instance.
- K8s CNI plugins that use OVS (e.g. Antrea, OVN-Kubernetes, OVS-CNI for
  Multus) attach pod interfaces to the same daemon.
- Risk: `mn --clean` (`sudo mn -c`) deletes **all** bridges starting with
  `s`, including those backing live K8s pods.  Same for crash recovery.

### 1.2 Network namespaces
- Mininet creates `mn-h0`, `mn-r1`, … with `ip netns add`.
- K8s pods also live in `ip netns` entries managed by CNI.  Different
  prefixes, so name collisions are rare, but `ip netns delete` is unbounded
  by default and may target the wrong namespace if a hook script greps
  loosely.

### 1.3 Linux Traffic Control (TC) and HTB
- Mininet `TCLink` attaches HTB qdiscs to virtual interfaces.
- Calico/Cilium/Antrea CNIs apply their own qdisc/eBPF programs on the
  physical NICs.
- TC operations require `CAP_NET_ADMIN`, which Mininet acquires via `sudo`;
  errant scripts can `tc qdisc del dev <real-nic>` and disrupt production
  traffic.

### 1.4 iptables / nftables
- Attack generators (`hping3 --flood`, `iperf3 -u`) push millions of pps.
  Even when destined to a Mininet host, the host kernel processes them:
  - `nf_conntrack` table can fill → drops on legitimate traffic.
  - `kube-proxy` iptables rules slow down due to contention.
  - `rp_filter` mis-match causes packets to leak onto the upstream NIC.

### 1.5 Reverse-path filtering and source spoofing
- `hping3 --rand-source -S` emits TCP SYN with random source IPs.
- If `net.ipv4.conf.all.rp_filter=0` (Mininet default), some packets exit
  the Mininet bridge to the real network — your **own** firewall logs and
  upstream ISP will see DDoS traffic from your ONAP server's IP.

### 1.6 Resource contention
- ONAP OOM consumes 64+ GB RAM and 32+ vCPU for a minimal install.
- Mininet plus 3 attack VMs and 3 victim VMs adds 2-4 GB and 4-8 vCPU.
- Heavy `hping3 --flood` saturates one CPU core; if pinned to the same
  NUMA node as `kube-apiserver`, API latency spikes and pods get marked
  `NotReady`.

### 1.7 Pod-network leakage
- Mininet hosts use private IPs (`10.0.0.0/16` by default for fat-tree
  topology).
- Many K8s pod CIDRs also fall in `10.0.0.0/8`.  Overlap causes routing
  ambiguity — Mininet packets may be delivered to K8s pods and vice versa.

---

## 2. Recommended deployment topology

```
                     Mininet VM (Ubuntu 22.04)
                     ┌─────────────────────────────┐
                     │  sudo mn --custom topology   │
                     │  hping3, iperf3, tcpreplay   │
                     │  Local Kafka producer        │
                     │   ↓ via 10.50.0.1 (host-only)│
                     └────────────┬────────────────┘
                                  │ host-only / VXLAN
                                  ▼
         ┌────────────────────────────────────────────────┐
         │           Bare-metal / production server        │
         │  ┌──────────────────────────────────────────┐  │
         │  │ Kubernetes cluster (K3s or vanilla)       │  │
         │  │ ┌──────────┐ ┌─────────────────────────┐ │  │
         │  │ │ ONAP OOM │ │ pad-onap namespace      │ │  │
         │  │ │   …      │ │  pad-onap-pipeline pod  │ │  │
         │  │ └──────────┘ └─────────────────────────┘ │  │
         │  └──────────────────────────────────────────┘  │
         └────────────────────────────────────────────────┘
```

The Mininet VM forwards telemetry to the ONAP server via a single host-only
or VXLAN link (one routing entry to audit), and is hard-wired with:

```
sudo sysctl -w net.ipv4.ip_forward=0     # cannot route to real net
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
```

---

## 3. If you absolutely must co-locate

A minimum isolation profile, in order of importance:

### 3.1 Run Mininet inside a dedicated Linux network namespace
```bash
# Outer namespace creation
sudo ip netns add mn-sandbox
# Move a veth pair into it for Kafka egress only
sudo ip link add veth-mn-in type veth peer name veth-mn-out
sudo ip link set veth-mn-out netns mn-sandbox
sudo ip addr add 10.99.99.1/30 dev veth-mn-in
sudo ip netns exec mn-sandbox ip addr add 10.99.99.2/30 dev veth-mn-out
# Enter the namespace before running Mininet
sudo ip netns exec mn-sandbox sudo python3 testbed/mininet/topology.py
```
This prevents `mn --clean` from touching K8s OVS bridges in the root
namespace.

### 3.2 Use a private OVS daemon
```bash
# Start a second ovsdb-server + ovs-vswitchd on alternate sockets
sudo mkdir -p /var/run/openvswitch-mn
sudo ovsdb-server /etc/openvswitch-mn/conf.db \
    --remote=punix:/var/run/openvswitch-mn/db.sock --pidfile --detach
sudo ovs-vswitchd unix:/var/run/openvswitch-mn/db.sock --pidfile --detach
# Tell Mininet to use that socket
export OVS_RUNDIR=/var/run/openvswitch-mn
```

### 3.3 cgroup CPU + memory limits
```bash
sudo systemd-run --slice=mn.slice --uid=$USER --gid=$USER \
    -p CPUQuota=400% -p MemoryMax=8G \
    sudo python3 testbed/mininet/topology.py
```
Caps Mininet to 4 CPU cores and 8 GiB even under flood traffic.

### 3.4 Block attack-traffic egress
Add an `iptables` rule that drops anything sourced from the Mininet
subnet on every real NIC:

```bash
for nic in $(ls /sys/class/net | grep -vE '^(lo|veth|ovs|tun|docker|cni)'); do
    sudo iptables -I FORWARD -s 10.0.0.0/8 -o "$nic" -j DROP
done
```

### 3.5 Distinct Pod CIDR
Mininet uses `10.0.0.0/16` (default); ONAP OOM Charts default to
`10.42.0.0/16` (K3s) or `192.168.0.0/16` (Calico).  **Verify** with:
```bash
kubectl cluster-info dump | grep -i cidr
```
If overlap exists, change Mininet's `--ipBase` or re-IP K8s pods.

### 3.6 Disable Mininet during ONAP closed-loop testing
Easiest: drop the Mininet VM offline whenever a real-ONAP integration
scenario is running.  The synthetic replay path
(`python -m pipeline.s4_orchestration.orchestrator --source replay`) does
not need Mininet at all and exercises the same M2→M4 logic.

---

## 4. Pre-flight script

A small wrapper script `scripts/verify_testbed.sh` (already in repo) runs
`mn --version`, `ovs-vsctl --version`, and `ip netns list` to confirm the
host can support Mininet.  When co-locating with ONAP, **also** check:

```bash
# Cluster health snapshot before launching Mininet
kubectl get nodes
kubectl get pods --all-namespaces | grep -vE '(Running|Completed)'
# Should be empty.  If not, do NOT start Mininet.
```

---

## 5. Cleanup

After every Mininet session, in this order:

```bash
# 1. Inside the sandbox netns, drain remaining flows
sudo ip netns exec mn-sandbox iperf3 -k 2>/dev/null || true

# 2. Mininet cleanup (only touches bridges starting with `s` and netns `mn-*`)
sudo mn -c

# 3. Verify K8s OVS bridges are still alive (if you use OVN-Kubernetes/Antrea)
sudo ovs-vsctl list-br | grep -E '(br-int|br-ex|antrea-)'

# 4. Quick conntrack reset (avoids residual flood state)
sudo conntrack -F 2>/dev/null || true
```

If `mn -c` reports unknown bridges, **stop**.  Investigate before re-running.

---

## 6. TL;DR

* Best path: separate VM for Mininet, single VXLAN/host-only link to ONAP.
* Co-location is possible but requires the 6 hardening steps above.
* When in doubt, prefer the synthetic replay harness — it produces the same
  closed-loop measurements without touching the kernel.
