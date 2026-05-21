# PAD-ONAP — Single-Server Testbed Topology

> 1 server vật lý chạy **đồng thời** ONAP+K8s và Mininet fat-tree k=4.
> Cô lập bằng network namespace + private OVS daemon + cgroup.
>
> Thay thế cho mô hình 3-zone trong [TESTBED_TOPOLOGY.md](TESTBED_TOPOLOGY.md)
> khi không có VM thứ hai. Bắt buộc đọc trước:
> [TESTBED_ISOLATION.md](TESTBED_ISOLATION.md) — vì sao co-locate có rủi ro.

---

## 1. Bố trí logic trên 1 server

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Server (Ubuntu 22.04 · 96 GB · 24 vCPU · NVMe 500 GB · GPU optional)        │
│                                                                               │
│  ┌─── ROOT netns (production) ─────────────────────────────────────────────┐ │
│  │                                                                          │ │
│  │  systemd: ovs-vswitchd  (socket /var/run/openvswitch/db.sock)            │ │
│  │  kubelet · containerd · CNI (Calico) · K8s pod CIDR 10.244.0.0/16        │ │
│  │                                                                          │ │
│  │  ┌── ns: onap ─────────────────────┐  ┌── ns: pad-onap ────────────────┐ │
│  │  │ SO · DMaaP MR · Policy · CLAMP  │  │ pad-onap-pipeline pod          │ │
│  │  │ AAI · SDC (OOM minimal)         │  │   ├─ NetFlow collector :7070   │ │
│  │  │   ~ 48 GB RAM, 12 vCPU          │  │   ├─ Flink M2 features         │ │
│  │  │                                 │  │   ├─ InferenceEngine M3        │ │
│  │  │                                 │  │   └─ DMaaP publisher → MR      │ │
│  │  │                                 │  │ pad-vnf-{rl,scrub,bh} pods    │ │
│  │  │                                 │  │   (do SO instantiate)          │ │
│  │  │                                 │  │   ~ 16 GB RAM, 6 vCPU          │ │
│  │  └─────────────────────────────────┘  └────────────────────────────────┘ │
│  │                                                                          │ │
│  │              ▲ veth-mn-in 10.99.99.1/30        (chỉ entry duy nhất       │ │
│  │              │                                  từ sandbox vào root)     │ │
│  └──────────────┼──────────────────────────────────────────────────────────┘ │
│                 │ veth pair (kernel)                                         │
│  ┌──────────────┼──────────────────────────────────────────────────────────┐ │
│  │  netns: mn-sandbox (SANDBOX)                                             │ │
│  │              │                                                            │ │
│  │              ▼ veth-mn-out 10.99.99.2/30                                  │ │
│  │  ┌────────────────────────────────────────────────────────────────────┐  │ │
│  │  │  PRIVATE OVS daemon (/var/run/openvswitch-mn/db.sock)              │  │ │
│  │  │  Mininet fat-tree k=4 — 20 switches, 16 hosts (10.0.0.0/16)        │  │ │
│  │  │  hping3 / iperf3 / tcpreplay từ h0..h7 → h15                       │  │ │
│  │  │  sFlow agent gửi tới 10.99.99.1:6343                               │  │ │
│  │  │  ~ 12 GB RAM, 6 vCPU (cgroup giới hạn)                              │  │ │
│  │  └────────────────────────────────────────────────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
│  Tổng tài nguyên: ONAP 48 + pad-onap 16 + Mininet 12 + OS/buffer 20 = 96 GB  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Bốn lớp cô lập (bắt buộc đủ 4, thiếu 1 = lỗi vận hành)

### 2.1 Network namespace riêng `mn-sandbox`

```bash
sudo ip netns add mn-sandbox
sudo ip link add veth-mn-in  type veth peer name veth-mn-out
sudo ip link set veth-mn-out netns mn-sandbox
sudo ip addr add 10.99.99.1/30 dev veth-mn-in
sudo ip link set veth-mn-in up
sudo ip netns exec mn-sandbox ip addr add 10.99.99.2/30 dev veth-mn-out
sudo ip netns exec mn-sandbox ip link set veth-mn-out up
sudo ip netns exec mn-sandbox ip link set lo up
sudo ip netns exec mn-sandbox ip route add default via 10.99.99.1
```

→ `sudo mn -c` chạy trong sandbox **không thể** xoá bridge `br-int` của Calico
trong root namespace.

### 2.2 Private OVS daemon (socket khác)

```bash
sudo mkdir -p /etc/openvswitch-mn /var/run/openvswitch-mn /var/log/openvswitch-mn
sudo ovsdb-tool create /etc/openvswitch-mn/conf.db \
    /usr/share/openvswitch/vswitch.ovsschema

sudo ovsdb-server /etc/openvswitch-mn/conf.db \
    --remote=punix:/var/run/openvswitch-mn/db.sock \
    --pidfile=/var/run/openvswitch-mn/ovsdb-server.pid --detach

sudo ovs-vsctl --db=unix:/var/run/openvswitch-mn/db.sock --no-wait init
sudo ovs-vswitchd unix:/var/run/openvswitch-mn/db.sock \
    --pidfile=/var/run/openvswitch-mn/ovs-vswitchd.pid \
    --log-file=/var/log/openvswitch-mn/ovs-vswitchd.log --detach

# Mininet sẽ dùng socket này
export OVS_RUNDIR=/var/run/openvswitch-mn
```

→ `ovs-vsctl list-br` trên socket production **không** thấy switch `s1..s20`
của Mininet. Hai daemon độc lập về flow table, controller, statistics.

### 2.3 cgroup CPU + RAM cap

```bash
sudo systemd-run --slice=mn.slice --scope \
    -p CPUQuota=600% -p MemoryMax=12G -p TasksMax=4096 \
    sudo ip netns exec mn-sandbox env OVS_RUNDIR=/var/run/openvswitch-mn \
        python3 testbed/mininet/fat_tree_topology.py
```

→ Mininet không thể chiếm hơn 6 core hoặc 12 GB ngay cả khi hping3 flood
cực mạnh → ONAP API server không bị starve.

### 2.4 iptables egress block trên root netns

```bash
# Cấm mọi packet từ 10.0.0.0/16 (Mininet host IP) thoát ra NIC vật lý
ROOT_NICS=$(ls /sys/class/net | grep -vE '^(lo|veth|cni|cali|docker|kube)')
for nic in $ROOT_NICS; do
    sudo iptables -I FORWARD -s 10.0.0.0/16 -o "$nic" -j DROP
done

# Cấm cả gói có random source (--rand-source) thoát qua mgmt
sudo iptables -I FORWARD -i veth-mn-in ! -d 10.99.99.0/30 -j DROP
sudo iptables -I FORWARD -i veth-mn-in -d 10.244.0.0/16 -j ACCEPT  # K8s pods OK

sudo sysctl -w net.ipv4.conf.all.rp_filter=1
```

→ Attack traffic chỉ có thể đi:
`Mininet host → veth-mn-out → veth-mn-in → veth pod victim` (qua CNI).
Không thoát ra Internet, không vào K8s namespace `onap`.

---

## 3. Đường đi 1 packet tấn công

```
h0 trong Mininet (10.0.0.1)
   │  hping3 --flood -S 10.244.5.42 -p 80 --rand-source
   ▼
OVS switch s1 (private daemon) → s5 (agg) → s9 (core) → s13 (agg) → s4 (edge)
   │  flow table xuất gói ra veth-mn-out
   ▼
veth-mn-out (mn-sandbox) ───── kernel pair ─────► veth-mn-in (root)
   │
   ▼
iptables FORWARD: rp_filter PASS, dst=10.244.5.42 → ACCEPT
   ▼
Calico CNI route → veth của pod victim (giả lập) trong ns pad-onap
   │
   ├──► pod victim drops packet (port 80 không listen) → counter ICMP
   │
   └──► sFlow agent trong Mininet gửi sample tới 10.99.99.1:6343
         │
         ▼
         pad-onap-pipeline pod (collector :6343) nhận sFlow
         → publish Kafka "pad.netflow.raw"
         → Flink tính 22 features
         → XGBoost + Transformer/LSTM → tier=3, type=SYN
         → DMaaP REST POST /events/PAD_ONAP_AI_SIGNALS
         ▼
         CLAMP (ns onap) polls DMaaP mỗi 15 s
         → Policy PDP eval Drools → SO.instantiate(vnfd-scrubber-v1)
         → kubectl create deploy pad-vnf-scrubber-xxxxx (ns pad-onap)
         → /health = 200 → LatencyTracker ghi M1→M4 = t8 − t1
```

Tất cả nằm trong **1 server**, không có hop vật lý.

---

## 4. Tài nguyên cụ thể

| Thành phần | RAM | vCPU | Ghi chú |
|---|---|---|---|
| Linux kernel + systemd | 4 GB | 2 | reserve |
| K8s control plane (kubeadm) | 4 GB | 2 | apiserver + etcd + scheduler |
| ONAP OOM minimal (ns onap) | 48 GB | 12 | giảm replica trong [values-override.yaml](values-override.yaml) |
| pad-onap pipeline + VNF pods | 16 GB | 6 | pipeline 4 GB, VNF spawn theo tier |
| Mininet sandbox (cgroup) | 12 GB | 6 | cap cứng |
| Prometheus + Grafana (root host) | 4 GB | 1 | Docker hoặc K8s |
| Buffer / page cache | 8 GB | – | tránh OOMKill |
| **Tổng** | **96 GB** | **29** | |

> 24 vCPU vẫn đủ vì K8s + ONAP không chạy 100% CPU thường xuyên; cgroup
> CPUQuota=600% cho Mininet chỉ kích hoạt lúc flood.

---

## 5. Script khởi động (đề xuất tạo mới)

```bash
# scripts/start_single_server_testbed.sh
set -euo pipefail

# 1. Đảm bảo K8s + ONAP đã Running
kubectl get pods -A | grep -vE '(Running|Completed|^NAMESPACE)' && {
    echo "Cluster chưa sạch — abort"; exit 1; }

# 2. Tạo sandbox netns + veth
sudo ip netns add mn-sandbox 2>/dev/null || true
sudo ip link add veth-mn-in type veth peer name veth-mn-out 2>/dev/null || true
sudo ip link set veth-mn-out netns mn-sandbox 2>/dev/null || true
sudo ip addr add 10.99.99.1/30 dev veth-mn-in 2>/dev/null || true
sudo ip link set veth-mn-in up
sudo ip netns exec mn-sandbox ip addr add 10.99.99.2/30 dev veth-mn-out 2>/dev/null || true
sudo ip netns exec mn-sandbox ip link set veth-mn-out up
sudo ip netns exec mn-sandbox ip link set lo up
sudo ip netns exec mn-sandbox ip route replace default via 10.99.99.1

# 3. Start private OVS daemon
sudo mkdir -p /etc/openvswitch-mn /var/run/openvswitch-mn /var/log/openvswitch-mn
[ -f /etc/openvswitch-mn/conf.db ] || sudo ovsdb-tool create \
    /etc/openvswitch-mn/conf.db /usr/share/openvswitch/vswitch.ovsschema
pgrep -f "openvswitch-mn/db.sock" >/dev/null || {
    sudo ovsdb-server /etc/openvswitch-mn/conf.db \
        --remote=punix:/var/run/openvswitch-mn/db.sock \
        --pidfile=/var/run/openvswitch-mn/ovsdb-server.pid --detach
    sudo ovs-vsctl --db=unix:/var/run/openvswitch-mn/db.sock --no-wait init
    sudo ovs-vswitchd unix:/var/run/openvswitch-mn/db.sock \
        --pidfile=/var/run/openvswitch-mn/ovs-vswitchd.pid --detach
}

# 4. Egress block
for nic in $(ls /sys/class/net | grep -vE '^(lo|veth|cni|cali|docker|kube)'); do
    sudo iptables -C FORWARD -s 10.0.0.0/16 -o "$nic" -j DROP 2>/dev/null || \
        sudo iptables -I FORWARD -s 10.0.0.0/16 -o "$nic" -j DROP
done
sudo sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null

# 5. Launch Mininet trong cgroup
sudo systemd-run --slice=mn.slice --scope \
    -p CPUQuota=600% -p MemoryMax=12G -p TasksMax=4096 \
    sudo ip netns exec mn-sandbox env OVS_RUNDIR=/var/run/openvswitch-mn \
        python3 testbed/mininet/fat_tree_topology.py "$@"
```

Cleanup tương ứng `scripts/stop_single_server_testbed.sh`:
```bash
sudo ip netns exec mn-sandbox mn -c || true
sudo pkill -f openvswitch-mn || true
sudo ip link del veth-mn-in 2>/dev/null || true
sudo ip netns del mn-sandbox 2>/dev/null || true
sudo iptables -D FORWARD -s 10.0.0.0/16 -j DROP 2>/dev/null || true
```

---

## 6. Khác biệt so với mô hình 3-zone

| Tiêu chí | 3-zone (2 VM/3 máy) | 1 server (mô hình này) |
|---|---|---|
| Cô lập network | Tuyệt đối (VXLAN qua NIC khác) | Logic (netns + private OVS) — đủ tốt nếu áp đủ 4 lớp |
| Risk `mn -c` xoá K8s bridge | Không thể | Đã chặn bằng private OVS daemon |
| Risk attack flood ảnh hưởng kube-apiserver | Không | Đã chặn bằng cgroup CPU + iptables |
| Risk spoof IP thoát Internet | Không | Đã chặn bằng FORWARD DROP + rp_filter |
| Latency M1→M4 đo được | Realistic (qua tunnel) | Hơi nhỏ hơn (không có RTT vật lý) — vẫn realistic vì CLAMP/SO/K8s là bottleneck thật |
| Chi phí | 3 máy | 1 máy |

→ Số latency luận văn vẫn dùng được, miễn là khai báo "single-server testbed
with logical isolation" trong methodology.

---

## 7. Checklist trước mỗi lần chạy

```
[ ] kubectl get pods -A    → không có pod NotReady / CrashLoop
[ ] python onap/scripts/preflight_check.py --host 127.0.0.1   → all PASS
[ ] ip netns list          → có mn-sandbox
[ ] pgrep -f openvswitch-mn → có 2 process (ovsdb + vswitchd)
[ ] iptables -L FORWARD -n | grep 10.0.0.0/16   → có rule DROP
[ ] systemctl status mn.slice  → active hoặc inactive (chưa run)
[ ] free -h  → available > 20 GB
```

---

## 8. Việc cần làm tiếp

1. Tạo `scripts/start_single_server_testbed.sh` và `stop_…sh` theo §5
2. Sửa `testbed/mininet/fat_tree_topology.py` thêm sFlow agent trỏ `10.99.99.1:6343`
3. Sửa `pad-onap-pipeline` deployment để collector lắng nghe sFlow trên pod IP
4. Cập nhật [scripts/verify_testbed.sh](../scripts/verify_testbed.sh) thêm 7 check ở §7
5. Chạy S1 baseline → đối chiếu latency với stub mode → ghi vào báo cáo
