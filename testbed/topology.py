"""
ProDDoS-NFV — Mininet Data Center Topology
=============================================
Creates a fat-tree-like topology simulating a cloud data center
with dedicated VNF hosts for DDoS mitigation.

Topology:
    Internet ─── [Edge Switch] ─── [Aggregation Switch] ─── [Core Switch]
                      │                    │
                  [VNF Hosts]         [Server Hosts]

VNF Hosts: dedicated nodes where VNF instances run
Server Hosts: simulated cloud workloads (targets)
Attacker Hosts: traffic generators (replay CIC-DDoS data)

Requires: mininet (sudo apt install mininet)
Run: sudo python topology.py
"""
import sys
import time
import logging

try:
    from mininet.net import Mininet
    from mininet.node import OVSKernelSwitch, RemoteController
    from mininet.link import TCLink
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False
    logging.warning("Mininet not installed. Running in simulation mode.")

logger = logging.getLogger("proddos.topology")


# ── Topology Configuration ─────────────────────────────────────────

TOPO_CONFIG = {
    # Switches
    "n_edge_switches": 2,
    "n_agg_switches": 2,
    "n_core_switches": 1,

    # Hosts
    "n_servers": 4,         # target servers
    "n_attackers": 2,       # traffic generators
    "n_vnf_hosts": 4,       # VNF instances

    # Links
    "server_bw": 1000,      # Mbps
    "edge_bw": 10000,       # Mbps
    "agg_bw": 10000,        # Mbps
    "attacker_bw": 1000,    # Mbps

    # Controller
    "controller_ip": "127.0.0.1",
    "controller_port": 6633,
}


def create_topology(config: dict = None):
    """
    Create the ProDDoS-NFV Mininet topology.

    Returns:
        Mininet network object
    """
    cfg = config or TOPO_CONFIG

    if not MININET_AVAILABLE:
        print("Mininet not available. Returning simulated topology info.")
        return _simulate_topology(cfg)

    net = Mininet(
        switch=OVSKernelSwitch,
        link=TCLink,
        controller=None,  # use remote controller
    )

    # ── Remote Controller (Ryu) ────────────────────────────────
    ctrl = net.addController(
        "ryu_controller",
        controller=RemoteController,
        ip=cfg["controller_ip"],
        port=cfg["controller_port"],
    )

    # ── Switches ───────────────────────────────────────────────
    core_switches = []
    for i in range(cfg["n_core_switches"]):
        s = net.addSwitch(f"cs{i+1}", protocols="OpenFlow13")
        core_switches.append(s)

    agg_switches = []
    for i in range(cfg["n_agg_switches"]):
        s = net.addSwitch(f"as{i+1}", protocols="OpenFlow13")
        agg_switches.append(s)

    edge_switches = []
    for i in range(cfg["n_edge_switches"]):
        s = net.addSwitch(f"es{i+1}", protocols="OpenFlow13")
        edge_switches.append(s)

    # ── Inter-switch Links ─────────────────────────────────────
    # Core ↔ Aggregation (full mesh)
    for cs in core_switches:
        for ag in agg_switches:
            net.addLink(cs, ag, bw=cfg["agg_bw"])

    # Aggregation ↔ Edge (round-robin)
    for i, es in enumerate(edge_switches):
        ag = agg_switches[i % len(agg_switches)]
        net.addLink(ag, es, bw=cfg["edge_bw"])

    # ── Server Hosts ───────────────────────────────────────────
    servers = []
    for i in range(cfg["n_servers"]):
        h = net.addHost(
            f"server{i+1}",
            ip=f"10.0.1.{i+1}/24",
            mac=f"00:00:00:00:01:{i+1:02x}",
        )
        # Connect to edge switches round-robin
        es = edge_switches[i % len(edge_switches)]
        net.addLink(h, es, bw=cfg["server_bw"])
        servers.append(h)

    # ── Attacker Hosts ─────────────────────────────────────────
    attackers = []
    for i in range(cfg["n_attackers"]):
        h = net.addHost(
            f"attacker{i+1}",
            ip=f"10.0.2.{i+1}/24",
            mac=f"00:00:00:00:02:{i+1:02x}",
        )
        es = edge_switches[i % len(edge_switches)]
        net.addLink(h, es, bw=cfg["attacker_bw"])
        attackers.append(h)

    # ── VNF Hosts ──────────────────────────────────────────────
    vnf_hosts = []
    for i in range(cfg["n_vnf_hosts"]):
        h = net.addHost(
            f"vnf{i+1}",
            ip=f"10.0.3.{i+1}/24",
            mac=f"00:00:00:00:03:{i+1:02x}",
        )
        # VNFs connect to aggregation switches for inline processing
        ag = agg_switches[i % len(agg_switches)]
        net.addLink(h, ag, bw=cfg["edge_bw"])
        vnf_hosts.append(h)

    return net


def _simulate_topology(cfg: dict) -> dict:
    """Return topology info as a dict (for testing without Mininet)."""
    topo = {
        "switches": {
            "core": [f"cs{i+1}" for i in range(cfg["n_core_switches"])],
            "aggregation": [f"as{i+1}" for i in range(cfg["n_agg_switches"])],
            "edge": [f"es{i+1}" for i in range(cfg["n_edge_switches"])],
        },
        "hosts": {
            "servers": [
                {"name": f"server{i+1}", "ip": f"10.0.1.{i+1}"}
                for i in range(cfg["n_servers"])
            ],
            "attackers": [
                {"name": f"attacker{i+1}", "ip": f"10.0.2.{i+1}"}
                for i in range(cfg["n_attackers"])
            ],
            "vnf_hosts": [
                {"name": f"vnf{i+1}", "ip": f"10.0.3.{i+1}"}
                for i in range(cfg["n_vnf_hosts"])
            ],
        },
        "links": {
            "core_agg": cfg["n_core_switches"] * cfg["n_agg_switches"],
            "agg_edge": cfg["n_edge_switches"],
            "total_hosts": (
                cfg["n_servers"] + cfg["n_attackers"] + cfg["n_vnf_hosts"]
            ),
        },
    }
    return topo


def start_testbed(interactive: bool = True):
    """Start the full testbed: topology + services."""
    if not MININET_AVAILABLE:
        print("=" * 60)
        print("ProDDoS-NFV Topology (Simulation Mode)")
        print("=" * 60)
        topo = _simulate_topology(TOPO_CONFIG)
        import json
        print(json.dumps(topo, indent=2))
        print("\nTo run with real Mininet:")
        print("  1. Install Mininet: sudo apt install mininet")
        print("  2. Start Ryu:       ryu-manager orchestration/ryu_app.py")
        print("  3. Start topology:  sudo python testbed/topology.py")
        return topo

    setLogLevel("info")
    net = create_topology()

    try:
        net.start()
        print("\n" + "=" * 60)
        print("ProDDoS-NFV Testbed Started")
        print("=" * 60)
        print(f"Servers:   {[h.name for h in net.hosts if 'server' in h.name]}")
        print(f"Attackers: {[h.name for h in net.hosts if 'attacker' in h.name]}")
        print(f"VNFs:      {[h.name for h in net.hosts if 'vnf' in h.name]}")
        print(f"Switches:  {[s.name for s in net.switches]}")

        # Test connectivity
        print("\nTesting connectivity...")
        net.pingAll()

        if interactive:
            print("\nEntering Mininet CLI. Type 'help' for commands.")
            CLI(net)
    finally:
        net.stop()


# ── Traffic Generation Helpers ─────────────────────────────────────

def generate_attack_traffic(net, attack_type: str, duration: int = 30):
    """
    Generate attack traffic from attacker hosts to servers.

    In production, use tcpreplay with PCAP files.
    Here we use hping3/scapy for quick simulation.
    """
    if not MININET_AVAILABLE or net is None:
        print(f"[SIMULATE] Generating {attack_type} traffic for {duration}s")
        return

    attackers = [h for h in net.hosts if "attacker" in h.name]
    servers = [h for h in net.hosts if "server" in h.name]

    if not attackers or not servers:
        return

    attacker = attackers[0]
    target = servers[0]
    target_ip = target.IP()

    attack_commands = {
        "Syn": f"hping3 -S --flood -p 80 {target_ip} &",
        "DrDoS_UDP": f"hping3 --udp --flood -p 53 {target_ip} &",
        "DrDoS_DNS": f"hping3 --udp --flood -p 53 {target_ip} &",
        "DrDoS_NTP": f"hping3 --udp --flood -p 123 {target_ip} &",
    }

    cmd = attack_commands.get(attack_type, f"hping3 --flood {target_ip} &")
    print(f"Starting {attack_type} attack: {attacker.name} → {target_ip}")
    attacker.cmd(cmd)
    time.sleep(duration)
    attacker.cmd("killall hping3")
    print(f"Attack {attack_type} stopped after {duration}s")


# ── Main ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    start_testbed(interactive=True)
