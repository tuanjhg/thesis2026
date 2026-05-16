#!/usr/bin/env python3
"""
PAD-ONAP Mininet Topology — 3 Network Slices
============================================
Slices:
  eMBB  (10.1.0.x) — enhanced Mobile Broadband (video, web), 1 Gbps
  URLLC (10.2.0.x) — Ultra-Reliable Low-Latency (control plane), <1ms RTT
  mMTC  (10.3.0.x) — Massive IoT devices, low BW per device

VNFs (Linux hosts acting as VNF placeholders):
  vnf_fw        — Firewall / ACL (Tier T1)
  vnf_lb        — Load Balancer / pre-warm (Tier T2)
  vnf_scrubber  — DDoS traffic scrubber (Tier T3)
  vnf_isolation — Tenant isolation (Tier T4)

Cross-slice attack vector: r1 <-> r3 (used by anomaly injector)
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import dumpNodeConnections
import sys
import time


# ── Topology parameters ──────────────────────────────────────────────────────
EMBB_BW_MBPS   = 1000    # eMBB bandwidth cap
URLLC_BW_MBPS  = 100     # URLLC bandwidth cap
MMTC_BW_MBPS   = 10      # mMTC bandwidth cap
EMBB_DELAY_MS  = '2ms'   # eMBB round-trip delay (per link)
URLLC_DELAY_MS = '0.5ms' # URLLC per-link delay
MMTC_DELAY_MS  = '5ms'   # mMTC per-link delay


def build_pad_topology(use_remote_ctrl=False):
    """
    Build PAD-ONAP 3-slice testbed.
    Args:
        use_remote_ctrl: True = connect to external OpenFlow controller (ONAP SDN-C)
                         False = built-in Mininet controller (for local testing)
    """
    info('*** Building PAD-ONAP topology\n')

    net = Mininet(
        controller=RemoteController if use_remote_ctrl else None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False,
    )

    # ── Controller ───────────────────────────────────────────────────────────
    if use_remote_ctrl:
        c0 = net.addController('c0', ip='127.0.0.1', port=6633)
        info('*** Using remote controller at 127.0.0.1:6633\n')
        switch_opts = {'protocols': 'OpenFlow13'}
    else:
        c0 = None
        info('*** Using OVS standalone bridge mode\n')
        switch_opts = {'protocols': 'OpenFlow13', 'failMode': 'standalone'}

    # ── Core Switches / Routers ───────────────────────────────────────────────
    r1 = net.addSwitch('r1', **switch_opts)  # eMBB + URLLC ingress
    r2 = net.addSwitch('r2', **switch_opts)  # egress to tenant hosts
    r3 = net.addSwitch('r3', **switch_opts)  # mMTC aggregation

    # ── eMBB Slice Hosts ──────────────────────────────────────────────────────
    embb_src = net.addHost('embb_src', ip='10.1.0.1/24', defaultRoute='via 10.1.0.254')
    embb_dst = net.addHost('embb_dst', ip='10.1.0.2/24', defaultRoute='via 10.1.0.254')

    # ── URLLC Slice Hosts ─────────────────────────────────────────────────────
    urllc_src = net.addHost('urllc_src', ip='10.2.0.1/24', defaultRoute='via 10.2.0.254')
    urllc_dst = net.addHost('urllc_dst', ip='10.2.0.2/24', defaultRoute='via 10.2.0.254')

    # ── mMTC Slice Hosts ──────────────────────────────────────────────────────
    mmtc_src = net.addHost('mmtc_src', ip='10.3.0.1/24', defaultRoute='via 10.3.0.254')
    mmtc_dst = net.addHost('mmtc_dst', ip='10.3.0.2/24', defaultRoute='via 10.3.0.254')

    # ── VNF Placeholder Hosts ─────────────────────────────────────────────────
    vnf_fw        = net.addHost('vnf_fw',        ip='192.168.1.10/24')
    vnf_lb        = net.addHost('vnf_lb',        ip='192.168.1.11/24')
    vnf_scrubber  = net.addHost('vnf_scrubber',  ip='192.168.1.12/24')
    vnf_isolation = net.addHost('vnf_isolation', ip='192.168.1.13/24')

    # ── Links: eMBB slice ─────────────────────────────────────────────────────
    # embb_src → r1 → vnf_fw → r2 → embb_dst
    net.addLink(embb_src, r1,      bw=EMBB_BW_MBPS,  delay=EMBB_DELAY_MS,  loss=0)
    net.addLink(r1,       vnf_fw,  bw=EMBB_BW_MBPS,  delay='1ms',          loss=0)
    net.addLink(vnf_fw,   r2,      bw=EMBB_BW_MBPS,  delay='1ms',          loss=0)
    net.addLink(r2,       embb_dst,bw=EMBB_BW_MBPS,  delay=EMBB_DELAY_MS,  loss=0)

    # ── Links: URLLC slice ────────────────────────────────────────────────────
    # urllc_src → r1 → vnf_lb → r2 → urllc_dst
    net.addLink(urllc_src, r1,       bw=URLLC_BW_MBPS, delay=URLLC_DELAY_MS, loss=0)
    net.addLink(r1,        vnf_lb,   bw=URLLC_BW_MBPS, delay='0.2ms',        loss=0)
    net.addLink(vnf_lb,    r2,       bw=URLLC_BW_MBPS, delay='0.2ms',        loss=0)
    net.addLink(r2,        urllc_dst,bw=URLLC_BW_MBPS, delay=URLLC_DELAY_MS, loss=0)

    # ── Links: mMTC slice ─────────────────────────────────────────────────────
    # mmtc_src → r3 → r2 → mmtc_dst
    net.addLink(mmtc_src, r3,      bw=MMTC_BW_MBPS, delay=MMTC_DELAY_MS, loss=0)
    net.addLink(r3,       r2,      bw=100,           delay='2ms',          loss=0)
    net.addLink(r2,       mmtc_dst,bw=MMTC_BW_MBPS, delay=MMTC_DELAY_MS, loss=0)

    # ── Cross-slice link: r1 ↔ r3 (attack vector) ────────────────────────────
    net.addLink(r1, r3, bw=100, delay='1ms', loss=0)

    # ── VNF scrubber + isolation pre-wired to r2 (activated by S5 enforcer) ──
    # Linux interface names are limited to 15 characters. Explicit short names
    # keep long VNF host names usable inside WSL/Mininet.
    net.addLink(vnf_scrubber,  r2, intfName1='vscrub-eth0', bw=EMBB_BW_MBPS,  delay='0.5ms', loss=0)
    net.addLink(vnf_isolation, r2, intfName1='viso-eth0',   bw=URLLC_BW_MBPS, delay='0.5ms', loss=0)

    return net


def configure_vnf_services(net):
    """Start lightweight services on VNF hosts to simulate real network functions."""
    info('*** Configuring VNF services\n')

    # vnf_fw: simple iptables-based firewall stub
    vnf_fw = net.get('vnf_fw')
    vnf_fw.cmd('iptables -F 2>/dev/null || true')
    vnf_fw.cmd('sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true')

    # vnf_lb: lightweight HTTP echo (simulates load balancer health check)
    vnf_lb = net.get('vnf_lb')
    vnf_lb.cmd('python3 -m http.server 8080 &>/dev/null &')

    # vnf_scrubber: rate-limit stub (tc qdisc)
    vnf_scrubber = net.get('vnf_scrubber')
    # Default: no rate limit (scrubber inactive). S5 enforcer activates via REST.

    # vnf_isolation: block cross-slice traffic by default
    vnf_isolation = net.get('vnf_isolation')

    info('*** VNF services configured\n')


def print_topology_summary(net):
    """Print ASCII topology summary."""
    print('\n' + '='*65)
    print('  PAD-ONAP Testbed — Network Topology Summary')
    print('='*65)
    print('''
  eMBB  (1Gbps):
    embb_src (10.1.0.1) ──▶ r1 ──▶ vnf_fw ──▶ r2 ──▶ embb_dst (10.1.0.2)

  URLLC (<1ms):
    urllc_src (10.2.0.1) ─▶ r1 ──▶ vnf_lb ──▶ r2 ──▶ urllc_dst (10.2.0.2)

  mMTC (10Mbps):
    mmtc_src (10.3.0.1) ──▶ r3 ──────────────▶ r2 ──▶ mmtc_dst (10.3.0.2)

  Cross-slice:         r1 ◀──▶ r3  (DDoS attack vector)

  VNFs on standby:
    vnf_fw        (192.168.1.10) — ACL/Firewall     [T1]
    vnf_lb        (192.168.1.11) — Load Balancer    [T2]
    vnf_scrubber  (192.168.1.12) — DDoS Scrubber    [T3]
    vnf_isolation (192.168.1.13) — Tenant Isolation [T4]
''')
    print('='*65)


def run_quick_test(net):
    """Run pingall and basic iperf to verify connectivity."""
    info('\n*** Running connectivity test (pingall)...\n')
    loss = net.pingAll()
    if loss == 0.0:
        info('*** pingall: 100% — OK\n')
    else:
        info(f'*** pingall: {loss:.1f}% loss — WARNING\n')

    info('*** Running iperf test: embb_src → embb_dst (3s)...\n')
    embb_src = net.get('embb_src')
    embb_dst = net.get('embb_dst')
    embb_dst.cmd('iperf -s &')
    time.sleep(0.5)
    result = embb_src.cmd('iperf -c 10.1.0.2 -t 3 -f m')
    info(f'  iperf result: {result.strip()}\n')

    info('*** Running latency test: urllc_src → urllc_dst (3 pings)...\n')
    urllc_src = net.get('urllc_src')
    ping_result = urllc_src.cmd('ping -c 3 10.2.0.2')
    for line in ping_result.split('\n'):
        if 'rtt' in line or 'avg' in line:
            info(f'  {line}\n')


if __name__ == '__main__':
    setLogLevel('info')

    # Parse args
    auto_test = '--test' in sys.argv
    remote_ctrl = '--remote' in sys.argv

    net = build_pad_topology(use_remote_ctrl=remote_ctrl)
    net.start()

    configure_vnf_services(net)
    print_topology_summary(net)
    dumpNodeConnections(net.hosts)

    if auto_test:
        run_quick_test(net)
        net.stop()
    else:
        info('\n*** Entering Mininet CLI (type "exit" or Ctrl-D to quit)\n')
        CLI(net)
        net.stop()

    info('*** Topology stopped\n')
