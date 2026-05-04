#!/usr/bin/env python3
"""
Fat-Tree k=4 Data-Center Topology (Al-Fares et al.)
===================================================
Standard data-center benchmark used in the thesis to demonstrate that the
PAD-ONAP orchestrator scales beyond the 3-slice PAD topology.

k = 4  →  4 pods · 4 edge + 4 aggregation + 4 core switches = 20 switches
              (k/2)^2 core = 4 core; k pods × k/2 edge × k/2 hosts = 16 hosts

Layout:
                core1 core2 core3 core4
                  \\ / \\ / \\ / \\ /
    ┌──── pod 0 ────┐ ┌──── pod 1 ────┐ ┌──── pod 2 ────┐ ┌──── pod 3 ────┐
     agg  agg        agg  agg          agg  agg          agg  agg
      │    │          │    │            │    │            │    │
     edge edge       edge edge         edge edge         edge edge
     │ │   │ │       │ │   │ │         │ │   │ │         │ │   │ │
     h0 h1 h2 h3     h4 h5 h6 h7       h8 h9 h10 h11    h12 h13 h14 h15

Every host-to-host path has (k/2)^2 = 4 equal-cost paths through the core —
this is what makes fat-tree interesting as a DCN benchmark (multipath,
bisection bandwidth, and traffic steering all become non-trivial).

Attacker / victim mapping used by evaluation scenarios:
    attacker:  h0   (pod 0, edge 0)
    victim:    h15  (pod 3, edge 1)
    bottleneck link crosses 3 pods → exercises core-layer steering

Usage:
    sudo python3 testbed/mininet/fat_tree_topology.py            # CLI
    sudo python3 testbed/mininet/fat_tree_topology.py --test     # pingall+iperf
    sudo python3 testbed/mininet/fat_tree_topology.py --k 4 --remote
"""

from __future__ import annotations

import argparse
import sys
import time

from mininet.net  import Mininet
from mininet.node import Controller, OVSSwitch, RemoteController, OVSController
from mininet.link import TCLink
from mininet.log  import setLogLevel, info
from mininet.cli  import CLI


HOST_LINK_BW_MBPS = 1000   # edge ↔ host
EDGE_LINK_BW_MBPS = 1000   # edge ↔ agg
CORE_LINK_BW_MBPS = 10000  # agg ↔ core  (10 GbE)
LINK_DELAY        = '0.1ms'


def _dpid(prefix: int, a: int, b: int = 0, c: int = 0) -> str:
    """Build a 16-char hex DPID like 0x01_00_00_0000 for readability."""
    return f'{prefix:02x}{a:02x}{b:02x}{c:02x}{0:08x}'


def build_fat_tree(k: int = 4, use_remote_ctrl: bool = False) -> Mininet:
    assert k % 2 == 0, "k must be even"
    assert k >= 2,    "k must be >= 2"

    n_core        = (k // 2) ** 2
    n_pods        = k
    agg_per_pod   = k // 2
    edge_per_pod  = k // 2
    hosts_per_ed  = k // 2

    info(f'*** Building fat-tree k={k}  '
         f'(core={n_core}  agg={n_pods*agg_per_pod}  edge={n_pods*edge_per_pod}  '
         f'hosts={n_pods*edge_per_pod*hosts_per_ed})\n')

    # Chế độ Standalone: Không cần controller binary, switch tự học MAC
    net = Mininet(
        controller = RemoteController if use_remote_ctrl else None,
        switch     = OVSSwitch,
        link       = TCLink,
        autoSetMacs = True,
    )
    if use_remote_ctrl:
        net.addController('c0', ip='127.0.0.1', port=6633)

    # ── Core switches ────────────────────────────────────────────────────────
    core_sw = []
    for i in range(n_core):
        s = net.addSwitch(f'c{i+1}', protocols='OpenFlow13',
                          dpid=_dpid(0x10, i), failMode='standalone')
        core_sw.append(s)

    # ── Pods ─────────────────────────────────────────────────────────────────
    all_hosts = []
    for p in range(n_pods):
        agg_sw  = []
        edge_sw = []
        for a in range(agg_per_pod):
            s = net.addSwitch(f'a{p}_{a}', protocols='OpenFlow13',
                              dpid=_dpid(0x20, p, a), failMode='standalone')
            agg_sw.append(s)
        for e in range(edge_per_pod):
            s = net.addSwitch(f'e{p}_{e}', protocols='OpenFlow13',
                              dpid=_dpid(0x30, p, e), failMode='standalone')
            edge_sw.append(s)

        # edge ↔ hosts
        for e_idx, edge in enumerate(edge_sw):
            for h in range(hosts_per_ed):
                host_id = len(all_hosts)
                # /8 prefix: all hosts share one broadcast domain so OVS
                # standalone MAC-learning forwards cross-pod traffic without
                # needing a gateway. Switch/link layout (fat-tree) unchanged.
                ip = f'10.{p}.{e_idx}.{h+1}/8'
                host = net.addHost(f'h{host_id}', ip=ip)
                net.addLink(host, edge,
                            bw=HOST_LINK_BW_MBPS, delay=LINK_DELAY)
                all_hosts.append(host)

        # edge ↔ agg (full bipartite within pod)
        for edge in edge_sw:
            for agg in agg_sw:
                net.addLink(edge, agg,
                            bw=EDGE_LINK_BW_MBPS, delay=LINK_DELAY)

        # agg ↔ core: agg a connects to cores [a*(k/2) .. a*(k/2)+k/2)
        for a_idx, agg in enumerate(agg_sw):
            for j in range(k // 2):
                core_idx = a_idx * (k // 2) + j
                net.addLink(agg, core_sw[core_idx],
                            bw=CORE_LINK_BW_MBPS, delay=LINK_DELAY)

    info(f'*** Total hosts: {len(all_hosts)}\n')
    return net


def attacker_victim(net: Mininet):
    """Return (attacker, victim) host pair with maximum hop count."""
    hosts = net.hosts
    return hosts[0], hosts[-1]


def run_quick_test(net: Mininet):
    info('*** pingall...\n')
    loss = net.pingAll(timeout='2')
    info(f'*** pingall loss: {loss:.1f}%\n')

    atk, vic = attacker_victim(net)
    info(f'*** iperf {atk.name} → {vic.name} (3s)...\n')
    vic.cmd('iperf -s &')
    time.sleep(0.5)
    out = atk.cmd(f'iperf -c {vic.IP()} -t 3 -f m')
    info(f'  {out.strip()}\n')
    vic.cmd('kill %iperf 2>/dev/null')


def print_summary(net: Mininet, k: int):
    n_core  = (k // 2) ** 2
    n_agg   = k * (k // 2)
    n_edge  = k * (k // 2)
    n_hosts = k * (k // 2) * (k // 2)
    print('\n' + '='*64)
    print(f'  Fat-Tree k={k}  —  DCN benchmark topology')
    print('='*64)
    print(f'  Core switches:  {n_core}')
    print(f'  Agg  switches:  {n_agg}  ({k} pods × {k//2}/pod)')
    print(f'  Edge switches:  {n_edge}  ({k} pods × {k//2}/pod)')
    print(f'  Hosts:          {n_hosts}  ({k//2}/edge)')
    print(f'  Equal-cost paths per host pair: {(k//2)**2}')
    print(f'  Attacker = {net.hosts[0].name}  Victim = {net.hosts[-1].name}')
    print('='*64 + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--k',      type=int, default=4)
    parser.add_argument('--test',   action='store_true')
    parser.add_argument('--remote', action='store_true')
    args = parser.parse_args()

    setLogLevel('info')
    net = build_fat_tree(k=args.k, use_remote_ctrl=args.remote)
    net.start()
    print_summary(net, args.k)

    if args.test:
        run_quick_test(net)
        net.stop()
    else:
        info('*** CLI (exit or Ctrl-D to quit)\n')
        CLI(net)
        net.stop()
