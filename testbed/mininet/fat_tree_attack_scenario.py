#!/usr/bin/env python3
"""
Fat-Tree k=4 Attack Scenario — PAD-ONAP Testbed
=================================================
Injects a UDP flood from h0 → h15 (cross-pod attack path) and measures
the time for SFC (Service Function Chain) rules to propagate across
3 pod layers. Also measures latency for same-pod vs cross-pod traffic
steering, validating the fat-tree DCN architecture claim in the thesis.

Prerequisites (Linux only):
    sudo apt-get install hping3 iperf3 tshark
    pip install mininet

Usage:
    sudo python3 testbed/mininet/fat_tree_attack_scenario.py
    sudo python3 testbed/mininet/fat_tree_attack_scenario.py --k 4 --duration 30
    sudo python3 testbed/mininet/fat_tree_attack_scenario.py --k 4 --duration 30 --remote

Output:
    testbed/logs/fat_tree_attack_<timestamp>.log   — per-event timing log
    testbed/logs/fat_tree_attack_<timestamp>.json  — machine-readable metrics
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Guard: must run as root on Linux
if sys.platform != 'linux' or os.geteuid() != 0:
    print('[ERROR] This script must be run as root on Linux: sudo python3 fat_tree_attack_scenario.py')
    sys.exit(1)

from mininet.net   import Mininet
from mininet.node  import Controller, OVSSwitch, RemoteController
from mininet.link  import TCLink
from mininet.log   import setLogLevel, info
from mininet.cli   import CLI

# Add project root to path
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from testbed.mininet.fat_tree_topology import build_fat_tree, attacker_victim

logger = logging.getLogger('fat_tree_attack')

# ── Log directory ──────────────────────────────────────────────────────────────
LOG_DIR = _ROOT / 'testbed' / 'logs'


# ─────────────────────────────────────────────────────────────────────────────
# Measurement helpers
# ─────────────────────────────────────────────────────────────────────────────

def measure_baseline_latency(net: Mininet, attacker, victim) -> dict:
    """Measure baseline RTT (no attack) between attacker and victim."""
    info('*** [Phase 1] Baseline ping: h0 → h15 (no attack)\n')
    result = attacker.cmd(f'ping -c 10 -i 0.2 {victim.IP()}')
    lines  = result.strip().splitlines()

    rtt_line = next((l for l in lines if 'rtt' in l or 'round-trip' in l), '')
    # parse "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.05 ms"
    rtt = {}
    if '=' in rtt_line:
        parts = rtt_line.split('=')[-1].strip().split('/')
        keys  = ['min_ms', 'avg_ms', 'max_ms', 'mdev_ms']
        rtt   = {k: float(v) for k, v in zip(keys, parts[:4])}
    loss_line = next((l for l in lines if 'packet loss' in l), '')
    loss_pct  = 0.0
    if 'packet loss' in loss_line:
        try:
            loss_pct = float(loss_line.split('%')[0].split()[-1])
        except ValueError:
            pass

    info(f'    RTT: {rtt}  loss={loss_pct}%\n')
    return {'phase': 'baseline', 'rtt': rtt, 'loss_pct': loss_pct}


def inject_udp_flood(attacker, victim, duration_s: int = 20) -> float:
    """
    Inject UDP flood from attacker → victim using hping3.
    Returns the timestamp when the flood started.
    """
    info(f'*** [Phase 2] UDP flood: {attacker.name} → {victim.name} for {duration_s}s\n')
    t_start = time.time()
    # hping3: UDP mode, flood rate, port 80, duration via --count approximation
    # Run in background; we time it externally
    pkt_count = duration_s * 1000   # ~1 kpps
    attacker.cmd(
        f'hping3 --udp -p 80 --flood --count {pkt_count} {victim.IP()} &'
    )
    return t_start


def measure_sfc_propagation(net: Mininet, attacker, victim, t_attack_start: float) -> dict:
    """
    Poll victim-side packet counter until the SFC rate-limit rule takes effect.
    Uses tc (traffic control) stats on the victim's ingress interface.

    Returns timing metrics: time_to_sfc_rule_s, windows_observed, etc.
    """
    info('*** [Phase 3] Measuring SFC rule propagation time...\n')

    # Get victim's interface name (connected to edge switch)
    vic_intf = victim.intf().name

    samples = []
    poll_interval = 0.5   # seconds
    max_polls     = 60    # up to 30 s

    prev_bytes = 0
    rule_active_t = None

    for i in range(max_polls):
        time.sleep(poll_interval)

        # Read RX bytes via /proc/net/dev
        try:
            proc = victim.cmd(f'cat /proc/net/dev | grep {vic_intf}')
            fields = proc.strip().split()
            rx_bytes = int(fields[1]) if len(fields) > 1 else 0
        except (ValueError, IndexError):
            rx_bytes = 0

        rx_rate = (rx_bytes - prev_bytes) / poll_interval if prev_bytes else 0
        prev_bytes = rx_bytes
        t_elapsed = time.time() - t_attack_start

        samples.append({
            'elapsed_s': round(t_elapsed, 2),
            'rx_bytes':  rx_bytes,
            'rx_rate_Bps': round(rx_rate, 1),
        })

        info(f'    t+{t_elapsed:.1f}s  rx_rate={rx_rate/1e6:.2f} Mbps\n')

        # Detect SFC rule: rate drops significantly (>50% drop from flood peak)
        if i > 4 and rule_active_t is None:
            peak_rate = max(s['rx_rate_Bps'] for s in samples)
            if peak_rate > 0 and rx_rate < peak_rate * 0.5:
                rule_active_t = time.time()
                info(f'    [✓] SFC rule detected at t+{t_elapsed:.2f}s '
                     f'(rate dropped {rx_rate/1e6:.2f} Mbps ← peak {peak_rate/1e6:.2f} Mbps)\n')
                break

    propagation_s = (rule_active_t - t_attack_start) if rule_active_t else None
    return {
        'phase': 'sfc_propagation',
        'sfc_rule_detected': rule_active_t is not None,
        'propagation_s': round(propagation_s, 3) if propagation_s else None,
        'samples': samples,
    }


def measure_cross_pod_vs_same_pod(net: Mininet) -> dict:
    """
    Compare latency for same-pod vs cross-pod host pairs.

    Same-pod:  h0 → h1 (both in pod 0)
    Cross-pod: h0 → h15 (pod 0 → pod 3, traverses core layer)
    """
    info('*** [Phase 4] Same-pod vs cross-pod latency comparison\n')

    h0  = net.get('h0')
    h1  = net.get('h1')    # same pod as h0 (pod 0)
    h15 = net.get('h15')   # different pod (pod 3)

    def _ping(src, dst, count=20):
        out = src.cmd(f'ping -c {count} -i 0.05 {dst.IP()}')
        for line in out.splitlines():
            if 'rtt' in line or 'round-trip' in line:
                parts = line.split('=')[-1].strip().split('/')
                if len(parts) >= 2:
                    return float(parts[1])   # avg ms
        return None

    same_pod_rtt  = _ping(h0, h1)
    cross_pod_rtt = _ping(h0, h15)

    info(f'    Same-pod  h0→h1:  avg RTT = {same_pod_rtt} ms\n')
    info(f'    Cross-pod h0→h15: avg RTT = {cross_pod_rtt} ms\n')

    overhead_ms = None
    if same_pod_rtt and cross_pod_rtt:
        overhead_ms = round(cross_pod_rtt - same_pod_rtt, 3)
        info(f'    Cross-pod overhead: {overhead_ms:.3f} ms '
             f'({overhead_ms / same_pod_rtt * 100:.1f}% vs same-pod)\n')

    return {
        'phase': 'pod_latency_comparison',
        'same_pod_avg_rtt_ms':  same_pod_rtt,
        'cross_pod_avg_rtt_ms': cross_pod_rtt,
        'cross_pod_overhead_ms': overhead_ms,
        'src_host': 'h0 (pod 0)',
        'same_pod_dst': 'h1 (pod 0)',
        'cross_pod_dst': 'h15 (pod 3)',
    }


def run_iperf_bandwidth(net: Mininet, attacker, victim) -> dict:
    """Measure baseline iperf3 bandwidth h0 → h15."""
    info('*** [Phase 5] iperf3 bandwidth: h0 → h15 (10s)\n')
    victim.cmd('iperf3 -s -D')
    time.sleep(0.5)
    out = attacker.cmd(f'iperf3 -c {victim.IP()} -t 10 -J')
    victim.cmd('pkill iperf3 2>/dev/null')

    try:
        data = json.loads(out)
        bw_bps = data.get('end', {}).get('sum_received', {}).get('bits_per_second', 0)
        retransmits = data.get('end', {}).get('sum_sent', {}).get('retransmits', 0)
        return {
            'phase': 'iperf3_bandwidth',
            'bandwidth_Mbps': round(bw_bps / 1e6, 2),
            'retransmits': retransmits,
        }
    except json.JSONDecodeError:
        # Fallback: parse text output
        for line in out.splitlines():
            if 'receiver' in line and 'Mbits' in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if 'Mbit' in p and i > 0:
                        try:
                            return {'phase': 'iperf3_bandwidth',
                                    'bandwidth_Mbps': float(parts[i - 1]),
                                    'retransmits': 0}
                        except ValueError:
                            pass
    return {'phase': 'iperf3_bandwidth', 'bandwidth_Mbps': None, 'retransmits': None}


# ─────────────────────────────────────────────────────────────────────────────
# Main scenario
# ─────────────────────────────────────────────────────────────────────────────

def run_attack_scenario(k: int = 4, duration_s: int = 20,
                        use_remote_ctrl: bool = False,
                        interactive: bool = False) -> dict:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_json = LOG_DIR / f'fat_tree_attack_{ts}.json'

    info(f'*** Building fat-tree k={k} topology\n')
    net = build_fat_tree(k=k, use_remote_ctrl=use_remote_ctrl)
    net.start()

    info('*** Waiting for switches to converge (3s)\n')
    time.sleep(3)

    # Validate basic connectivity
    info('*** pingall (initial connectivity check)\n')
    loss = net.pingAll(timeout='2')
    info(f'    pingall packet loss: {loss:.1f}%\n')

    attacker, victim = attacker_victim(net)
    info(f'*** Attacker: {attacker.name} ({attacker.IP()})  '
         f'Victim: {victim.name} ({victim.IP()})\n')

    results = {
        'topology': {'k': k, 'n_hosts': len(net.hosts),
                     'attacker': attacker.name, 'victim': victim.name},
        'pingall_loss_pct': loss,
        'phases': [],
    }

    # Phase 1: baseline latency
    results['phases'].append(measure_baseline_latency(net, attacker, victim))

    # Phase 5: iperf3 bandwidth before attack
    results['phases'].append(run_iperf_bandwidth(net, attacker, victim))

    # Phase 4: same-pod vs cross-pod latency
    results['phases'].append(measure_cross_pod_vs_same_pod(net))

    # Phase 2+3: inject attack and measure SFC propagation
    t_start = inject_udp_flood(attacker, victim, duration_s=duration_s)
    sfc_result = measure_sfc_propagation(net, attacker, victim, t_attack_start=t_start)
    results['phases'].append(sfc_result)

    # Kill attacker flood
    attacker.cmd('pkill hping3 2>/dev/null')
    time.sleep(2)

    # Phase 5b: iperf3 bandwidth after attack
    info('*** [Phase 5b] iperf3 post-attack bandwidth\n')
    results['phases'].append(run_iperf_bandwidth(net, attacker, victim))

    # Save results
    log_json.write_text(json.dumps(results, indent=2))
    info(f'\n[✓] Results saved: {log_json}\n')

    # Summary
    print('\n' + '='*64)
    print(f'Fat-Tree k={k} Attack Scenario — Summary')
    print('='*64)
    for phase in results['phases']:
        p = phase.get('phase', '?')
        if p == 'baseline':
            rtt = phase.get('rtt', {})
            print(f'  Baseline RTT  h0→h15: avg={rtt.get("avg_ms","?")} ms  loss={phase["loss_pct"]}%')
        elif p == 'sfc_propagation':
            detected = phase.get('sfc_rule_detected')
            prop_s   = phase.get('propagation_s')
            print(f'  SFC propagation: detected={detected}  time={prop_s} s')
        elif p == 'pod_latency_comparison':
            print(f'  Same-pod RTT:  {phase.get("same_pod_avg_rtt_ms")} ms')
            print(f'  Cross-pod RTT: {phase.get("cross_pod_avg_rtt_ms")} ms')
            print(f'  Core-layer overhead: {phase.get("cross_pod_overhead_ms")} ms')
        elif p == 'iperf3_bandwidth':
            print(f'  iperf3: {phase.get("bandwidth_Mbps")} Mbps')
    print('='*64)
    print(f'Log: {log_json}')

    if interactive:
        info('*** CLI mode (exit or Ctrl-D to quit)\n')
        CLI(net)

    net.stop()
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    setLogLevel('info')
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(
        description='Fat-Tree k=4 UDP flood attack scenario with SFC rule propagation measurement')
    parser.add_argument('--k',          type=int,  default=4,    help='Fat-tree radix (default: 4)')
    parser.add_argument('--duration',   type=int,  default=20,   help='Attack duration in seconds')
    parser.add_argument('--remote',     action='store_true',     help='Use RemoteController (e.g. Ryu)')
    parser.add_argument('--interactive',action='store_true',     help='Open Mininet CLI after scenario')
    args = parser.parse_args()

    run_attack_scenario(
        k               = args.k,
        duration_s      = args.duration,
        use_remote_ctrl = args.remote,
        interactive     = args.interactive,
    )
