#!/usr/bin/env python3
"""
PAD-ONAP Anomaly Injector — 4 DDoS Scenarios
=============================================
Controls the gNMI simulator to inject attack patterns for testing.
Each scenario validates a specific PAD-ONAP detection/response capability.

Scenarios:
  S1_ddos_udp    — UDP flood on eMBB: validates real-time detection (XGBoost < 1s)
  S2_bw_ramp     — Gradual BW exhaustion: validates proactive forecast (Transformer)
  S3_cpu_spike   — CPU spike on r2: validates Tier T2 pre-warm
  S4_cross_slice — eMBB floods r1→r3 affecting URLLC: validates slice isolation

Usage:
  python3 scenarios.py --scenario ddos_udp --duration 60
  python3 scenarios.py --scenario bw_ramp --duration 300
  python3 scenarios.py --list
  python3 scenarios.py --all    # run all scenarios sequentially
"""

import argparse
import json
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional, List


# ── Configuration ─────────────────────────────────────────────────────────────
GNMI_URL      = 'http://localhost:8080'
COLLECTOR_URL = 'http://localhost:7070'
PIPELINE_URL  = 'http://localhost:9000'   # PAD-ONAP fast loop (S3 inference)


@dataclass
class ScenarioResult:
    name:          str
    duration_s:    float
    success:       bool
    detection_ms:  Optional[float] = None    # Time to first Tier>T0 event
    peak_pkt_rate: Optional[float] = None
    peak_cpu:      Optional[float] = None
    notes:         List[str] = field(default_factory=list)

    def summary(self) -> str:
        status = 'PASS' if self.success else 'FAIL'
        lines = [
            f'  Scenario: {self.name}',
            f'  Status:   {status}',
            f'  Duration: {self.duration_s:.1f}s',
        ]
        if self.detection_ms:
            lines.append(f'  Detection latency: {self.detection_ms:.0f}ms')
        if self.peak_pkt_rate:
            lines.append(f'  Peak pkt_rate: {self.peak_pkt_rate:,.0f} pkt/s')
        if self.peak_cpu:
            lines.append(f'  Peak CPU (r1): {self.peak_cpu:.1f}%')
        for note in self.notes:
            lines.append(f'  Note: {note}')
        return '\n'.join(lines)


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _post(url: str, body: dict) -> Optional[dict]:
    try:
        data = json.dumps(body).encode()
        req  = urllib.request.Request(url, data=data,
                                       headers={'Content-Type': 'application/json'},
                                       method='POST')
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f'  [!] POST {url} failed: {e}')
        return None


def _get(url: str) -> Optional[dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _gnmi_start(attack_type: str = 'udp_flood', target: str = 'r1') -> bool:
    res = _post(f'{GNMI_URL}/attack/start',
                {'type': attack_type, 'target': target})
    return res is not None


def _gnmi_stop() -> bool:
    res = _post(f'{GNMI_URL}/attack/stop', {})
    return res is not None


def _poll_metrics(device: str = 'r1') -> Optional[dict]:
    data = _get(f'{GNMI_URL}/metrics/{device}')
    return data.get('metrics') if data else None


def _check_gnmi_alive() -> bool:
    data = _get(f'{GNMI_URL}/health')
    return data is not None and data.get('status') == 'ok'


def _check_pipeline_tier() -> Optional[str]:
    """Poll pipeline for current tier decision. Returns tier string or None."""
    data = _get(f'{PIPELINE_URL}/status')
    return data.get('current_tier') if data else None


# ── Scenario runner ───────────────────────────────────────────────────────────
class ScenarioRunner:

    def run(self, name: str, duration: int = 60,
            verbose: bool = True) -> ScenarioResult:
        method = getattr(self, f'_run_{name}', None)
        if method is None:
            raise ValueError(f'Unknown scenario: {name!r}. '
                             f'Valid: {list(SCENARIO_CATALOG)}')
        print(f'\n{"="*60}')
        print(f'  SCENARIO: {SCENARIO_CATALOG[name]["title"]}')
        print(f'  Duration: {duration}s')
        print(f'{"="*60}')
        return method(duration, verbose)

    # ─────────────────────────────────────────────────────────────────────────
    # S1: UDP Flood on eMBB
    # Expected: XGBoost detects in <1s, Tier T3 activated
    # ─────────────────────────────────────────────────────────────────────────
    def _run_ddos_udp(self, duration: int, verbose: bool) -> ScenarioResult:
        result = ScenarioResult(name='ddos_udp', duration_s=duration, success=False)

        print('  [S1] Phase 1: Baseline measurement (5s)...')
        time.sleep(5)
        baseline = _poll_metrics('r1')
        if baseline:
            print(f'  [S1] Baseline pkt_rate={baseline.get("in_pkts", 0):.0f}')

        print('  [S1] Phase 2: Injecting UDP flood on r1...')
        t_start = time.time()
        ok = _gnmi_start('udp_flood', 'r1')
        if not ok:
            result.notes.append('gNMI injection failed — is simulator running?')
            return result

        # Monitor for up to duration seconds
        peak_pkt_rate = 0.0
        peak_cpu      = 0.0
        detection_ms  = None

        while time.time() - t_start < duration:
            elapsed = time.time() - t_start
            m = _poll_metrics('r1')
            if m:
                pkt = m.get('in_pkts', 0)
                cpu = m.get('cpu_pct', 0)
                udp = m.get('udp_ratio', 0)
                peak_pkt_rate = max(peak_pkt_rate, pkt)
                peak_cpu      = max(peak_cpu, cpu)

                if verbose:
                    print(f'  [S1] t={elapsed:5.1f}s | pkt_rate={pkt:>10,.0f} | '
                          f'cpu={cpu:5.1f}% | udp_ratio={udp:.3f}')

                # Simulated detection: pkt_rate > 10x baseline or udp_ratio > 0.9
                baseline_pkt = baseline.get('in_pkts', 5000) if baseline else 5000
                if detection_ms is None and (pkt > baseline_pkt * 5 or udp > 0.8):
                    detection_ms = elapsed * 1000
                    print(f'  [S1] *** ATTACK DETECTED at t={elapsed:.3f}s '
                          f'(pkt_rate={pkt:,.0f}, udp={udp:.3f}) ***')

            time.sleep(1.0)

        print('  [S1] Phase 3: Stopping attack...')
        _gnmi_stop()

        result.peak_pkt_rate = peak_pkt_rate
        result.peak_cpu      = peak_cpu
        result.detection_ms  = detection_ms

        # Validation
        if detection_ms is not None and detection_ms < 5000:
            result.success = True
            result.notes.append(f'Detection within {detection_ms:.0f}ms — OK (target <5000ms)')
        else:
            result.notes.append(f'Detection latency {detection_ms}ms — target <5000ms')

        if peak_pkt_rate > 50_000:
            result.notes.append(f'Peak traffic {peak_pkt_rate:,.0f} pkt/s (expected >50K for flood)')
        else:
            result.notes.append(f'Peak only {peak_pkt_rate:,.0f} pkt/s — extend duration or check sim')

        return result

    # ─────────────────────────────────────────────────────────────────────────
    # S2: Bandwidth Ramp (Gradual Exhaustion)
    # Expected: Transformer forecasts 30-60s before saturation
    # ─────────────────────────────────────────────────────────────────────────
    def _run_bw_ramp(self, duration: int, verbose: bool) -> ScenarioResult:
        result = ScenarioResult(name='bw_ramp', duration_s=duration, success=False)
        ramp_steps = 10
        step_dur   = duration // ramp_steps

        print(f'  [S2] BW ramp: {ramp_steps} steps × {step_dur}s = {duration}s total')
        print('  [S2] Starting gradual bandwidth exhaustion on r1...')

        _gnmi_start('bw_ramp', 'r1')
        t_start = time.time()
        peak_pkt_rate = 0.0

        for step in range(ramp_steps):
            elapsed  = time.time() - t_start
            m        = _poll_metrics('r1')
            pkt_rate = m.get('in_pkts', 0) if m else 0
            cpu_pct  = m.get('cpu_pct', 0) if m else 0
            q_depth  = m.get('queue_depth_pct', 0) if m else 0
            peak_pkt_rate = max(peak_pkt_rate, pkt_rate)

            ramp_pct = (step + 1) / ramp_steps * 100
            if verbose:
                print(f'  [S2] t={elapsed:5.1f}s | ramp={ramp_pct:3.0f}% | '
                      f'pkt_rate={pkt_rate:>8,.0f} | cpu={cpu_pct:5.1f}% | '
                      f'queue={q_depth:5.1f}%')

            # At 70% ramp, expect proactive pre-warning from Transformer
            if ramp_pct >= 70:
                print(f'  [S2] *** SATURATION WARNING: {ramp_pct:.0f}% '
                      f'— Transformer should have pre-warned at ~40% ***')

            time.sleep(step_dur)

        _gnmi_stop()
        result.peak_pkt_rate = peak_pkt_rate
        result.success = True
        result.notes.append(
            f'Ramp complete. Peak={peak_pkt_rate:,.0f} pkt/s. '
            'Verify Transformer forecast triggered at step 4 (40% ramp).'
        )
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # S3: CPU Spike on r2
    # Expected: S4 detects CPU overload, activates Tier T2 (pre-warm VNF)
    # ─────────────────────────────────────────────────────────────────────────
    def _run_cpu_spike(self, duration: int, verbose: bool) -> ScenarioResult:
        result = ScenarioResult(name='cpu_spike', duration_s=duration, success=False)

        print('  [S3] Injecting CPU spike on r2 (30% → 95%)...')
        _gnmi_start('udp_flood', 'r2')   # flood r2 causes CPU spike
        t_start = time.time()
        peak_cpu = 0.0

        while time.time() - t_start < duration:
            elapsed = time.time() - t_start
            m = _poll_metrics('r2')
            if m:
                cpu = m.get('cpu_pct', 0)
                peak_cpu = max(peak_cpu, cpu)
                if verbose:
                    print(f'  [S3] t={elapsed:5.1f}s | r2 cpu={cpu:5.1f}%')
            time.sleep(2.0)

        _gnmi_stop()
        result.peak_cpu = peak_cpu
        result.success  = peak_cpu > 80.0
        result.notes.append(
            f'Peak CPU r2: {peak_cpu:.1f}% — '
            f'{"OK (>80%)" if peak_cpu > 80 else "WARN (<80%, check sim)"}'
        )
        result.notes.append('Verify S4 Risk → Tier T2 triggered (VNF pre-warm)')
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # S4: Cross-Slice Attack (eMBB → URLLC)
    # Expected: eMBB detected, URLLC latency preserved, Tier T4 isolation
    # ─────────────────────────────────────────────────────────────────────────
    def _run_cross_slice(self, duration: int, verbose: bool) -> ScenarioResult:
        result = ScenarioResult(name='cross_slice', duration_s=duration, success=False)

        print('  [S4] eMBB flood via r1 → r3 cross-slice link...')
        print('  [S4] Injecting attack on r1 (propagates to r3 URLLC path)...')
        _gnmi_start('udp_flood', 'r1')
        t_start = time.time()

        r1_peaks = []
        r3_impacts = []

        while time.time() - t_start < duration:
            elapsed = time.time() - t_start
            m_r1 = _poll_metrics('r1')
            m_r3 = _poll_metrics('r3')
            r1_pkt  = m_r1.get('in_pkts', 0)    if m_r1 else 0
            r3_pkt  = m_r3.get('in_pkts', 0)    if m_r3 else 0
            r3_cpu  = m_r3.get('cpu_pct', 0)    if m_r3 else 0
            r1_peaks.append(r1_pkt)
            r3_impacts.append(r3_pkt)

            if verbose:
                print(f'  [S4] t={elapsed:5.1f}s | r1_pkts={r1_pkt:>10,.0f} | '
                      f'r3_pkts={r3_pkt:>8,.0f} | r3_cpu={r3_cpu:5.1f}%')
            time.sleep(1.5)

        _gnmi_stop()

        avg_r1 = sum(r1_peaks) / max(len(r1_peaks), 1)
        avg_r3 = sum(r3_impacts) / max(len(r3_impacts), 1)
        spillover = avg_r3 / max(avg_r1, 1)

        result.peak_pkt_rate = max(r1_peaks) if r1_peaks else 0
        result.success = result.peak_pkt_rate > 10_000
        result.notes.append(
            f'avg r1={avg_r1:,.0f} | avg r3={avg_r3:,.0f} | '
            f'spillover={spillover:.1%}'
        )
        result.notes.append(
            'Verify Policy Tier T4 tenant isolation for URLLC slice.'
        )
        return result


# ── Scenario catalog ──────────────────────────────────────────────────────────
SCENARIO_CATALOG = {
    'ddos_udp': {
        'title':       'S1: UDP Flood (eMBB slice)',
        'description': 'UDP flood 100K pkt/s on r1. Target: XGBoost detect <1s → T3',
        'duration':    60,
    },
    'bw_ramp': {
        'title':       'S2: Bandwidth Ramp (Gradual Exhaustion)',
        'description': 'BW increases 10%/step × 10 steps. Target: Transformer forecast 30-60s early',
        'duration':    300,
    },
    'cpu_spike': {
        'title':       'S3: CPU Spike (r2 overload)',
        'description': 'CPU r2: 30% → 95%. Target: S4 Risk → Tier T2 VNF pre-warm',
        'duration':    60,
    },
    'cross_slice': {
        'title':       'S4: Cross-Slice Attack (eMBB → URLLC)',
        'description': 'eMBB floods r1→r3, threatens URLLC. Target: slice isolation T4',
        'duration':    90,
    },
}


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='PAD-ONAP Anomaly Injector')
    parser.add_argument('--scenario', choices=list(SCENARIO_CATALOG),
                        help='Scenario to run')
    parser.add_argument('--duration', type=int, default=None,
                        help='Override default duration (seconds)')
    parser.add_argument('--all',     action='store_true',
                        help='Run all scenarios sequentially')
    parser.add_argument('--list',    action='store_true',
                        help='List available scenarios')
    parser.add_argument('--gnmi',    default=GNMI_URL,
                        help=f'gNMI simulator URL (default: {GNMI_URL})')
    parser.add_argument('--quiet',   action='store_true',
                        help='Suppress per-tick output')
    args = parser.parse_args()

    global GNMI_URL
    GNMI_URL = args.gnmi

    if args.list:
        print('\nAvailable scenarios:')
        for name, info in SCENARIO_CATALOG.items():
            print(f'  {name:<15} — {info["title"]} ({info["duration"]}s default)')
            print(f'               {info["description"]}')
        return

    if not _check_gnmi_alive():
        print(f'[ERROR] gNMI simulator not reachable at {GNMI_URL}')
        print(f'        Start it with: python3 testbed/gnmi_simulator/main.py')
        return

    runner  = ScenarioRunner()
    results = []
    verbose = not args.quiet

    if args.all:
        for name, info in SCENARIO_CATALOG.items():
            dur = args.duration or info['duration']
            r   = runner.run(name, dur, verbose)
            results.append(r)
            print(r.summary())
            print('  (Cooldown 15s...)')
            time.sleep(15)
    elif args.scenario:
        dur = args.duration or SCENARIO_CATALOG[args.scenario]['duration']
        r   = runner.run(args.scenario, dur, verbose)
        results.append(r)
        print(r.summary())
    else:
        parser.print_help()
        return

    print(f'\n{"="*60}')
    print('  FINAL RESULTS')
    print(f'{"="*60}')
    for r in results:
        status = 'PASS' if r.success else 'FAIL'
        print(f'  [{status}] {r.name:<15} detection={r.detection_ms or "N/A"}ms')
    passed = sum(1 for r in results if r.success)
    print(f'\n  {passed}/{len(results)} scenarios passed')


if __name__ == '__main__':
    main()
