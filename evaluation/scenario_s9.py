#!/usr/bin/env python3
"""
Adaptive Attacker Scenario S9 — Low-and-Slow Attack
=====================================================
S9: Attacker knows the rate-limit threshold (pkt_rate > 3000 → T2, > 10000 → T3)
and deliberately stays BELOW the threshold (pkt_rate ≈ 2500 pkt/s) for 60 windows,
then gradually ramps to 3500 pkt/s while manipulating syn_ratio.

Tests Hypothesis:
  - Can the Transformer+LSTM forecast detect the sub-threshold trend?
  - Does the orchestrator fire T2 proactively before the attack breaches threshold?

Expected result: PASS if T2 proactive fires, FAIL if attack goes undetected.

Add to evaluation/scenarios.py and run via:
    python -m evaluation.scenarios --scenario S9
"""
from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logger = logging.getLogger('scenario_s9')


def _low_and_slow_features(n: int, intensity: float = 1.0, seed: int = 9) -> np.ndarray:
    """
    Low-and-slow SYN attack: pkt_rate stays BELOW 3000 threshold,
    but syn_ratio, src_ip_entropy show attack characteristics.
    """
    rng = np.random.default_rng(seed)
    from evaluation.scenarios import _normal_features
    X = _normal_features(n, seed)

    # pkt_rate: deliberately sub-threshold (2000–2800 pkt/s)
    X[:, 0] = rng.uniform(2000, 2800, n) * intensity
    # syn_ratio: elevated but not extreme (0.3–0.5, below 0.60 threshold)
    X[:, 9] = rng.uniform(0.30, 0.50, n)
    # src_ip_entropy: slightly lower than normal (spoofing pattern)
    X[:, 2] = rng.uniform(0.9, 1.8, n)
    # proto_dist_tcp: high (SYN flood is TCP)
    X[:, 6] = rng.uniform(0.75, 0.95, n)
    X[:, 7] = rng.uniform(0.01, 0.10, n)
    return X


def _slow_ramp_features(n: int, seed: int = 9) -> np.ndarray:
    """
    Slow ramp from sub-threshold to just-above-threshold over n windows.
    pkt_rate goes from 2500 → 3500 linearly.
    """
    rng = np.random.default_rng(seed)
    from evaluation.scenarios import _normal_features, _syn_flood_features
    base   = _low_and_slow_features(1, seed=seed)[0]
    target = _syn_flood_features(1, intensity=0.5, seed=seed)[0]
    X = np.array([
        base + (target - base) * (i / max(n - 1, 1))
        for i in range(n)
    ], dtype=np.float32)
    return X


def build_s9_scenario():
    """Build scenario S9 and inject it into evaluation.scenarios.SCENARIOS."""
    from evaluation.scenarios import ScenarioSpec, SCENARIOS, _normal_features

    # Check if S9 already exists
    if any('S9' in s.name for s in SCENARIOS):
        logger.info('S9 already in SCENARIOS')
        return

    n_norm = 30
    s9 = ScenarioSpec(
        name        = 'S9_adaptive_low_and_slow',
        description = (
            'Attacker stays below threshold for 60 windows (low-and-slow), '
            'then ramps to just above T2 threshold. '
            'Tests forecast detection of sub-threshold attack trend.'
        ),
        windows     = np.vstack([
            _normal_features(n_norm),                          # 30 normal lead-in
            _low_and_slow_features(60),                        # 60 sub-threshold attack
            _slow_ramp_features(20),                           # 20-window ramp to threshold
            _normal_features(n_norm),                          # 30 cool-down
        ]),
        expected_max_tier = 3,
        expected_min_tier = 1,   # must detect at LEAST T1 (if forecast catches it → T2)
    )
    SCENARIOS.append(s9)
    logger.info('S9 added: %d windows', len(s9.windows))
    return s9


def run_s9(model_dir: str, data_dir: str, out_dir: Path) -> dict:
    """Run S9 through the full AI orchestrator and return results."""
    from pipeline.s4_orchestration.orchestrator import Orchestrator
    from evaluation.scenarios import run_scenario, SCENARIOS

    build_s9_scenario()
    s9 = next(s for s in SCENARIOS if 'S9' in s.name)

    orch = Orchestrator(
        model_dir    = model_dir,
        data_dir     = data_dir,
        device       = 'auto',
        shap_enabled = False,
        latency_port = 9305,
        eval_mode    = True,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    result = run_scenario(s9, orch, out_dir)
    rd = asdict(result)

    # Save to summary
    summary_path = out_dir / 'S9_summary.json'
    summary_path.write_text(json.dumps(rd, indent=2))
    logger.info('[OK] S9 result: %s  max_tier=T%d  proactive=%d',
                rd['pass_fail'], rd['max_tier_reached'], rd['proactive_count'])

    # Print interpretation
    pro = rd['proactive_count']
    if pro > 0:
        print('\n[S9 RESULT] Forecast DETECTED low-and-slow attack proactively!')
        print(f'  Proactive windows: {pro}')
        print(f'  T2 P50: {rd["tier2_latency_ms"]["p50"]} ms')
        print('  --> Hypothesis CONFIRMED: Transformer catches sub-threshold trends')
    else:
        print('\n[S9 RESULT] No proactive detection -- low-and-slow evaded forecast.')
        print(f'  Max tier reached: T{rd["max_tier_reached"]}')
        print('  --> Documented limitation: purely sub-threshold attack is evasive')

    return rd


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(description='S9 adaptive low-and-slow attack scenario')
    parser.add_argument('--model-dir', default=str(_ROOT / 'pad_onap_v3' / 'models'))
    parser.add_argument('--data-dir',  default=str(_ROOT / 'pad_onap_v3' / 'processed'))
    parser.add_argument('--out-dir',   default=str(_ROOT / 'evaluation' / 'results'))
    args = parser.parse_args()

    run_s9(args.model_dir, args.data_dir, Path(args.out_dir))
