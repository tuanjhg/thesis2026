#!/usr/bin/env python3
"""
Multi-Seed Evaluation Runner
=============================
Runs all S1–S8 scenarios with N different random seeds and aggregates
mean ± std for each metric. Uses the real Orchestrator + AI models.

Usage:
    python -m evaluation.multi_seed_runner
    python -m evaluation.multi_seed_runner --seeds 42,43,44,45,46
    python -m evaluation.multi_seed_runner --seeds 42,43,44,45,46 --out-dir evaluation/results_multi_seed

Output:
    evaluation/results/multi_seed_summary.json   — machine-readable
    evaluation/results/multi_seed_table.md       — human-readable mean ± std table
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Dict

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

logger = logging.getLogger('multi_seed_runner')


# ─────────────────────────────────────────────────────────────────────────────
# Seed-parameterised scenario rebuild
# ─────────────────────────────────────────────────────────────────────────────

def _build_seeded_scenarios(seed: int):
    """
    Return a list of ScenarioSpec objects built with the given seed.
    We import and monkey-patch the module-level helpers so every stochastic
    call uses the requested seed as its base.
    """
    import importlib
    import evaluation.scenarios as sc_mod

    # Reload to get a fresh SCENARIOS list each time
    importlib.reload(sc_mod)

    # Override _normal_features default seed
    _orig_normal = sc_mod._normal_features
    _orig_udp    = sc_mod._udp_flood_features
    _orig_syn    = sc_mod._syn_flood_features
    _orig_http   = sc_mod._http_flood_features
    _orig_icmp   = sc_mod._icmp_amp_features

    def _patched_normal(n, s=None):
        return _orig_normal(n, seed=s if s is not None else seed)

    def _patched_udp(n, intensity=1.0, s=None):
        return _orig_udp(n, intensity=intensity, seed=s if s is not None else seed)

    def _patched_syn(n, intensity=1.0, s=None):
        return _orig_syn(n, intensity=intensity, seed=s if s is not None else seed)

    def _patched_http(n, s=None):
        return _orig_http(n, seed=s if s is not None else seed)

    def _patched_icmp(n, s=None):
        return _orig_icmp(n, seed=s if s is not None else seed)

    sc_mod._normal_features   = _patched_normal
    sc_mod._udp_flood_features = _patched_udp
    sc_mod._syn_flood_features = _patched_syn
    sc_mod._http_flood_features = _patched_http
    sc_mod._icmp_amp_features  = _patched_icmp

    # Rebuild scenarios with patched generators
    sc_mod.SCENARIOS.clear()
    sc_mod._build_scenarios()

    # Restore originals for safety
    sc_mod._normal_features    = _orig_normal
    sc_mod._udp_flood_features = _orig_udp
    sc_mod._syn_flood_features = _orig_syn
    sc_mod._http_flood_features = _orig_http
    sc_mod._icmp_amp_features  = _orig_icmp

    return list(sc_mod.SCENARIOS)


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_all_seeds(
    seeds:     List[int],
    model_dir: str,
    data_dir:  str,
    out_dir:   str,
    device:    str = 'auto',
) -> None:
    from pipeline.s4_orchestration.orchestrator import Orchestrator
    import evaluation.scenarios as sc_mod

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Metric accumulators: {scenario_name: {metric: [values across seeds]}}
    accum: Dict[str, Dict[str, List[float]]] = {}

    for seed_idx, seed in enumerate(seeds):
        logger.info(f'\n{"="*60}')
        logger.info(f'SEED {seed}  ({seed_idx+1}/{len(seeds)})')
        logger.info(f'{"="*60}')

        # Rebuild scenarios with this seed
        scenarios = _build_seeded_scenarios(seed)

        # Fresh orchestrator per seed (resets all stateful buffers)
        orch = Orchestrator(
            model_dir    = model_dir,
            data_dir     = data_dir,
            device       = device,
            shap_enabled = False,
            latency_port = 9295 + seed_idx,   # avoid port collision
            eval_mode    = True,
        )

        seed_out = out / f'seed_{seed}'
        seed_out.mkdir(parents=True, exist_ok=True)

        for sc in scenarios:
            result = sc_mod.run_scenario(sc, orch, seed_out)
            rd = asdict(result)
            name = rd['scenario']
            if name not in accum:
                accum[name] = {
                    'pass_count':    [],
                    'max_tier':      [],
                    'proactive':     [],
                    't2_p50':        [],
                    't3_p50':        [],
                    'sla_ok':        [],
                }
            accum[name]['pass_count'].append(1 if rd['pass_fail'] == 'PASS' else 0)
            accum[name]['max_tier'].append(rd['max_tier_reached'])
            accum[name]['proactive'].append(rd['proactive_count'])
            accum[name]['t2_p50'].append(rd['tier2_latency_ms'].get('p50', 0) or 0)
            accum[name]['t3_p50'].append(rd['tier3_latency_ms'].get('p50', 0) or 0)
            accum[name]['sla_ok'].append(1 if rd['sla_ok'] else 0)

    # ── Aggregate ──────────────────────────────────────────────────────────────
    summary = {'seeds': seeds, 'n_seeds': len(seeds), 'scenarios': {}}

    for name, metrics in accum.items():
        agg = {}
        for k, vals in metrics.items():
            arr = np.array(vals, dtype=float)
            agg[k] = {
                'mean':   round(float(np.mean(arr)),   4),
                'std':    round(float(np.std(arr)),    4),
                'min':    round(float(np.min(arr)),    4),
                'max':    round(float(np.max(arr)),    4),
                'values': [round(float(v), 4) for v in arr],
            }
        # 95% CI half-width (t-distribution, df=n-1)
        n = len(seeds)
        from scipy import stats as sp_stats
        for k in agg:
            arr = np.array(accum[name][k], dtype=float)
            if n > 1:
                ci = sp_stats.t.ppf(0.975, df=n - 1) * np.std(arr, ddof=1) / np.sqrt(n)
            else:
                ci = 0.0
            agg[k]['ci95'] = round(float(ci), 4)
        summary['scenarios'][name] = agg

    # Save JSON
    json_out = out / 'multi_seed_summary.json'
    json_out.write_text(json.dumps(summary, indent=2))
    logger.info(f'\n[✓] JSON → {json_out}')

    # ── Markdown table ──────────────────────────────────────────────────────────
    md_lines = [
        '# Multi-Seed Evaluation Results',
        '',
        f'Seeds: `{seeds}` (n={len(seeds)})',
        '',
        '## Pass Rate & Latency (mean ± 95% CI)',
        '',
        '| Scenario | Pass rate | Max tier | T2 P50 (ms) | T3 P50 (ms) | Proactive | SLA ok |',
        '|----------|:---------:|:--------:|:-----------:|:-----------:|:---------:|:------:|',
    ]

    for name, agg in summary['scenarios'].items():
        short = name.split('_', 1)[0]   # e.g. "S3"
        desc  = '_'.join(name.split('_')[1:])[:25]

        def cell(k):
            m  = agg[k]['mean']
            ci = agg[k]['ci95']
            return f'{m:.1f} ± {ci:.1f}'

        pass_pct = agg['pass_count']['mean'] * 100
        md_lines.append(
            f'| {short} {desc} | {pass_pct:.0f}% | {cell("max_tier")} | '
            f'{cell("t2_p50")} | {cell("t3_p50")} | {cell("proactive")} | '
            f'{agg["sla_ok"]["mean"]*100:.0f}% |'
        )

    md_lines += [
        '',
        '> Values are mean ± 95% CI across all seeds.',
        '> T2/T3 P50 = 0 means tier was not triggered in this scenario.',
        '',
    ]

    md_out = out / 'multi_seed_table.md'
    md_out.write_text('\n'.join(md_lines))
    logger.info(f'[✓] Markdown table → {md_out}')

    # Print table to stdout
    print('\n' + '\n'.join(md_lines))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(description='Multi-seed evaluation runner')
    parser.add_argument('--seeds',     default='42,43,44,45,46',
                        help='Comma-separated list of seeds (default: 42,43,44,45,46)')
    parser.add_argument('--model-dir', default=str(_ROOT / 'pad_onap_v3' / 'models'))
    parser.add_argument('--data-dir',  default=str(_ROOT / 'pad_onap_v3' / 'processed'))
    parser.add_argument('--out-dir',   default=str(_ROOT / 'evaluation' / 'results'))
    parser.add_argument('--device',    default='auto', choices=['auto', 'cuda', 'cpu'])
    args = parser.parse_args()

    seeds = [int(s.strip()) for s in args.seeds.split(',')]
    run_all_seeds(
        seeds     = seeds,
        model_dir = args.model_dir,
        data_dir  = args.data_dir,
        out_dir   = args.out_dir,
        device    = args.device,
    )
