#!/usr/bin/env python3
"""
Plot: Latency Comparison — T2 Proactive vs T3 Reactive (AI) vs Baseline Reactive
==================================================================================
Usage:
    python evaluation/plot_latency_comparison.py
    python evaluation/plot_latency_comparison.py --out custom/path.png --dpi 300
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker
import numpy as np

_ROOT = Path(__file__).resolve().parent.parent

C_T2  = '#2196F3'   # blue  — T2 proactive (AI)
C_T3  = '#FF9800'   # orange — T3 reactive  (AI)
C_BASE = '#E53935'  # red   — baseline reactive

SCENARIO_SHORT = {
    'S1_normal_baseline':             'S1\nNormal',
    'S2_sudden_udp_flood':            'S2\nUDP flood',
    'S3_gradual_syn_ramp':            'S3\nSYN ramp',
    'S4_http_flood_ood':              'S4\nHTTP (OOD)',
    'S5_icmp_burst_ood':              'S5\nICMP (OOD)',
    'S6_multi_attack_udp_syn':        'S6\nMulti-atk',
    'S7_sla_fairness_3tenant':        'S7\nSLA 3-tenant',
    'S8_proactive_t2_vs_reactive_t3': 'S8\nNovelty',
}


def _p50(d: dict, key: str) -> float:
    return d.get(key, {}).get('p50', 0.0) or 0.0


def main(ai_json: Path, base_json: Path, out_png: Path, dpi: int = 300) -> None:
    ai_data   = json.loads(ai_json.read_text())
    base_data = json.loads(base_json.read_text())
    base_idx  = {s['scenario']: s for s in base_data['scenarios']}

    names   = [s['scenario'] for s in ai_data['scenarios']]
    t2_vals = [_p50(s, 'tier2_latency_ms') for s in ai_data['scenarios']]
    t3_ai   = [_p50(s, 'tier3_latency_ms') for s in ai_data['scenarios']]
    t3_base = []
    for n in names:
        b = base_idx.get(n, {})
        v = _p50(b, 'tier3_latency_ms') or _p50(b, 'tier2_latency_ms')
        t3_base.append(v)

    labels = [SCENARIO_SHORT.get(n, n) for n in names]
    x      = np.arange(len(labels))
    w      = 0.26

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.set_facecolor('#F5F5F5')

    b1 = ax.bar(x - w, t2_vals,  w, label='T2 Proactive — AI',          color=C_T2,   alpha=0.92, zorder=3)
    b2 = ax.bar(x,     t3_ai,    w, label='T3 Reactive — AI',            color=C_T3,   alpha=0.92, zorder=3)
    b3 = ax.bar(x + w, t3_base,  w, label='T3/T2 Reactive — Baseline',   color=C_BASE, alpha=0.92, zorder=3)

    def annotate(bars, vals):
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 80,
                        f'{v/1000:.1f}s', ha='center', va='bottom',
                        fontsize=7.5, color='#212121')

    annotate(b1, t2_vals)
    annotate(b2, t3_ai)
    annotate(b3, t3_base)

    ax.set_xlabel('Scenario', fontsize=12, labelpad=8)
    ax.set_ylabel('VNF Activation Latency (ms)', fontsize=12, labelpad=8)
    ax.set_title(
        'PAD-ONAP: VNF Activation Latency — T2 Proactive vs T3 Reactive vs Threshold Baseline\n'
        '(P50 over tier-transition events; 0 = tier not triggered in this scenario)',
        fontsize=11, pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 7800)
    ax.yaxis.set_major_formatter(
        matplotlib.ticker.FuncFormatter(lambda v, _: f'{v/1000:.0f}s' if v >= 1000 else f'{int(v)}ms'))
    ax.grid(axis='y', color='#BDBDBD', linestyle='--', linewidth=0.6, zorder=0)
    ax.spines[['top', 'right']].set_visible(False)

    ax.axhline(505,  color=C_T2,   linewidth=0.9, linestyle=':', alpha=0.7)
    ax.axhline(6006, color=C_T3,   linewidth=0.9, linestyle=':', alpha=0.7)
    ax.text(len(labels) - 0.45, 580,  'T2 target ≈ 505 ms',  color=C_T2,  fontsize=7.5)
    ax.text(len(labels) - 0.45, 6086, 'T3 target ≈ 6 006 ms', color=C_T3, fontsize=7.5)

    # Highlight S8
    ax.axvspan(x[-1] - 0.5, x[-1] + 0.5, alpha=0.07, color='purple', zorder=1)
    ax.text(x[-1], 7500, '★ Key Novelty (S8)', ha='center', fontsize=8.5,
            color='purple', style='italic')

    ax.legend(fontsize=9, loc='upper left', framealpha=0.9)
    plt.tight_layout()
    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_png, dpi=dpi, bbox_inches='tight')
    plt.close()
    print('[OK] Saved: ' + str(out_png).encode('ascii', errors='replace').decode('ascii'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ai-json',   default=str(_ROOT / 'evaluation' / 'results' / 'evaluation_summary.json'))
    parser.add_argument('--base-json', default=str(_ROOT / 'evaluation' / 'results_baseline' / 'baseline_summary.json'))
    parser.add_argument('--out',       default=str(_ROOT / 'Docs' / 'thesis' / 'figures' / 'fig_latency_comparison.png'))
    parser.add_argument('--dpi',       type=int, default=300)
    args = parser.parse_args()
    main(Path(args.ai_json), Path(args.base_json), Path(args.out), args.dpi)
