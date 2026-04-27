#!/usr/bin/env python3
"""
Architecture Figures Generator
================================
Generates 3 vector-quality PNG figures for the PAD-ONAP thesis:

  1. fig_architecture_4tier.png  — 4-stage pipeline S1→S4 + ONAP closed-loop
  2. fig_state_machine.png       — 5-tier escalation state machine (T0→T4, hysteresis)
  3. fig_fat_tree.png            — Fat-tree k=4 topology with attack path h0→h15

Usage:
    python evaluation/plot_architecture.py
    python evaluation/plot_architecture.py --out-dir Docs/thesis/figures --dpi 300
"""
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patches as mpl_patches
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import numpy as np

_ROOT = Path(__file__).resolve().parent.parent

# ── Colour tokens ──────────────────────────────────────────────────────────────
COL_STAGE    = '#1565C0'   # dark blue — pipeline stages
COL_AI       = '#6A1B9A'   # purple    — AI components
COL_ONAP     = '#00695C'   # teal      — ONAP components
COL_ATTACK   = '#C62828'   # red       — attack path / high tier
COL_NORMAL   = '#2E7D32'   # green     — normal/benign
COL_PROACT   = '#1976D2'   # blue      — proactive tier
COL_REACT    = '#E65100'   # deep orange — reactive tier
COL_T0       = '#4CAF50'
COL_T1       = '#8BC34A'
COL_T2       = '#FFC107'
COL_T3       = '#FF5722'
COL_T4       = '#B71C1C'
COL_EDGE     = '#424242'   # dark grey — arrows


def _bbox(ax, x, y, w, h, text, color, fontsize=9, text_color='white', radius=0.08,
          alpha=1.0, style='round,pad=0.05'):
    """Draw a rounded rectangle with centred text."""
    box = FancyBboxPatch(
        (x - w/2, y - h/2), w, h,
        boxstyle=f'round,pad=0.04',
        linewidth=1.2,
        edgecolor='white',
        facecolor=color,
        alpha=alpha,
        zorder=3,
    )
    ax.add_patch(box)
    ax.text(x, y, text, ha='center', va='center',
            fontsize=fontsize, color=text_color, zorder=4,
            fontfamily='DejaVu Sans', fontweight='bold',
            wrap=True)


def _arrow(ax, x0, y0, x1, y1, color=COL_EDGE, lw=1.5,
           arrowstyle='->', mutation_scale=14, label=''):
    ax.annotate('', xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle=arrowstyle, color=color,
                                lw=lw, mutation_scale=mutation_scale),
                zorder=5)
    if label:
        mx, my = (x0 + x1) / 2, (y0 + y1) / 2
        ax.text(mx + 0.01, my, label, ha='left', va='center',
                fontsize=7, color=color, zorder=6)


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 1 — 4-tier architecture pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def fig_architecture(out_path: Path, dpi: int):
    fig, ax = plt.subplots(figsize=(16, 7))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 7)
    ax.axis('off')
    ax.set_facecolor('#FAFAFA')
    fig.patch.set_facecolor('#FAFAFA')

    # ── Main pipeline row (y=5) ────────────────────────────────────────────────
    stages = [
        (1.5, 5.0, 'S1\nNetwork\nMonitor',   COL_STAGE),
        (4.0, 5.0, 'S2\nFeature\nExtractor', COL_STAGE),
        (6.5, 5.0, 'S3\nAI Engine',          COL_AI),
        (9.0, 5.0, 'S4\nOrchestrator',       COL_STAGE),
    ]
    for (x, y, txt, col) in stages:
        _bbox(ax, x, y, 2.0, 1.4, txt, col, fontsize=9)

    # Arrows between stages
    for i in range(len(stages) - 1):
        x0 = stages[i][0] + 1.0
        x1 = stages[i+1][0] - 1.0
        y  = 5.0
        _arrow(ax, x0, y, x1, y, color=COL_EDGE)

    # ── ONAP stack (right side) ────────────────────────────────────────────────
    onap = [
        (12.5, 6.2, 'ONAP\nPolicy\nEngine',  COL_ONAP),
        (12.5, 4.8, 'ONAP SO\n(VNF Boot)',   COL_ONAP),
        (12.5, 3.4, 'SFC\nManager',          COL_ONAP),
    ]
    for (x, y, txt, col) in onap:
        _bbox(ax, x, y, 2.0, 1.0, txt, col, fontsize=8)

    # S4 → ONAP Policy
    _arrow(ax, 10.0, 5.0, 11.5, 5.7, color=COL_ONAP, label='tier decision')
    # Policy → SO
    _arrow(ax, 12.5, 5.7, 12.5, 5.3, color=COL_ONAP)
    # SO → SFC
    _arrow(ax, 12.5, 4.3, 12.5, 3.9, color=COL_ONAP)
    # SFC → back to network (closed loop)
    _arrow(ax, 11.5, 3.4, 2.5, 3.4, color=COL_ONAP, label='SFC rules → VNF chain')
    _arrow(ax, 2.5, 3.4, 2.5, 4.3, color=COL_ONAP)

    # ── AI sub-components (below S3) ──────────────────────────────────────────
    _bbox(ax, 5.5, 2.8, 1.8, 0.9, 'XGBoost\n7-class', COL_AI, fontsize=8)
    _bbox(ax, 7.5, 2.8, 1.8, 0.9, 'Transformer\n+LSTM', COL_AI, fontsize=8)
    _arrow(ax, 6.5, 4.3, 5.5, 3.25, color=COL_AI, label='detect')
    _arrow(ax, 6.5, 4.3, 7.5, 3.25, color=COL_AI, label='forecast')

    # ── Input / Output labels ─────────────────────────────────────────────────
    ax.text(0.3, 5.0, 'NetFlow\n/ gNMI', ha='center', va='center',
            fontsize=8, color='#37474F',
            bbox=dict(boxstyle='round', fc='#ECEFF1', ec='#90A4AE', lw=1))
    _arrow(ax, 0.7, 5.0, 0.5, 5.0, color=COL_EDGE)

    # ── Tier labels annotation ─────────────────────────────────────────────────
    tier_info = [
        (9.0, 3.8, 'T0 Normal', COL_T0),
        (9.0, 3.3, 'T1 Alert →', COL_T1),
        (9.0, 2.8, 'T2 Rate-limit (proactive)', COL_T2),
        (9.0, 2.3, 'T3 Scrub (reactive)', COL_T3),
    ]
    for (x, y, txt, col) in tier_info:
        ax.text(x, y, txt, ha='left', va='center', fontsize=7.5, color=col,
                fontfamily='DejaVu Sans')

    # ── Proactive path highlight ──────────────────────────────────────────────
    ax.annotate('', xy=(9.0, 5.4), xytext=(6.5, 5.4),
                arrowprops=dict(arrowstyle='->', color=COL_PROACT, lw=2.0,
                                linestyle='dashed', mutation_scale=14))
    ax.text(7.75, 5.55, 'forecast path (T2, ~505 ms)',
            ha='center', va='bottom', fontsize=7.5, color=COL_PROACT, style='italic')

    # ── Title ─────────────────────────────────────────────────────────────────
    ax.set_title(
        'PAD-ONAP — 4-Stage Pipeline Architecture with ONAP Closed-Loop\n'
        '(S1: Monitor → S2: Features → S3: AI → S4: Orchestrator → ONAP SO → SFC)',
        fontsize=11, pad=12, fontfamily='DejaVu Sans',
    )

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=dpi, bbox_inches='tight')
    plt.close()
    print('[OK] ' + str(out_path).encode('ascii', errors='replace').decode('ascii'))


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 2 — 5-tier escalation state machine
# ═══════════════════════════════════════════════════════════════════════════════

def fig_state_machine(out_path: Path, dpi: int):
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 6)
    ax.axis('off')
    ax.set_facecolor('#FAFAFA')
    fig.patch.set_facecolor('#FAFAFA')

    # ── Tier nodes ────────────────────────────────────────────────────────────
    tiers = [
        (1.5, 3.0, 'T0\nNormal',            COL_T0, 'No VNF'),
        (4.0, 3.0, 'T1\nAlert',             COL_T1, 'Log only'),
        (6.5, 3.0, 'T2\nPreempt\n(rate-limit)', COL_T2, 'Rate-limiter\n~505 ms'),
        (9.0, 3.0, 'T3\nMitigate\n(scrub)',  COL_T3, 'Scrubber\n~6 000 ms'),
        (11.5, 3.0, 'T4\nBlackhole',        COL_T4, 'Blackhole\n~200 ms'),
    ]
    for (x, y, txt, col, vnf) in tiers:
        # Main circle
        circle = plt.Circle((x, y), 0.9, color=col, zorder=3, alpha=0.92)
        ax.add_patch(circle)
        ax.text(x, y + 0.15, txt, ha='center', va='center',
                fontsize=8, color='white', zorder=4, fontweight='bold')
        # VNF label below
        ax.text(x, y - 1.35, vnf, ha='center', va='top',
                fontsize=7.5, color='#424242', style='italic')

    # ── Escalation arrows (top, left-to-right) ────────────────────────────────
    for i in range(len(tiers) - 1):
        x0 = tiers[i][0] + 0.9
        x1 = tiers[i+1][0] - 0.9
        y  = 3.55
        ax.annotate('', xy=(x1, y), xytext=(x0, y),
                    arrowprops=dict(arrowstyle='->', color=COL_ATTACK, lw=2.0,
                                    connectionstyle='arc3,rad=-0.25',
                                    mutation_scale=14), zorder=5)

    ax.text(6.5, 4.75, 'Escalation (AI confidence ↑ or forecast ↑)',
            ha='center', va='center', fontsize=8, color=COL_ATTACK,
            bbox=dict(fc='#FFEBEE', ec=COL_ATTACK, lw=1, boxstyle='round,pad=0.3'))

    # ── De-escalation arrows (bottom, right-to-left) ──────────────────────────
    for i in range(len(tiers) - 1, 0, -1):
        x0 = tiers[i][0] - 0.9
        x1 = tiers[i-1][0] + 0.9
        y  = 2.45
        ax.annotate('', xy=(x1, y), xytext=(x0, y),
                    arrowprops=dict(arrowstyle='->', color=COL_NORMAL, lw=1.5,
                                    connectionstyle='arc3,rad=-0.25',
                                    mutation_scale=12), zorder=5)

    ax.text(6.5, 1.3, 'De-escalation (normal windows > hysteresis threshold)',
            ha='center', va='center', fontsize=8, color=COL_NORMAL,
            bbox=dict(fc='#E8F5E9', ec=COL_NORMAL, lw=1, boxstyle='round,pad=0.3'))

    # ── Hysteresis + frequency guard labels ───────────────────────────────────
    ax.text(6.5, 0.5,
            'Hysteresis guard: must see N consecutive normal windows before de-escalation\n'
            'Frequency guard: minimum interval between tier changes (prevents VNF churn)',
            ha='center', va='center', fontsize=7.5, color='#37474F',
            bbox=dict(fc='#F3E5F5', ec='#7B1FA2', lw=1, boxstyle='round,pad=0.4'))

    # ── Proactive path annotation ──────────────────────────────────────────────
    ax.annotate('Forecast fires T2\nbefore threshold crossed',
                xy=(6.5, 3.9), xytext=(6.5, 5.2),
                ha='center', fontsize=7.5, color=COL_PROACT,
                arrowprops=dict(arrowstyle='->', color=COL_PROACT, lw=1.5),
                bbox=dict(fc='#E3F2FD', ec=COL_PROACT, lw=1, boxstyle='round,pad=0.3'))

    ax.set_title(
        'PAD-ONAP — 5-Tier Escalation State Machine\n'
        '(T0 Normal → T4 Blackhole; hysteresis + frequency guard prevent VNF flapping)',
        fontsize=11, pad=12)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=dpi, bbox_inches='tight')
    plt.close()
    print('[OK] ' + str(out_path).encode('ascii', errors='replace').decode('ascii'))


# ═══════════════════════════════════════════════════════════════════════════════
# Figure 3 — Fat-tree k=4 topology with attack path
# ═══════════════════════════════════════════════════════════════════════════════

def fig_fat_tree(out_path: Path, dpi: int):
    """
    Draws fat-tree k=4:
        4 core switches (top)
        8 aggregation (2/pod × 4 pods)
        8 edge switches (2/pod × 4 pods)
        16 hosts (2/edge × 2 edge/pod × 4 pods)
    Attack path h0 → h15 highlighted in red.
    """
    fig, ax = plt.subplots(figsize=(16, 9))
    ax.set_xlim(-0.5, 15.5)
    ax.set_ylim(-1, 10)
    ax.axis('off')
    ax.set_facecolor('#FAFAFA')
    fig.patch.set_facecolor('#FAFAFA')

    k = 4
    n_core = (k // 2) ** 2   # 4

    # ── Layer y positions ──────────────────────────────────────────────────────
    Y_CORE = 8.5
    Y_AGG  = 6.5
    Y_EDGE = 4.5
    Y_HOST = 2.5

    # ── Core switches ──────────────────────────────────────────────────────────
    core_x = [3.0, 5.5, 8.5, 11.0]
    core_pos = [(x, Y_CORE) for x in core_x]
    for i, (cx, cy) in enumerate(core_pos):
        circ = plt.Circle((cx, cy), 0.45, color='#1565C0', zorder=3)
        ax.add_patch(circ)
        ax.text(cx, cy, f'C{i+1}', ha='center', va='center',
                fontsize=8, color='white', fontweight='bold', zorder=4)

    # ── Pods: aggregation + edge + hosts ──────────────────────────────────────
    pod_colors = ['#7B1FA2', '#1976D2', '#388E3C', '#F57C00']
    agg_pos  = []
    edge_pos = []
    host_pos = []
    host_idx = 0

    for p in range(k):
        pod_x_start = p * 3.7 + 0.5
        # 2 agg per pod
        agg_xs = [pod_x_start + 0.8, pod_x_start + 1.9]
        for ax_x in agg_xs:
            agg_pos.append((ax_x, Y_AGG, p))
        # 2 edge per pod
        edge_xs = [pod_x_start + 0.8, pod_x_start + 1.9]
        for ex_x in edge_xs:
            edge_pos.append((ex_x, Y_EDGE, p))
        # 2 hosts per edge
        for ex_x in edge_xs:
            host_pos.append((ex_x - 0.45, Y_HOST, host_idx, p))
            host_pos.append((ex_x + 0.45, Y_HOST, host_idx + 1, p))
            host_idx += 2

    # Draw agg
    for (x, y, p) in agg_pos:
        sq = FancyBboxPatch((x - 0.4, y - 0.3), 0.8, 0.6,
                            boxstyle='round,pad=0.04',
                            facecolor=pod_colors[p], edgecolor='white', lw=1.2, zorder=3, alpha=0.9)
        ax.add_patch(sq)
        ax.text(x, y, f'A{p}', ha='center', va='center',
                fontsize=7.5, color='white', fontweight='bold', zorder=4)

    # Draw edge
    for (x, y, p) in edge_pos:
        sq = FancyBboxPatch((x - 0.4, y - 0.3), 0.8, 0.6,
                            boxstyle='round,pad=0.04',
                            facecolor=pod_colors[p], edgecolor='white', lw=1.2, zorder=3, alpha=0.7)
        ax.add_patch(sq)
        ax.text(x, y, f'E{p}', ha='center', va='center',
                fontsize=7.5, color='white', fontweight='bold', zorder=4)

    # Draw hosts
    ATTACK_HOST = 0    # h0
    VICTIM_HOST = 15   # h15
    for (x, y, idx, p) in host_pos:
        is_attacker = (idx == ATTACK_HOST)
        is_victim   = (idx == VICTIM_HOST)
        col = COL_ATTACK if is_attacker else ('#E53935' if is_victim else '#90A4AE')
        circ = plt.Circle((x, y), 0.32, color=col, zorder=3)
        ax.add_patch(circ)
        ax.text(x, y, f'h{idx}', ha='center', va='center',
                fontsize=6.5, color='white', fontweight='bold', zorder=4)

    # ── Connectivity (grey for normal, red for attack path) ───────────────────
    attack_path_links = {
        # h0 edge (e0_0) → agg0_0 → core1 → agg3_0 → e3_1 → h15
        # Simplified: we just highlight the cross-pod links
    }

    def draw_link(x0, y0, x1, y1, is_attack=False, lw=0.8, alpha=0.35):
        color = COL_ATTACK if is_attack else '#455A64'
        lw_   = 2.2 if is_attack else lw
        al_   = 0.85 if is_attack else alpha
        ax.plot([x0, x1], [y0, y1], color=color, lw=lw_, alpha=al_, zorder=2)

    # Host → edge links
    for (hx, hy, hidx, p) in host_pos:
        edge_idx = p * 2 + (0 if hidx % 4 < 2 else 1)
        if edge_idx < len(edge_pos):
            ex, ey, _ = edge_pos[edge_idx]
            is_atk = hidx == ATTACK_HOST or hidx == VICTIM_HOST
            draw_link(hx, hy + 0.32, ex, ey - 0.3, is_attack=is_atk)

    # Edge → agg links (within pod)
    for p in range(k):
        for ei in range(2):   # 2 edges per pod
            ex, ey, _ = edge_pos[p * 2 + ei]
            for ai in range(2):   # 2 aggs per pod
                ax_x, ay, _ = agg_pos[p * 2 + ai]
                draw_link(ex, ey + 0.3, ax_x, ay - 0.3)

    # Agg → core links
    for p in range(k):
        for ai in range(2):
            ax_x, ay, _ = agg_pos[p * 2 + ai]
            # agg ai in pod p → core[ai*2 + j] for j in range(2)
            for j in range(2):
                cidx = ai * 2 + j
                if cidx < len(core_pos):
                    cx, cy = core_pos[cidx]
                    is_atk = (p == 0 and ai == 0 and cidx == 0) or (p == 3 and ai == 0 and cidx == 0)
                    draw_link(ax_x, ay + 0.3, cx, cy - 0.45, is_attack=is_atk)

    # ── Attack path arrow overlay ─────────────────────────────────────────────
    h0_pos  = host_pos[0]
    h15_pos = host_pos[15]
    ax.annotate('', xy=(h15_pos[0], h15_pos[1] + 0.35),
                xytext=(h0_pos[0], h0_pos[1] + 0.35),
                arrowprops=dict(arrowstyle='->', color=COL_ATTACK, lw=2.5,
                                connectionstyle='arc3,rad=-0.25',
                                mutation_scale=16), zorder=6)
    ax.text((h0_pos[0] + h15_pos[0]) / 2, 1.3,
            'UDP Flood Attack Path  h0 → h15  (cross-pod, 3 pod hops)',
            ha='center', va='center', fontsize=9, color=COL_ATTACK, fontweight='bold',
            bbox=dict(fc='#FFEBEE', ec=COL_ATTACK, lw=1.5, boxstyle='round,pad=0.4'))

    # ── Layer labels ──────────────────────────────────────────────────────────
    for y, lbl in [(Y_CORE, 'Core layer (4 switches)'),
                   (Y_AGG,  'Aggregation layer (8 switches, 2/pod)'),
                   (Y_EDGE, 'Edge layer (8 switches, 2/pod)'),
                   (Y_HOST, 'Hosts (16, 2/edge)')]:
        ax.text(-0.3, y, lbl, ha='right', va='center', fontsize=8, color='#37474F',
                fontfamily='DejaVu Sans')

    # ── Pod brackets ──────────────────────────────────────────────────────────
    for p in range(k):
        px_start = p * 3.7 + 0.3
        px_end   = px_start + 2.5
        ax.annotate('', xy=(px_end, 0.1), xytext=(px_start, 0.1),
                    arrowprops=dict(arrowstyle='<->', color=pod_colors[p], lw=1.5))
        ax.text((px_start + px_end) / 2, -0.3, f'Pod {p}',
                ha='center', va='center', fontsize=8, color=pod_colors[p], fontweight='bold')

    ax.set_title(
        'Fat-Tree k=4 Data-Center Topology — UDP Flood Attack Path h0 → h15\n'
        f'(4 core · 8 agg · 8 edge switches · 16 hosts;  equal-cost paths = {(k//2)**2})',
        fontsize=11, pad=12)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=dpi, bbox_inches='tight')
    plt.close()
    print('[OK] ' + str(out_path).encode('ascii', errors='replace').decode('ascii'))


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main(out_dir: Path, dpi: int):
    fig_architecture(out_dir / 'fig_architecture_4tier.png',  dpi)
    fig_state_machine(out_dir / 'fig_state_machine.png',       dpi)
    fig_fat_tree(out_dir / 'fig_fat_tree.png',                 dpi)
    print('[OK] All 3 figures saved to: ' + str(out_dir).encode('ascii', errors='replace').decode('ascii'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate thesis architecture figures')
    parser.add_argument('--out-dir', default=str(_ROOT / 'Docs' / 'thesis' / 'figures'))
    parser.add_argument('--dpi',     type=int, default=300)
    args = parser.parse_args()
    main(Path(args.out_dir), args.dpi)
