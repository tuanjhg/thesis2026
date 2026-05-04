"""
analyze_real_testbed.py — Read real_e2e_data_<ts>.json and produce a
side-by-side AI vs Threshold comparison report (Markdown + console).

Inputs are produced by testbed/netflow_e2e_pipeline.py.

Usage:
    # latest run
    python evaluation/analyze_real_testbed.py

    # specific file
    python evaluation/analyze_real_testbed.py --json evaluation/results/real_e2e_data_20260504_144437.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT       = Path(__file__).resolve().parent.parent
RESULTS_DIR = _ROOT / 'evaluation' / 'results'


def _latest_json() -> Path | None:
    candidates = sorted(RESULTS_DIR.glob('real_e2e_data_*.json'),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def _fmt(v, suffix: str = '', n: int = 2) -> str:
    if v is None:
        return 'n/a'
    if isinstance(v, float):
        return f'{v:.{n}f}{suffix}'
    return f'{v}{suffix}'


def _verdict(metrics: dict) -> str:
    """Heuristic pass/fail per claim."""
    out = []
    lt = metrics.get('lead_time_vs_baseline_s')
    if lt is None:
        out.append('LEAD-TIME: ⚠  AI did not escalate to T2 OR Baseline did not escalate to T3 — re-run with stronger attack.')
    elif lt > 0:
        out.append(f'LEAD-TIME: ✓  AI proactive {lt:.1f}s ahead of Threshold reactive.')
    else:
        out.append(f'LEAD-TIME: ✗  AI was NOT ahead (delta={lt:.1f}s).')

    ai = metrics['classification_ai']
    bs = metrics['classification_baseline']
    if ai['f1'] > bs['f1']:
        out.append(f'CLASSIFICATION: ✓  AI F1={ai["f1"]:.2f} > Baseline F1={bs["f1"]:.2f}.')
    elif ai['f1'] == bs['f1']:
        out.append(f'CLASSIFICATION: =  Both F1={ai["f1"]:.2f}.')
    else:
        out.append(f'CLASSIFICATION: ✗  AI F1={ai["f1"]:.2f} < Baseline F1={bs["f1"]:.2f}.')

    return '\n'.join(out)


def _markdown(report: dict, src: Path) -> str:
    cfg     = report.get('config', {})
    metrics = report.get('metrics', {})
    ai      = metrics.get('classification_ai', {})
    bs      = metrics.get('classification_baseline', {})
    gp_legit  = metrics.get('goodput_legit_mbps_by_phase',  {})
    gp_victim = metrics.get('goodput_victim_mbps_by_phase', {})
    fw      = metrics.get('first_window', {})
    n       = metrics.get('n_windows', 0)

    lines = [
        f'# Real Mininet Testbed Report',
        '',
        f'- Source: `{src.name}`',
        f'- k = {cfg.get("k")}, attack = {cfg.get("duration")} s, window = {cfg.get("window_sec")} s',
        f'- Windows collected: **{n}**',
        '',
        '## 1. Lead Time',
        '',
        '| Event | Window index | Time vs attack-start |',
        '|---|---:|---:|',
        f'| AI first Tier ≥ 2  (proactive)        | {_fmt(fw.get("ai_tier2"))}   | — |',
        f'| AI first Tier ≥ 3  (reactive)         | {_fmt(fw.get("ai_tier3"))}   | — |',
        f'| Baseline first Tier ≥ 3 (reactive)    | {_fmt(fw.get("base_tier3"))} | — |',
        '',
        f'- **Lead time AI proactive vs Baseline reactive**: '
        f'`{_fmt(metrics.get("lead_time_vs_baseline_s"), " s")}`',
        f'- AI proactive vs AI own reactive (internal): '
        f'`{_fmt(metrics.get("lead_time_proactive_internal_s"), " s")}`',
        '',
        '## 2. Classification per window',
        '',
        '(Ground truth = phase 2; AI positive ≡ Tier ≥ 2; Baseline positive ≡ Tier ≥ 3.)',
        '',
        '| Detector | TP | FP | FN | TN | TPR | FPR | Precision | F1 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|',
        f'| AI       | {ai.get("tp")} | {ai.get("fp")} | {ai.get("fn")} | {ai.get("tn")} | {ai.get("tpr")} | {ai.get("fpr")} | {ai.get("precision")} | {ai.get("f1")} |',
        f'| Baseline | {bs.get("tp")} | {bs.get("fp")} | {bs.get("fn")} | {bs.get("tn")} | {bs.get("tpr")} | {bs.get("fpr")} | {bs.get("precision")} | {bs.get("f1")} |',
        '',
        '## 3. Goodput (Mbps mean per phase)',
        '',
        '| Stream | Baseline | Attack | Recovery |',
        '|---|---:|---:|---:|',
        f'| Legit user h2 → victim (offered 5 Mbps) | {_fmt(gp_legit.get("baseline"))}  | {_fmt(gp_legit.get("attack"))}  | {_fmt(gp_legit.get("recovery"))} |',
        f'| Victim received (legit only)            | {_fmt(gp_victim.get("baseline"))} | {_fmt(gp_victim.get("attack"))} | {_fmt(gp_victim.get("recovery"))} |',
        '',
        '## 4. Verdict',
        '',
        '```',
        _verdict(metrics),
        '```',
        '',
    ]
    return '\n'.join(lines)


def _console(report: dict):
    metrics = report.get('metrics', {})
    cfg     = report.get('config', {})
    ai      = metrics.get('classification_ai', {})
    bs      = metrics.get('classification_baseline', {})
    gp_v    = metrics.get('goodput_victim_mbps_by_phase', {})
    gp_l    = metrics.get('goodput_legit_mbps_by_phase', {})

    print('═' * 64)
    print(f'  Real Mininet Testbed — k={cfg.get("k")} duration={cfg.get("duration")}s')
    print('═' * 64)
    print(f'  Windows               : {metrics.get("n_windows")}')
    print(f'  Lead time vs Baseline : {_fmt(metrics.get("lead_time_vs_baseline_s"), " s")}')
    print(f'  AI proactive→reactive : {_fmt(metrics.get("lead_time_proactive_internal_s"), " s")}')
    print('─' * 64)
    print(f'  {"Detector":<10} {"TPR":>6} {"FPR":>6} {"Prec":>6} {"F1":>6}')
    print(f'  {"AI":<10} {ai.get("tpr",0):>6.2f} {ai.get("fpr",0):>6.2f} '
          f'{ai.get("precision",0):>6.2f} {ai.get("f1",0):>6.2f}')
    print(f'  {"Baseline":<10} {bs.get("tpr",0):>6.2f} {bs.get("fpr",0):>6.2f} '
          f'{bs.get("precision",0):>6.2f} {bs.get("f1",0):>6.2f}')
    print('─' * 64)
    print(f'  Goodput (Mbps)   {"baseline":>10} {"attack":>10} {"recovery":>10}')
    print(f'  legit h2→h15     {gp_l.get("baseline",0):>10.2f} '
          f'{gp_l.get("attack",0):>10.2f} {gp_l.get("recovery",0):>10.2f}')
    print(f'  victim received  {gp_v.get("baseline",0):>10.2f} '
          f'{gp_v.get("attack",0):>10.2f} {gp_v.get("recovery",0):>10.2f}')
    print('═' * 64)
    print()
    print(_verdict(metrics))


def main():
    p = argparse.ArgumentParser(description='Analyze real Mininet testbed run.')
    p.add_argument('--json', type=Path, default=None,
                   help='Path to real_e2e_data_<ts>.json (default: latest in evaluation/results/)')
    p.add_argument('--out',  type=Path, default=None,
                   help='Markdown output path (default: alongside the JSON)')
    args = p.parse_args()

    src = args.json or _latest_json()
    if src is None or not src.exists():
        sys.exit('No real_e2e_data_*.json found. Run testbed/netflow_e2e_pipeline.py first.')

    with open(src) as f:
        report = json.load(f)

    _console(report)

    md = _markdown(report, src)
    out = args.out or src.with_name(src.stem.replace('real_e2e_data_', 'real_e2e_summary_') + '.md')
    out.write_text(md, encoding='utf-8')
    print(f'\n[✓] Markdown summary written: {out}')


if __name__ == '__main__':
    main()
