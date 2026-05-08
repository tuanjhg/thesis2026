"""
Evaluation Metrics — Spec §7.3 (PAD-ONAP v3)
============================================

Spec-aligned metric calculators for Track A (XGBoost) and Track B (LSTM)
plus the M3/M4 orchestration and AI-vs-no-AI comparison metrics.

Public functions:

  Track A — classifier
    track_a_classification_report(y_true, y_pred, y_proba) -> dict
    fpr_at_threshold(y_true_binary, y_proba_attack, threshold) -> float
    shap_jaccard_stability(top_k_per_window) -> float
    brier_score(y_true_binary, p_attack) -> float
    expected_calibration_error(y_true_binary, p_attack, n_bins=10) -> float

  Track B — forecaster
    forecast_quality_per_horizon(y_true_per_h, y_proba_per_h, thresholds) -> dict
    mean_lead_time_per_tier(events) -> dict[int, float]      # tier → minutes
    tier_specific_trigger_precision(events, horizon_min, window_min) -> float
    inter_horizon_correlation(y_proba_per_h) -> float

  Orchestration / NFV (M3 / M4)
    tier_assignment_accuracy(td_pred, td_truth) -> float
    pod_thrashing_rate(policy_decisions, hours) -> float
    nfv_deployment_summary(metrics_records) -> dict

  AI-vs-no-AI A/B
    ab_compare(records_ai, records_no_ai) -> dict

All functions are NumPy/sklearn-friendly and degrade gracefully when sklearn
is unavailable (a small built-in implementation is used instead).
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# Spec §4.2 / §4.6 — 12-class taxonomy
# ─────────────────────────────────────────────────────────────────────────────

CICDDOS_CLASS_NAMES = [
    'BENIGN', 'DrDoS_DNS', 'DrDoS_LDAP', 'DrDoS_MSSQL', 'DrDoS_NetBIOS',
    'DrDoS_NTP', 'DrDoS_SNMP', 'DrDoS_SSDP', 'DrDoS_UDP',
    'Syn', 'UDP-lag', 'WebDDoS',
]

# Spec §4.3 / §5.3 — operating thresholds + lead-time targets per tier
TIER_THRESHOLDS_MIN = {15: 0.50, 5: 0.70, 1: 0.85}
TIER_LEAD_TARGETS_S = {1: 10 * 60, 2: 3 * 60, 3: 30}      # spec §7.3 floors


# ─────────────────────────────────────────────────────────────────────────────
# Track A — classification
# ─────────────────────────────────────────────────────────────────────────────

def track_a_classification_report(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    y_proba: Optional[np.ndarray] = None,
) -> dict:
    """
    Per-class P/R/F1 over the 12-class taxonomy plus macro/weighted averages.
    `y_proba` is (N, 12) — used for FPR / Brier / ECE.  Returns a flat dict
    suitable for JSON serialisation.
    """
    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_pred, dtype=int)
    n_cls = len(CICDDOS_CLASS_NAMES)

    out: dict = {'accuracy': float((yt == yp).mean()) if yt.size else 0.0}

    per_class = {}
    for c in range(n_cls):
        tp = int(((yt == c) & (yp == c)).sum())
        fp = int(((yt != c) & (yp == c)).sum())
        fn = int(((yt == c) & (yp != c)).sum())
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        per_class[CICDDOS_CLASS_NAMES[c]] = {
            'precision': prec, 'recall': rec, 'f1': f1,
            'support':   int((yt == c).sum()),
        }
    out['per_class'] = per_class

    # macro / weighted
    f1s   = [v['f1']        for v in per_class.values()]
    precs = [v['precision'] for v in per_class.values()]
    recs  = [v['recall']    for v in per_class.values()]
    sup   = np.array([v['support'] for v in per_class.values()], dtype=float)
    w     = sup / sup.sum() if sup.sum() > 0 else np.zeros_like(sup)

    out['macro']    = {'precision': float(np.mean(precs)),
                       'recall':    float(np.mean(recs)),
                       'f1':        float(np.mean(f1s))}
    out['weighted'] = {'precision': float(np.dot(w, precs)),
                       'recall':    float(np.dot(w, recs)),
                       'f1':        float(np.dot(w, f1s))}

    # FPR (binary BENIGN-vs-attack)
    yt_attack = (yt != 0).astype(int)
    yp_attack = (yp != 0).astype(int)
    n_neg = int((yt_attack == 0).sum())
    fp    = int(((yt_attack == 0) & (yp_attack == 1)).sum())
    out['fpr'] = (fp / n_neg) if n_neg > 0 else 0.0

    if y_proba is not None and y_proba.size:
        p_attack = 1.0 - y_proba[:, 0]
        out['brier_score'] = brier_score(yt_attack, p_attack)
        out['ece']         = expected_calibration_error(yt_attack, p_attack)

    return out


def fpr_at_threshold(
    y_true_binary: Sequence[int], y_proba_attack: Sequence[float],
    threshold: float = 0.5,
) -> float:
    yt = np.asarray(y_true_binary)
    yp = (np.asarray(y_proba_attack) >= threshold).astype(int)
    n_neg = int((yt == 0).sum())
    fp    = int(((yt == 0) & (yp == 1)).sum())
    return (fp / n_neg) if n_neg > 0 else 0.0


def shap_jaccard_stability(top_k_per_window: Iterable[Sequence[str]]) -> float:
    """
    Spec §7.3 — average pairwise Jaccard over top-K SHAP feature sets across
    perturbed windows.  Returns 1.0 for perfect stability, 0.0 for none.
    """
    sets = [set(t) for t in top_k_per_window if t]
    if len(sets) < 2:
        return 1.0
    sims = []
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            inter = len(sets[i] & sets[j])
            union = len(sets[i] | sets[j])
            if union > 0:
                sims.append(inter / union)
    return float(np.mean(sims)) if sims else 0.0


def brier_score(y_true_binary, p_attack) -> float:
    yt = np.asarray(y_true_binary, dtype=float)
    pa = np.asarray(p_attack, dtype=float)
    if yt.size == 0:
        return 0.0
    return float(((pa - yt) ** 2).mean())


def expected_calibration_error(y_true_binary, p_attack, n_bins: int = 10) -> float:
    yt = np.asarray(y_true_binary, dtype=float)
    pa = np.asarray(p_attack, dtype=float)
    if yt.size == 0:
        return 0.0
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece  = 0.0
    for i in range(n_bins):
        mask = (pa >= bins[i]) & (pa < bins[i + 1])
        if i == n_bins - 1:
            mask = (pa >= bins[i]) & (pa <= bins[i + 1])
        if not mask.any():
            continue
        conf = pa[mask].mean()
        acc  = yt[mask].mean()
        ece += (mask.sum() / yt.size) * abs(conf - acc)
    return float(ece)


# ─────────────────────────────────────────────────────────────────────────────
# Track B — forecast quality
# ─────────────────────────────────────────────────────────────────────────────

def _auc_roc(y_true, y_proba) -> float:
    """Mann-Whitney AUC.  Returns 0.5 for degenerate input."""
    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_proba, dtype=float)
    pos = yp[yt == 1]
    neg = yp[yt == 0]
    if pos.size == 0 or neg.size == 0:
        return 0.5
    n_correct = 0
    n_total   = pos.size * neg.size
    # Vectorised pairwise comparison (memory friendly on small samples)
    grid = np.subtract.outer(pos, neg)
    n_correct = float((grid > 0).sum() + 0.5 * (grid == 0).sum())
    return n_correct / n_total


def _auprc(y_true, y_proba) -> float:
    """Average precision (area under PR curve)."""
    yt = np.asarray(y_true, dtype=int)
    yp = np.asarray(y_proba, dtype=float)
    if yt.size == 0 or (yt == 1).sum() == 0:
        return 0.0
    order = np.argsort(-yp)
    yt = yt[order]
    tp = np.cumsum(yt == 1)
    fp = np.cumsum(yt == 0)
    fn = (yt == 1).sum() - tp
    precision = tp / np.maximum(tp + fp, 1)
    recall    = tp / np.maximum(tp + fn, 1)
    # Stair-step AP
    ap = 0.0
    prev_recall = 0.0
    for p, r in zip(precision, recall):
        ap += float(p) * float(r - prev_recall)
        prev_recall = float(r)
    return ap


def forecast_quality_per_horizon(
    y_true_per_h:  dict[int, Sequence[int]],
    y_proba_per_h: dict[int, Sequence[float]],
    thresholds:    Optional[dict[int, float]] = None,
) -> dict:
    """
    Per-horizon AUC, AUPRC, RMSE, P/R at the spec thresholds (Spec §7.3).
    `y_true_per_h` and `y_proba_per_h` are keyed by horizon minutes (1, 5, 15).
    """
    thresholds = thresholds or TIER_THRESHOLDS_MIN
    out = {}
    for h, y_true in y_true_per_h.items():
        y_pr = np.asarray(y_proba_per_h.get(h, []), dtype=float)
        y_tr = np.asarray(y_true, dtype=int)
        thr  = thresholds.get(h, 0.5)
        if y_tr.size == 0 or y_pr.size == 0:
            out[f'h{h}min'] = {'auc_roc': 0.5, 'auprc': 0.0, 'rmse': 0.0,
                               'precision': 0.0, 'recall': 0.0,
                               'threshold': thr}
            continue
        auc   = _auc_roc(y_tr, y_pr)
        auprc = _auprc(y_tr, y_pr)
        rmse  = float(np.sqrt(((y_pr - y_tr) ** 2).mean()))
        y_hat = (y_pr >= thr).astype(int)
        tp = int(((y_tr == 1) & (y_hat == 1)).sum())
        fp = int(((y_tr == 0) & (y_hat == 1)).sum())
        fn = int(((y_tr == 1) & (y_hat == 0)).sum())
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        out[f'h{h}min'] = {
            'auc_roc': auc, 'auprc': auprc, 'rmse': rmse,
            'precision': prec, 'recall': rec, 'threshold': thr,
            'support_pos': int((y_tr == 1).sum()),
            'support_neg': int((y_tr == 0).sum()),
        }
    return out


@dataclass
class TierTriggerEvent:
    """Helper struct for lead-time / trigger-precision analysis."""
    timestamp_s:        float                # event time
    tier:               int                  # 1, 2, 3, 4
    triggered_horizon:  Optional[int]        # 1 / 5 / 15 / None
    p_attack_1min:      float = 0.0
    p_attack_5min:      float = 0.0
    p_attack_15min:     float = 0.0
    confidence:         float = 0.0
    actual_attack_onset_s: Optional[float] = None  # ground-truth onset


def mean_lead_time_per_tier(events: Sequence[TierTriggerEvent]) -> dict:
    """
    Spec §7.3 — for each tier, mean seconds between first crossing and the
    actual attack onset.  Targets:
      Tier 1 ≥ 600 s (10 min)   Tier 2 ≥ 180 s (3 min)   Tier 3 ≥ 30 s
    """
    by_tier: dict[int, list[float]] = defaultdict(list)
    seen:    set[tuple[int, float]] = set()
    for ev in events:
        if ev.actual_attack_onset_s is None or ev.tier < 1:
            continue
        key = (ev.tier, ev.actual_attack_onset_s)
        if key in seen:
            continue
        lead = ev.actual_attack_onset_s - ev.timestamp_s
        if lead > 0:
            by_tier[ev.tier].append(lead)
            seen.add(key)

    summary = {}
    for tier, leads in by_tier.items():
        target = TIER_LEAD_TARGETS_S.get(tier, 0)
        summary[f'tier_{tier}'] = {
            'mean_lead_s':    float(np.mean(leads)),
            'median_lead_s':  float(np.median(leads)),
            'n_events':       len(leads),
            'target_s':       target,
            'meets_target':   bool(np.mean(leads) >= target) if target else None,
        }
    return summary


def tier_specific_trigger_precision(
    events: Sequence[TierTriggerEvent], horizon_min: int, window_min: int,
) -> float:
    """
    Fraction of `P(t+horizon_min) > threshold` events that are followed by an
    actual attack onset within `window_min` minutes (Spec §7.3 trigger
    precision).
    """
    thr   = TIER_THRESHOLDS_MIN[horizon_min]
    win_s = window_min * 60
    n_fired = 0
    n_followed = 0
    for ev in events:
        p = {1: ev.p_attack_1min, 5: ev.p_attack_5min, 15: ev.p_attack_15min}[horizon_min]
        if p <= thr:
            continue
        n_fired += 1
        if ev.actual_attack_onset_s is not None:
            delta = ev.actual_attack_onset_s - ev.timestamp_s
            if 0 < delta <= win_s:
                n_followed += 1
    return (n_followed / n_fired) if n_fired > 0 else 0.0


def inter_horizon_correlation(y_proba_per_h: dict[int, Sequence[float]]) -> float:
    """Mean pairwise Pearson ρ between horizon heads (Spec target ρ ∈ [0.4, 0.8])."""
    keys = sorted(y_proba_per_h.keys())
    if len(keys) < 2:
        return 1.0
    rs = []
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a = np.asarray(y_proba_per_h[keys[i]], dtype=float)
            b = np.asarray(y_proba_per_h[keys[j]], dtype=float)
            n = min(a.size, b.size)
            if n < 2:
                continue
            a = a[:n]; b = b[:n]
            if np.std(a) == 0 or np.std(b) == 0:
                continue
            rs.append(float(np.corrcoef(a, b)[0, 1]))
    return float(np.mean(rs)) if rs else 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration / NFV
# ─────────────────────────────────────────────────────────────────────────────

def tier_assignment_accuracy(td_pred: Sequence[int], td_truth: Sequence[int]) -> float:
    p = np.asarray(td_pred, dtype=int)
    t = np.asarray(td_truth, dtype=int)
    if p.size == 0:
        return 0.0
    return float((p == t).mean())


def pod_thrashing_rate(policy_decisions, hours: float = 1.0) -> float:
    """
    Number of escalate→deescalate→escalate triplets per hour.
    `policy_decisions` is a list of `PolicyDecision`-like objects with
    `.action.value` strings.
    """
    if hours <= 0 or not policy_decisions:
        return 0.0
    actions = [
        getattr(d.action, 'value', str(d.action))
        for d in policy_decisions
    ]
    triplets = 0
    for i in range(len(actions) - 2):
        if (actions[i].startswith('ESCAL') and
                actions[i + 1] == 'DEESCALATE' and
                actions[i + 2].startswith('ESCAL')):
            triplets += 1
    return triplets / hours


def nfv_deployment_summary(metrics_records) -> dict:
    """Wraps NFVMetricsCollector.summary() so consumers don't import that class."""
    if hasattr(metrics_records, 'summary'):
        return metrics_records.summary()
    if not metrics_records:
        return {}
    boots = np.array([getattr(r, 'boot_time_s', 0.0) for r in metrics_records])
    cpu   = np.array([getattr(r, 'peak_cpu_pct', 0.0) for r in metrics_records])
    ram   = np.array([getattr(r, 'peak_ram_gb', 0.0)  for r in metrics_records])
    sfc   = np.array([getattr(r, 'sfc_update_ms', 0.0) for r in metrics_records])
    return {
        'boot_time_s_p50': float(np.percentile(boots, 50)) if boots.size else 0.0,
        'boot_time_s_p95': float(np.percentile(boots, 95)) if boots.size else 0.0,
        'boot_time_s_p99': float(np.percentile(boots, 99)) if boots.size else 0.0,
        'peak_cpu_pct_mean': float(cpu.mean()) if cpu.size else 0.0,
        'peak_ram_gb_mean':  float(ram.mean()) if ram.size else 0.0,
        'sfc_update_ms_p50': float(np.percentile(sfc[sfc > 0], 50)) if (sfc > 0).any() else 0.0,
        'sfc_update_ms_p95': float(np.percentile(sfc[sfc > 0], 95)) if (sfc > 0).any() else 0.0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# AI vs no-AI comparison (Spec §7.3 — A/B scenarios S2 and S4)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScenarioOutcome:
    """One scenario run summary used for A/B comparison."""
    time_to_first_action_ms:  float
    time_to_clean_traffic_ms: float
    blocked_attack_pct:       float
    preserved_legitimate_pct: float
    sla_violation_minutes:    float
    worst_case_throughput_drop_pct: float
    n_cnf_instantiations:     int
    avg_cnf_cpu_pct:          float
    avg_cnf_ram_gb:           float
    n_policy_actions:         int


def ab_compare(records_ai: ScenarioOutcome, records_no_ai: ScenarioOutcome) -> dict:
    """
    Spec §7.3 — pairwise deltas between the AI-enabled and AI-disabled runs.
    Positive deltas mean AI-enabled is better (higher blocked %, higher
    preserved %, lower latency / SLA impact).
    """
    def _delta(a, b):    return float(a - b)
    def _ratio(a, b):    return float(a / b) if b != 0 else 0.0
    return {
        'time_to_first_action_delta_ms':
            _delta(records_no_ai.time_to_first_action_ms,
                   records_ai.time_to_first_action_ms),
        'time_to_clean_traffic_delta_ms':
            _delta(records_no_ai.time_to_clean_traffic_ms,
                   records_ai.time_to_clean_traffic_ms),
        'blocked_attack_pct_delta':
            _delta(records_ai.blocked_attack_pct,
                   records_no_ai.blocked_attack_pct),
        'preserved_legitimate_pct_delta':
            _delta(records_ai.preserved_legitimate_pct,
                   records_no_ai.preserved_legitimate_pct),
        'sla_violation_minutes_delta':
            _delta(records_no_ai.sla_violation_minutes,
                   records_ai.sla_violation_minutes),
        'worst_case_throughput_drop_pct_delta':
            _delta(records_no_ai.worst_case_throughput_drop_pct,
                   records_ai.worst_case_throughput_drop_pct),
        'cnf_instantiation_overhead_ratio':
            _ratio(records_ai.n_cnf_instantiations,
                   records_no_ai.n_cnf_instantiations),
        'policy_action_overhead_ratio':
            _ratio(records_ai.n_policy_actions,
                   records_no_ai.n_policy_actions),
    }


# ── CLI smoke test ───────────────────────────────────────────────────────────
if __name__ == '__main__':
    rng = np.random.default_rng(0)
    yt = rng.integers(0, 12, size=200)
    yp = yt.copy(); yp[::13] = (yp[::13] + 1) % 12
    proba = rng.dirichlet(np.ones(12), size=200)
    print(track_a_classification_report(yt, yp, proba))
