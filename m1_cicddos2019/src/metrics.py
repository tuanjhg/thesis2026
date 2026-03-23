from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import accuracy_score, average_precision_score, f1_score, precision_score, recall_score, roc_auc_score


def _confusion_from_threshold(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    fpr = fp / (fp + tn + 1e-12)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "fpr": float(fpr),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
    }


def threshold_search_under_fpr(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    max_fpr: float = 0.05,
    num_steps: int = 200,
) -> Tuple[float, Dict[str, float]]:
    best_thr = 0.5
    best_f1 = -1.0
    best_stats = {}
    best_fpr = float("inf")
    best_fpr_f1 = -1.0
    best_fpr_thr = 0.5
    best_fpr_stats = {}

    for thr in np.linspace(0.01, 0.99, num_steps):
        y_pred = (y_prob >= thr).astype(int)
        tp = int(((y_pred == 1) & (y_true == 1)).sum())
        fp = int(((y_pred == 1) & (y_true == 0)).sum())
        tn = int(((y_pred == 0) & (y_true == 0)).sum())
        fn = int(((y_pred == 0) & (y_true == 1)).sum())
        fpr = fp / (fp + tn + 1e-12)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        if fpr < best_fpr or (abs(fpr - best_fpr) <= 1e-12 and f1 > best_fpr_f1):
            best_fpr = float(fpr)
            best_fpr_f1 = float(f1)
            best_fpr_thr = float(thr)
            best_fpr_stats = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "fpr": fpr, "f1": f1}

        if fpr <= max_fpr and f1 > best_f1:
            best_f1 = f1
            best_thr = float(thr)
            best_stats = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "fpr": fpr, "f1": f1}

    if best_f1 < 0:
        # If no threshold satisfies max_fpr, use the smallest-FPR threshold
        # instead of forcing 0.5 (which can cause unstable false alarms).
        best_thr = best_fpr_thr
        best_stats = best_fpr_stats

    return best_thr, best_stats


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, float]:
    cm = _confusion_from_threshold(y_true, y_prob, threshold)
    auc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else float("nan")
    pr_auc = average_precision_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else float("nan")

    return {
        "accuracy": cm["accuracy"],
        "precision": cm["precision"],
        "recall": cm["recall"],
        "f1": cm["f1"],
        "roc_auc": float(auc),
        "pr_auc": float(pr_auc),
        "fpr": cm["fpr"],
        "tp": cm["tp"],
        "fp": cm["fp"],
        "tn": cm["tn"],
        "fn": cm["fn"],
    }


def threshold_sweep_metrics(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    thresholds: List[float] | np.ndarray,
) -> List[Dict[str, float]]:
    rows: List[Dict[str, float]] = []
    for thr in thresholds:
        thr_value = float(thr)
        row = {"threshold": thr_value}
        row.update(_confusion_from_threshold(y_true, y_prob, thr_value))
        rows.append(row)
    return rows
