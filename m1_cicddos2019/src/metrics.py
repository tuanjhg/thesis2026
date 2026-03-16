from __future__ import annotations

from typing import Dict, Tuple

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score


def threshold_search_under_fpr(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    max_fpr: float = 0.05,
    num_steps: int = 200,
) -> Tuple[float, Dict[str, float]]:
    best_thr = 0.5
    best_f1 = -1.0
    best_stats = {}

    for thr in np.linspace(0.01, 0.99, num_steps):
        y_pred = (y_prob >= thr).astype(int)
        tp = int(((y_pred == 1) & (y_true == 1)).sum())
        fp = int(((y_pred == 1) & (y_true == 0)).sum())
        tn = int(((y_pred == 0) & (y_true == 0)).sum())
        fn = int(((y_pred == 0) & (y_true == 1)).sum())
        fpr = fp / (fp + tn + 1e-12)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        if fpr <= max_fpr and f1 > best_f1:
            best_f1 = f1
            best_thr = float(thr)
            best_stats = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "fpr": fpr, "f1": f1}

    if best_f1 < 0:
        best_thr = 0.5
        y_pred = (y_prob >= best_thr).astype(int)
        tp = int(((y_pred == 1) & (y_true == 1)).sum())
        fp = int(((y_pred == 1) & (y_true == 0)).sum())
        tn = int(((y_pred == 0) & (y_true == 0)).sum())
        fn = int(((y_pred == 0) & (y_true == 1)).sum())
        fpr = fp / (fp + tn + 1e-12)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        best_stats = {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "fpr": fpr, "f1": f1}

    return best_thr, best_stats


def binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> Dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    fpr = fp / (fp + tn + 1e-12)
    auc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else float("nan")

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(auc),
        "fpr": float(fpr),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }
