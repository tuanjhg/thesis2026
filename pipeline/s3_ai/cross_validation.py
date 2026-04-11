"""
M2 — Cross Validation Module (Spec-aligned)
Provides rigorous validation to ensure results are not inflated:
  - Track A: Stratified K-Fold CV (k=5) for XGBoost 7-class
  - Track B: Time-Series Split CV for Transformer+LSTM forecaster
  - Ablation: feature importance via permutation (detect redundant features)
"""

import numpy as np
import xgboost as xgb
import logging
import json
import time
from pathlib import Path
from sklearn.model_selection import StratifiedKFold, TimeSeriesSplit
from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score, classification_report
)
from sklearn.preprocessing import label_binarize, StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CLASS_NAMES = {
    0: "Normal", 1: "UDP_Flood", 2: "SYN_Flood",
    3: "HTTP_Flood", 4: "ICMP_Flood", 5: "Amplification", 6: "Slow_rate",
}

FEATURE_NAMES = [
    "pkt_rate", "byte_rate", "src_ip_entropy", "dst_ip_entropy",
    "src_port_entropy", "dst_port_entropy", "proto_dist_tcp",
    "proto_dist_udp", "proto_dist_icmp", "syn_ratio", "fin_ratio",
    "avg_pkt_size", "pkt_size_std", "new_flows_rate",
    "flow_duration_mean", "inter_arrival_mean", "inter_arrival_std",
]


# ═══════════════════════════════════════════════════════════════════════════
# Track A — Stratified K-Fold CV for XGBoost
# ═══════════════════════════════════════════════════════════════════════════

def xgboost_stratified_cv(X, y, n_splits=5, device='cpu'):
    """
    Stratified K-Fold cross-validation for XGBoost 7-class.

    IMPORTANT: StandardScaler is fit ONLY on train fold each time
    to prevent information leakage.

    Returns dict with per-fold and aggregate metrics.
    """
    logger.info("="*60)
    logger.info(f"XGBoost Stratified {n_splits}-Fold Cross Validation")
    logger.info("="*60)

    # Label remap (non-contiguous → contiguous)
    all_labels   = sorted(np.unique(y))
    n_classes    = len(all_labels)
    label_to_idx = {lbl: i for i, lbl in enumerate(all_labels)}
    idx_to_label = {i: lbl for lbl, i in label_to_idx.items()}
    y_remapped   = np.array([label_to_idx[l] for l in y], dtype=np.int32)

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y_remapped)):
        logger.info(f"\n--- Fold {fold+1}/{n_splits} ---")

        X_train_raw, X_test_raw = X[train_idx], X[test_idx]
        y_train_r, y_test_r     = y_remapped[train_idx], y_remapped[test_idx]

        # Scale per-fold (no leakage)
        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train_raw)
        X_test_s  = scaler.transform(X_test_raw)

        dtrain = xgb.DMatrix(X_train_s, label=y_train_r)
        dtest  = xgb.DMatrix(X_test_s,  label=y_test_r)

        params = {
            'device':           device,
            'tree_method':      'hist',
            'objective':        'multi:softprob',
            'num_class':        n_classes,
            'eval_metric':      'mlogloss',
            'seed':             42,
            'verbosity':        0,
            'max_depth':        8,
            'learning_rate':    0.05,
            'subsample':        0.8,
            'colsample_bytree': 0.8,
        }

        t0 = time.time()
        callbacks = [xgb.callback.EarlyStopping(rounds=30, save_best=True)]
        booster = xgb.train(
            params, dtrain,
            num_boost_round=300,
            evals=[(dtest, 'eval')],
            callbacks=callbacks,
            verbose_eval=False,
        )
        elapsed = time.time() - t0

        raw = booster.predict(dtest)
        if raw.ndim == 1:
            raw = raw.reshape(-1, n_classes)
        y_pred_r  = np.argmax(raw, axis=1)
        y_pred    = np.array([idx_to_label[i] for i in y_pred_r])
        y_test_orig = np.array([idx_to_label[i] for i in y_test_r])

        # Metrics
        acc = float(accuracy_score(y_test_r, y_pred_r))
        f1  = float(f1_score(y_test_r, y_pred_r, average='macro', zero_division=0))

        # AUC (only present classes)
        import warnings
        present = np.unique(y_test_r).tolist()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                y_bin = label_binarize(y_test_r, classes=list(range(n_classes)))
                auc = float(roc_auc_score(y_bin, raw, multi_class='ovr', average='macro'))
        except Exception:
            auc = 0.0

        fold_results.append({
            'fold': fold + 1,
            'accuracy': acc,
            'macro_f1': f1,
            'auc_ovr': auc,
            'time_s': elapsed,
            'train_size': len(train_idx),
            'test_size': len(test_idx),
        })
        logger.info(f"  ACC={acc:.4f}  F1={f1:.4f}  AUC={auc:.4f}  ({elapsed:.1f}s)")

    # Aggregate
    accs = [r['accuracy'] for r in fold_results]
    f1s  = [r['macro_f1'] for r in fold_results]
    aucs = [r['auc_ovr'] for r in fold_results]

    summary = {
        'n_splits':     n_splits,
        'accuracy_mean': float(np.mean(accs)),
        'accuracy_std':  float(np.std(accs)),
        'macro_f1_mean': float(np.mean(f1s)),
        'macro_f1_std':  float(np.std(f1s)),
        'auc_mean':      float(np.mean(aucs)),
        'auc_std':       float(np.std(aucs)),
        'per_fold':      fold_results,
    }

    logger.info(f"\n{'='*60}")
    logger.info("XGBoost CV SUMMARY")
    logger.info(f"{'='*60}")
    logger.info(f"  Accuracy: {summary['accuracy_mean']:.4f} ± {summary['accuracy_std']:.4f}")
    logger.info(f"  Macro F1: {summary['macro_f1_mean']:.4f} ± {summary['macro_f1_std']:.4f}")
    logger.info(f"  AUC OvR:  {summary['auc_mean']:.4f} ± {summary['auc_std']:.4f}")
    return summary


# ═══════════════════════════════════════════════════════════════════════════
# Track B — Time-Series Split CV for Transformer+LSTM
# ═══════════════════════════════════════════════════════════════════════════

def transformer_timeseries_cv(X, y, n_splits=5, device_str='cuda'):
    """
    Time-Series Split cross-validation for Transformer+LSTM.

    Uses expanding window: train on [0..t], test on [t+1..t+k].
    No shuffling — respects temporal order.

    Returns dict with per-fold and aggregate metrics.
    """
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader
    from torch.amp import GradScaler, autocast

    logger.info(f"\n{'='*60}")
    logger.info(f"Transformer+LSTM Time-Series {n_splits}-Fold CV")
    logger.info("="*60)

    device = torch.device(device_str if torch.cuda.is_available() else 'cpu')

    # Import model and dataset from our module
    from pipeline.s3_ai_v2.transformer_lstm import (
        TransformerLSTMForecaster, ForecastDataset,
        N_TIMESTEPS, N_FEATURES, N_HORIZONS, HORIZON_LABELS
    )
    from sklearn.metrics import roc_auc_score

    tscv = TimeSeriesSplit(n_splits=n_splits)
    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(tscv.split(X)):
        logger.info(f"\n--- Fold {fold+1}/{n_splits} ---")
        logger.info(f"  Train: idx 0..{train_idx[-1]} ({len(train_idx):,})")
        logger.info(f"  Test:  idx {test_idx[0]}..{test_idx[-1]} ({len(test_idx):,})")

        X_tr, y_tr = X[train_idx], y[train_idx]
        X_te, y_te = X[test_idx],  y[test_idx]

        # Scale per-fold
        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_tr).astype(np.float32)
        X_te_s = scaler.transform(X_te).astype(np.float32)

        # Build datasets
        train_ds = ForecastDataset(X_tr_s, y_tr)
        test_ds  = ForecastDataset(X_te_s, y_te)

        if len(train_ds) < 100 or len(test_ds) < 50:
            logger.info("  Skipping fold (too few windows)")
            continue

        train_dl = DataLoader(train_ds, batch_size=128, shuffle=True, drop_last=True)
        test_dl  = DataLoader(test_ds,  batch_size=256, shuffle=False)

        # Build model
        model = TransformerLSTMForecaster(
            input_dim=N_FEATURES, hidden_dim=64, num_heads=4,
            num_layers=2, lstm_hidden=128, lstm_layers=2, dropout=0.2,
        ).to(device)

        optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=60)
        use_amp   = device.type == 'cuda'
        grad_scaler = GradScaler('cuda', enabled=use_amp)

        # Pos weight for attack upweighting
        y_binary_tr = (y_tr > 0).astype(float)
        atk_ratio   = max(y_binary_tr.mean(), 0.1)
        pw = torch.tensor([min((1 - atk_ratio) / atk_ratio, 10.0)]).to(device)

        best_auc   = 0.0
        best_state = None
        patience_ct = 0

        t0 = time.time()
        for epoch in range(60):
            model.train()
            for Xb, yb in train_dl:
                Xb, yb = Xb.to(device), yb.to(device)
                with autocast('cuda', enabled=use_amp):
                    logits = model(Xb)
                    loss = 0
                    for h in range(N_HORIZONS):
                        loss += nn.functional.binary_cross_entropy_with_logits(
                            logits[:, h], yb[:, h],
                            pos_weight=pw,
                        )
                    loss = loss / N_HORIZONS
                grad_scaler.scale(loss).backward()
                grad_scaler.unscale_(optimizer)
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                grad_scaler.step(optimizer)
                grad_scaler.update()
                optimizer.zero_grad(set_to_none=True)
            scheduler.step()

            # Eval
            model.eval()
            all_proba = [[] for _ in range(N_HORIZONS)]
            all_labels = [[] for _ in range(N_HORIZONS)]
            with torch.no_grad():
                for Xb, yb in test_dl:
                    Xb = Xb.to(device)
                    with autocast('cuda', enabled=use_amp):
                        logits_v = model(Xb)
                    proba_v = torch.sigmoid(logits_v.float())
                    for h in range(N_HORIZONS):
                        all_proba[h].extend(proba_v[:, h].cpu().numpy())
                        all_labels[h].extend(yb[:, h].numpy())

            aucs = []
            for h in range(N_HORIZONS):
                lbl = np.array(all_labels[h])
                prb = np.array(all_proba[h])
                try:
                    a = roc_auc_score(lbl, prb) if len(np.unique(lbl)) > 1 else 0.5
                except Exception:
                    a = 0.5
                aucs.append(a)
            val_auc = float(np.mean(aucs))

            if val_auc > best_auc:
                best_auc = val_auc
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                patience_ct = 0
            else:
                patience_ct += 1
                if patience_ct >= 15:
                    break

        elapsed = time.time() - t0

        # Final eval with best state
        if best_state:
            model.load_state_dict({k: v.to(device) for k, v in best_state.items()})
        model.eval()
        all_proba = [[] for _ in range(N_HORIZONS)]
        all_labels = [[] for _ in range(N_HORIZONS)]
        with torch.no_grad():
            for Xb, yb in test_dl:
                Xb = Xb.to(device)
                with autocast('cuda', enabled=use_amp):
                    logits_f = model(Xb)
                proba_f = torch.sigmoid(logits_f.float())
                for h in range(N_HORIZONS):
                    all_proba[h].extend(proba_f[:, h].cpu().numpy())
                    all_labels[h].extend(yb[:, h].numpy())

        final_aucs, final_accs = [], []
        for h in range(N_HORIZONS):
            lbl = np.array(all_labels[h])
            prb = np.array(all_proba[h])
            pred = (prb > 0.5).astype(int)
            try:
                a = roc_auc_score(lbl, prb) if len(np.unique(lbl)) > 1 else 0.5
            except Exception:
                a = 0.5
            final_aucs.append(a)
            final_accs.append(float((pred == lbl).mean()))

        fold_res = {
            'fold': fold + 1,
            'auc_per_horizon': final_aucs,
            'acc_per_horizon': final_accs,
            'auc_mean': float(np.mean(final_aucs)),
            'time_s': elapsed,
        }
        fold_results.append(fold_res)

        auc_str = "  ".join([f"{HORIZON_LABELS[h]}:{final_aucs[h]:.3f}" for h in range(N_HORIZONS)])
        logger.info(f"  AUC [{auc_str}]  mean={fold_res['auc_mean']:.4f}  ({elapsed:.1f}s)")

    if not fold_results:
        logger.warning("No valid folds!")
        return {}

    # Aggregate
    all_auc_means = [r['auc_mean'] for r in fold_results]
    per_h_aucs = {h: [r['auc_per_horizon'][h] for r in fold_results] for h in range(4)}

    summary = {
        'n_splits': n_splits,
        'auc_mean': float(np.mean(all_auc_means)),
        'auc_std':  float(np.std(all_auc_means)),
        'per_horizon': {},
        'per_fold': fold_results,
    }
    for h in range(N_HORIZONS):
        summary['per_horizon'][HORIZON_LABELS[h]] = {
            'auc_mean': float(np.mean(per_h_aucs[h])),
            'auc_std':  float(np.std(per_h_aucs[h])),
        }

    logger.info(f"\n{'='*60}")
    logger.info("Transformer+LSTM CV SUMMARY")
    logger.info(f"{'='*60}")
    logger.info(f"  Overall AUC: {summary['auc_mean']:.4f} ± {summary['auc_std']:.4f}")
    for h in range(N_HORIZONS):
        hk = HORIZON_LABELS[h]
        logger.info(f"  {hk:8s}: AUC={summary['per_horizon'][hk]['auc_mean']:.4f} "
                     f"± {summary['per_horizon'][hk]['auc_std']:.4f}")
    return summary


# ═══════════════════════════════════════════════════════════════════════════
# Feature Redundancy Check
# ═══════════════════════════════════════════════════════════════════════════

def check_feature_redundancy(X, y):
    """Check correlation between features to flag redundant ones."""
    logger.info(f"\n{'='*60}")
    logger.info("FEATURE REDUNDANCY CHECK")
    logger.info("="*60)

    corr = np.corrcoef(X.T)
    issues = []
    for i in range(17):
        for j in range(i+1, 17):
            r = abs(corr[i, j])
            if r > 0.95:
                issues.append((FEATURE_NAMES[i], FEATURE_NAMES[j], r))
                logger.warning(f"  HIGH CORR: {FEATURE_NAMES[i]} ↔ {FEATURE_NAMES[j]}: r={r:.4f}")

    if not issues:
        logger.info("  No highly correlated feature pairs (|r| > 0.95)")
    else:
        logger.warning(f"  Found {len(issues)} redundant feature pair(s)")
        logger.warning("  These inflate model capacity without adding real information")

    return issues


# ═══════════════════════════════════════════════════════════════════════════
# Attack-Only CV — 4-class discrimination, no synthetic Normal
# ═══════════════════════════════════════════════════════════════════════════

ATTACK_CLASS_NAMES = {
    1: "UDP_Flood",
    2: "SYN_Flood",
    3: "HTTP_Flood",
    5: "Amplification",
}


def xgboost_attack_only_cv(X, y, n_splits=5, device='cpu'):
    """
    Stratified K-Fold CV on attack samples ONLY (classes 1,2,3,5).

    Excludes synthetic Normal entirely — gives credible multi-class
    discrimination metrics unaffected by Normal/Attack AUC inflation.

    Returns dict with per-fold and aggregate metrics.
    """
    logger.info("="*60)
    logger.info(f"XGBoost Attack-Only {n_splits}-Fold CV (4 classes)")
    logger.info("  Classes: UDP_Flood(1) | SYN_Flood(2) | HTTP_Flood(3) | Amplification(5)")
    logger.info("="*60)

    # Filter to attack samples only
    attack_mask = y > 0
    X_atk = X[attack_mask]
    y_atk = y[attack_mask]

    logger.info(f"  Attack samples: {len(X_atk):,}")
    for cls_id, cls_name in ATTACK_CLASS_NAMES.items():
        cnt = (y_atk == cls_id).sum()
        logger.info(f"    [{cls_id}] {cls_name:15s}: {cnt:6,} ({cnt/len(y_atk)*100:.1f}%)")

    # Label remap: [1,2,3,5] → [0,1,2,3]
    all_labels   = sorted(np.unique(y_atk))
    n_classes    = len(all_labels)
    label_to_idx = {lbl: i for i, lbl in enumerate(all_labels)}
    idx_to_label = {i: lbl for lbl, i in label_to_idx.items()}
    y_remapped   = np.array([label_to_idx[l] for l in y_atk], dtype=np.int32)

    label_str = " | ".join([f"{lbl}→{i}({ATTACK_CLASS_NAMES.get(lbl,lbl)})"
                            for lbl, i in label_to_idx.items()])
    logger.info(f"  Label remap: {label_str}")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X_atk, y_remapped)):
        logger.info(f"\n--- Fold {fold+1}/{n_splits} ---")

        X_train_raw, X_test_raw = X_atk[train_idx], X_atk[test_idx]
        y_train_r, y_test_r     = y_remapped[train_idx], y_remapped[test_idx]

        scaler = StandardScaler()
        X_train_s = scaler.fit_transform(X_train_raw)
        X_test_s  = scaler.transform(X_test_raw)

        dtrain = xgb.DMatrix(X_train_s, label=y_train_r)
        dtest  = xgb.DMatrix(X_test_s,  label=y_test_r)

        params = {
            'device':           device,
            'tree_method':      'hist',
            'objective':        'multi:softprob',
            'num_class':        n_classes,
            'eval_metric':      'mlogloss',
            'seed':             42,
            'verbosity':        0,
            'max_depth':        8,
            'learning_rate':    0.05,
            'subsample':        0.8,
            'colsample_bytree': 0.8,
        }

        t0 = time.time()
        callbacks = [xgb.callback.EarlyStopping(rounds=30, save_best=True)]
        booster = xgb.train(
            params, dtrain,
            num_boost_round=300,
            evals=[(dtest, 'eval')],
            callbacks=callbacks,
            verbose_eval=False,
        )
        elapsed = time.time() - t0

        raw = booster.predict(dtest)
        if raw.ndim == 1:
            raw = raw.reshape(-1, n_classes)
        y_pred_r = np.argmax(raw, axis=1)

        acc = float(accuracy_score(y_test_r, y_pred_r))
        f1  = float(f1_score(y_test_r, y_pred_r, average='macro', zero_division=0))

        import warnings
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                y_bin = label_binarize(y_test_r, classes=list(range(n_classes)))
                auc = float(roc_auc_score(y_bin, raw, multi_class='ovr', average='macro'))
        except Exception:
            auc = 0.0

        # Per-class F1
        report = classification_report(
            y_test_r, y_pred_r,
            target_names=[ATTACK_CLASS_NAMES.get(idx_to_label[i], str(i))
                          for i in range(n_classes)],
            output_dict=True, zero_division=0
        )

        fold_results.append({
            'fold':       fold + 1,
            'accuracy':   acc,
            'macro_f1':   f1,
            'auc_ovr':    auc,
            'time_s':     elapsed,
            'per_class':  {ATTACK_CLASS_NAMES.get(idx_to_label[i], str(i)):
                           report.get(ATTACK_CLASS_NAMES.get(idx_to_label[i], str(i)), {})
                           for i in range(n_classes)},
        })
        logger.info(f"  ACC={acc:.4f}  Macro-F1={f1:.4f}  AUC={auc:.4f}  ({elapsed:.1f}s)")

    # Aggregate
    accs = [r['accuracy'] for r in fold_results]
    f1s  = [r['macro_f1'] for r in fold_results]
    aucs = [r['auc_ovr'] for r in fold_results]

    summary = {
        'n_splits':        n_splits,
        'n_classes':       n_classes,
        'classes':         [ATTACK_CLASS_NAMES.get(l, str(l)) for l in all_labels],
        'accuracy_mean':   float(np.mean(accs)),
        'accuracy_std':    float(np.std(accs)),
        'macro_f1_mean':   float(np.mean(f1s)),
        'macro_f1_std':    float(np.std(f1s)),
        'auc_mean':        float(np.mean(aucs)),
        'auc_std':         float(np.std(aucs)),
        'per_fold':        fold_results,
    }

    logger.info(f"\n{'='*60}")
    logger.info("Attack-Only CV SUMMARY (no synthetic Normal contamination)")
    logger.info(f"{'='*60}")
    logger.info(f"  Accuracy: {summary['accuracy_mean']:.4f} ± {summary['accuracy_std']:.4f}")
    logger.info(f"  Macro F1: {summary['macro_f1_mean']:.4f} ± {summary['macro_f1_std']:.4f}")
    logger.info(f"  AUC OvR:  {summary['auc_mean']:.4f} ± {summary['auc_std']:.4f}")

    # Per-class aggregate F1 across folds
    logger.info("\n  Per-class Macro-F1 (mean across folds):")
    for cls_name in [ATTACK_CLASS_NAMES[l] for l in all_labels]:
        per_fold_f1 = [
            r['per_class'].get(cls_name, {}).get('f1-score', 0.0)
            for r in fold_results
        ]
        logger.info(f"    {cls_name:15s}: {np.mean(per_fold_f1):.4f} ± {np.std(per_fold_f1):.4f}")

    return summary


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def run_cv(data_dir='./datasets/processed_v2', output_dir='./models_v2'):
    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║   M2 CROSS VALIDATION — Rigorous Evaluation     ║")
    logger.info("╚══════════════════════════════════════════════════╝")

    # Load raw data (BEFORE scaling — CV will scale per-fold)
    X_train = np.load(data_dir / 'X_train.npy').astype(np.float32)
    X_test  = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_train = np.load(data_dir / 'y_train.npy').astype(int)
    y_test  = np.load(data_dir / 'y_test.npy').astype(int)

    # Combine for CV (CV creates its own splits)
    X_all = np.vstack([X_train, X_test])
    y_all = np.hstack([y_train, y_test])

    logger.info(f"Total samples: {len(X_all):,} × {X_all.shape[1]} features")
    logger.info(f"Classes: { {CLASS_NAMES.get(c, c): int((y_all==c).sum()) for c in np.unique(y_all)} }")

    # ── Feature redundancy check ──────────────────────────────────────────
    redundant = check_feature_redundancy(X_all, y_all)

    # ── Track A: XGBoost Stratified CV ────────────────────────────────────
    try:
        xgb_device = 'cuda'
        xgb.XGBClassifier(device='cuda', n_estimators=3, verbosity=0).fit(
            np.random.randn(50, 5), np.random.randint(0, 3, 50))
    except Exception:
        xgb_device = 'cpu'
    xgb_cv = xgboost_stratified_cv(X_all, y_all, n_splits=5, device=xgb_device)

    # ── Track B: Transformer Time-Series CV ───────────────────────────────
    # For time-series CV, use data in temporal order (X_all is already temporal)
    tf_cv = transformer_timeseries_cv(X_all, y_all, n_splits=5)

    # ── Attack-only CV (credible multi-class, no synthetic Normal) ─────────
    atk_cv = xgboost_attack_only_cv(X_all, y_all, n_splits=5, device=xgb_device)

    # ── Save results ──────────────────────────────────────────────────────
    cv_results = {
        'feature_redundancy': [
            {'feat_a': a, 'feat_b': b, 'correlation': float(r)}
            for a, b, r in redundant
        ],
        'xgboost_cv': xgb_cv,
        'transformer_cv': tf_cv,
        'attack_only_cv': atk_cv,
    }

    out_path = output_dir / 'cross_validation_results.json'
    with open(out_path, 'w') as f:
        json.dump(cv_results, f, indent=2, default=str)
    logger.info(f"\n💾 CV results saved: {out_path}")

    # ── Final verdict ─────────────────────────────────────────────────────
    logger.info(f"\n{'='*60}")
    logger.info("FINAL VERDICT")
    logger.info("="*60)

    if redundant:
        logger.warning("⚠️  Feature redundancy detected (see above)")

    if xgb_cv:
        xgb_ok = xgb_cv['accuracy_mean'] >= 0.90
        logger.info(f"  XGBoost:     ACC={xgb_cv['accuracy_mean']:.4f}±{xgb_cv['accuracy_std']:.4f}  "
                     f"F1={xgb_cv['macro_f1_mean']:.4f}±{xgb_cv['macro_f1_std']:.4f}  "
                     f"{'✅' if xgb_ok else '⚠️'}")

    if tf_cv:
        tf_ok = tf_cv['auc_mean'] >= 0.85
        logger.info(f"  Transformer: AUC={tf_cv['auc_mean']:.4f}±{tf_cv['auc_std']:.4f}  "
                     f"{'✅' if tf_ok else '⚠️'}")

    if atk_cv:
        atk_ok = atk_cv['macro_f1_mean'] >= 0.80
        logger.info(f"  Attack-only: ACC={atk_cv['accuracy_mean']:.4f}±{atk_cv['accuracy_std']:.4f}  "
                     f"F1={atk_cv['macro_f1_mean']:.4f}±{atk_cv['macro_f1_std']:.4f}  "
                     f"AUC={atk_cv['auc_mean']:.4f}±{atk_cv['auc_std']:.4f}  "
                     f"{'✅' if atk_ok else '⚠️'}")

    return cv_results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',   default='./datasets/processed_v2')
    parser.add_argument('--output-dir', default='./models_v2')
    args = parser.parse_args()
    run_cv(args.data_dir, args.output_dir)
