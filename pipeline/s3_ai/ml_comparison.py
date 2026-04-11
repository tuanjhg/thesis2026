"""
M2 Track A — ML Model Comparison
XGBoost vs LightGBM vs Random Forest (7-class + binary)

- class_weight='balanced' for RF and LightGBM (handles imbalance without data loss)
- FGSM adversarial augmentation (consistent with XGBoost baseline)
- 5-Fold Stratified CV for each model
- SHAP TreeExplainer for all models
- Saves comparison table to models_v2/ml_comparison.json
"""

import numpy as np
import xgboost as xgb
import lightgbm as lgb
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import logging, json, time, warnings
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler, label_binarize
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, accuracy_score
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CLASS_NAMES = {
    0: "Normal", 1: "UDP_Flood", 2: "SYN_Flood",
    3: "HTTP_Flood", 5: "Amplification",
}

FEATURE_NAMES = [
    "pkt_rate", "byte_rate", "src_ip_entropy", "dst_ip_entropy",
    "src_port_entropy", "dst_port_entropy", "proto_dist_tcp",
    "proto_dist_udp", "proto_dist_icmp", "syn_ratio", "fin_ratio",
    "avg_pkt_size", "pkt_size_std", "new_flows_rate",
    "flow_duration_mean", "inter_arrival_mean", "inter_arrival_std",
]


# ── FGSM ──────────────────────────────────────────────────────────────────
def fgsm_attack(X, epsilon=0.01):
    delta = epsilon * np.sign(np.gradient(X, axis=0))
    return np.clip(X + delta, X.min(axis=0), X.max(axis=0))


def augment_with_fgsm(X, y):
    attack_mask = y > 0
    X_adv = fgsm_attack(X[attack_mask], epsilon=0.01)
    y_adv = y[attack_mask]
    return np.vstack([X, X_adv]), np.hstack([y, y_adv])


# ── Label remap (non-contiguous → contiguous) ─────────────────────────────
def make_label_remap(y):
    labels = sorted(np.unique(y))
    l2i = {l: i for i, l in enumerate(labels)}
    i2l = {i: l for l, i in l2i.items()}
    return l2i, i2l, np.array([l2i[l] for l in y], dtype=np.int32)


# ── Evaluate predictions ──────────────────────────────────────────────────
def evaluate(y_true, y_pred, y_proba, n_train_classes):
    """
    y_true / y_pred are in remapped contiguous space [0..n_train_classes-1].
    y_proba: (N, n_train_classes).
    Only classes present in y_true are used for AUC to avoid NaN.
    """
    acc = float(accuracy_score(y_true, y_pred))
    f1  = float(f1_score(y_true, y_pred, average='macro', zero_division=0))
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            present = np.unique(y_true).tolist()
            if len(present) < 2:
                auc = 0.0
            else:
                yb  = label_binarize(y_true, classes=list(range(n_train_classes)))
                if yb.shape[1] == 1:          # binary edge case
                    auc = float(roc_auc_score(y_true, y_proba[:, 1]))
                else:
                    # use only columns of present classes
                    auc = float(roc_auc_score(
                        yb[:, present], y_proba[:, present],
                        multi_class='ovr', average='macro'))
        except Exception:
            auc = 0.0
    return {'accuracy': acc, 'macro_f1': f1, 'auc_ovr': auc}


# ═══════════════════════════════════════════════════════════════════════════
# XGBoost
# ═══════════════════════════════════════════════════════════════════════════
def train_xgboost(X_tr, y_tr, X_te, y_te, device='cpu'):
    l2i, i2l, y_tr_r = make_label_remap(y_tr)
    _, _, y_te_r      = make_label_remap(np.concatenate([y_tr, y_te]))
    y_te_r = np.array([l2i[l] for l in y_te], dtype=np.int32)
    n_cls  = len(l2i)

    dtrain = xgb.DMatrix(X_tr, label=y_tr_r)
    dtest  = xgb.DMatrix(X_te, label=y_te_r)

    params = {
        'device': device, 'tree_method': 'hist',
        'objective': 'multi:softprob', 'num_class': n_cls,
        'eval_metric': 'mlogloss', 'seed': 42, 'verbosity': 0,
        'max_depth': 8, 'learning_rate': 0.05,
        'subsample': 0.8, 'colsample_bytree': 0.8,
    }
    booster = xgb.train(
        params, dtrain, num_boost_round=300,
        evals=[(dtest, 'eval')],
        callbacks=[xgb.callback.EarlyStopping(rounds=30, save_best=True)],
        verbose_eval=False,
    )
    raw    = booster.predict(dtest).reshape(-1, n_cls)
    y_pred = np.argmax(raw, axis=1)
    metrics = evaluate(y_te_r, y_pred, raw, n_cls)
    return booster, metrics, raw, y_pred, y_te_r


# ═══════════════════════════════════════════════════════════════════════════
# LightGBM
# ═══════════════════════════════════════════════════════════════════════════
def train_lightgbm(X_tr, y_tr, X_te, y_te):
    l2i, i2l, y_tr_r = make_label_remap(y_tr)
    y_te_r = np.array([l2i[l] for l in y_te], dtype=np.int32)
    n_cls  = len(l2i)

    model = lgb.LGBMClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight='balanced',    # handles imbalance without undersampling
        random_state=42,
        verbosity=-1,
        n_jobs=-1,
        objective='multiclass',
        num_class=n_cls,
    )
    model.fit(
        X_tr, y_tr_r,
        eval_set=[(X_te, y_te_r)],
        callbacks=[lgb.early_stopping(30, verbose=False),
                   lgb.log_evaluation(period=-1)],
    )
    proba  = model.predict_proba(X_te)
    y_pred = np.argmax(proba, axis=1)
    metrics = evaluate(y_te_r, y_pred, proba, n_cls)
    return model, metrics, proba, y_pred, y_te_r


# ═══════════════════════════════════════════════════════════════════════════
# Random Forest
# ═══════════════════════════════════════════════════════════════════════════
def train_rf(X_tr, y_tr, X_te, y_te):
    l2i, i2l, y_tr_r = make_label_remap(y_tr)
    y_te_r = np.array([l2i[l] for l in y_te], dtype=np.int32)
    n_cls  = len(l2i)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,             # fully grown trees (RF default)
        min_samples_leaf=2,
        class_weight='balanced',    # handles imbalance without undersampling
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_tr, y_tr_r)
    proba  = model.predict_proba(X_te)
    y_pred = np.argmax(proba, axis=1)
    metrics = evaluate(y_te_r, y_pred, proba, n_cls)
    return model, metrics, proba, y_pred, y_te_r


# ═══════════════════════════════════════════════════════════════════════════
# 5-Fold Stratified CV
# ═══════════════════════════════════════════════════════════════════════════
def run_cv(X_attack, y_attack, X_benign_raw, model_name, device='cpu', n_splits=5):
    """
    Correct CV that avoids BENIGN-oversampling leakage:
    - Split is done on attack + raw (unique) BENIGN windows only
    - Oversampling happens INSIDE each fold on the train split only
    - Test fold contains only unique BENIGN windows → no data leakage
    """
    logger.info(f"\n{'─'*60}")
    logger.info(f"  {model_name} — {n_splits}-Fold Stratified CV (leak-free)")
    logger.info(f"{'─'*60}")

    rng = np.random.default_rng(42)
    n_raw_benign = len(X_benign_raw)
    y_benign_raw = np.zeros(n_raw_benign, dtype=int)

    # Combine attack + raw BENIGN (no oversampling yet)
    X_all = np.vstack([X_attack, X_benign_raw]).astype(np.float32)
    y_all = np.hstack([y_attack, y_benign_raw])

    l2i, i2l, y_all_r = make_label_remap(y_all)
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_results = []

    for fold, (tr_idx, te_idx) in enumerate(skf.split(X_all, y_all_r)):
        X_tr_raw, X_te_raw = X_all[tr_idx], X_all[te_idx]
        y_tr_raw, y_te_raw = y_all[tr_idx], y_all[te_idx]

        # Oversample BENIGN in train fold only (test stays with unique windows)
        benign_tr_mask = y_tr_raw == 0
        X_benign_tr = X_tr_raw[benign_tr_mask]
        n_attack_tr  = (y_tr_raw > 0).sum()
        if len(X_benign_tr) > 0 and len(X_benign_tr) < n_attack_tr:
            idx = rng.choice(len(X_benign_tr), size=n_attack_tr, replace=True)
            X_benign_os = X_benign_tr[idx]
            y_benign_os = np.zeros(n_attack_tr, dtype=int)
            X_tr_raw = np.vstack([X_tr_raw[~benign_tr_mask], X_benign_os])
            y_tr_raw = np.hstack([y_tr_raw[~benign_tr_mask], y_benign_os])

        sc = StandardScaler()
        X_tr = sc.fit_transform(X_tr_raw).astype(np.float32)
        X_te = sc.transform(X_te_raw).astype(np.float32)

        X_tr_aug, y_tr_aug = augment_with_fgsm(X_tr, y_tr_raw)

        t0 = time.time()
        if model_name == 'XGBoost':
            _, m, _, _, _ = train_xgboost(X_tr_aug, y_tr_aug, X_te, y_te_raw, device)
        elif model_name == 'LightGBM':
            _, m, _, _, _ = train_lightgbm(X_tr_aug, y_tr_aug, X_te, y_te_raw)
        else:
            _, m, _, _, _ = train_rf(X_tr_aug, y_tr_aug, X_te, y_te_raw)
        elapsed = time.time() - t0

        m['fold'] = fold + 1
        m['time_s'] = elapsed
        fold_results.append(m)
        logger.info(f"  Fold {fold+1}: ACC={m['accuracy']:.4f}  "
                    f"F1={m['macro_f1']:.4f}  AUC={m['auc_ovr']:.4f}  ({elapsed:.1f}s)")

    accs = [r['accuracy'] for r in fold_results]
    f1s  = [r['macro_f1'] for r in fold_results]
    aucs = [r['auc_ovr'] for r in fold_results]

    summary = {
        'model': model_name,
        'accuracy_mean': float(np.mean(accs)), 'accuracy_std': float(np.std(accs)),
        'macro_f1_mean': float(np.mean(f1s)),  'macro_f1_std': float(np.std(f1s)),
        'auc_mean':      float(np.mean(aucs)), 'auc_std':      float(np.std(aucs)),
        'per_fold': fold_results,
    }
    logger.info(f"\n  {model_name} CV Summary:")
    logger.info(f"    ACC: {summary['accuracy_mean']:.4f} ± {summary['accuracy_std']:.4f}")
    logger.info(f"    F1:  {summary['macro_f1_mean']:.4f} ± {summary['macro_f1_std']:.4f}")
    logger.info(f"    AUC: {summary['auc_mean']:.4f} ± {summary['auc_std']:.4f}")
    return summary


# ═══════════════════════════════════════════════════════════════════════════
# SHAP comparison plot
# ═══════════════════════════════════════════════════════════════════════════
def plot_shap_comparison(models_dict, X_sample, output_dir):
    fig, axes = plt.subplots(1, len(models_dict), figsize=(7 * len(models_dict), 6))
    if len(models_dict) == 1:
        axes = [axes]

    for ax, (name, model) in zip(axes, models_dict.items()):
        try:
            explainer = shap.TreeExplainer(model)
            sv = explainer(X_sample).values
            if sv.ndim == 3:
                mean_shap = np.abs(sv).mean(axis=(0, 2))
            else:
                mean_shap = np.abs(sv).mean(axis=0)
            top_idx = np.argsort(mean_shap)[-10:][::-1]
            ax.barh([FEATURE_NAMES[i] for i in top_idx[::-1]],
                    mean_shap[top_idx[::-1]], color='steelblue')
            ax.set_title(f'{name} — Top 10 SHAP features')
            ax.set_xlabel('Mean |SHAP|')
        except Exception as e:
            ax.set_title(f'{name} — SHAP failed: {e}')

    plt.tight_layout()
    path = output_dir / 'shap_comparison.png'
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    logger.info(f"  Saved: {path}")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════
def run_comparison(data_dir='./datasets/processed_v2', output_dir='./models_v2'):
    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("╔══════════════════════════════════════════════════════╗")
    logger.info("║   ML Comparison: XGBoost vs LightGBM vs RF          ║")
    logger.info("║   class_weight='balanced' for LightGBM & RF         ║")
    logger.info("╚══════════════════════════════════════════════════════╝")

    X_train = np.load(data_dir / 'X_train.npy').astype(np.float32)
    X_test  = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_train = np.load(data_dir / 'y_train.npy').astype(int)
    y_test  = np.load(data_dir / 'y_test.npy').astype(int)

    logger.info(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    logger.info(f"Class distribution (train):")
    for cls_id, cls_name in CLASS_NAMES.items():
        cnt = (y_train == cls_id).sum()
        if cnt > 0:
            logger.info(f"  [{cls_id}] {cls_name:15s}: {cnt:6,} ({cnt/len(y_train)*100:.1f}%)")

    # Check GPU for XGBoost
    try:
        xgb.XGBClassifier(device='cuda', n_estimators=3, verbosity=0).fit(
            np.random.randn(50, 5), np.random.randint(0, 3, 50))
        device = 'cuda'
    except Exception:
        device = 'cpu'
    logger.info(f"XGBoost device: {device}")

    # FGSM augmentation for holdout training
    X_train_aug, y_train_aug = augment_with_fgsm(X_train, y_train)
    logger.info(f"\nFGSM augmented train set: {len(X_train_aug):,} samples")

    # ── Holdout evaluation ────────────────────────────────────────────────
    logger.info("\n" + "═"*60)
    logger.info("HOLDOUT EVALUATION (train=80%, test=20%)")
    logger.info("═"*60)

    holdout_results = {}
    trained_models  = {}

    # XGBoost
    logger.info("\n[1/3] XGBoost...")
    t0 = time.time()
    xgb_model, xgb_metrics, xgb_proba, xgb_pred, y_te_r = train_xgboost(
        X_train_aug, y_train_aug, X_test, y_test, device)
    xgb_metrics['time_s'] = time.time() - t0
    holdout_results['XGBoost'] = xgb_metrics
    trained_models['XGBoost']  = xgb_model
    logger.info(f"  ACC={xgb_metrics['accuracy']:.4f}  "
                f"F1={xgb_metrics['macro_f1']:.4f}  "
                f"AUC={xgb_metrics['auc_ovr']:.4f}  "
                f"({xgb_metrics['time_s']:.1f}s)")

    # LightGBM
    logger.info("\n[2/3] LightGBM (class_weight='balanced')...")
    t0 = time.time()
    lgbm_model, lgbm_metrics, lgbm_proba, lgbm_pred, _ = train_lightgbm(
        X_train_aug, y_train_aug, X_test, y_test)
    lgbm_metrics['time_s'] = time.time() - t0
    holdout_results['LightGBM'] = lgbm_metrics
    trained_models['LightGBM']  = lgbm_model
    logger.info(f"  ACC={lgbm_metrics['accuracy']:.4f}  "
                f"F1={lgbm_metrics['macro_f1']:.4f}  "
                f"AUC={lgbm_metrics['auc_ovr']:.4f}  "
                f"({lgbm_metrics['time_s']:.1f}s)")

    # Random Forest
    logger.info("\n[3/3] Random Forest (class_weight='balanced', n=300)...")
    t0 = time.time()
    rf_model, rf_metrics, rf_proba, rf_pred, _ = train_rf(
        X_train_aug, y_train_aug, X_test, y_test)
    rf_metrics['time_s'] = time.time() - t0
    holdout_results['RandomForest'] = rf_metrics
    trained_models['RandomForest']  = rf_model
    logger.info(f"  ACC={rf_metrics['accuracy']:.4f}  "
                f"F1={rf_metrics['macro_f1']:.4f}  "
                f"AUC={rf_metrics['auc_ovr']:.4f}  "
                f"({rf_metrics['time_s']:.1f}s)")

    # ── Detailed classification report for each model ─────────────────────
    logger.info("\n" + "═"*60)
    logger.info("DETAILED CLASSIFICATION REPORTS")
    logger.info("═"*60)

    # Use the same label remap as the models (built from y_train_aug which has all classes)
    l2i, i2l, y_test_r = make_label_remap(y_train_aug)
    y_test_rr    = np.array([l2i[l] for l in y_test], dtype=np.int32)
    n_cls_all    = len(l2i)
    target_names = [CLASS_NAMES.get(i2l[i], str(i)) for i in range(n_cls_all)]

    for name, pred in [('XGBoost', xgb_pred), ('LightGBM', lgbm_pred), ('RF', rf_pred)]:
        logger.info(f"\n{name}:")
        logger.info(classification_report(y_test_rr, pred,
                                          target_names=target_names,
                                          labels=list(range(n_cls_all)),
                                          digits=4, zero_division=0))

    # ── 5-Fold CV for all models ──────────────────────────────────────────
    logger.info("\n" + "═"*60)
    logger.info("5-FOLD STRATIFIED CROSS VALIDATION (leak-free)")
    logger.info("  Oversampling done inside each fold on train split only")
    logger.info("═"*60)

    # Load raw (unique) BENIGN windows — 646 windows, no repetition
    benign_raw_path = data_dir / 'X_benign_raw.npy'
    if benign_raw_path.exists():
        X_benign_raw = np.load(benign_raw_path).astype(np.float32)
        logger.info(f"  Raw BENIGN windows: {len(X_benign_raw):,} (unique, no oversampling)")
    else:
        # Fallback: extract unique BENIGN windows from combined data
        X_all_tmp = np.vstack([X_train, X_test])
        y_all_tmp = np.hstack([y_train, y_test])
        X_benign_raw = X_all_tmp[y_all_tmp == 0]
        logger.warning(f"  X_benign_raw.npy not found — using {len(X_benign_raw):,} "
                       f"BENIGN windows from data (may include oversampled copies)")

    # Attack samples only (no BENIGN) from combined train+test
    X_all_tmp = np.vstack([X_train, X_test])
    y_all_tmp = np.hstack([y_train, y_test])
    attack_mask = y_all_tmp > 0
    X_attack_all = X_all_tmp[attack_mask]
    y_attack_all = y_all_tmp[attack_mask]
    logger.info(f"  Attack windows: {len(X_attack_all):,}")

    cv_results = {}
    cv_results['XGBoost']      = run_cv(X_attack_all, y_attack_all, X_benign_raw, 'XGBoost',  device)
    cv_results['LightGBM']     = run_cv(X_attack_all, y_attack_all, X_benign_raw, 'LightGBM')
    cv_results['RandomForest'] = run_cv(X_attack_all, y_attack_all, X_benign_raw, 'RandomForest')

    # ── Comparison summary table ──────────────────────────────────────────
    logger.info("\n" + "═"*60)
    logger.info("COMPARISON TABLE — CV Results")
    logger.info("═"*60)
    logger.info(f"  {'Model':15s} {'ACC':>14s} {'F1 Macro':>14s} {'AUC OvR':>14s}")
    logger.info("  " + "─"*57)
    for name, cv in cv_results.items():
        logger.info(f"  {name:15s} "
                    f"{cv['accuracy_mean']:.4f}±{cv['accuracy_std']:.4f}  "
                    f"{cv['macro_f1_mean']:.4f}±{cv['macro_f1_std']:.4f}  "
                    f"{cv['auc_mean']:.4f}±{cv['auc_std']:.4f}")

    # ── SHAP comparison plot ──────────────────────────────────────────────
    logger.info("\nGenerating SHAP comparison plot...")
    X_sample = X_test[:500]
    plot_shap_comparison(trained_models, X_sample, output_dir)

    # ── Inference latency comparison ──────────────────────────────────────
    logger.info("\nInference latency (100 samples, 200 runs):")
    X_bench_xgb = xgb.DMatrix(X_test[:100])
    X_bench     = X_test[:100]

    latency_results = {}
    for name, fn in [
        ('XGBoost',  lambda: xgb_model.predict(X_bench_xgb)),
        ('LightGBM', lambda: lgbm_model.predict_proba(X_bench)),
        ('RF',       lambda: rf_model.predict_proba(X_bench)),
    ]:
        times = []
        for _ in range(200):
            t0 = time.time()
            fn()
            times.append((time.time() - t0) * 1000)
        lat = {
            'p50_ms': float(np.percentile(times, 50)),
            'p95_ms': float(np.percentile(times, 95)),
            'p99_ms': float(np.percentile(times, 99)),
        }
        latency_results[name] = lat
        logger.info(f"  {name:15s}: P50={lat['p50_ms']:.2f}ms  P99={lat['p99_ms']:.2f}ms")

    # ── Save ──────────────────────────────────────────────────────────────
    output = {
        'holdout': holdout_results,
        'cv':      cv_results,
        'latency': latency_results,
        'note':    'class_weight=balanced used in LightGBM and RF (no undersampling)',
    }
    out_path = output_dir / 'ml_comparison.json'
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    logger.info(f"\n  Saved: {out_path}")
    logger.info("\n✅ ML comparison complete!")
    return output


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',   default='./datasets/processed_v2')
    parser.add_argument('--output-dir', default='./models_v2')
    args = parser.parse_args()
    run_comparison(args.data_dir, args.output_dir)
