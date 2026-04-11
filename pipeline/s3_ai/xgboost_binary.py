"""
M2 Track A — XGBoost Binary Classifier (Normal vs Attack)
+ Stratified 5-Fold Cross Validation
+ FGSM adversarial augmentation
+ SHAP TreeExplainer

Complements the 7-class model by providing a robust binary detection baseline.
"""

import numpy as np
import xgboost as xgb
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import logging, json, time, warnings
from pathlib import Path
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, accuracy_score, roc_curve
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "pkt_rate", "byte_rate", "src_ip_entropy", "dst_ip_entropy",
    "src_port_entropy", "dst_port_entropy", "proto_dist_tcp",
    "proto_dist_udp", "proto_dist_icmp", "syn_ratio", "fin_ratio",
    "avg_pkt_size", "pkt_size_std", "new_flows_rate",
    "flow_duration_mean", "inter_arrival_mean", "inter_arrival_std",
]

TARGET = {'accuracy': 0.95, 'f1': 0.93, 'auc': 0.97}

HP = dict(max_depth=8, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8)


def fgsm_attack(X, epsilon=0.01):
    delta = epsilon * np.sign(np.gradient(X, axis=0))
    return np.clip(X + delta, X.min(axis=0), X.max(axis=0))


def check_gpu():
    try:
        m = xgb.XGBClassifier(device='cuda', n_estimators=3, verbosity=0)
        m.fit(np.random.randn(50, 5), np.random.randint(0, 2, 50))
        return 'cuda'
    except Exception:
        return 'cpu'


def train_binary(X_train, y_train, X_test, y_test, device, n_est=300):
    """Train single binary XGBoost and return booster + metrics."""
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest  = xgb.DMatrix(X_test,  label=y_test)

    params = {
        'device':           device,
        'tree_method':      'hist',
        'objective':        'binary:logistic',
        'eval_metric':      'logloss',
        'seed':             42,
        'verbosity':        0,
        **HP,
    }

    callbacks = [xgb.callback.EarlyStopping(rounds=30, save_best=True)]
    booster = xgb.train(
        params, dtrain,
        num_boost_round=n_est,
        evals=[(dtest, 'eval')],
        callbacks=callbacks,
        verbose_eval=False,
    )

    y_proba = booster.predict(dtest)
    y_pred  = (y_proba > 0.5).astype(int)

    acc = float(accuracy_score(y_test, y_pred))
    f1  = float(f1_score(y_test, y_pred, zero_division=0))
    try:
        auc = float(roc_auc_score(y_test, y_proba))
    except Exception:
        auc = 0.0

    return booster, y_proba, {'accuracy': acc, 'f1': f1, 'auc': auc}


def run_training(data_dir='./datasets/processed_v2', output_dir='./models_v2'):
    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("="*60)
    logger.info("M2 TRACK A — XGBoost BINARY (Normal vs Attack)")
    logger.info("="*60)

    X_train = np.load(data_dir / 'X_train.npy').astype(np.float32)
    X_test  = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_train_mc = np.load(data_dir / 'y_train.npy').astype(int)
    y_test_mc  = np.load(data_dir / 'y_test.npy').astype(int)

    # Binary: 0=Normal, 1=Attack (any class > 0)
    y_train = (y_train_mc > 0).astype(int)
    y_test  = (y_test_mc  > 0).astype(int)

    logger.info(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    logger.info(f"Train: Normal={int((y_train==0).sum()):,}  Attack={int((y_train==1).sum()):,}")
    logger.info(f"Test:  Normal={int((y_test==0).sum()):,}  Attack={int((y_test==1).sum()):,}")

    # ── FGSM Adversarial Augmentation ─────────────────────────────────────
    logger.info("\n[1/4] FGSM adversarial augmentation...")
    attack_mask = y_train == 1
    X_adv = fgsm_attack(X_train[attack_mask], epsilon=0.01)
    X_train_aug = np.vstack([X_train, X_adv])
    y_train_aug = np.hstack([y_train, np.ones(len(X_adv), dtype=int)])
    logger.info(f"  +{len(X_adv):,} adversarial attack samples")
    logger.info(f"  Augmented: {len(X_train_aug):,} total")

    device = check_gpu()
    logger.info(f"  Device: {device}")

    # ── Train on holdout split ────────────────────────────────────────────
    logger.info("\n[2/4] Training on holdout split...")
    booster, y_proba, metrics = train_binary(
        X_train_aug, y_train_aug, X_test, y_test, device, n_est=300
    )
    y_pred = (y_proba > 0.5).astype(int)

    logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
    logger.info(f"  F1:       {metrics['f1']:.4f}")
    logger.info(f"  AUC:      {metrics['auc']:.4f}")

    logger.info("\n" + classification_report(
        y_test, y_pred,
        target_names=["Normal", "Attack"],
        digits=4, zero_division=0
    ))

    cm = confusion_matrix(y_test, y_pred)
    logger.info(f"Confusion Matrix:\n{cm}")
    tn, fp, fn, tp = cm.ravel()
    logger.info(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    logger.info(f"  FPR={fp/(fp+tn):.4f}  FNR={fn/(fn+tp):.4f}")

    # ── 5-Fold Stratified CV ──────────────────────────────────────────────
    logger.info(f"\n[3/4] Stratified 5-Fold Cross Validation...")
    X_all = np.vstack([X_train, X_test])
    y_all = np.hstack([y_train, y_test])

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = []

    for fold, (tr_idx, te_idx) in enumerate(skf.split(X_all, y_all)):
        X_tr, X_te = X_all[tr_idx], X_all[te_idx]
        y_tr, y_te = y_all[tr_idx], y_all[te_idx]

        # Scale per-fold
        sc = StandardScaler()
        X_tr_s = sc.fit_transform(X_tr).astype(np.float32)
        X_te_s = sc.transform(X_te).astype(np.float32)

        # FGSM augment
        atk = y_tr == 1
        X_adv_cv = fgsm_attack(X_tr_s[atk], epsilon=0.01)
        X_tr_aug = np.vstack([X_tr_s, X_adv_cv])
        y_tr_aug = np.hstack([y_tr, np.ones(len(X_adv_cv), dtype=int)])

        _, _, fold_m = train_binary(X_tr_aug, y_tr_aug, X_te_s, y_te, device, n_est=300)
        cv_results.append(fold_m)
        logger.info(f"  Fold {fold+1}: ACC={fold_m['accuracy']:.4f}  "
                     f"F1={fold_m['f1']:.4f}  AUC={fold_m['auc']:.4f}")

    accs = [r['accuracy'] for r in cv_results]
    f1s  = [r['f1'] for r in cv_results]
    aucs = [r['auc'] for r in cv_results]

    cv_summary = {
        'accuracy': f"{np.mean(accs):.4f} ± {np.std(accs):.4f}",
        'f1':       f"{np.mean(f1s):.4f} ± {np.std(f1s):.4f}",
        'auc':      f"{np.mean(aucs):.4f} ± {np.std(aucs):.4f}",
        'per_fold': cv_results,
    }
    logger.info(f"\n  CV Accuracy: {np.mean(accs):.4f} ± {np.std(accs):.4f}")
    logger.info(f"  CV F1:       {np.mean(f1s):.4f} ± {np.std(f1s):.4f}")
    logger.info(f"  CV AUC:      {np.mean(aucs):.4f} ± {np.std(aucs):.4f}")

    # ── SHAP ──────────────────────────────────────────────────────────────
    logger.info("\n[4/4] SHAP explanations...")
    try:
        explainer = shap.TreeExplainer(booster)
        X_shap    = X_test[:500]
        shap_out  = explainer(X_shap)
        sv = shap_out.values
        if sv.ndim == 2:
            mean_shap = np.abs(sv).mean(axis=0)
        else:
            mean_shap = np.abs(sv).mean(axis=(0, 2)) if sv.ndim == 3 else np.abs(sv).mean(axis=0)

        top5_idx = np.argsort(mean_shap)[-5:][::-1]
        top5 = {FEATURE_NAMES[i]: float(mean_shap[i]) for i in top5_idx}
        logger.info("  Top-5 SHAP features:")
        for feat, val in top5.items():
            logger.info(f"    {feat}: {val:.4f}")

        plt.figure(figsize=(10, 6))
        shap.summary_plot(shap_out, X_shap, feature_names=FEATURE_NAMES,
                          show=False, max_display=17)
        plt.tight_layout()
        plt.savefig(output_dir / 'shap_binary_v2.png', dpi=150, bbox_inches='tight')
        plt.close()
        logger.info(f"  Saved: {output_dir}/shap_binary_v2.png")
    except Exception as e:
        logger.warning(f"  SHAP error: {e}")
        top5 = {}

    # ── ROC Curve ─────────────────────────────────────────────────────────
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    plt.figure(figsize=(6, 6))
    plt.plot(fpr, tpr, 'b-', lw=2, label=f"AUC={metrics['auc']:.4f}")
    plt.plot([0, 1], [0, 1], 'k--', lw=1)
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve — Binary XGBoost (Normal vs Attack)')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / 'roc_binary_v2.png', dpi=150)
    plt.close()
    logger.info(f"  Saved: {output_dir}/roc_binary_v2.png")

    # ── Inference speed ───────────────────────────────────────────────────
    dm_bench = xgb.DMatrix(X_test[:100])
    times = []
    for _ in range(200):
        t0 = time.time()
        booster.predict(dm_bench)
        times.append((time.time() - t0) * 1000)
    latency = {
        'p50_ms': float(np.percentile(times, 50)),
        'p95_ms': float(np.percentile(times, 95)),
        'p99_ms': float(np.percentile(times, 99)),
    }
    logger.info(f"\n  Inference: P50={latency['p50_ms']:.2f}ms  P99={latency['p99_ms']:.2f}ms")

    # ── Save ──────────────────────────────────────────────────────────────
    model_path = output_dir / 'xgboost_binary_v2.json'
    booster.save_model(str(model_path))
    logger.info(f"\n  Model saved: {model_path}")

    metadata = {
        'model_type':    'XGBoost_binary',
        'version':       '2.0',
        'task':          'Normal_vs_Attack',
        'device':        device,
        'n_features':    17,
        'feature_names': FEATURE_NAMES,
        'adversarial':   'FGSM_epsilon_0.01',
        'holdout_metrics': metrics,
        'cv_summary':    cv_summary,
        'latency_ms':    latency,
        'top5_shap':     top5,
        'confusion':     {'TP': int(tp), 'FP': int(fp), 'TN': int(tn), 'FN': int(fn)},
    }
    with open(output_dir / 'xgboost_binary_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logger.info("\n✅ XGBoost binary training + CV complete!")
    return booster, metrics, cv_summary


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',   default='./datasets/processed_v2')
    parser.add_argument('--output-dir', default='./models_v2')
    args = parser.parse_args()
    run_training(args.data_dir, args.output_dir)
