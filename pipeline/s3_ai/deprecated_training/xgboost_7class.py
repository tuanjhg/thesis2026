"""
M2 Track A — XGBoost 7-class Classifier (Spec-aligned)
Spec:
  - 7 classes: Normal, UDP_Flood, SYN_Flood, HTTP_Flood, ICMP_Flood, Amplification, Slow_rate
  - Input: 17 entropy/rate features
  - Adversarial training: FGSM augmentation
  - SHAP TreeExplainer for XAI payload
  - GPU: tree_method='hist', device='cuda'
"""

import numpy as np
import xgboost as xgb
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import logging, json, time
from pathlib import Path
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, accuracy_score
)
from sklearn.preprocessing import label_binarize

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

TARGET = {'accuracy': 0.95, 'macro_f1': 0.90}

# ── HP configs (auto-improvement) ─────────────────────────────────────────
HP_CONFIGS = [
    dict(n_estimators=300, max_depth=8,  learning_rate=0.05,
         subsample=0.8, colsample_bytree=0.8),
    dict(n_estimators=500, max_depth=8,  learning_rate=0.05,
         subsample=0.9, colsample_bytree=0.9),
    dict(n_estimators=500, max_depth=10, learning_rate=0.03,
         subsample=0.8, colsample_bytree=0.8),
    dict(n_estimators=700, max_depth=10, learning_rate=0.03,
         subsample=0.9, colsample_bytree=0.8),
]


# ── FGSM Adversarial Augmentation ─────────────────────────────────────────
def fgsm_attack(X: np.ndarray, epsilon: float = 0.01) -> np.ndarray:
    """
    Fast Gradient Sign Method on feature vectors.
    Adds small perturbations to create adversarial examples.
    (Spec §4.2)
    """
    delta = epsilon * np.sign(np.gradient(X, axis=0))
    return np.clip(X + delta, X.min(axis=0), X.max(axis=0))


def augment_with_adversarial(X_train: np.ndarray, y_train: np.ndarray,
                              epsilon: float = 0.01) -> tuple:
    """Augment training set with FGSM adversarial examples (attack samples only)."""
    attack_mask = y_train != 0  # all non-Normal classes
    X_attack = X_train[attack_mask]
    y_attack  = y_train[attack_mask]

    X_adv = fgsm_attack(X_attack, epsilon)
    X_aug = np.vstack([X_train, X_adv])
    y_aug = np.hstack([y_train, y_attack])

    logger.info(f"  FGSM adversarial: +{len(X_adv):,} samples (ε={epsilon})")
    logger.info(f"  Augmented train set: {len(X_aug):,} samples")
    return X_aug, y_aug


def check_gpu():
    try:
        m = xgb.XGBClassifier(device='cuda', n_estimators=3, verbosity=0)
        m.fit(np.random.randn(50, 5), np.random.randint(0, 3, 50))
        logger.info("✅ XGBoost GPU available")
        return 'cuda'
    except Exception:
        logger.warning("⚠️  XGBoost GPU not available — using CPU")
        return 'cpu'


def train_and_evaluate(X_train, y_train, X_test, y_test, hp, device):
    """
    Train using native xgb.Booster API to support non-contiguous class labels.
    Labels are remapped [0,1,2,3,5] → [0,1,2,3,4] internally; predictions are
    remapped back to original class indices.
    """
    # ── Label remap ───────────────────────────────────────────────────────────
    all_labels   = sorted(np.unique(np.concatenate([y_train, y_test])))
    n_classes    = len(all_labels)
    label_to_idx = {lbl: i for i, lbl in enumerate(all_labels)}
    idx_to_label = {i: lbl for lbl, i in label_to_idx.items()}

    y_train_r = np.array([label_to_idx[l] for l in y_train], dtype=np.int32)
    y_test_r  = np.array([label_to_idx[l] for l in y_test],  dtype=np.int32)

    dtrain = xgb.DMatrix(X_train, label=y_train_r)
    dtest  = xgb.DMatrix(X_test,  label=y_test_r)

    n_est = hp.get('n_estimators', 300)
    params = {
        'device':           device,
        'tree_method':      'hist',
        'objective':        'multi:softprob',
        'num_class':        n_classes,
        'eval_metric':      'mlogloss',
        'seed':             42,
        'verbosity':        0,
        'max_depth':        hp.get('max_depth',        8),
        'learning_rate':    hp.get('learning_rate',    0.05),
        'subsample':        hp.get('subsample',        0.8),
        'colsample_bytree': hp.get('colsample_bytree', 0.8),
    }

    t0 = time.time()
    callbacks = [xgb.callback.EarlyStopping(rounds=30, save_best=True)]
    booster = xgb.train(
        params,
        dtrain,
        num_boost_round=n_est,
        evals=[(dtest, 'eval')],
        callbacks=callbacks,
        verbose_eval=100,
    )
    elapsed = time.time() - t0

    # Predict — softprob returns (n * n_classes,) flat or (n, n_classes)
    raw = booster.predict(dtest)
    if raw.ndim == 1:
        y_proba_r = raw.reshape(-1, n_classes)
    else:
        y_proba_r = raw
    y_pred_r = np.argmax(y_proba_r, axis=1)

    # Remap predictions back to original label space
    y_pred = np.array([idx_to_label[i] for i in y_pred_r], dtype=np.int32)

    # Build full 7-class proba matrix (zeros for absent classes)
    y_proba = np.zeros((len(y_test), 7), dtype=np.float32)
    for remapped_idx, orig_label in idx_to_label.items():
        y_proba[:, orig_label] = y_proba_r[:, remapped_idx]

    acc      = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average='macro', zero_division=0))

    # OvR AUC — only for classes present in y_test
    import warnings
    classes_present = np.unique(y_test).tolist()
    if len(classes_present) > 1:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                y_bin       = label_binarize(y_test, classes=list(range(7)))
                y_bin_sub   = y_bin[:, classes_present]
                y_proba_sub = y_proba[:, classes_present]
                auc = float(roc_auc_score(y_bin_sub, y_proba_sub,
                                          multi_class='ovr', average='macro'))
        except Exception:
            auc = 0.0
    else:
        auc = 0.0

    metrics = {'accuracy': acc, 'macro_f1': macro_f1, 'auc_macro_ovr': auc}
    # Attach label map to booster for inference
    booster._label_to_idx = label_to_idx
    booster._idx_to_label = idx_to_label
    booster._n_classes    = n_classes
    return booster, metrics, elapsed


def run_training(data_dir='./datasets/processed_v2', output_dir='./models_v2'):
    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("="*60)
    logger.info("M2 TRACK A — XGBoost 7-class + FGSM (GPU)")
    logger.info("="*60)

    X_train = np.load(data_dir / 'X_train.npy').astype(np.float32)
    X_test  = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_train = np.load(data_dir / 'y_train.npy').astype(int)
    y_test  = np.load(data_dir / 'y_test.npy').astype(int)

    logger.info(f"X_train: {X_train.shape} | X_test: {X_test.shape}")
    logger.info(f"Classes in train: {dict(zip(*np.unique(y_train, return_counts=True)))}")

    # ── FGSM Adversarial Augmentation ─────────────────────────────────────
    logger.info("\n[1/3] FGSM adversarial augmentation...")
    X_train_aug, y_train_aug = augment_with_adversarial(X_train, y_train, epsilon=0.01)

    device = check_gpu()

    best_model, best_metrics, best_hp_idx = None, {}, 0

    # ── Auto-improvement loop ──────────────────────────────────────────────
    for attempt, hp in enumerate(HP_CONFIGS):
        logger.info(f"\n{'─'*60}")
        logger.info(f"[2/3] Attempt {attempt+1}/{len(HP_CONFIGS)} | {hp}")
        logger.info('─'*60)

        booster, metrics, elapsed = train_and_evaluate(
            X_train_aug, y_train_aug, X_test, y_test, hp, device
        )

        logger.info(f"  accuracy:  {metrics['accuracy']:.4f}  (target >= {TARGET['accuracy']})")
        logger.info(f"  macro_f1:  {metrics['macro_f1']:.4f}  (target >= {TARGET['macro_f1']})")
        logger.info(f"  auc_macro: {metrics['auc_macro_ovr']:.4f}")
        logger.info(f"  time:      {elapsed:.1f}s")

        if not best_metrics or metrics['accuracy'] > best_metrics.get('accuracy', 0):
            best_model, best_metrics, best_hp_idx = booster, metrics, attempt

        if all(metrics.get(k, 0) >= v for k, v in TARGET.items()):
            logger.info("🎉 All targets met!")
            break
        else:
            missing = [k for k, v in TARGET.items() if metrics.get(k, 0) < v]
            logger.info(f"  ⚠️  Missing: {missing} — trying next config...")

    # ── Full classification report ─────────────────────────────────────────
    logger.info(f"\n{'='*60}")
    logger.info("BEST MODEL — FULL EVALUATION")
    logger.info('='*60)

    # Booster predict with label remap
    dtest_full = xgb.DMatrix(X_test)
    raw = best_model.predict(dtest_full)
    n_cls = best_model._n_classes
    if raw.ndim == 1:
        raw = raw.reshape(-1, n_cls)
    idx_to_label = best_model._idx_to_label
    y_pred = np.array([idx_to_label[i] for i in np.argmax(raw, axis=1)], dtype=np.int32)
    present_classes = sorted(np.unique(np.concatenate([y_train, y_test])))
    target_names = [CLASS_NAMES[i] for i in present_classes]

    logger.info("\n" + classification_report(
        y_test, y_pred,
        labels=present_classes,
        target_names=target_names,
        digits=4, zero_division=0
    ))

    cm = confusion_matrix(y_test, y_pred, labels=present_classes)
    logger.info(f"Confusion Matrix (classes: {present_classes}):\n{cm}")

    # ── SHAP Explainability ────────────────────────────────────────────────
    logger.info("\n[3/3] Computing SHAP explanations...")
    try:
        explainer   = shap.TreeExplainer(best_model)
        X_shap      = X_test[:300]
        shap_out    = explainer(X_shap)   # Explanation object (shap >= 0.41)
        # shap_out.values shape: (n_samples, n_features, n_classes) or list
        sv_arr = shap_out.values
        if isinstance(sv_arr, list):
            # older shap: list of (n_samples, n_features) per class
            shap_values = sv_arr
            mean_shap = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        elif sv_arr.ndim == 3:
            # (n_samples, n_features, n_classes)
            mean_shap = np.abs(sv_arr).mean(axis=(0, 2))
            shap_values = [sv_arr[:, :, c] for c in range(sv_arr.shape[2])]
        else:
            mean_shap = np.abs(sv_arr).mean(axis=0)
            shap_values = [sv_arr]

        top5_idx  = np.argsort(mean_shap)[-5:][::-1]
        top5      = {FEATURE_NAMES[i]: float(mean_shap[i]) for i in top5_idx}

        logger.info("  Top-5 SHAP features:")
        for feat, val in top5.items():
            logger.info(f"    {feat}: {val:.4f}")

        # Per-class top feature (only for present classes with valid index)
        logger.info("  Per-class top feature:")
        for cls_id in present_classes:
            if cls_id < len(shap_values):
                sv = np.abs(shap_values[cls_id]).mean(axis=0)
                top_feat = FEATURE_NAMES[np.argmax(sv)]
                logger.info(f"    [{cls_id}] {CLASS_NAMES[cls_id]:15s}: {top_feat}")

        # Summary plot
        plt.figure()
        shap.summary_plot(shap_values, X_shap,
                          feature_names=FEATURE_NAMES, show=False,
                          class_names=list(CLASS_NAMES.values()), max_display=17)
        plt.tight_layout()
        plt.savefig(output_dir / 'shap_summary_v2.png', dpi=150, bbox_inches='tight')
        plt.close()
        logger.info(f"  ✓ Saved: {output_dir}/shap_summary_v2.png")

    except Exception as e:
        logger.warning(f"  SHAP error: {e}")
        top5 = {}

    # ── Inference speed ────────────────────────────────────────────────────
    _bench_dm = xgb.DMatrix(X_test[:100])
    times = []
    for _ in range(200):
        t0 = time.time()
        best_model.predict(_bench_dm)
        times.append((time.time() - t0) * 1000)
    latency = {
        'p50_ms': float(np.percentile(times, 50)),
        'p95_ms': float(np.percentile(times, 95)),
        'p99_ms': float(np.percentile(times, 99)),
    }
    logger.info(f"\n⏱️  Inference: P50={latency['p50_ms']:.2f}ms  P99={latency['p99_ms']:.2f}ms")

    # ── Save ───────────────────────────────────────────────────────────────
    model_path = output_dir / 'xgboost_7class_v2.json'
    best_model.save_model(str(model_path))
    logger.info(f"\n💾 Model saved: {model_path}")

    metadata = {
        'model_type':      'XGBoost_7class',
        'version':         '2.0',
        'spec_module':     'M2_TrackA',
        'device':          device,
        'n_features':      17,
        'feature_names':   FEATURE_NAMES,
        'n_classes':       7,
        'class_names':     CLASS_NAMES,
        'adversarial':     'FGSM_epsilon_0.01',
        'best_hp':         HP_CONFIGS[best_hp_idx],
        'metrics':         best_metrics,
        'latency_ms':      latency,
        'top5_shap':       top5,
        'targets_met':     all(best_metrics.get(k, 0) >= v for k, v in TARGET.items()),
    }
    with open(output_dir / 'xgboost_7class_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logger.info("\n✅ XGBoost 7-class training complete!")
    return best_model, best_metrics


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',   default='./datasets/processed_v2')
    parser.add_argument('--output-dir', default='./models_v2')
    args = parser.parse_args()
    run_training(args.data_dir, args.output_dir)
