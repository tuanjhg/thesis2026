"""
Run Attack-Only Cross Validation (#7)

Uses existing processed_v2 data — NO re-extraction needed.
Filters to attack classes only (1=UDP_Flood, 2=SYN_Flood, 3=HTTP_Flood, 5=Amplification)
to get credible multi-class discrimination metrics unaffected by synthetic Normal.
"""

import numpy as np
import xgboost as xgb
import logging
import json
from pathlib import Path
from pipeline.s3_ai_v2.cross_validation import xgboost_attack_only_cv, check_feature_redundancy

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run(data_dir='./datasets/processed_v2', output_dir='./models_v2'):
    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║   ATTACK-ONLY CV — 4-class multi-class CV       ║")
    logger.info("║   (no synthetic Normal, credible metrics)        ║")
    logger.info("╚══════════════════════════════════════════════════╝")

    X_train = np.load(data_dir / 'X_train.npy').astype(np.float32)
    X_test  = np.load(data_dir / 'X_test.npy').astype(np.float32)
    y_train = np.load(data_dir / 'y_train.npy').astype(int)
    y_test  = np.load(data_dir / 'y_test.npy').astype(int)

    X_all = np.vstack([X_train, X_test])
    y_all = np.hstack([y_train, y_test])

    logger.info(f"Total samples: {len(X_all):,} (all classes)")

    # Check GPU
    try:
        xgb.XGBClassifier(device='cuda', n_estimators=3, verbosity=0).fit(
            np.random.randn(50, 5), np.random.randint(0, 3, 50))
        device = 'cuda'
    except Exception:
        device = 'cpu'
    logger.info(f"Device: {device}")

    # Feature redundancy check on attack samples only
    attack_mask = y_all > 0
    logger.info(f"\nChecking feature redundancy on attack-only subset ({attack_mask.sum():,} samples)...")
    redundant = check_feature_redundancy(X_all[attack_mask], y_all[attack_mask])

    # Run attack-only CV
    atk_cv = xgboost_attack_only_cv(X_all, y_all, n_splits=5, device=device)

    # Save
    out_path = output_dir / 'attack_only_cv_results.json'
    with open(out_path, 'w') as f:
        json.dump({
            'feature_redundancy_attack_subset': [
                {'feat_a': a, 'feat_b': b, 'correlation': float(r)}
                for a, b, r in redundant
            ],
            'attack_only_cv': atk_cv,
        }, f, indent=2, default=str)

    logger.info(f"\n  Results saved: {out_path}")
    logger.info("\n✅ Attack-only CV complete!")
    return atk_cv


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',   default='./datasets/processed_v2')
    parser.add_argument('--output-dir', default='./models_v2')
    args = parser.parse_args()
    run(args.data_dir, args.output_dir)
