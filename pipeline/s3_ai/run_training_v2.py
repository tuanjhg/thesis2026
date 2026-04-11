"""
M2 — Master Training Script (Spec-aligned, v2)
Runs the full pipeline:
  Step 1: Feature extraction (17 entropy features from CICDDoS2019)
  Step 2: XGBoost 7-class + FGSM adversarial training
  Step 3: Transformer+LSTM 4-horizon forecast training
  Step 4: AI Output smoke test

Usage:
  python run_training_v2.py --data-dir ./Dataset --output-dir ./output_v2
  python run_training_v2.py --skip-extract  # if processed_v2/ already exists
  python run_training_v2.py --step xgboost  # run only one step
"""

import argparse
import logging
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║         PAD-ONAP — M2 AI Training Pipeline (v2)             ║
║         Spec-aligned: 17 features, 7 classes, 4 horizons    ║
╚══════════════════════════════════════════════════════════════╝
"""


def step_extract(data_dir: str, processed_dir: str, args) -> bool:
    logger.info("\n" + "═"*60)
    logger.info("STEP 1/3 — Feature Extraction (17 entropy features)")
    logger.info("═"*60)
    try:
        from pipeline.s3_ai_v2.feature_extractor import build_dataset
        build_dataset(
            data_dir=data_dir,
            output_dir=processed_dir,
            samples_per_file=args.samples_per_file,
            window_size=args.window_size,
            step=args.step,
        )
        return True
    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        return False


def step_xgboost(processed_dir: str, models_dir: str) -> bool:
    logger.info("\n" + "═"*60)
    logger.info("STEP 2/3 — XGBoost 7-class + FGSM Adversarial")
    logger.info("═"*60)
    try:
        from pipeline.s3_ai_v2.xgboost_7class import run_training
        model, metrics = run_training(
            data_dir=processed_dir,
            output_dir=models_dir,
        )
        logger.info(f"\nXGBoost results: {metrics}")
        return True
    except Exception as e:
        logger.error(f"XGBoost training failed: {e}")
        return False


def step_transformer(processed_dir: str, models_dir: str, args) -> bool:
    logger.info("\n" + "═"*60)
    logger.info("STEP 3/3 — Transformer+LSTM 4-horizon Forecast")
    logger.info("═"*60)
    try:
        from pipeline.s3_ai_v2.transformer_lstm import run_training
        model, metrics = run_training(
            data_dir=processed_dir,
            output_dir=models_dir,
        )
        logger.info(f"\nTransformer results: {metrics}")
        return True
    except Exception as e:
        logger.error(f"Transformer training failed: {e}")
        return False


def step_smoke_test() -> bool:
    logger.info("\n" + "═"*60)
    logger.info("SMOKE TEST — AI Output JSON schema")
    logger.info("═"*60)
    try:
        import numpy as np
        from pipeline.s3_ai_v2.ai_output import build_output, payload_to_json

        fake_class_probs = np.array([0.01, 0.01, 0.92, 0.02, 0.0, 0.03, 0.01])
        fake_forecast    = [0.88, 0.82, 0.75, 0.68]
        fake_shap        = {"syn_ratio": 0.45, "pkt_rate": 0.22}

        payload = build_output(
            window_id=0,
            class_probs=fake_class_probs,
            forecast=fake_forecast,
            top_features=fake_shap,
        )

        json_str = payload_to_json(payload)
        logger.info("Sample AI output payload:")
        logger.info(json_str)

        assert payload.proactive_trigger.triggered is True
        assert payload.detection.attack_type == "SYN_Flood"
        logger.info("✅ Smoke test passed")
        return True
    except Exception as e:
        logger.error(f"Smoke test failed: {e}")
        return False


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description='PAD-ONAP M2 v2 training pipeline')
    parser.add_argument('--data-dir',         default='./Dataset',
                        help='Path to CICDDoS2019 Dataset folder')
    parser.add_argument('--output-dir',       default='./output_v2',
                        help='Root output directory')
    parser.add_argument('--skip-extract',     action='store_true',
                        help='Skip feature extraction (use existing processed_v2)')
    parser.add_argument('--step',             choices=['extract', 'xgboost', 'transformer', 'all'],
                        default='all', help='Run only a specific step')
    parser.add_argument('--samples-per-file', type=int, default=50000)
    parser.add_argument('--window-size',      type=int, default=100)
    parser.add_argument('--step-size',        type=int, default=50, dest='step')
    args = parser.parse_args()

    output_dir    = Path(args.output_dir)
    processed_dir = str(output_dir / 'processed_v2')
    models_dir    = str(output_dir / 'models_v2')

    output_dir.mkdir(parents=True, exist_ok=True)
    Path(processed_dir).mkdir(parents=True, exist_ok=True)
    Path(models_dir).mkdir(parents=True, exist_ok=True)

    t_start  = time.time()
    results  = {}
    run_step = args.step

    # Step 1 — Feature Extraction
    if not args.skip_extract and run_step in ('all', 'extract'):
        results['extract'] = step_extract(args.data_dir, processed_dir, args)
        if not results['extract'] and run_step == 'all':
            logger.error("Aborting pipeline: feature extraction failed")
            sys.exit(1)
    else:
        logger.info("\n[Step 1/3] Feature extraction SKIPPED (using existing data)")

    # Smoke test (always runs unless --step != all)
    if run_step == 'all':
        step_smoke_test()

    # Step 2 — XGBoost
    if run_step in ('all', 'xgboost'):
        results['xgboost'] = step_xgboost(processed_dir, models_dir)

    # Step 3 — Transformer+LSTM
    if run_step in ('all', 'transformer'):
        results['transformer'] = step_transformer(processed_dir, models_dir, args)

    # ── Summary ────────────────────────────────────────────────────────────────
    elapsed = time.time() - t_start
    logger.info("\n" + "═"*60)
    logger.info("PIPELINE SUMMARY")
    logger.info("═"*60)
    for step_name, ok in results.items():
        status = "✅ PASS" if ok else "❌ FAIL"
        logger.info(f"  {step_name:20s}: {status}")
    logger.info(f"\n  Total elapsed: {elapsed/60:.1f} min")
    logger.info(f"  Models saved:  {models_dir}")
    logger.info(f"  Data saved:    {processed_dir}")

    all_ok = all(results.values())
    if all_ok:
        logger.info("\n🎉 All pipeline steps completed successfully!")
    else:
        logger.warning("\n⚠️  Some steps failed — check logs above.")
        sys.exit(1)


if __name__ == '__main__':
    main()
