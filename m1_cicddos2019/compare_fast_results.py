from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare fast-model evaluation artifacts")
    parser.add_argument("--artifacts-dir", type=str, default="./artifacts")
    parser.add_argument("--models", type=str, default="m1_tcn_fast,m1_lstm_fast")
    parser.add_argument("--out-dir", type=str, default="./artifacts/fast_comparison")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model_names = [m.strip() for m in args.models.split(",") if m.strip()]
    summary_rows = []
    sweep_frames = []

    for model_name in model_names:
        model_dir = artifacts_dir / model_name
        metrics_path = model_dir / "eval_metrics.json"
        sweep_path = model_dir / "eval_threshold_sweep.csv"

        if not metrics_path.exists() or not sweep_path.exists():
            print(f"[WARN] Missing eval files for {model_name}, skipping")
            continue

        metrics_df = pd.read_json(metrics_path, typ="series").to_frame().T
        metrics_df.insert(0, "model", model_name)
        summary_rows.append(metrics_df)

        sweep_df = pd.read_csv(sweep_path)
        sweep_df.insert(0, "model", model_name)
        sweep_frames.append(sweep_df)

    if not summary_rows:
        raise RuntimeError("No valid model eval artifacts found for comparison")

    summary_df = pd.concat(summary_rows, ignore_index=True)
    ordered_cols = [
        "model",
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "pr_auc",
        "fpr",
        "tp",
        "fp",
        "tn",
        "fn",
    ]
    summary_df = summary_df[[c for c in ordered_cols if c in summary_df.columns]]
    summary_df.to_csv(out_dir / "summary.csv", index=False)
    summary_df.to_json(out_dir / "summary.json", orient="records", indent=2)

    if sweep_frames:
        all_sweep_df = pd.concat(sweep_frames, ignore_index=True)
        all_sweep_df.to_csv(out_dir / "threshold_sweep_all_models.csv", index=False)

        pivot_metrics = ["tp", "fp", "tn", "fn", "fpr", "precision", "recall", "f1", "accuracy"]
        pivot_df = all_sweep_df.pivot_table(
            index="threshold",
            columns="model",
            values=pivot_metrics,
            aggfunc="first",
        )
        pivot_df.sort_index(inplace=True)
        pivot_df.to_csv(out_dir / "threshold_sweep_pivot.csv")

    print("Comparison artifacts saved")
    print(f"Summary: {out_dir / 'summary.csv'}")
    print(f"Threshold sweep: {out_dir / 'threshold_sweep_all_models.csv'}")


if __name__ == "__main__":
    main()
