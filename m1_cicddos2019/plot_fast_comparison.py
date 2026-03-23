from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve


def load_model_predictions(artifacts_dir: Path, model_name: str) -> pd.DataFrame:
    pred_path = artifacts_dir / model_name / "eval_predictions.csv"
    if not pred_path.exists():
        raise FileNotFoundError(f"Missing predictions file: {pred_path}")
    return pd.read_csv(pred_path)


def load_threshold_sweep(artifacts_dir: Path, model_name: str) -> pd.DataFrame:
    sweep_path = artifacts_dir / model_name / "eval_threshold_sweep.csv"
    if not sweep_path.exists():
        raise FileNotFoundError(f"Missing threshold sweep file: {sweep_path}")
    return pd.read_csv(sweep_path)


def plot_pr_curve(artifacts_dir: Path, model_names: list[str], out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 6))

    for model_name in model_names:
        df = load_model_predictions(artifacts_dir, model_name)
        y_true = df["y_true"].to_numpy()
        y_prob = df["y_prob"].to_numpy()

        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = average_precision_score(y_true, y_prob)
        ax.plot(recall, precision, linewidth=2, label=f"{model_name} (PR-AUC={pr_auc:.4f})")

    ax.set_title("Precision-Recall Curve (Fast Models)")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.05)
    ax.grid(alpha=0.25)
    ax.legend(loc="lower left")

    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def _heatmap(ax: plt.Axes, values: np.ndarray, row_labels: list[str], col_labels: list[str], title: str) -> None:
    im = ax.imshow(values, aspect="auto", cmap="YlOrRd")
    ax.set_title(title)
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)
    ax.set_xticks(np.arange(len(col_labels)))
    ax.set_xticklabels(col_labels)

    for i in range(values.shape[0]):
        for j in range(values.shape[1]):
            ax.text(j, i, f"{values[i, j]:.3f}", ha="center", va="center", color="black", fontsize=8)

    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)


def plot_confusion_heatmaps(artifacts_dir: Path, model_names: list[str], out_dir: Path) -> None:
    for model_name in model_names:
        df = load_threshold_sweep(artifacts_dir, model_name).sort_values("threshold")

        thresholds = [f"{v:.2f}" for v in df["threshold"].tolist()]

        counts = df[["tp", "fp", "tn", "fn"]].to_numpy(dtype=float).T
        totals = counts.sum(axis=0, keepdims=True)
        totals = np.where(totals == 0.0, 1.0, totals)
        rates = counts / totals

        fig, axes = plt.subplots(1, 2, figsize=(16, 7), sharey=True)
        _heatmap(
            ax=axes[0],
            values=counts,
            row_labels=["TP", "FP", "TN", "FN"],
            col_labels=thresholds,
            title=f"{model_name}: Confusion Counts by Threshold",
        )
        _heatmap(
            ax=axes[1],
            values=rates,
            row_labels=["TP", "FP", "TN", "FN"],
            col_labels=thresholds,
            title=f"{model_name}: Confusion Rates by Threshold",
        )

        axes[0].set_xlabel("Threshold")
        axes[1].set_xlabel("Threshold")
        axes[0].set_ylabel("Confusion Components")

        fig.tight_layout()
        fig.savefig(out_dir / f"{model_name}_confusion_heatmap_threshold.png", dpi=180)
        plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot PR curve and confusion-threshold heatmaps for fast models")
    parser.add_argument("--artifacts-dir", type=str, default="./artifacts")
    parser.add_argument("--models", type=str, default="m1_tcn_fast,m1_lstm_fast")
    parser.add_argument("--out-dir", type=str, default="./artifacts/fast_comparison/figures")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model_names = [m.strip() for m in args.models.split(",") if m.strip()]
    if not model_names:
        raise ValueError("No model names provided")

    plot_pr_curve(artifacts_dir, model_names, out_dir / "pr_curve_fast_models.png")
    plot_confusion_heatmaps(artifacts_dir, model_names, out_dir)

    print("Visualization files generated")
    print(f"PR curve: {out_dir / 'pr_curve_fast_models.png'}")
    for model_name in model_names:
        print(f"Heatmap: {out_dir / (model_name + '_confusion_heatmap_threshold.png')}")


if __name__ == "__main__":
    main()
