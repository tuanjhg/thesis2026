from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader

from src.config import load_config, save_json
from src.data_pipeline import SequenceDataset, build_sequences, chronological_split, fit_scale_transform, load_and_resample
from src.metrics import binary_metrics, threshold_sweep_metrics
from src.model import BinaryFocalLoss, build_model_from_checkpoint


def parse_thresholds(raw: str) -> np.ndarray:
    values = [float(v.strip()) for v in raw.split(",") if v.strip()]
    if not values:
        raise ValueError("No valid thresholds were provided")
    for v in values:
        if v < 0.0 or v > 1.0:
            raise ValueError(f"Threshold out of range [0,1]: {v}")
    return np.asarray(values, dtype=float)


def infer_probs(model: torch.nn.Module, loader: DataLoader, device: torch.device) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    probs = []
    trues = []
    with torch.no_grad():
        for batch in loader:
            x = batch.X.to(device)
            y = batch.y.cpu().numpy().astype(int)
            p = model(x).cpu().numpy()
            probs.append(p)
            trues.append(y)
    return np.concatenate(trues), np.concatenate(probs)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate M1 TCN predictor")
    parser.add_argument("--config", type=str, default="./config.yaml")
    parser.add_argument("--model-dir", type=str, default="./artifacts/m1_tcn")
    parser.add_argument(
        "--thresholds",
        type=str,
        default="0.05,0.10,0.15,0.20,0.25,0.30,0.35,0.40,0.45,0.50,0.55,0.60,0.65,0.70,0.75,0.80,0.85,0.90,0.95",
        help="Comma-separated threshold list for confusion-matrix sweep",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    model_dir = Path(args.model_dir)
    ckpt_path = model_dir / "model.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(f"Checkpoint not found: {ckpt_path}")

    frame, feature_cols = load_and_resample(cfg)
    seq = build_sequences(
        frame=frame,
        feature_cols=feature_cols,
        window_size=cfg.window_size,
        horizon_steps=cfg.horizon_steps,
    )
    split = chronological_split(
        X=seq["X"],
        y=seq["y"],
        ts_now=seq["ts_now"],
        ts_target=seq["ts_target"],
        train_ratio=cfg.train_ratio,
        val_ratio=cfg.val_ratio,
    )

    scaler_path = model_dir / "scaler.joblib"
    if not scaler_path.exists():
        # fallback for first-time standalone eval
        fit_scale_transform(split, scaler_path)
    else:
        import joblib

        scaler = joblib.load(scaler_path)
        for key in ["train", "val", "test"]:
            X = split[key]["X"]
            b, w, f = X.shape
            split[key]["X"] = scaler.transform(X.reshape(b * w, f)).reshape(b, w, f)

    test_ds = SequenceDataset(split["test"]["X"], split["test"]["y"])
    test_loader = DataLoader(test_ds, batch_size=cfg.batch_size, shuffle=False)

    ckpt = torch.load(ckpt_path, map_location="cpu")
    model = build_model_from_checkpoint(ckpt)
    model.load_state_dict(ckpt["model_state"])
    threshold = float(ckpt["threshold"])

    device = torch.device(cfg.device if cfg.device != "auto" else ("cuda" if torch.cuda.is_available() else "cpu"))
    model = model.to(device)

    y_true, y_prob = infer_probs(model, test_loader, device)
    metrics = binary_metrics(y_true, y_prob, threshold)
    thresholds = parse_thresholds(args.thresholds)
    sweep_rows = threshold_sweep_metrics(y_true, y_prob, thresholds)

    save_json(model_dir / "eval_metrics.json", metrics)
    save_json(model_dir / "eval_threshold_sweep.json", {"rows": sweep_rows})
    pd.DataFrame(sweep_rows).to_csv(model_dir / "eval_threshold_sweep.csv", index=False)

    pred_df = pd.DataFrame(
        {
            "ts_now": split["test"]["ts_now"],
            "ts_target": split["test"]["ts_target"],
            "y_true": y_true,
            "y_prob": y_prob,
            "y_pred": (y_prob >= threshold).astype(int),
        }
    )
    pred_df.to_csv(model_dir / "eval_predictions.csv", index=False)

    # Optional loss reporting
    criterion = BinaryFocalLoss(alpha=cfg.focal_alpha, gamma=cfg.focal_gamma)
    with torch.no_grad():
        x_t = torch.from_numpy(split["test"]["X"]).to(device)
        y_t = torch.from_numpy(split["test"]["y"]).to(device)
        loss = criterion(model(x_t), y_t).item()
    save_json(model_dir / "eval_loss.json", {"focal_loss": float(loss)})

    print("Evaluation completed")
    print(metrics)


if __name__ == "__main__":
    main()
