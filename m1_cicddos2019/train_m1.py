from __future__ import annotations

import argparse
from pathlib import Path
import random

import numpy as np
import torch
from torch.utils.data import DataLoader
from tqdm import tqdm

from src.config import M1Config, config_to_dict, load_config, save_json
from src.data_pipeline import (
    SequenceDataset,
    build_sequences,
    chronological_split,
    fit_scale_transform,
    load_and_resample,
)
from src.metrics import binary_metrics, threshold_search_under_fpr
from src.model import BinaryFocalLoss, TCNBinaryPredictor


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def run_epoch(
    model: torch.nn.Module,
    loader: DataLoader,
    criterion: torch.nn.Module,
    optimizer: torch.optim.Optimizer | None,
    device: torch.device,
) -> tuple[float, np.ndarray, np.ndarray]:
    is_train = optimizer is not None
    model.train(is_train)

    losses = []
    all_prob = []
    all_true = []

    for batch in loader:
        x = batch.X.to(device)
        y = batch.y.to(device)

        if is_train:
            optimizer.zero_grad(set_to_none=True)

        prob = model(x)
        loss = criterion(prob, y)

        if is_train:
            loss.backward()
            optimizer.step()

        losses.append(float(loss.item()))
        all_prob.append(prob.detach().cpu().numpy())
        all_true.append(y.detach().cpu().numpy())

    y_prob = np.concatenate(all_prob)
    y_true = np.concatenate(all_true).astype(int)
    return float(np.mean(losses)), y_true, y_prob


def main() -> None:
    parser = argparse.ArgumentParser(description="Train M1 TCN predictor on CICDDoS2019")
    parser.add_argument("--config", type=str, default="./config.yaml", help="Path to config file")
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg.random_seed)

    output_dir = Path(cfg.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    model_dir = output_dir / cfg.model_name
    model_dir.mkdir(parents=True, exist_ok=True)

    print("[1/6] Loading and resampling CICDDoS2019 CSV files...")
    frame, feature_cols = load_and_resample(cfg)

    print("[2/6] Building sequence dataset...")
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
    fit_scale_transform(split, scaler_path)

    train_ds = SequenceDataset(split["train"]["X"], split["train"]["y"])
    val_ds = SequenceDataset(split["val"]["X"], split["val"]["y"])
    test_ds = SequenceDataset(split["test"]["X"], split["test"]["y"])

    train_loader = DataLoader(
        train_ds,
        batch_size=cfg.batch_size,
        shuffle=True,
        num_workers=cfg.num_workers,
    )
    val_loader = DataLoader(
        val_ds,
        batch_size=cfg.batch_size,
        shuffle=False,
        num_workers=cfg.num_workers,
    )
    test_loader = DataLoader(
        test_ds,
        batch_size=cfg.batch_size,
        shuffle=False,
        num_workers=cfg.num_workers,
    )

    device = torch.device(cfg.device if cfg.device != "auto" else ("cuda" if torch.cuda.is_available() else "cpu"))
    model = TCNBinaryPredictor(
        in_features=len(feature_cols),
        channels=cfg.tcn_channels,
        kernel_size=cfg.tcn_kernel_size,
        dropout=cfg.tcn_dropout,
    ).to(device)
    criterion = BinaryFocalLoss(alpha=cfg.focal_alpha, gamma=cfg.focal_gamma)
    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg.learning_rate, weight_decay=cfg.weight_decay)

    print(f"[3/6] Training on device={device} ...")
    best_val_loss = float("inf")
    best_state = None
    wait = 0
    history = []

    for epoch in tqdm(range(1, cfg.max_epochs + 1), desc="Training"):
        train_loss, y_train, p_train = run_epoch(model, train_loader, criterion, optimizer, device)
        val_loss, y_val, p_val = run_epoch(model, val_loader, criterion, None, device)

        thr, _ = threshold_search_under_fpr(
            y_true=y_val,
            y_prob=p_val,
            max_fpr=cfg.threshold_search_fpr_max,
        )
        val_metric = binary_metrics(y_val, p_val, thr)

        row = {
            "epoch": epoch,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "val_threshold": thr,
            "val_f1": val_metric["f1"],
            "val_fpr": val_metric["fpr"],
            "val_auc": val_metric["roc_auc"],
        }
        history.append(row)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.cpu() for k, v in model.state_dict().items()}
            wait = 0
        else:
            wait += 1
            if wait >= cfg.early_stopping_patience:
                print(f"Early stopping at epoch {epoch}")
                break

    if best_state is None:
        raise RuntimeError("Training failed: no best state was saved")

    model.load_state_dict(best_state)

    print("[4/6] Selecting threshold on validation split...")
    _, y_val, p_val = run_epoch(model, val_loader, criterion, None, device)
    best_thr, thr_stats = threshold_search_under_fpr(
        y_true=y_val,
        y_prob=p_val,
        max_fpr=cfg.threshold_search_fpr_max,
    )

    print("[5/6] Evaluating on test split...")
    _, y_test, p_test = run_epoch(model, test_loader, criterion, None, device)
    test_metric = binary_metrics(y_test, p_test, best_thr)

    checkpoint_path = model_dir / "model.pt"
    payload = {
        "model_state": model.state_dict(),
        "feature_columns": feature_cols,
        "threshold": float(best_thr),
        "window_size": cfg.window_size,
        "horizon_steps": cfg.horizon_steps,
        "poll_interval_seconds": cfg.poll_interval_seconds,
        "tcn_channels": cfg.tcn_channels,
        "tcn_kernel_size": cfg.tcn_kernel_size,
        "tcn_dropout": cfg.tcn_dropout,
    }
    torch.save(payload, checkpoint_path)

    print("[6/6] Saving artifacts...")
    save_json(model_dir / "config_used.json", config_to_dict(cfg))
    save_json(model_dir / "training_history.json", {"history": history})
    save_json(model_dir / "threshold_stats.json", thr_stats)
    save_json(model_dir / "test_metrics.json", test_metric)

    print("Done.")
    print(f"Model: {checkpoint_path}")
    print(f"Scaler: {scaler_path}")
    print(f"Test metrics: {model_dir / 'test_metrics.json'}")


if __name__ == "__main__":
    main()
