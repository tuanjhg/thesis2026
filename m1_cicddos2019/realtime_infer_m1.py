from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
from typing import Dict, Optional

import joblib
import numpy as np
import torch

from src.model import TCNBinaryPredictor


class M1RealtimePredictor:
    def __init__(self, model_dir: str | Path, device: str = "cpu") -> None:
        model_dir = Path(model_dir)
        ckpt = torch.load(model_dir / "model.pt", map_location="cpu")
        self.feature_columns = ckpt["feature_columns"]
        self.window_size = int(ckpt["window_size"])
        self.threshold = float(ckpt["threshold"])
        self.horizon_steps = int(ckpt["horizon_steps"])
        self.poll_interval_seconds = int(ckpt["poll_interval_seconds"])

        self.scaler = joblib.load(model_dir / "scaler.joblib")
        self.device = torch.device(device)
        self.model = TCNBinaryPredictor(
            in_features=len(self.feature_columns),
            channels=ckpt["tcn_channels"],
            kernel_size=ckpt["tcn_kernel_size"],
            dropout=ckpt["tcn_dropout"],
        ).to(self.device)
        self.model.load_state_dict(ckpt["model_state"])
        self.model.eval()

        self.window = deque(maxlen=self.window_size)

    def _vectorize(self, sample: Dict[str, float]) -> np.ndarray:
        row = []
        for c in self.feature_columns:
            if c not in sample:
                raise KeyError(f"Missing feature '{c}' in input sample")
            row.append(float(sample[c]))
        return np.asarray(row, dtype=np.float32)

    def push(self, sample: Dict[str, float]) -> Optional[Dict[str, float]]:
        vec = self._vectorize(sample)
        self.window.append(vec)
        if len(self.window) < self.window_size:
            return None

        arr = np.stack(self.window, axis=0)
        arr = self.scaler.transform(arr)
        x = torch.from_numpy(arr[None, :, :].astype(np.float32)).to(self.device)

        with torch.no_grad():
            p = float(self.model(x).item())

        result = {
            "p_attack_future": p,
            "pre_alert": int(p >= 0.60),
            "full_alert": int(p >= 0.80),
            "model_threshold": self.threshold,
            "predict_horizon_seconds": self.horizon_steps * self.poll_interval_seconds,
        }
        return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Realtime inference for M1. Input is JSONL with one feature sample per line."
    )
    parser.add_argument("--model-dir", type=str, required=True)
    parser.add_argument("--input-jsonl", type=str, required=True)
    parser.add_argument("--output-jsonl", type=str, default="./m1_predictions.jsonl")
    parser.add_argument("--device", type=str, default="cpu")
    args = parser.parse_args()

    predictor = M1RealtimePredictor(model_dir=args.model_dir, device=args.device)
    in_path = Path(args.input_jsonl)
    out_path = Path(args.output_jsonl)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with open(in_path, "r", encoding="utf-8") as f_in, open(out_path, "w", encoding="utf-8") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            sample = json.loads(line)
            result = predictor.push(sample)
            if result is None:
                continue
            f_out.write(json.dumps(result) + "\n")
            written += 1

    print(f"Wrote {written} predictions to {out_path}")


if __name__ == "__main__":
    main()
