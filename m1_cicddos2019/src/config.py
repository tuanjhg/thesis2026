from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional
import json


@dataclass
class M1Config:
    data_dir: str = "./data/cicddos2019"
    output_dir: str = "./artifacts"
    model_name: str = "m1_tcn"

    timestamp_column: Optional[str] = None
    label_column: str = "Label"
    benign_keywords: List[str] = None

    poll_interval_seconds: int = 3
    window_size: int = 30
    forecast_horizon_seconds: int = 30

    feature_columns: Optional[List[str]] = None
    drop_columns: List[str] = None

    train_ratio: float = 0.7
    val_ratio: float = 0.15
    random_seed: int = 42

    batch_size: int = 128
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    max_epochs: int = 60
    early_stopping_patience: int = 10

    tcn_channels: List[int] = None
    tcn_kernel_size: int = 3
    tcn_dropout: float = 0.2

    focal_alpha: float = 0.25
    focal_gamma: float = 2.0

    threshold_search_fpr_max: float = 0.05

    num_workers: int = 0
    device: str = "cpu"

    def __post_init__(self) -> None:
        if self.benign_keywords is None:
            self.benign_keywords = ["benign", "normal"]
        if self.drop_columns is None:
            self.drop_columns = ["Flow ID", "Source IP", "Destination IP"]
        if self.tcn_channels is None:
            self.tcn_channels = [64, 64, 32]

    @property
    def horizon_steps(self) -> int:
        return max(1, self.forecast_horizon_seconds // self.poll_interval_seconds)


def load_config(path: str | Path) -> M1Config:
    import yaml

    with open(path, "r", encoding="utf-8") as f:
        payload = yaml.safe_load(f)
    return M1Config(**payload)


def save_json(path: str | Path, payload: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def config_to_dict(cfg: M1Config) -> dict:
    return asdict(cfg)
