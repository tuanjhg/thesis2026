from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import torch
from torch.utils.data import Dataset

from src.config import M1Config


TIME_CANDIDATES = [
    "Timestamp",
    "timestamp",
    "Time",
    "time",
    "Date",
    "date",
]

M2_FEATURES = [
    "pkt_rate",
    "byte_rate",
    "syn_rate",
    "src_ip_entropy",
    "dst_ip_entropy",
    "pkt_len_mean",
    "pkt_len_std",
    "flow_rate",
    "iat_mean",
    "iat_std",
    "tcp_flag_ratio",
    "retry_rate",
    "icmp_rate",
    "udp_rate",
    "http_rate",
]


def m2_required_raw_columns(cfg: M1Config) -> set[str]:
    cols = set(TIME_CANDIDATES)
    cols.add(cfg.label_column)

    # Raw columns used to derive the 15 engineered features.
    cols.update(
        {
            "Flow Duration",
            "Total Fwd Packets",
            "Tot Fwd Pkts",
            "Total Backward Packets",
            "Tot Bwd Pkts",
            "Total Length of Fwd Packets",
            "TotLen Fwd Pkts",
            "Total Length of Bwd Packets",
            "TotLen Bwd Pkts",
            "Flow Packets/s",
            "Flow Bytes/s",
            "SYN Flag Count",
            "RST Flag Count",
            "ACK Flag Count",
            "FIN Flag Count",
            "PSH Flag Count",
            "URG Flag Count",
            "Packet Length Mean",
            "Average Packet Size",
            "Packet Length Std",
            "Pkt Len Std",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Source IP",
            "Src IP",
            "Src_IP",
            "Destination IP",
            "Dst IP",
            "Dst_IP",
            "Protocol",
            "Destination Port",
            "Dst Port",
            "Dst_Port",
        }
    )
    return cols


def list_csv_files(data_dir: str | Path) -> List[Path]:
    return sorted(Path(data_dir).rglob("*.csv"))


def detect_timestamp_column(df: pd.DataFrame, configured: Optional[str]) -> str:
    if configured and configured in df.columns:
        return configured
    for col in TIME_CANDIDATES:
        if col in df.columns:
            return col
    raise ValueError(
        "No timestamp column found. Set timestamp_column in config.yaml."
    )


def make_binary_label(series: pd.Series, benign_keywords: List[str]) -> pd.Series:
    s = series.astype(str).str.strip().str.lower()
    benign_mask = np.zeros(len(s), dtype=bool)
    for key in benign_keywords:
        benign_mask |= s.str.contains(key.lower(), na=False)
    return (~benign_mask).astype(int)


def _safe_numeric(df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
    out = df.copy()
    for c in cols:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    out = out.replace([np.inf, -np.inf], np.nan)
    return out


def _pick_first_existing(df: pd.DataFrame, candidates: List[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _to_numeric_series(df: pd.DataFrame, col: Optional[str], default: float = 0.0) -> pd.Series:
    if col is None:
        return pd.Series(default, index=df.index, dtype="float64")
    return pd.to_numeric(df[col], errors="coerce").fillna(default)


def _safe_divide(a: pd.Series, b: pd.Series, eps: float = 1e-9) -> pd.Series:
    return a / (b.abs() + eps)


def _shannon_entropy(values: pd.Series) -> float:
    if values.empty:
        return 0.0
    probs = values.value_counts(normalize=True, dropna=True).to_numpy()
    if probs.size == 0:
        return 0.0
    return float(-(probs * np.log2(probs + 1e-12)).sum())


def build_m2_engineered_features(df: pd.DataFrame, ts_col: str, cfg: M1Config) -> pd.DataFrame:
    # Column aliases seen across CICDDoS/CICIDS exports
    flow_duration_col = _pick_first_existing(df, ["Flow Duration"])

    fwd_pkt_col = _pick_first_existing(df, ["Total Fwd Packets", "Tot Fwd Pkts"])
    bwd_pkt_col = _pick_first_existing(df, ["Total Backward Packets", "Tot Bwd Pkts"])
    fwd_len_col = _pick_first_existing(df, ["Total Length of Fwd Packets", "TotLen Fwd Pkts"])
    bwd_len_col = _pick_first_existing(df, ["Total Length of Bwd Packets", "TotLen Bwd Pkts"])

    flow_pkt_rate_col = _pick_first_existing(df, ["Flow Packets/s"])
    flow_byte_rate_col = _pick_first_existing(df, ["Flow Bytes/s"])

    syn_flag_col = _pick_first_existing(df, ["SYN Flag Count"])
    rst_flag_col = _pick_first_existing(df, ["RST Flag Count"])
    ack_flag_col = _pick_first_existing(df, ["ACK Flag Count"])
    fin_flag_col = _pick_first_existing(df, ["FIN Flag Count"])
    psh_flag_col = _pick_first_existing(df, ["PSH Flag Count"])
    urg_flag_col = _pick_first_existing(df, ["URG Flag Count"])

    pkt_len_mean_col = _pick_first_existing(df, ["Packet Length Mean", "Average Packet Size"])
    pkt_len_std_col = _pick_first_existing(df, ["Packet Length Std", "Pkt Len Std"])
    iat_mean_col = _pick_first_existing(df, ["Flow IAT Mean"])
    iat_std_col = _pick_first_existing(df, ["Flow IAT Std"])

    src_ip_col = _pick_first_existing(df, ["Source IP", "Src IP", "Src_IP"])
    dst_ip_col = _pick_first_existing(df, ["Destination IP", "Dst IP", "Dst_IP"])
    protocol_col = _pick_first_existing(df, ["Protocol"])
    dst_port_col = _pick_first_existing(df, ["Destination Port", "Dst Port", "Dst_Port"])

    duration_us = _to_numeric_series(df, flow_duration_col, default=1.0).clip(lower=1.0)
    duration_s = duration_us / 1_000_000.0

    total_pkts = _to_numeric_series(df, fwd_pkt_col) + _to_numeric_series(df, bwd_pkt_col)
    total_bytes = _to_numeric_series(df, fwd_len_col) + _to_numeric_series(df, bwd_len_col)

    pkt_rate = _to_numeric_series(df, flow_pkt_rate_col)
    if flow_pkt_rate_col is None:
        pkt_rate = _safe_divide(total_pkts, duration_s)

    byte_rate = _to_numeric_series(df, flow_byte_rate_col)
    if flow_byte_rate_col is None:
        byte_rate = _safe_divide(total_bytes, duration_s)

    syn_rate = _safe_divide(_to_numeric_series(df, syn_flag_col), duration_s)

    pkt_len_mean = _to_numeric_series(df, pkt_len_mean_col)
    pkt_len_std = _to_numeric_series(df, pkt_len_std_col)
    iat_mean = _to_numeric_series(df, iat_mean_col)
    iat_std = _to_numeric_series(df, iat_std_col)

    tcp_flag_sum = (
        _to_numeric_series(df, syn_flag_col)
        + _to_numeric_series(df, ack_flag_col)
        + _to_numeric_series(df, fin_flag_col)
        + _to_numeric_series(df, psh_flag_col)
        + _to_numeric_series(df, urg_flag_col)
        + _to_numeric_series(df, rst_flag_col)
    )
    tcp_flag_ratio = _safe_divide(tcp_flag_sum, total_pkts.replace(0, np.nan)).fillna(0.0)
    retry_rate = _safe_divide(_to_numeric_series(df, rst_flag_col), duration_s)

    parsed_ts = pd.to_datetime(df[ts_col], errors="coerce", dayfirst=True)

    engineered = pd.DataFrame(
        {
            ts_col: parsed_ts,
            "attack_binary": make_binary_label(df[cfg.label_column], cfg.benign_keywords),
            "pkt_rate": pkt_rate,
            "byte_rate": byte_rate,
            "syn_rate": syn_rate,
            "pkt_len_mean": pkt_len_mean,
            "pkt_len_std": pkt_len_std,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "tcp_flag_ratio": tcp_flag_ratio,
            "retry_rate": retry_rate,
        }
    )

    # Protocol-derived rates at per-flow level, aggregated later per time bucket
    proto = _to_numeric_series(df, protocol_col, default=-1)
    dport = _to_numeric_series(df, dst_port_col, default=-1)
    engineered["is_icmp"] = (proto == 1).astype(float)
    engineered["is_udp"] = (proto == 17).astype(float)
    engineered["is_http"] = ((dport == 80) | (dport == 443) | (dport == 8080)).astype(float)

    # Keep IP columns for entropy, if present.
    engineered["_src_ip"] = df[src_ip_col].astype(str) if src_ip_col else "unknown"
    engineered["_dst_ip"] = df[dst_ip_col].astype(str) if dst_ip_col else "unknown"

    engineered = engineered.dropna(subset=[ts_col])
    # Guard against malformed dates that explode the resample range.
    engineered = engineered[
        (engineered[ts_col] >= pd.Timestamp("2017-01-01"))
        & (engineered[ts_col] <= pd.Timestamp("2025-12-31"))
    ]
    engineered = engineered.sort_values(ts_col)
    engineered = engineered.set_index(ts_col)

    freq = f"{cfg.poll_interval_seconds}s"
    stat_cols = [
        "pkt_rate",
        "byte_rate",
        "syn_rate",
        "pkt_len_mean",
        "pkt_len_std",
        "iat_mean",
        "iat_std",
        "tcp_flag_ratio",
        "retry_rate",
    ]

    agg_stats = engineered[stat_cols].resample(freq).mean()
    attack = engineered[["attack_binary"]].resample(freq).max()

    # flow_rate = number of flows per second within each bucket
    flow_count = engineered[["attack_binary"]].resample(freq).size().rename("flow_count")
    flow_rate = (flow_count / float(cfg.poll_interval_seconds)).rename("flow_rate")

    # protocol-based rates from per-flow indicators
    icmp_rate = (engineered[["is_icmp"]].resample(freq).sum()["is_icmp"] / float(cfg.poll_interval_seconds)).rename("icmp_rate")
    udp_rate = (engineered[["is_udp"]].resample(freq).sum()["is_udp"] / float(cfg.poll_interval_seconds)).rename("udp_rate")
    http_rate = (engineered[["is_http"]].resample(freq).sum()["is_http"] / float(cfg.poll_interval_seconds)).rename("http_rate")

    src_entropy = engineered["_src_ip"].resample(freq).apply(_shannon_entropy).rename("src_ip_entropy")
    dst_entropy = engineered["_dst_ip"].resample(freq).apply(_shannon_entropy).rename("dst_ip_entropy")

    out = pd.concat(
        [
            agg_stats,
            src_entropy,
            dst_entropy,
            flow_rate,
            icmp_rate,
            udp_rate,
            http_rate,
            attack,
        ],
        axis=1,
    ).replace([np.inf, -np.inf], np.nan)

    out = out.dropna().reset_index().rename(columns={ts_col: "timestamp"})
    # Ensure fixed column order for downstream compatibility
    out = out[["timestamp"] + M2_FEATURES + ["attack_binary"]]
    return out


def _choose_feature_columns(df: pd.DataFrame, cfg: M1Config, ts_col: str) -> List[str]:
    if cfg.feature_columns:
        missing = [c for c in cfg.feature_columns if c not in df.columns]
        if missing:
            raise ValueError(f"Configured feature columns not found: {missing}")
        return cfg.feature_columns

    forbidden = {ts_col, cfg.label_column}
    forbidden.update(cfg.drop_columns)
    candidates = []
    for c in df.columns:
        if c in forbidden:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            candidates.append(c)
    if not candidates:
        raise ValueError("No numeric feature columns available after filtering.")
    return candidates


def preprocess_single_csv(path: Path, cfg: M1Config) -> Tuple[pd.DataFrame, List[str]]:
    expected = cfg.feature_columns or []
    if expected and set(expected) == set(M2_FEATURES):
        needed = m2_required_raw_columns(cfg)
        df = pd.read_csv(
            path,
            low_memory=True,
            usecols=lambda c: str(c).strip() in needed,
        )
    else:
        df = pd.read_csv(path, low_memory=False)

    # CIC datasets often include leading/trailing spaces in header names.
    df.columns = [str(c).strip() for c in df.columns]
    ts_col = detect_timestamp_column(df, cfg.timestamp_column)

    if cfg.label_column not in df.columns:
        raise ValueError(f"Label column '{cfg.label_column}' not found in {path}")

    if expected and set(expected) == set(M2_FEATURES):
        out = build_m2_engineered_features(df, ts_col, cfg)
        return out, expected

    df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce", dayfirst=True)
    df = df.dropna(subset=[ts_col]).sort_values(ts_col)
    df["attack_binary"] = make_binary_label(df[cfg.label_column], cfg.benign_keywords)

    feature_cols = _choose_feature_columns(df, cfg, ts_col)
    df = _safe_numeric(df, feature_cols)

    work = df[[ts_col, "attack_binary"] + feature_cols].dropna(subset=feature_cols)
    work = work.set_index(ts_col)

    agg = work[feature_cols].resample(f"{cfg.poll_interval_seconds}s").mean()
    attack = work[["attack_binary"]].resample(f"{cfg.poll_interval_seconds}s").max()
    out = pd.concat([agg, attack], axis=1).dropna()
    out = out.reset_index().rename(columns={ts_col: "timestamp"})
    return out, feature_cols


def load_and_resample(cfg: M1Config) -> Tuple[pd.DataFrame, List[str]]:
    files = list_csv_files(cfg.data_dir)
    if not files:
        raise FileNotFoundError(f"No CSV files found under {cfg.data_dir}")

    all_frames = []
    agreed_features: Optional[List[str]] = None
    for p in files:
        frame, feat = preprocess_single_csv(p, cfg)
        if agreed_features is None:
            agreed_features = feat
        else:
            common = [c for c in agreed_features if c in feat]
            if not common:
                raise ValueError(
                    "No common feature columns across CSV files. "
                    "Set feature_columns explicitly in config.yaml"
                )
            agreed_features = common
        all_frames.append(frame)

    merged = pd.concat(all_frames, axis=0, ignore_index=True)
    merged = merged.sort_values("timestamp").reset_index(drop=True)
    merged = merged[["timestamp"] + agreed_features + ["attack_binary"]]
    return merged, agreed_features


def build_sequences(
    frame: pd.DataFrame,
    feature_cols: List[str],
    window_size: int,
    horizon_steps: int,
) -> Dict[str, np.ndarray]:
    values = frame[feature_cols].to_numpy(dtype=np.float32)
    attack = frame["attack_binary"].to_numpy(dtype=np.int64)
    timestamps = frame["timestamp"].to_numpy()

    xs = []
    ys = []
    ts_now = []
    ts_target = []
    last_idx = len(frame) - horizon_steps

    for i in range(window_size - 1, last_idx):
        start = i - window_size + 1
        end = i + 1
        xs.append(values[start:end])
        ys.append(attack[i + horizon_steps])
        ts_now.append(timestamps[i])
        ts_target.append(timestamps[i + horizon_steps])

    if not xs:
        raise ValueError("No sequences generated. Reduce window_size or horizon_steps.")

    return {
        "X": np.asarray(xs, dtype=np.float32),
        "y": np.asarray(ys, dtype=np.float32),
        "ts_now": np.asarray(ts_now),
        "ts_target": np.asarray(ts_target),
    }


def chronological_split(
    X: np.ndarray,
    y: np.ndarray,
    ts_now: np.ndarray,
    ts_target: np.ndarray,
    train_ratio: float,
    val_ratio: float,
) -> Dict[str, Dict[str, np.ndarray]]:
    n = len(X)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    n_test = n - n_train - n_val
    if min(n_train, n_val, n_test) <= 0:
        raise ValueError("Split sizes invalid. Adjust train_ratio/val_ratio.")

    idx1 = n_train
    idx2 = n_train + n_val

    return {
        "train": {
            "X": X[:idx1],
            "y": y[:idx1],
            "ts_now": ts_now[:idx1],
            "ts_target": ts_target[:idx1],
        },
        "val": {
            "X": X[idx1:idx2],
            "y": y[idx1:idx2],
            "ts_now": ts_now[idx1:idx2],
            "ts_target": ts_target[idx1:idx2],
        },
        "test": {
            "X": X[idx2:],
            "y": y[idx2:],
            "ts_now": ts_now[idx2:],
            "ts_target": ts_target[idx2:],
        },
    }


def fit_scale_transform(
    split_dict: Dict[str, Dict[str, np.ndarray]],
    scaler_path: str | Path,
) -> StandardScaler:
    X_train = split_dict["train"]["X"]
    b, w, f = X_train.shape

    scaler = StandardScaler()
    scaler.fit(X_train.reshape(b * w, f))

    for key in ["train", "val", "test"]:
        X = split_dict[key]["X"]
        b2, w2, f2 = X.shape
        split_dict[key]["X"] = scaler.transform(X.reshape(b2 * w2, f2)).reshape(b2, w2, f2)

    scaler_path = Path(scaler_path)
    scaler_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, scaler_path)
    return scaler


@dataclass
class SequenceTensors:
    X: torch.Tensor
    y: torch.Tensor


class SequenceDataset(Dataset):
    def __init__(self, X: np.ndarray, y: np.ndarray) -> None:
        self.X = torch.from_numpy(X.astype(np.float32))
        self.y = torch.from_numpy(y.astype(np.float32))

    def __len__(self) -> int:
        return self.X.shape[0]

    def __getitem__(self, idx: int) -> SequenceTensors:
        return SequenceTensors(X=self.X[idx], y=self.y[idx])
