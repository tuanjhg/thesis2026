"""
M2 — Feature Extractor (Spec-aligned)
Computes 17 entropy/rate features per 5-second window from CICDDoS2019 flow records.

Spec reference:
  Feature set: pkt_rate, byte_rate, src_ip_entropy, dst_ip_entropy,
               src_port_entropy, dst_port_entropy, proto_dist_tcp/udp/icmp,
               syn_ratio, fin_ratio, avg_pkt_size, pkt_size_std,
               new_flows_rate, flow_duration_mean,
               inter_arrival_mean, inter_arrival_std
  Window: 5-second sliding, 1-second slide
  Source: gNMI counters + flow records (simulated via CICDDoS2019)
"""

import numpy as np
import pandas as pd
from pathlib import Path
import logging
import pickle
import json
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ── 17 canonical feature names (from spec) ────────────────────────────────
FEATURE_NAMES = [
    "pkt_rate",           # 1  packets/second
    "byte_rate",          # 2  bytes/second
    "src_ip_entropy",     # 3  Shannon entropy of source IPs
    "dst_ip_entropy",     # 4  Shannon entropy of destination IPs
    "src_port_entropy",   # 5  Shannon entropy of source ports
    "dst_port_entropy",   # 6  Shannon entropy of destination ports
    "proto_dist_tcp",     # 7  fraction of TCP traffic
    "proto_dist_udp",     # 8  fraction of UDP traffic
    "proto_dist_icmp",    # 9  fraction of ICMP traffic
    "syn_ratio",          # 10 SYN / total TCP packets
    "fin_ratio",          # 11 FIN / total TCP packets
    "avg_pkt_size",       # 12 mean packet size (bytes)
    "pkt_size_std",       # 13 std dev of packet sizes
    "new_flows_rate",     # 14 new flows per second
    "flow_duration_mean", # 15 mean active flow duration
    "inter_arrival_mean", # 16 mean packet inter-arrival time
    "inter_arrival_std",  # 17 std dev of inter-arrival time
]

# ── 7-class labels (from spec) ─────────────────────────────────────────────
CLASS_NAMES = {
    0: "Normal",
    1: "UDP_Flood",
    2: "SYN_Flood",
    3: "HTTP_Flood",
    4: "ICMP_Flood",
    5: "Amplification",
    6: "Slow_rate",
}

# CICDDoS2019 label → spec class mapping
LABEL_TO_CLASS = {
    # Normal
    "BENIGN":          0,
    # UDP Flood
    "DrDoS_UDP":       1,
    "UDP":             1,
    "UDP-lag":         1,
    "UDP-Lag":         1,
    "UDPLag":          1,
    # SYN Flood
    "Syn":             2,
    # HTTP Flood (TFTP used as HTTP-like flood proxy)
    "TFTP":            3,
    # ICMP Flood — not present in CICDDoS2019; will be synthesized
    # Amplification (DNS, NTP, SNMP, SSDP, LDAP, MSSQL, NetBIOS, Portmap)
    "DrDoS_DNS":       5,
    "DrDoS_NTP":       5,
    "DrDoS_SNMP":      5,
    "DrDoS_SSDP":      5,
    "DrDoS_LDAP":      5,
    "DrDoS_MSSQL":     5,
    "DrDoS_NetBIOS":   5,
    "Portmap":         5,
    "LDAP":            5,
    "MSSQL":           5,
    "NetBIOS":         5,
    # Slow-rate
    "DrDoS_HTTP":      6,
}


def shannon_entropy(values: np.ndarray) -> float:
    """Shannon entropy of a discrete distribution."""
    if len(values) == 0:
        return 0.0
    _, counts = np.unique(values, return_counts=True)
    probs = counts / counts.sum()
    return float(-np.sum(probs * np.log2(probs + 1e-12)))


def extract_17_features(df_window: pd.DataFrame) -> np.ndarray:
    """
    Compute 17 spec features from a DataFrame window of flow records.

    Args:
        df_window: DataFrame slice with CICDDoS2019 columns (stripped names)
    Returns:
        np.ndarray of shape (17,)
    """
    n = len(df_window)
    if n == 0:
        return np.zeros(17, dtype=np.float32)

    def col(name, default=0.0):
        return df_window[name].values if name in df_window.columns else np.full(n, default)

    duration_col = col('Flow Duration', 1.0)
    duration_col = np.where(duration_col <= 0, 1.0, duration_col)

    # 1. pkt_rate: total packets / mean flow duration
    total_pkts = col('Total Fwd Packets') + col('Total Backward Packets')
    pkt_rate = float(np.sum(total_pkts) / np.sum(duration_col) * 1e6)  # per second

    # 2. byte_rate
    total_bytes = col('Total Length of Fwd Packets') + col('Total Length of Bwd Packets')
    byte_rate = float(np.sum(total_bytes) / np.sum(duration_col) * 1e6)

    # 3–6. Entropy features
    src_port_entropy = shannon_entropy(col('Source Port', 0).astype(int))
    dst_port_entropy = shannon_entropy(col('Destination Port', 0).astype(int))
    # IP entropy proxies — physically distinct from port entropy:
    #   src_ip_entropy: entropy of forward segment sizes (diverse sources → varied pkt sizes)
    #   dst_ip_entropy: entropy of backward segment sizes (diverse dests → varied response sizes)
    # DDoS floods have uniform fwd sizes (same tool/reflector) → LOW entropy.
    # Normal diverse traffic has varied sizes → HIGH entropy. Distinct from port entropy.
    fwd_seg = col('Avg Fwd Segment Size', 64.0)
    bwd_seg = col('Avg Bwd Segment Size', 64.0)
    src_ip_entropy = shannon_entropy((fwd_seg * 10).astype(int))   # discretize to int buckets
    dst_ip_entropy = shannon_entropy((bwd_seg * 10).astype(int))

    # 7–9. Protocol distribution
    proto = col('Protocol', 6).astype(int)
    total_flows = max(n, 1)
    proto_dist_tcp  = float((proto == 6).sum()  / total_flows)
    proto_dist_udp  = float((proto == 17).sum() / total_flows)
    proto_dist_icmp = float((proto == 1).sum()  / total_flows)

    # 10. syn_ratio: SYN Flag Count / total packets in TCP flows
    syn_count = col('SYN Flag Count', 0)
    tcp_mask = (proto == 6)
    tcp_pkts = float(total_pkts[tcp_mask].sum()) if tcp_mask.any() else 1.0
    syn_ratio = float(syn_count.sum() / max(tcp_pkts, 1))

    # 11. fin_ratio
    fin_count = col('FIN Flag Count', 0)
    fin_ratio = float(fin_count.sum() / max(tcp_pkts, 1))

    # 12–13. Packet size stats
    pkt_sizes = col('Average Packet Size', 64.0)
    avg_pkt_size = float(pkt_sizes.mean())
    pkt_size_std = float(pkt_sizes.std() + 1e-8)

    # 14. new_flows_rate: flows per second
    window_duration_s = float(np.sum(duration_col) / 1e6 / max(n, 1))
    window_duration_s = max(window_duration_s, 0.001)
    new_flows_rate = float(n / window_duration_s)

    # 15. flow_duration_mean (microseconds → ms)
    flow_duration_mean = float(duration_col.mean() / 1000.0)

    # 16–17. Inter-arrival time
    iat_mean_col = col('Flow IAT Mean', 1000.0)
    iat_std_col  = col('Flow IAT Std',  500.0)
    inter_arrival_mean = float(iat_mean_col.mean() / 1000.0)  # → ms
    inter_arrival_std  = float(iat_std_col.mean()  / 1000.0)

    features = np.array([
        pkt_rate, byte_rate,
        src_ip_entropy, dst_ip_entropy,
        src_port_entropy, dst_port_entropy,
        proto_dist_tcp, proto_dist_udp, proto_dist_icmp,
        syn_ratio, fin_ratio,
        avg_pkt_size, pkt_size_std,
        new_flows_rate, flow_duration_mean,
        inter_arrival_mean, inter_arrival_std,
    ], dtype=np.float32)

    # Replace inf/nan
    features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=0.0)
    return features


def build_dataset(data_dir: str,
                  output_dir: str,
                  max_windows_per_class: int = 50000,
                  window_size: int = 100,
                  step: int = 50) -> None:
    """
    Build the 17-feature dataset from CICDDoS2019 — full dataset streaming.

    Workflow:
    1. Stream ALL rows from every CSV in chunks (no per-file row cap).
    2. Collect ALL real BENIGN rows in RAM (~100K rows, ~32MB, manageable).
    3. For attack rows: maintain a per-label rolling buffer; extract windows
       on-the-fly and cap at max_windows_per_class to avoid redundancy from
       long uniform flood segments.
    4. Build BENIGN windows from pooled rows; oversample if needed.
    5. Interleave Normal + Attack, temporal split 80/20, save.

    Args:
        data_dir: path to Dataset/ folder containing CICDDoS2019 CSV files
        output_dir: path to save processed data
        max_windows_per_class: cap on windows per attack class (avoids millions
            of near-identical windows from long uniform flood segments).
            Set to 0 to disable the cap and use all windows.
        window_size: flows per window (100 flows ≈ 5s at medium rate)
        step: sliding window step
    """
    from collections import defaultdict

    data_dir   = Path(data_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("="*60)
    logger.info("M2 FEATURE EXTRACTION — Full dataset streaming")
    logger.info("="*60)

    csv_files = sorted(data_dir.rglob("*.csv"))
    logger.info(f"Found {len(csv_files)} CSV files")
    logger.info(f"max_windows_per_class={max_windows_per_class} "
                f"({'unlimited' if max_windows_per_class == 0 else 'capped'})")

    # carry_over[label] = leftover rows (< window_size) from previous chunk
    # These are prepended to the next chunk's rows for that label to maintain
    # cross-chunk window continuity.
    carry_over: dict[int, pd.DataFrame] = defaultdict(lambda: pd.DataFrame())

    attack_windows_X: dict[int, list] = defaultdict(list)
    attack_windows_y: dict[int, list] = defaultdict(list)
    benign_chunks: list[pd.DataFrame] = []
    total_rows_read = 0

    def _extract_from_buffer(label: int, buf: pd.DataFrame) -> pd.DataFrame:
        """
        Extract sliding windows from buf (rows for one label).
        Returns the carry-over tail (rows after the last complete window start).
        """
        n = len(buf)
        i = 0
        while i + window_size <= n:
            if max_windows_per_class > 0 and \
                    len(attack_windows_X[label]) >= max_windows_per_class:
                break
            w = buf.iloc[i:i + window_size]
            feats = extract_17_features(w)
            attack_windows_X[label].append(feats)
            attack_windows_y[label].append(label)
            i += step
        # Keep the tail for cross-chunk continuity (overlap = window_size - step)
        return buf.iloc[i:].reset_index(drop=True)

    # ── Stream every CSV fully (no row cap) ──────────────────────────────
    for csv_path in csv_files:
        logger.info(f"\nProcessing: {csv_path.name}")
        file_rows = 0
        try:
            for chunk in pd.read_csv(csv_path, chunksize=200_000,
                                     low_memory=False, on_bad_lines='skip'):
                chunk.columns = [c.strip() for c in chunk.columns]
                label_col = next((c for c in chunk.columns if c.lower() == 'label'), None)
                if label_col is None:
                    continue

                chunk['_class'] = chunk[label_col].str.strip().map(LABEL_TO_CLASS)
                chunk = chunk.dropna(subset=['_class'])
                chunk['_class'] = chunk['_class'].astype(int)
                file_rows += len(chunk)

                # ── BENIGN rows → collect all (~100K rows total, ~32MB RAM) ─
                benign_mask = chunk['_class'] == 0
                if benign_mask.any():
                    benign_chunks.append(chunk[benign_mask].copy())

                # ── Attack rows → per-label streaming window extraction ─────
                attack_chunk = chunk[~benign_mask]
                for label_id, grp in attack_chunk.groupby('_class', sort=True):
                    label_id = int(label_id)
                    if max_windows_per_class > 0 and \
                            len(attack_windows_X[label_id]) >= max_windows_per_class:
                        continue
                    # Prepend leftover from previous chunk
                    prev = carry_over[label_id]
                    buf  = pd.concat([prev, grp.reset_index(drop=True)],
                                     ignore_index=True) if len(prev) > 0 else \
                           grp.reset_index(drop=True)
                    carry_over[label_id] = _extract_from_buffer(label_id, buf)

            total_rows_read += file_rows
            logger.info(f"  {file_rows:,} rows read")
        except Exception as e:
            logger.warning(f"  Error processing {csv_path.name}: {e}")
            continue

    # Flush any remaining carry-over rows (< window_size, discard — too small)
    logger.info(f"\nTotal rows read across all files: {total_rows_read:,}")
    logger.info("Attack windows extracted per class:")
    for lbl in sorted(attack_windows_X.keys()):
        logger.info(f"  class {lbl} ({CLASS_NAMES.get(lbl,'?')}): "
                    f"{len(attack_windows_X[lbl]):,} windows")

    # ── Rebuild attack arrays from per-label dicts ────────────────────────
    attack_X_list, attack_y_list = [], []
    for label_id in sorted(attack_windows_X.keys()):
        wins = attack_windows_X[label_id]
        if wins:
            attack_X_list.extend(wins)
            attack_y_list.extend(attack_windows_y[label_id])
            logger.info(f"  class {label_id} ({CLASS_NAMES.get(label_id,'?')}): "
                        f"{len(wins):,} windows")

    if not attack_X_list:
        raise RuntimeError("No attack windows extracted!")

    X_attack = np.stack(attack_X_list).astype(np.float32)
    y_attack  = np.array(attack_y_list, dtype=np.int32)
    logger.info(f"\nTotal attack windows: {len(X_attack):,}")

    # ── Build BENIGN windows from pooled real BENIGN rows ─────────────────
    logger.info("\n" + "─"*60)
    if not benign_chunks:
        raise RuntimeError("No BENIGN rows found in any CSV file!")

    df_all_benign = pd.concat(benign_chunks, ignore_index=True)
    total_benign_rows = len(df_all_benign)
    logger.info(f"Total real BENIGN rows pooled: {total_benign_rows:,}")

    raw_benign_X = []
    for i in range(0, len(df_all_benign) - window_size, step):
        w     = df_all_benign.iloc[i:i+window_size]
        feats = extract_17_features(w)
        raw_benign_X.append(feats)

    if not raw_benign_X:
        raise RuntimeError(f"Not enough BENIGN rows for even one window "
                           f"(need >= {window_size}, got {total_benign_rows})")

    raw_benign_X = np.stack(raw_benign_X).astype(np.float32)
    n_raw_benign = len(raw_benign_X)
    logger.info(f"Raw BENIGN windows: {n_raw_benign:,}")

    # ── Balance BENIGN vs attack ───────────────────────────────────────────
    n_target = len(X_attack)
    rng = np.random.default_rng(42)
    if n_raw_benign < n_target:
        indices  = rng.choice(n_raw_benign, size=n_target, replace=True)
        X_normal = raw_benign_X[indices]
        factor   = n_target / n_raw_benign
        logger.info(f"Oversampled BENIGN: {n_raw_benign:,} → {n_target:,} (×{factor:.1f})")
    else:
        X_normal = raw_benign_X[:n_target]
        logger.info(f"BENIGN windows (no oversample needed): {n_target:,}")

    y_normal = np.zeros(n_target, dtype=np.int32)

    # ── Interleave Normal blocks with attack data (temporal realism) ──────
    n_attack = len(X_attack)
    n_blocks = max(len(csv_files), 1)
    normal_chunk      = n_target  // (n_blocks + 1)
    attack_chunk_size = n_attack  // n_blocks

    X_interleaved, y_interleaved = [], []
    for b in range(n_blocks):
        ns, ne = b * normal_chunk, (b + 1) * normal_chunk
        X_interleaved.append(X_normal[ns:ne])
        y_interleaved.append(y_normal[ns:ne])
        astart = b * attack_chunk_size
        aend   = (b + 1) * attack_chunk_size if b < n_blocks - 1 else n_attack
        X_interleaved.append(X_attack[astart:aend])
        y_interleaved.append(y_attack[astart:aend])
    X_interleaved.append(X_normal[n_blocks * normal_chunk:])
    y_interleaved.append(y_normal[n_blocks * normal_chunk:])

    X = np.vstack(X_interleaved).astype(np.float32)
    y = np.hstack(y_interleaved).astype(np.int32)

    logger.info(f"\n✅ Total: {len(X)} windows × 17 features "
                f"(real BENIGN oversampled, temporal interleaved)")
    logger.info(f"Class distribution:")
    for cls_id, cls_name in CLASS_NAMES.items():
        cnt = (y == cls_id).sum()
        if cnt > 0:
            logger.info(f"  [{cls_id}] {cls_name:15s}: {cnt:6,} ({cnt/len(y)*100:.1f}%)")

    # ── Temporal split (NO shuffle) ───────────────────────────────────────
    # Keep temporal order: first 80% = train, last 20% = test
    # This ensures Track B forecaster has meaningful future labels.
    split = int(len(X) * 0.8)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    # Standardize
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # Save
    np.save(output_dir / 'X_train.npy', X_train_s)
    np.save(output_dir / 'X_test.npy',  X_test_s)
    np.save(output_dir / 'y_train.npy', y_train)
    np.save(output_dir / 'y_test.npy',  y_test)
    # Save raw (unoversampled) BENIGN windows for leak-free CV
    np.save(output_dir / 'X_benign_raw.npy', raw_benign_X)
    with open(output_dir / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    with open(output_dir / 'features.txt', 'w') as f:
        f.write('\n'.join(FEATURE_NAMES))

    metadata = {
        'source':       'CICDDoS2019_real_benign',
        'benign_source': f'real BENIGN rows from CICDDoS2019 ({total_benign_rows} rows → {n_raw_benign} windows → oversampled to {n_target})',
        'n_features':   17,
        'feature_names': FEATURE_NAMES,
        'n_classes':    7,
        'class_names':  CLASS_NAMES,
        'window_size':  window_size,
        'step':         step,
        'train_samples': int(len(X_train)),
        'test_samples':  int(len(X_test)),
        'class_dist_train': {CLASS_NAMES[i]: int((y_train==i).sum()) for i in range(7)},
        'class_dist_test':  {CLASS_NAMES[i]: int((y_test==i).sum())  for i in range(7)},
    }
    with open(output_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)

    logger.info(f"\n  X_train: {X_train_s.shape}")
    logger.info(f"  X_test:  {X_test_s.shape}")
    logger.info(f"  Saved to: {output_dir}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir',         default='./Dataset')
    parser.add_argument('--output-dir',       default='./datasets/processed_v2')
    parser.add_argument('--max-windows-per-class', type=int, default=50000,
                        help='Max windows per attack class (0=unlimited)')
    parser.add_argument('--window-size',      type=int, default=100)
    parser.add_argument('--step',             type=int, default=50)
    args = parser.parse_args()

    build_dataset(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        max_windows_per_class=args.max_windows_per_class,
        window_size=args.window_size,
        step=args.step,
    )
