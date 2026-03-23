# M1: Proactive DDoS Predictor (TCN) with CICDDoS2019

This folder contains a complete implementation of the M1 module:
- Sequence generation from CICDDoS2019 CSV files
- Binary attack forecasting at horizon Delta (default 30s ahead)
- TCN model with focal loss for imbalanced data
- Threshold tuning under FPR constraint (default <= 5%)
- Realtime inference script for DCAE-style event streams

## 1) Folder Layout

```
m1_cicddos2019/
  requirements.txt
  config.yaml
  train_m1.py
  evaluate_m1.py
  realtime_infer_m1.py
  src/
    config.py
    data_pipeline.py
    model.py
    metrics.py
```

## 2) Install Dependencies

```bash
pip install -r requirements.txt
```

### Kaggle Setup (recommended for cloud training)

If you train inside Kaggle Notebook, use the Kaggle-specific dependency file:

```bash
!pip install -q -r /kaggle/working/Main/m1_cicddos2019/requirements-kaggle.txt
```

Suggested Kaggle notebook workflow:

1. Attach your dataset (or upload zipped project + dataset).
2. Copy project to writable workspace:

```bash
!cp -r /kaggle/input/<your-project-dataset>/Main /kaggle/working/Main
```

3. Train from the M1 folder:

```bash
%cd /kaggle/working/Main/m1_cicddos2019
!python train_m1.py --config ./config.kaggle.yaml
!python evaluate_m1.py --config ./config.kaggle.yaml --model-dir /kaggle/working/artifacts/m1_tcn
```

4. Save artifacts as Kaggle outputs (download after run):
  - `./artifacts/m1_tcn/model.pt`
  - `./artifacts/m1_tcn/scaler.joblib`
  - `./artifacts/m1_tcn/test_metrics.json`
  - `./artifacts/m1_tcn/eval_metrics.json`

## 3) Prepare Data

Place CICDDoS2019 CSV files under:

```
./data/cicddos2019/
```

The loader scans recursively (`**/*.csv`).

Required columns:
- `Timestamp` (or configure another name in `config.yaml`)
- `Label`

Feature setup:
- The config is now pinned to the same 15 engineered features used in M2:
  pkt_rate, byte_rate, syn_rate, src_ip_entropy, dst_ip_entropy,
  pkt_len_mean, pkt_len_std, flow_rate, iat_mean, iat_std,
  tcp_flag_ratio, retry_rate, icmp_rate, udp_rate, http_rate.
- The pipeline auto-derives these 15 features from raw CICDDoS2019 columns.
- No manual feature export is required as long as standard CICDDoS2019 columns are present.

## 4) Train M1

```bash
python train_m1.py --config ./config.yaml
```

Artifacts are saved to:

```
./artifacts/m1_tcn/
  model.pt
  scaler.joblib
  test_metrics.json
  training_history.json
  threshold_stats.json
  config_used.json
```

## 5) Evaluate M1

```bash
python evaluate_m1.py --config ./config.yaml --model-dir ./artifacts/m1_tcn
```

Outputs:
- `eval_metrics.json`
- `eval_predictions.csv`
- `eval_loss.json`

## 6) Realtime Inference

Input format: JSONL file where each line is one feature sample:

```json
{"Flow Duration": 1234, "Total Fwd Packets": 9, "...": 0.12}
```

Run:

```bash
python realtime_infer_m1.py --model-dir ./artifacts/m1_tcn --input-jsonl ./samples.jsonl --output-jsonl ./m1_predictions.jsonl
```

Each output line contains:
- `p_attack_future`
- `pre_alert` (threshold 0.60)
- `full_alert` (threshold 0.80)
- `predict_horizon_seconds`

## 7) ONAP/CLAMP Hook

For pipeline integration:
- Publish `p_attack_future` into DMaaP topic (example: `pad.events`)
- CLAMP policy logic:
  - `p > 0.80`: active mitigation chain
  - `0.60 < p <= 0.80`: standby pre-provisioning
  - else: monitor/scale-down

## 8) Notes for CICDDoS2019

- Some files have format differences; set `timestamp_column` if needed.
- If labels are not exactly `BENIGN`, update `benign_keywords` list.
- For strict thesis setup, pin `feature_columns` to your chosen 15 engineered features.
