#!/usr/bin/env python3
"""
PAD-ONAP Live Pipeline — Phase 1 → Phase 2 Bridge
====================================================
Kết nối NetFlow Collector / Kafka (Phase 1) với InferenceEngine (Phase 2).

Hai chế độ nguồn dữ liệu:
  --source http  (mặc định)
      collector  GET /flows/latest  →  feature dict (17 keys)

  --source kafka
      Kafka topic pad.telemetry.features  →  feature dict (17 keys)
      (do flink_processor.py publish)

Luồng chung:
  feature dict → np.ndarray (theo thứ tự FEATURE_NAMES)
      ↓
  InferenceEngine.infer()
      ├─ XGBoost  → attack_type + confidence + SHAP top-5
      └─ Transformer+LSTM → P(t+30s/60s/90s/120s)
      ↓
  AIOutputPayload  →  stdout + JSON log + DMaaP stub

Usage:
  # HTTP polling mode (gNMI + collector đang chạy):
  python pipeline/s3_ai/live_pipeline.py --source http

  # Kafka mode (full stack: docker compose up -d):
  python pipeline/s3_ai/live_pipeline.py --source kafka

  # Chỉ định URL collector và model dir:
  python pipeline/s3_ai/live_pipeline.py \\
      --source http \\
      --collector http://localhost:7070 \\
      --model-dir ./pad_onap_v3/models \\
      --data-dir  ./pad_onap_v3/processed \\
      --interval  1.0

  # Kafka với broker cụ thể:
  python pipeline/s3_ai/live_pipeline.py \\
      --source kafka \\
      --broker localhost:9092

  # Không dùng SHAP (nhanh hơn ~1-2ms):
  python pipeline/s3_ai/live_pipeline.py --no-shap

  # Lưu output ra file JSON (append):
  python pipeline/s3_ai/live_pipeline.py --out ./pad_onap_v3/live_output.jsonl
"""

import argparse
import json
import logging
import signal
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

# Ensure project root is on sys.path when run as a script
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import numpy as np

# ── FEATURE_NAMES phải khớp với FlowFeatureExtractor và scaler training ───────
FEATURE_NAMES = [
    'pkt_rate', 'byte_rate',
    'src_ip_entropy', 'dst_ip_entropy',
    'src_port_entropy', 'dst_port_entropy',
    'proto_dist_tcp', 'proto_dist_udp', 'proto_dist_icmp',
    'syn_ratio', 'fin_ratio',
    'avg_pkt_size', 'pkt_size_std',
    'new_flows_rate', 'flow_duration_mean',
    'inter_arrival_mean', 'inter_arrival_std',
]

# Tier thresholds (aligned với ai_output.py)
TIER_RULES = [
    (4, lambda conf, p30: conf > 0.95 and p30 > 0.95),
    (3, lambda conf, p30: conf > 0.90 and p30 > 0.90),
    (2, lambda conf, p30: p30 > 0.70 or conf > 0.80),
    (1, lambda conf, p30: conf > 0.50),
    (0, lambda conf, p30: True),
]

TIER_LABEL = {
    0: "Normal — no action",
    1: "Low    — rate-limit",
    2: "Medium — VNF firewall",
    3: "High   — scale-out scrubber",
    4: "Critical — traffic isolation",
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('live_pipeline')


# ── Collector client (HTTP mode) ──────────────────────────────────────────────

def fetch_latest(collector_url: str, timeout: float = 3.0) -> Optional[dict]:
    """
    GET /flows/latest từ NetFlow Collector.
    Returns feature dict hoặc None nếu không có dữ liệu / lỗi kết nối.
    """
    url = f'{collector_url.rstrip("/")}/flows/latest'
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read())
    except Exception as e:
        logger.debug(f"Collector fetch failed: {e}")
        return None


# ── Kafka consumer (Kafka mode) ────────────────────────────────────────────────

class KafkaFeatureConsumer:
    """
    Consumes pre-computed feature vectors from `pad.telemetry.features`.
    Supports auto-reconnect with exponential backoff on connection loss.

    Each Kafka message published by flink_processor.py has shape:
      { "timestamp": "...", "features": { "pkt_rate": ..., ... } }
    """

    TOPIC = 'pad.telemetry.features'

    def __init__(self, broker: str, group_id: str = 'pad-live-pipeline'):
        self._broker   = broker
        self._group_id = group_id
        self._consumer = self._connect()

    def _connect(self):
        from kafka import KafkaConsumer
        delay   = 2
        attempt = 0
        while True:
            attempt += 1
            try:
                c = KafkaConsumer(
                    self.TOPIC,
                    bootstrap_servers=[self._broker],
                    group_id=self._group_id,
                    auto_offset_reset='latest',
                    enable_auto_commit=True,
                    value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                    consumer_timeout_ms=500,
                    session_timeout_ms=30_000,
                    heartbeat_interval_ms=10_000,
                    max_poll_interval_ms=60_000,
                )
                logger.info(
                    f"[Kafka consumer attempt {attempt}] "
                    f"Subscribed to {self.TOPIC} @ {self._broker}"
                )
                return c
            except Exception as e:
                logger.warning(
                    f"[Kafka consumer attempt {attempt}] Failed: {e} "
                    f"— retry in {delay}s"
                )
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def poll_latest(self) -> Optional[dict]:
        """
        Non-blocking poll. Drains all pending messages, returns the most
        recent (avoids processing stale vectors accumulated during downtime).
        Returns None if no messages available.
        """
        latest = None
        try:
            for msg in self._consumer:
                latest = msg.value
        except StopIteration:
            pass   # consumer_timeout_ms expired — normal
        except Exception as e:
            logger.error(f"Kafka consumer error: {e} — reconnecting...")
            try:
                self._consumer.close()
            except Exception:
                pass
            self._consumer = self._connect()
        return latest

    def close(self):
        try:
            self._consumer.close()
        except Exception:
            pass


def features_dict_to_array(features: dict) -> np.ndarray:
    """
    Chuyển features dict từ collector → np.ndarray (17,) theo đúng thứ tự FEATURE_NAMES.
    Thiếu key nào → điền 0.0.
    """
    return np.array(
        [float(features.get(name, 0.0)) for name in FEATURE_NAMES],
        dtype=np.float32,
    )


def get_tier(confidence: float, p30: float, attack_class: int) -> int:
    if attack_class == 0:
        return 0
    for tier, rule in TIER_RULES:
        if rule(confidence, p30):
            return tier
    return 0


# ── Live loop ─────────────────────────────────────────────────────────────────

def run_live(
    source:        str,
    collector_url: str,
    broker:        str,
    model_dir:     str,
    data_dir:      str,
    interval:      float,
    device:        str,
    shap_enabled:  bool,
    out_path:      Optional[str],
    max_windows:   Optional[int],
):
    from pipeline.s3_ai.inference_layer import InferenceEngine
    from pipeline.s3_ai.ai_output import payload_to_dict

    logger.info("=" * 62)
    logger.info("  PAD-ONAP Live Pipeline  (Phase 1 → Phase 2)")
    logger.info("=" * 62)
    logger.info(f"  Source    : {source.upper()}")
    if source == 'http':
        logger.info(f"  Collector : {collector_url}")
    else:
        logger.info(f"  Broker    : {broker}  (topic: pad.telemetry.features)")
    logger.info(f"  Models    : {model_dir}")
    logger.info(f"  Interval  : {interval}s")
    logger.info(f"  SHAP      : {shap_enabled}")
    logger.info(f"  Output    : {out_path or 'stdout only'}")
    logger.info("=" * 62)

    # Load engine
    engine = InferenceEngine.load(
        model_dir    = model_dir,
        data_dir     = data_dir,
        device       = device,
        shap_enabled = shap_enabled,
    )

    # Set up Kafka consumer if needed
    kafka_consumer = None
    if source == 'kafka':
        kafka_consumer = KafkaFeatureConsumer(broker=broker)

    # Open output file (append JSONL)
    out_file = open(out_path, 'a') if out_path else None

    # Graceful shutdown
    _running = [True]
    def _handler(sig, frame):
        logger.info("Shutdown signal received — stopping...")
        _running[0] = False
    signal.signal(signal.SIGINT,  _handler)
    signal.signal(signal.SIGTERM, _handler)

    window_count   = 0
    last_timestamp = None
    consecutive_errors = 0
    MAX_ERRORS = 10

    logger.info("Waiting for first feature vector...")

    while _running[0]:
        t_loop = time.perf_counter()

        # ── Fetch feature vector ───────────────────────────────────────────────
        if source == 'kafka':
            raw = kafka_consumer.poll_latest()
            if raw is None:
                time.sleep(max(0.0, interval - (time.perf_counter() - t_loop)))
                continue
        else:
            raw = fetch_latest(collector_url)
            if raw is None:
                consecutive_errors += 1
                if consecutive_errors == 1:
                    logger.warning(
                        f"Collector not responding at {collector_url}/flows/latest "
                        f"— is it running?"
                    )
                if consecutive_errors >= MAX_ERRORS:
                    logger.error(
                        f"{MAX_ERRORS} consecutive fetch errors — check collector. "
                        f"Run: python testbed/netflow_collector/collector.py --mode synthetic"
                    )
                    consecutive_errors = 0
                time.sleep(interval)
                continue
            consecutive_errors = 0

        # ── Deduplication by timestamp ────────────────────────────────────────
        ts = raw.get('timestamp')
        if ts is not None and ts == last_timestamp:
            remaining = interval - (time.perf_counter() - t_loop)
            if remaining > 0:
                time.sleep(remaining)
            continue
        last_timestamp = ts

        # ── Convert dict → ndarray ────────────────────────────────────────────
        features_dict = raw.get('features', {})
        if not features_dict:
            time.sleep(interval)
            continue

        missing = [n for n in FEATURE_NAMES if n not in features_dict]
        if missing:
            logger.warning(f"Collector missing features: {missing} — filling 0.0")

        x_raw = features_dict_to_array(features_dict)

        # ── Inference ─────────────────────────────────────────────────────────
        t_inf = time.perf_counter()
        payload = engine.infer(x_raw)
        inf_ms  = (time.perf_counter() - t_inf) * 1000
        window_count += 1

        # ── Compute tier ──────────────────────────────────────────────────────
        tier = get_tier(
            confidence   = payload.detection.confidence,
            p30          = payload.forecast.p_attack_30s,
            attack_class = payload.detection.attack_class,
        )

        # ── Print summary ─────────────────────────────────────────────────────
        proactive_marker = " [PROACTIVE]" if payload.proactive_trigger.triggered else ""
        print(
            f"\n[W{window_count:04d}] {payload.timestamp[:19]}Z  "
            f"latency={inf_ms:.1f}ms{proactive_marker}"
        )
        print(
            f"  Attack   : {payload.detection.attack_type:<14} "
            f"conf={payload.detection.confidence:.3f}"
        )
        print(
            f"  Forecast : P30={payload.forecast.p_attack_30s:.3f}  "
            f"P60={payload.forecast.p_attack_60s:.3f}  "
            f"P90={payload.forecast.p_attack_90s:.3f}  "
            f"P120={payload.forecast.p_attack_120s:.3f}"
        )
        print(f"  Tier     : T{tier} — {TIER_LABEL[tier]}")
        if payload.proactive_trigger.triggered:
            print(
                f"  *** PROACTIVE: {payload.forecast.recommended_action} "
                f"(P30={payload.forecast.p_attack_30s:.3f} > 0.70) ***"
            )
        if payload.detection.top_features:
            top5 = sorted(payload.detection.top_features.items(),
                          key=lambda kv: -kv[1])[:5]
            print(f"  SHAP top5: " +
                  "  ".join(f"{k}={v:.3f}" for k, v in top5))
        print(
            f"  Live features: "
            f"pkt_rate={features_dict.get('pkt_rate', 0):.0f}  "
            f"udp={features_dict.get('proto_dist_udp', 0):.3f}  "
            f"syn={features_dict.get('syn_ratio', 0):.3f}  "
            f"entropy={features_dict.get('src_ip_entropy', 0):.2f}"
        )

        # ── Write JSONL ────────────────────────────────────────────────────────
        if out_file:
            record = payload_to_dict(payload)
            record['tier'] = tier
            record['live_features'] = features_dict
            out_file.write(json.dumps(record) + '\n')
            out_file.flush()

        # ── Max windows guard ─────────────────────────────────────────────────
        if max_windows and window_count >= max_windows:
            logger.info(f"Reached max_windows={max_windows} — stopping.")
            break

        # ── Latency summary every 50 windows ─────────────────────────────────
        if window_count % 50 == 0:
            lat = engine.latency_summary()
            logger.info(
                f"[W{window_count}] Latency summary: "
                f"xgb P99={lat['xgboost_ms']['p99']:.1f}ms  "
                f"tf P99={lat['transformer_ms']['p99']:.1f}ms"
            )

        # ── Sleep for remaining interval ──────────────────────────────────────
        elapsed  = time.perf_counter() - t_loop
        sleep_t  = max(0.0, interval - elapsed)
        time.sleep(sleep_t)

    # ── Cleanup ────────────────────────────────────────────────────────────────
    if kafka_consumer:
        kafka_consumer.close()
    if out_file:
        out_file.close()

    logger.info(f"\nLive pipeline stopped after {window_count} windows.")
    if window_count > 0:
        lat = engine.latency_summary()
        logger.info(
            f"Final latency — XGBoost P99={lat['xgboost_ms']['p99']:.1f}ms  "
            f"Transformer P99={lat['transformer_ms']['p99']:.1f}ms"
        )


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Live Pipeline (Phase 1 → Phase 2)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--source',       default='http',
                        choices=['http', 'kafka'],
                        help='Feature source: http (collector REST) or kafka (pad.telemetry.features topic)')
    parser.add_argument('--collector',   default='http://localhost:7070',
                        help='NetFlow Collector base URL (used with --source http)')
    parser.add_argument('--broker',      default='localhost:9092',
                        help='Kafka bootstrap server (used with --source kafka)')
    # Default model paths: resolved relative to project root (not CWD),
    # so the script works regardless of where it is launched from.
    _root = Path(__file__).resolve().parent.parent.parent
    parser.add_argument('--model-dir',   default=str(_root / 'pad_onap_v3' / 'models'),
                        help='Absolute path to model directory')
    parser.add_argument('--data-dir',    default=str(_root / 'pad_onap_v3' / 'processed'),
                        help='Absolute path to processed data directory (scaler.pkl, y_train.npy)')
    parser.add_argument('--interval',    type=float, default=1.0,
                        help='Polling interval in seconds (http mode only)')
    parser.add_argument('--device',      default='auto',
                        choices=['auto', 'cuda', 'cpu'],
                        help='Inference device')
    parser.add_argument('--no-shap',     action='store_true',
                        help='Disable SHAP computation (faster)')
    parser.add_argument('--out',         default=None,
                        help='Output JSONL file path (append mode)')
    parser.add_argument('--max-windows', type=int, default=None,
                        help='Stop after N inference windows (default: run forever)')
    args = parser.parse_args()

    run_live(
        source        = args.source,
        collector_url = args.collector,
        broker        = args.broker,
        model_dir     = args.model_dir,
        data_dir      = args.data_dir,
        interval      = args.interval,
        device        = args.device,
        shap_enabled  = not args.no_shap,
        out_path      = args.out,
        max_windows   = args.max_windows,
    )


if __name__ == '__main__':
    main()
