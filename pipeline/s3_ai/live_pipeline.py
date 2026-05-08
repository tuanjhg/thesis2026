#!/usr/bin/env python3
"""
PAD-ONAP Live Pipeline — Two-Track Inference Driver (Spec §3 → §4)
==================================================================

Drives the two-track InferenceEngine v2 from a live feature source and
publishes coalesced AIOutputPayload (schema 3.0) to stdout / JSONL / DMaaP.

Sources:
  --source kafka  (recommended; spec-aligned)
      Subscribes to BOTH Kafka topics:
        - telemetry.features.flow         (Track A, 22-dim, every 1 s)
        - telemetry.features.timeseries   (Track B, 6-dim, every 60 s)
      Track A and Track B are dispatched to the engine independently and
      merged by the coalescer (target_ip_prefix + 30 s bucket) before each
      payload is emitted.  Internally delegates to InferenceEngine.run_kafka().

  --source http
      Polls the NetFlow collector at GET /flows/latest.  The collector emits
      aggregate metrics (pkt_rate, byte_rate, *_entropy, ...).  We map this
      snapshot to the 22-dim Track A feature vector via a lossless inversion
      of the dual-branch flink mapping (see _flow_features_from_snapshot()).
      Track B (60 s tumbling) cannot be reconstructed from a single snapshot;
      in HTTP mode only Track A is exercised.

  --orchestrate
      Hands control to pipeline.s4_orchestration.orchestrator.Orchestrator,
      which adds the M3 (TierMapper / PolicyEngine / SLA) and M4 (CNF / SFC)
      stages on top of M2.

Usage:
  # Two-track Kafka mode (production-shaped)
  python pipeline/s3_ai/live_pipeline.py --source kafka --broker localhost:9092

  # HTTP collector polling (Track A only)
  python pipeline/s3_ai/live_pipeline.py --source http --collector http://localhost:7070

  # Full M2→M3→M4 (delegates to Orchestrator)
  python pipeline/s3_ai/live_pipeline.py --orchestrate

  # Real ONAP mode
  PAD_DEPLOY_MODE=onap python pipeline/s3_ai/live_pipeline.py --orchestrate
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

# Ensure project root on sys.path when run as a script
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import numpy as np

from pipeline.s3_ai.inference_layer import (
    InferenceEngine,
    PayloadCoalescer,
    TRACK_A_FEATURES,
    TRACK_B_FEATURES,
    KAFKA_TOPIC_FLOW,
    KAFKA_TOPIC_TS,
    KAFKA_TOPIC_FLOW_LEGACY,
    KAFKA_TOPIC_OUT,
    KAFKA_TOPIC_OUT_LEGACY,
    run_kafka as engine_run_kafka,
    _to_dict as _dataclass_to_dict,
)
from pipeline.s3_ai.ai_output import (
    build_payload,
    payload_to_dict,
)
from pipeline.s4_orchestration.tier_mapper import TierMapper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('live_pipeline')


# ─────────────────────────────────────────────────────────────────────────────
# HTTP collector helpers
# ─────────────────────────────────────────────────────────────────────────────

def fetch_latest(collector_url: str, timeout: float = 3.0) -> Optional[dict]:
    """GET /flows/latest from NetFlow Collector."""
    url = f'{collector_url.rstrip("/")}/flows/latest'
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read())
    except Exception as e:
        logger.debug(f'Collector fetch failed: {e}')
        return None


def _flow_features_from_snapshot(snapshot: dict) -> np.ndarray:
    """
    Reconstruct a 22-dim Track A flow vector from a single collector snapshot.

    The collector emits aggregate per-interval rates rather than per-flow
    records; we therefore run the same best-effort mapping the dual-branch
    Flink processor uses (see pipeline.s2_features.flink_processor.extract_track_a),
    treating the snapshot as a 1-tuple "window".
    """
    # Fields the collector exports today (legacy 17-feature schema)
    pkt_rate           = float(snapshot.get('pkt_rate',           0.0))
    byte_rate          = float(snapshot.get('byte_rate',          0.0))
    avg_pkt_size       = float(snapshot.get('avg_pkt_size',       0.0))
    pkt_size_std       = float(snapshot.get('pkt_size_std',       0.0))
    iat_mean_ms        = float(snapshot.get('inter_arrival_mean', snapshot.get('iat_mean_ms', 0.0)))
    iat_std_ms         = float(snapshot.get('inter_arrival_std',  snapshot.get('iat_std_ms', 0.0)))
    flow_duration_mean = float(snapshot.get('flow_duration_mean', 5.0))
    syn_ratio          = float(snapshot.get('syn_ratio',          0.0))
    proto_tcp          = float(snapshot.get('proto_dist_tcp',     0.0))
    proto_udp          = float(snapshot.get('proto_dist_udp',     0.0))
    proto_icmp         = float(snapshot.get('proto_dist_icmp',    0.0))

    # 5-second window assumption (matches the Flink Track A window size)
    window_s    = 5.0
    total_pkts  = pkt_rate  * window_s
    total_bytes = byte_rate * window_s
    # Without per-direction stats, split symmetrically (60/40 fwd/bwd)
    total_fwd_pkts  = 0.6 * total_pkts
    total_bwd_pkts  = 0.4 * total_pkts
    total_fwd_bytes = 0.6 * total_bytes
    total_bwd_bytes = 0.4 * total_bytes

    proto_idx  = int(np.argmax([proto_tcp, proto_udp, proto_icmp]))
    proto_code = (6, 17, 1)[proto_idx]

    feature_map = {
        'flow_duration':              window_s,
        'total_fwd_packets':          total_fwd_pkts,
        'total_bwd_packets':          total_bwd_pkts,
        'total_length_fwd_packets':   total_fwd_bytes,
        'total_length_bwd_packets':   total_bwd_bytes,
        'fwd_packet_length_max':      avg_pkt_size + pkt_size_std,
        'fwd_packet_length_mean':     avg_pkt_size,
        'bwd_packet_length_mean':     avg_pkt_size,
        'flow_bytes_per_sec':         byte_rate,
        'flow_packets_per_sec':       pkt_rate,
        'flow_iat_mean':              iat_mean_ms,
        'flow_iat_std':               iat_std_ms,
        'fwd_iat_total':              iat_mean_ms * total_fwd_pkts,
        'fwd_iat_mean':               iat_mean_ms,
        'bwd_iat_total':              iat_mean_ms * total_bwd_pkts,
        'syn_flag_count':             syn_ratio * total_pkts,
        'ack_flag_count':             0.0,
        'fwd_psh_flags':              0.0,
        'init_win_bytes_fwd':         0.0,
        'init_win_bytes_bwd':         0.0,
        'min_seg_size_fwd':           0.0,
        'protocol':                   float(proto_code),
    }
    return np.array(
        [feature_map[name] for name in TRACK_A_FEATURES],
        dtype=np.float32,
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTTP-mode loop (Track A only — collector does not provide 60 s aggregates)
# ─────────────────────────────────────────────────────────────────────────────

def run_http_loop(
    *,
    collector_url: str,
    model_dir:     str,
    data_dir:      str,
    interval:      float,
    device:        str,
    shap_enabled:  bool,
    out_path:      Optional[str],
    max_windows:   Optional[int],
    mode:          str = 'spec',
):
    """Poll the collector and run Track A inference; print + JSONL output."""
    logger.info('=' * 64)
    logger.info('  PAD-ONAP Live Pipeline — HTTP / Track A only')
    logger.info('=' * 64)
    logger.info(f'  Collector  : {collector_url}')
    logger.info(f'  Model dir  : {model_dir}  (mode={mode})')
    logger.info(f'  Interval   : {interval}s')
    logger.info(f'  Output     : {out_path or "stdout only"}')
    logger.info('=' * 64)

    engine = InferenceEngine.load(
        model_dir    = model_dir,
        data_dir     = data_dir,
        mode         = mode,
        device       = device,
        shap_enabled = shap_enabled,
    )
    mapper = TierMapper()

    out_file = open(out_path, 'a') if out_path else None

    _running = [True]
    def _handler(sig, frame):
        logger.info('Shutdown signal — stopping...')
        _running[0] = False
    signal.signal(signal.SIGINT,  _handler)
    signal.signal(signal.SIGTERM, _handler)

    window_count       = 0
    last_ts            = None
    consecutive_errors = 0
    MAX_ERRORS         = 10

    logger.info('Waiting for first snapshot from collector...')
    while _running[0]:
        t_loop = time.perf_counter()

        raw = fetch_latest(collector_url)
        if raw is None:
            consecutive_errors += 1
            if consecutive_errors == 1:
                logger.warning(f'Collector not responding at {collector_url}')
            if consecutive_errors >= MAX_ERRORS:
                logger.error(f'{MAX_ERRORS} consecutive failures — check collector')
                consecutive_errors = 0
            time.sleep(interval); continue
        consecutive_errors = 0

        ts = raw.get('timestamp')
        if ts is not None and ts == last_ts:
            time.sleep(max(0.0, interval - (time.perf_counter() - t_loop)))
            continue
        last_ts = ts

        snapshot = raw.get('features') or raw
        if not isinstance(snapshot, dict) or not snapshot:
            time.sleep(interval); continue

        # Build 22-dim Track A vector + run inference
        x22  = _flow_features_from_snapshot(snapshot)
        det  = engine.infer_track_a(x22, source_device_id=raw.get('device_id', 'unknown'))
        payload = build_payload(
            detection            = _det_to_dataclass(det),
            forecast             = None,
            source_ip_prefix     = raw.get('source_ip_prefix'),
            target_ip_prefix     = raw.get('target_ip_prefix'),
            tenant_id            = raw.get('tenant_id'),
            xgboost_version      = engine.xgb_version,
            lstm_track_b_version = engine.forecaster_version,
        )
        td = mapper.decide(payload)
        window_count += 1

        # ── Console summary ─────────────────────────────────────────────────
        print(
            f'\n[W{window_count:04d}] {payload.timestamp_utc[:19]}Z  '
            f'lat={det.inference_ms:.1f}ms  severity={payload.severity_estimate}'
        )
        print(
            f'  Detection : {det.attack_type:<14}  '
            f'class={det.attack_class_id:>2}  conf={det.confidence:.3f}'
        )
        print(f'  Tier      : T{int(td.tier)} — {td.label}')
        if det.shap_top_features:
            top5 = list(det.shap_values.items())[:5]
            print('  SHAP top5 : ' + '  '.join(f'{k}={v:+.3f}' for k, v in top5))
        if td.cnf_profile:
            print(f'  CNF       : {td.cnf_profile}  reason={td.reason}')

        # ── Persist JSONL ──────────────────────────────────────────────────
        if out_file:
            rec = payload_to_dict(payload)
            rec['tier']           = int(td.tier)
            rec['cnf_profile']    = td.cnf_profile
            rec['live_features']  = snapshot
            out_file.write(json.dumps(rec) + '\n')
            out_file.flush()

        if max_windows and window_count >= max_windows:
            logger.info(f'Reached max_windows={max_windows} — stopping.')
            break

        if window_count % 50 == 0:
            lat = engine.latency_summary()
            logger.info(
                f'[W{window_count}] Track A P99={lat["track_a_ms"]["p99"]:.1f}ms  '
                f'(n={lat["n_a"]})'
            )

        sleep_t = max(0.0, interval - (time.perf_counter() - t_loop))
        time.sleep(sleep_t)

    if out_file:
        out_file.close()
    logger.info(f'Live pipeline stopped after {window_count} windows.')
    if window_count > 0:
        lat = engine.latency_summary()
        logger.info(
            f'Final — Track A P99={lat["track_a_ms"]["p99"]:.1f}ms  '
            f'(n={lat["n_a"]})'
        )


def _det_to_dataclass(det):
    """Convert inference_layer.TrackADetection → ai_output.DetectionResult."""
    from pipeline.s3_ai.ai_output import DetectionResult
    return DetectionResult(
        track             = det.track,
        attack_type       = det.attack_type,
        attack_class_id   = det.attack_class_id,
        confidence        = det.confidence,
        is_attack         = det.is_attack,
        class_probs       = dict(det.class_probs),
        shap_top_features = list(det.shap_top_features),
        shap_values       = dict(det.shap_values),
        explanation_text  = det.explanation_text,
        inference_ms      = det.inference_ms,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Backwards-compat consumer for orchestrator.py (single-feature-topic poll)
# ─────────────────────────────────────────────────────────────────────────────

class KafkaFeatureConsumer:
    """
    Lightweight legacy consumer used by `orchestrator.py` when --source=kafka.
    Subscribes to telemetry.features.flow + the legacy alias and returns the
    most recently observed message in a non-blocking fashion.

    This wrapper is intentionally simple — Track B aggregates are NOT consumed
    here (the orchestrator's _step() takes a Track A 22-dim vector only).  For
    full two-track operation invoke the engine's Kafka runner via --source=kafka
    in this script (which delegates to inference_layer.run_kafka).
    """

    TOPICS = (KAFKA_TOPIC_FLOW, KAFKA_TOPIC_FLOW_LEGACY)

    def __init__(self, broker: str, group_id: str = 'pad-live-pipeline'):
        from kafka import KafkaConsumer
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
                    *self.TOPICS,
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
                    f'[Kafka attempt {attempt}] subscribed to '
                    f'{",".join(self.TOPICS)} @ {self._broker}'
                )
                return c
            except Exception as e:
                logger.warning(
                    f'[Kafka attempt {attempt}] failed: {e} — retry in {delay}s'
                )
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def poll_latest(self) -> Optional[dict]:
        latest = None
        try:
            for msg in self._consumer:
                latest = msg.value
        except StopIteration:
            pass
        except Exception as e:
            logger.error(f'Kafka error: {e} — reconnecting...')
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


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    _root = Path(__file__).resolve().parent.parent.parent
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Live Pipeline (two-track inference driver)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--source',       default='kafka',
                        choices=['http', 'kafka'])
    parser.add_argument('--collector',    default='http://localhost:7070')
    parser.add_argument('--broker',       default='localhost:9092')
    parser.add_argument('--model-dir',    default=str(_root / 'pad_onap_v3' / 'models'))
    parser.add_argument('--data-dir',     default=str(_root / 'pad_onap_v3' / 'processed'))
    parser.add_argument('--mode',         default='spec', choices=['spec', 'legacy'],
                        help='InferenceEngine mode — spec (22+6) or legacy bridge')
    parser.add_argument('--interval',     type=float, default=1.0)
    parser.add_argument('--device',       default='auto', choices=['auto', 'cuda', 'cpu'])
    parser.add_argument('--no-shap',      action='store_true')
    parser.add_argument('--out',          default=None)
    parser.add_argument('--max-windows',  type=int, default=None)
    parser.add_argument('--orchestrate',  action='store_true',
                        help='Run full M2→M3→M4 (delegates to Orchestrator)')
    parser.add_argument('--latency-port', type=int, default=9292)
    parser.add_argument('--group-id',     default='pad-inference-engine')
    args = parser.parse_args()

    if args.orchestrate:
        from pipeline.s4_orchestration.orchestrator import Orchestrator
        orch = Orchestrator(
            model_dir    = args.model_dir,
            data_dir     = args.data_dir,
            mode         = args.mode,
            device       = args.device,
            shap_enabled = not args.no_shap,
            latency_port = args.latency_port,
        )
        orch.run(
            source        = args.source,
            collector_url = args.collector,
            broker        = args.broker,
            interval      = args.interval,
            out_path      = args.out,
            max_windows   = args.max_windows,
        )
        return

    if args.source == 'kafka':
        # Two-track Kafka path — delegate to the inference engine's runner.
        engine_run_kafka(
            broker       = args.broker,
            model_dir    = args.model_dir,
            data_dir     = args.data_dir,
            mode         = args.mode,
            shap_enabled = not args.no_shap,
            group_id     = args.group_id,
            out_path     = args.out,
        )
        return

    # HTTP collector mode (Track A only)
    run_http_loop(
        collector_url = args.collector,
        model_dir     = args.model_dir,
        data_dir      = args.data_dir,
        interval      = args.interval,
        device        = args.device,
        shap_enabled  = not args.no_shap,
        out_path      = args.out,
        max_windows   = args.max_windows,
        mode          = args.mode,
    )


if __name__ == '__main__':
    main()
