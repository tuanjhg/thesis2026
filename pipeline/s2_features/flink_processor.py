#!/usr/bin/env python3
"""
PAD-ONAP Flink Processor — Dual-branch streaming feature extractor (Spec §3.2-3.4)
==================================================================================
Consumes raw gNMI snapshots from `telemetry.raw` and emits two parallel streams:

  Branch A (Track A — XGBoost classifier)
    Window  : 5 s sliding / 1 s slide
    Output  : 22-feature CICFlowMeter-style vector (Spec §3.3 top-22 by Extra Trees Gini)
    Topic   : telemetry.features.flow

  Branch B (Track B — Multivariate LSTM forecaster)
    Window  : 60 s tumbling
    Output  : 6 aggregated network-state variables (Spec §3.4)
    Topic   : telemetry.features.timeseries

Performance / stability:
  - Single Kafka consumer feeds both windows in the same loop (one pass over inputs)
  - Auto-reconnect with exponential backoff on consumer/producer failure
  - Producer flushes after every emit; non-blocking poll keeps cadence stable
  - Graceful SIGINT/SIGTERM shutdown; spam-throttled "empty window" logs

Best-effort upstream mapping:
  The current gNMI simulator exports aggregate per-interval metrics
  (in_pkts/out_pkts/in_bytes/out_bytes, *_ratio, *_entropy, iat_mean_ms, ...) rather
  than per-flow records.  We therefore reconstruct the 22 CICFlowMeter-style features
  from these aggregates; lossy fields default to 0 and are documented at use site.
  unique_*_ip_count is recovered from *_ip_entropy via Hartley exp(H) approximation.

Usage:
  python pipeline/s2_features/flink_processor.py
  python pipeline/s2_features/flink_processor.py \
      --broker localhost:9092 --flow-window 5.0 --flow-slide 1.0 --ts-window 60.0
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import signal
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('flink-processor')

# ── Topics (Spec §3.5) ────────────────────────────────────────────────────────
TOPIC_RAW       = 'telemetry.raw'
TOPIC_FLOW      = 'telemetry.features.flow'
TOPIC_TS        = 'telemetry.features.timeseries'

# Backwards-compat aliases — accept either canonical or legacy `pad.*` topic names.
TOPIC_RAW_LEGACY = 'pad.telemetry.raw'

# ── Track A — 22 CICFlowMeter-style features (Spec §3.3) ──────────────────────
TRACK_A_FEATURES = [
    'flow_duration',              # 1
    'total_fwd_packets',          # 2
    'total_bwd_packets',          # 3
    'total_length_fwd_packets',   # 4
    'total_length_bwd_packets',   # 5
    'fwd_packet_length_max',      # 6
    'fwd_packet_length_mean',     # 7
    'bwd_packet_length_mean',     # 8
    'flow_bytes_per_sec',         # 9
    'flow_packets_per_sec',       # 10
    'flow_iat_mean',              # 11
    'flow_iat_std',               # 12
    'fwd_iat_total',              # 13
    'fwd_iat_mean',               # 14
    'bwd_iat_total',              # 15
    'syn_flag_count',             # 16
    'ack_flag_count',             # 17
    'fwd_psh_flags',              # 18
    'init_win_bytes_fwd',         # 19
    'init_win_bytes_bwd',         # 20
    'min_seg_size_fwd',           # 21
    'protocol',                   # 22
]

# ── Track B — 6 aggregated variables (Spec §3.4) ──────────────────────────────
TRACK_B_FEATURES = [
    'pkt_count_total',
    'byte_count_total',
    'unique_src_ip_count',
    'unique_dst_ip_count',
    'avg_pkt_size',
    'syn_count',
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _f(val, default: float = 0.0) -> float:
    """Safe float coercion."""
    try:
        return float(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def _hartley_cardinality(entropy_bits: float) -> float:
    """
    Approximate unique cardinality from Shannon entropy in bits.
    Upper-bounded by 2**H (Hartley estimator); lossless for uniform distributions.
    Returns 0 for non-positive entropy.
    """
    h = max(0.0, _f(entropy_bits))
    if h <= 0.0:
        return 0.0
    return float(min(2 ** h, 1e9))   # clamp to avoid overflow on garbage input


# ── Track A feature extraction (5 s sliding window) ──────────────────────────

def extract_track_a(window: list[dict], window_s: float) -> dict:
    """
    Aggregate a window of raw gNMI snapshots into the 22-dim Track A feature vector.

    Mapping rationale (Spec §3.3 column → upstream metric):
      flow_duration            ← window_s (constant per window)
      total_fwd_packets        ← Σ in_pkts                       (ingress = forward)
      total_bwd_packets        ← Σ out_pkts                      (egress  = backward)
      total_length_fwd_packets ← Σ in_bytes
      total_length_bwd_packets ← Σ out_bytes
      fwd_packet_length_max    ← max(avg_pkt_size) over snapshots (proxy)
      fwd_packet_length_mean   ← mean(avg_pkt_size)               (no per-direction split)
      bwd_packet_length_mean   ← mean(avg_pkt_size)               (same — simulator limit)
      flow_bytes_per_sec       ← total_bytes / window_s
      flow_packets_per_sec     ← total_pkts  / window_s
      flow_iat_mean            ← mean(iat_mean_ms)
      flow_iat_std             ← mean(iat_std_ms)
      fwd_iat_total            ← iat_mean_ms × total_fwd_packets  (approx)
      fwd_iat_mean             ← mean(iat_mean_ms)
      bwd_iat_total            ← iat_mean_ms × total_bwd_packets  (approx)
      syn_flag_count           ← Σ (syn_ratio × pkts_per_snapshot)
      ack_flag_count           ← Σ (ack_ratio × pkts_per_snapshot)  (0 if upstream lacks ack_ratio)
      fwd_psh_flags            ← Σ (psh_ratio × in_pkts)            (0 if missing)
      init_win_bytes_fwd       ← last known init_win_fwd            (0 if missing)
      init_win_bytes_bwd       ← last known init_win_bwd            (0 if missing)
      min_seg_size_fwd         ← min(min_seg_size_fwd) over snapshots (0 if missing)
      protocol                 ← argmax(tcp_ratio, udp_ratio, icmp_ratio) → 6 / 17 / 1
    """
    if not window:
        return {name: 0.0 for name in TRACK_A_FEATURES}

    n = len(window)

    # ── Direct sums / means ──────────────────────────────────────────────────
    in_pkts   = [_f(s.get('in_pkts'))   for s in window]
    out_pkts  = [_f(s.get('out_pkts'))  for s in window]
    in_bytes  = [_f(s.get('in_bytes'))  for s in window]
    out_bytes = [_f(s.get('out_bytes')) for s in window]
    apsizes   = [_f(s.get('avg_pkt_size')) for s in window]
    iat_means = [_f(s.get('iat_mean_ms')) for s in window]
    iat_stds  = [_f(s.get('iat_std_ms'))  for s in window]

    total_fwd_pkts  = float(sum(in_pkts))
    total_bwd_pkts  = float(sum(out_pkts))
    total_fwd_bytes = float(sum(in_bytes))
    total_bwd_bytes = float(sum(out_bytes))
    total_pkts      = total_fwd_pkts + total_bwd_pkts
    total_bytes     = total_fwd_bytes + total_bwd_bytes
    duration_s      = max(window_s, 1e-6)

    iat_mean = float(np.mean(iat_means)) if iat_means else 0.0
    iat_std  = float(np.mean(iat_stds))  if iat_stds  else 0.0

    # ── Flag counts ──────────────────────────────────────────────────────────
    syn_count = 0.0
    ack_count = 0.0
    psh_count = 0.0
    for s, ip, op in zip(window, in_pkts, out_pkts):
        pkts_total = ip + op
        syn_count += _f(s.get('syn_ratio')) * pkts_total
        ack_count += _f(s.get('ack_ratio')) * pkts_total
        psh_count += _f(s.get('psh_ratio')) * ip   # PSH on forward direction

    # ── Window-level scalars ─────────────────────────────────────────────────
    init_win_fwd = _f(window[-1].get('init_win_fwd'))
    init_win_bwd = _f(window[-1].get('init_win_bwd'))
    min_segs     = [_f(s.get('min_seg_size_fwd')) for s in window]
    min_seg_fwd  = float(min([v for v in min_segs if v > 0], default=0.0))

    # ── Protocol decode (dominant) ───────────────────────────────────────────
    tcp_r  = float(np.mean([_f(s.get('tcp_ratio'))  for s in window]))
    udp_r  = float(np.mean([_f(s.get('udp_ratio'))  for s in window]))
    icmp_r = float(np.mean([_f(s.get('icmp_ratio')) for s in window]))
    proto_idx = int(np.argmax([tcp_r, udp_r, icmp_r]))
    proto_code = (6, 17, 1)[proto_idx]   # IANA: TCP=6, UDP=17, ICMP=1

    return {
        'flow_duration':              float(duration_s),
        'total_fwd_packets':          total_fwd_pkts,
        'total_bwd_packets':          total_bwd_pkts,
        'total_length_fwd_packets':   total_fwd_bytes,
        'total_length_bwd_packets':   total_bwd_bytes,
        'fwd_packet_length_max':      float(max(apsizes)) if apsizes else 0.0,
        'fwd_packet_length_mean':     float(np.mean(apsizes)) if apsizes else 0.0,
        'bwd_packet_length_mean':     float(np.mean(apsizes)) if apsizes else 0.0,
        'flow_bytes_per_sec':         total_bytes / duration_s,
        'flow_packets_per_sec':       total_pkts  / duration_s,
        'flow_iat_mean':              iat_mean,
        'flow_iat_std':               iat_std,
        'fwd_iat_total':              iat_mean * total_fwd_pkts,
        'fwd_iat_mean':               iat_mean,
        'bwd_iat_total':              iat_mean * total_bwd_pkts,
        'syn_flag_count':             float(syn_count),
        'ack_flag_count':             float(ack_count),
        'fwd_psh_flags':              float(psh_count),
        'init_win_bytes_fwd':         init_win_fwd,
        'init_win_bytes_bwd':         init_win_bwd,
        'min_seg_size_fwd':           min_seg_fwd,
        'protocol':                   float(proto_code),
    }


# ── Track B feature extraction (60 s tumbling window) ────────────────────────

def extract_track_b(window: list[dict], window_s: float) -> dict:
    """
    Aggregate a 60-second tumbling window into 6 Track B variables (Spec §3.4).

    Mapping:
      pkt_count_total      ← Σ (in_pkts + out_pkts)
      byte_count_total     ← Σ (in_bytes + out_bytes)
      unique_src_ip_count  ← max(2 ** src_ip_entropy)  (Hartley)
      unique_dst_ip_count  ← max(2 ** dst_ip_entropy)
      avg_pkt_size         ← mean(avg_pkt_size)
      syn_count            ← Σ (syn_ratio × pkts_total)

    Cardinality is taken as the maximum of the per-snapshot Hartley estimate
    over the minute (rather than the mean) to avoid under-counting bursty
    spoofed-source attacks.
    """
    if not window:
        return {name: 0.0 for name in TRACK_B_FEATURES}

    in_pkts   = [_f(s.get('in_pkts'))   for s in window]
    out_pkts  = [_f(s.get('out_pkts'))  for s in window]
    in_bytes  = [_f(s.get('in_bytes'))  for s in window]
    out_bytes = [_f(s.get('out_bytes')) for s in window]
    apsizes   = [_f(s.get('avg_pkt_size')) for s in window]

    pkt_count_total  = float(sum(in_pkts) + sum(out_pkts))
    byte_count_total = float(sum(in_bytes) + sum(out_bytes))

    src_card = max((_hartley_cardinality(_f(s.get('src_ip_entropy'))) for s in window),
                   default=0.0)
    dst_card = max((_hartley_cardinality(_f(s.get('dst_ip_entropy'))) for s in window),
                   default=0.0)

    syn_total = 0.0
    for s, ip, op in zip(window, in_pkts, out_pkts):
        syn_total += _f(s.get('syn_ratio')) * (ip + op)

    return {
        'pkt_count_total':     pkt_count_total,
        'byte_count_total':    byte_count_total,
        'unique_src_ip_count': float(src_card),
        'unique_dst_ip_count': float(dst_card),
        'avg_pkt_size':        float(np.mean(apsizes)) if apsizes else 0.0,
        'syn_count':           float(syn_total),
    }


# ── Window primitives ────────────────────────────────────────────────────────

class SlidingWindow:
    """Time-bounded sliding window with configurable slide cadence."""

    def __init__(self, window_s: float, slide_s: float):
        self.window_s   = window_s
        self.slide_s    = slide_s
        self._buf: deque[tuple[float, dict]] = deque()
        self._last_emit = time.monotonic()

    def add(self, metrics: dict) -> None:
        self._buf.append((time.monotonic(), metrics))

    def should_emit(self) -> bool:
        return (time.monotonic() - self._last_emit) >= self.slide_s

    def emit(self) -> Optional[list[dict]]:
        now    = time.monotonic()
        cutoff = now - self.window_s
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()
        self._last_emit = now
        if not self._buf:
            return None
        return [m for _, m in self._buf]


class TumblingWindow:
    """Non-overlapping fixed-size tumbling window."""

    def __init__(self, window_s: float):
        self.window_s   = window_s
        self._buf: list[dict] = []
        self._opened_at = time.monotonic()

    def add(self, metrics: dict) -> None:
        self._buf.append(metrics)

    def should_emit(self) -> bool:
        return (time.monotonic() - self._opened_at) >= self.window_s

    def emit(self) -> Optional[list[dict]]:
        snapshot = self._buf
        self._buf = []
        self._opened_at = time.monotonic()
        return snapshot if snapshot else None


# ── Kafka helpers with reconnect ─────────────────────────────────────────────

def _connect_with_backoff(factory_fn, label: str):
    """Call factory_fn() with exponential backoff until it succeeds (max 60 s)."""
    delay = 2
    attempt = 0
    while True:
        attempt += 1
        try:
            obj = factory_fn()
            logger.info(f'[{label}] connected (attempt {attempt})')
            return obj
        except Exception as e:
            logger.warning(f'[{label}] attempt {attempt} failed: {e} — retry in {delay}s')
            time.sleep(delay)
            delay = min(delay * 2, 60)


def make_consumer(broker: str, group_id: str):
    from kafka import KafkaConsumer
    # Subscribe to both canonical and legacy raw topics so existing simulators
    # publishing to `pad.telemetry.raw` keep working without redeploy.
    return KafkaConsumer(
        TOPIC_RAW, TOPIC_RAW_LEGACY,
        bootstrap_servers=[broker],
        group_id=group_id,
        auto_offset_reset='latest',
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode('utf-8')),
        consumer_timeout_ms=300,        # non-blocking poll
        session_timeout_ms=30_000,
        heartbeat_interval_ms=10_000,
        max_poll_interval_ms=60_000,
    )


def make_producer(broker: str):
    from kafka import KafkaProducer
    return KafkaProducer(
        bootstrap_servers=[broker],
        # Partition key = source_device_id (Spec §3.2) — bytes
        key_serializer=lambda k: k.encode('utf-8') if isinstance(k, str) else k,
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        acks=1,
        linger_ms=50,
        retries=3,
        retry_backoff_ms=300,
        request_timeout_ms=10_000,
    )


# ── Main run loop ────────────────────────────────────────────────────────────

def run(
    broker:       str,
    flow_window:  float,
    flow_slide:   float,
    ts_window:    float,
    group_id:     str,
    max_emit:     Optional[int],
):
    logger.info('=' * 64)
    logger.info('  PAD-ONAP Flink Processor — dual-branch (Track A + Track B)')
    logger.info('=' * 64)
    logger.info(f'  Broker         : {broker}')
    logger.info(f'  Track A window : {flow_window}s sliding / {flow_slide}s slide')
    logger.info(f'  Track B window : {ts_window}s tumbling')
    logger.info(f'  Input          : {TOPIC_RAW} (legacy alias: {TOPIC_RAW_LEGACY})')
    logger.info(f'  Outputs        : {TOPIC_FLOW}   (Track A — 22-dim CICFlowMeter)')
    logger.info(f'                   {TOPIC_TS}     (Track B — 6-dim aggregates)')
    logger.info('=' * 64)

    consumer = _connect_with_backoff(
        lambda: make_consumer(broker, group_id), 'consumer')
    producer = _connect_with_backoff(
        lambda: make_producer(broker), 'producer')

    # Graceful shutdown
    _running = [True]
    def _handler(sig, frame):
        logger.info('Shutdown — stopping flink processor...')
        _running[0] = False
    signal.signal(signal.SIGINT,  _handler)
    signal.signal(signal.SIGTERM, _handler)

    flow_win = SlidingWindow(window_s=flow_window, slide_s=flow_slide)
    ts_win   = TumblingWindow(window_s=ts_window)

    flow_emits     = 0
    ts_emits       = 0
    last_empty_log = 0.0

    # Track the most recently observed source_device_id for partition keying.
    last_device_id: str = 'unknown'

    logger.info(f'Listening on {TOPIC_RAW}... (Ctrl+C to stop)')

    while _running[0]:

        # ── Consume available raw snapshots ────────────────────────────────
        try:
            for msg in consumer:
                payload = msg.value or {}
                metrics = payload.get('metrics', {})
                if not metrics:
                    continue
                dev = payload.get('source_device_id') or payload.get('device_id')
                if dev:
                    last_device_id = str(dev)
                flow_win.add(metrics)
                ts_win.add(metrics)
        except StopIteration:
            pass   # consumer_timeout_ms expired — normal
        except Exception as e:
            logger.error(f'Consumer error: {e} — reconnecting...')
            try:
                consumer.close()
            except Exception:
                pass
            consumer = _connect_with_backoff(
                lambda: make_consumer(broker, group_id), 'consumer')
            continue

        # ── Branch A: Track A flow features (5 s sliding / 1 s slide) ──────
        if flow_win.should_emit():
            snapshots = flow_win.emit()
            if snapshots is None:
                now = time.monotonic()
                if now - last_empty_log > 30.0:
                    logger.debug('Track A: window empty (no raw messages?)')
                    last_empty_log = now
            else:
                features = extract_track_a(snapshots, window_s=flow_window)
                out = {
                    'timestamp':         datetime.now(timezone.utc).isoformat(),
                    'source_device_id':  last_device_id,
                    'track':             'A',
                    'window_type':       'sliding',
                    'window_s':          flow_window,
                    'slide_s':           flow_slide,
                    'features':          features,
                }
                if not _send(producer, broker, TOPIC_FLOW, last_device_id, out):
                    producer = _connect_with_backoff(
                        lambda: make_producer(broker), 'producer')
                    continue
                flow_emits += 1
                if flow_emits <= 5 or flow_emits % 20 == 0:
                    logger.info(
                        f'[A W{flow_emits:05d}] '
                        f'pkt/s={features["flow_packets_per_sec"]:.0f}  '
                        f'byte/s={features["flow_bytes_per_sec"]:.0f}  '
                        f'syn={features["syn_flag_count"]:.1f}  '
                        f'proto={int(features["protocol"])}'
                    )

        # ── Branch B: Track B aggregated time-series (60 s tumbling) ───────
        if ts_win.should_emit():
            snapshots = ts_win.emit()
            if snapshots is not None:
                features = extract_track_b(snapshots, window_s=ts_window)
                out = {
                    'timestamp':         datetime.now(timezone.utc).isoformat(),
                    'source_device_id':  last_device_id,
                    'track':             'B',
                    'window_type':       'tumbling',
                    'window_s':          ts_window,
                    'features':          features,
                }
                if not _send(producer, broker, TOPIC_TS, last_device_id, out):
                    producer = _connect_with_backoff(
                        lambda: make_producer(broker), 'producer')
                    continue
                ts_emits += 1
                logger.info(
                    f'[B W{ts_emits:05d}] '
                    f'pkts={features["pkt_count_total"]:.0f}  '
                    f'bytes={features["byte_count_total"]:.0f}  '
                    f'src_ips~{features["unique_src_ip_count"]:.0f}  '
                    f'syn={features["syn_count"]:.1f}'
                )

        if max_emit and flow_emits >= max_emit:
            logger.info(f'Reached max_emit={max_emit} — stopping.')
            break

    # ── Cleanup ────────────────────────────────────────────────────────────
    try:
        consumer.close()
    except Exception:
        pass
    try:
        producer.flush(timeout=5)
        producer.close()
    except Exception:
        pass
    logger.info(
        f'Flink processor stopped. Track A emits={flow_emits} | Track B emits={ts_emits}'
    )


def _send(producer, broker: str, topic: str, key: str, value: dict) -> bool:
    """Send + flush; return False if producer errored (caller should reconnect)."""
    try:
        producer.send(topic, key=key, value=value)
        producer.flush(timeout=3)
        return True
    except Exception as e:
        logger.error(f'Producer error on {topic}: {e} — reconnecting...')
        try:
            producer.close(timeout=2)
        except Exception:
            pass
        return False


def main():
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Flink Processor — dual-branch (Track A 5s/1s + Track B 60s)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--broker',       default='localhost:9092')
    parser.add_argument('--flow-window',  type=float, default=5.0,
                        help='Track A sliding window size (seconds)')
    parser.add_argument('--flow-slide',   type=float, default=1.0,
                        help='Track A slide interval (seconds)')
    parser.add_argument('--ts-window',    type=float, default=60.0,
                        help='Track B tumbling window size (seconds)')
    parser.add_argument('--group-id',     default='pad-flink-processor')
    parser.add_argument('--max-emit',     type=int,   default=None,
                        help='Stop after this many Track A emits (None = run forever)')
    args = parser.parse_args()

    run(
        broker      = args.broker,
        flow_window = args.flow_window,
        flow_slide  = args.flow_slide,
        ts_window   = args.ts_window,
        group_id    = args.group_id,
        max_emit    = args.max_emit,
    )


if __name__ == '__main__':
    main()
