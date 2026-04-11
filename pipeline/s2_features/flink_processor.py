#!/usr/bin/env python3
"""
PAD-ONAP Flink Processor — Phase 2: Sliding-Window Feature Extraction
======================================================================
Consumes raw gNMI snapshots from `pad.telemetry.raw`,
applies a sliding-window aggregation (default: 5s window / 1s slide),
publishes 17-feature vectors to `pad.telemetry.features`.

Stability features:
  - Auto-reconnect: recreates consumer/producer on connection loss
  - Exponential backoff on Kafka connect (2s → 4s → ... max 60s)
  - Producer flush after every emit (no silent message loss)
  - Spam-free logging: "window empty" logged at most once per 30s
  - Graceful SIGINT/SIGTERM shutdown

Feature set (17 — matches FEATURE_NAMES in live_pipeline.py and inference_layer.py):
  pkt_rate, byte_rate, src_ip_entropy, dst_ip_entropy,
  src_port_entropy, dst_port_entropy,
  proto_dist_tcp, proto_dist_udp, proto_dist_icmp,
  syn_ratio, fin_ratio, avg_pkt_size, pkt_size_std,
  new_flows_rate, flow_duration_mean, inter_arrival_mean, inter_arrival_std

Usage:
  python pipeline/s2_features/flink_processor.py
  python pipeline/s2_features/flink_processor.py --broker localhost:9092 --window 5.0 --slide 1.0
"""

import argparse
import json
import logging
import signal
import sys
import time
from collections import deque
from datetime import datetime, timezone

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('flink-processor')

TOPIC_RAW      = 'pad.telemetry.raw'
TOPIC_FEATURES = 'pad.telemetry.features'

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


# ── Feature extraction ────────────────────────────────────────────────────────

def _f(val, default=0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def extract_features(window: list[dict]) -> dict:
    """Aggregate a window of raw gNMI metric dicts into a 17-feature vector."""
    if not window:
        return {name: 0.0 for name in FEATURE_NAMES}

    def mean(field):
        return float(np.mean([_f(s.get(field)) for s in window]))

    def std(field):
        vals = [_f(s.get(field)) for s in window]
        return float(np.std(vals)) if len(vals) > 1 else 0.0

    return {
        'pkt_rate':           mean('in_pkts') + mean('out_pkts'),
        'byte_rate':          mean('in_bytes') + mean('out_bytes'),
        # Entropy: passed through from SyntheticFlowGenerator (already calibrated)
        'src_ip_entropy':     mean('src_ip_entropy'),
        'dst_ip_entropy':     mean('dst_ip_entropy'),
        'src_port_entropy':   mean('src_port_entropy'),
        'dst_port_entropy':   mean('dst_port_entropy'),
        'proto_dist_tcp':     mean('tcp_ratio'),
        'proto_dist_udp':     mean('udp_ratio'),
        'proto_dist_icmp':    mean('icmp_ratio'),
        'syn_ratio':          mean('syn_ratio'),
        'fin_ratio':          mean('fin_ratio'),
        'avg_pkt_size':       mean('avg_pkt_size'),
        'pkt_size_std':       std('avg_pkt_size'),   # variation across window
        'new_flows_rate':     mean('new_flows_rate'),
        'flow_duration_mean': mean('flow_duration_mean'),
        'inter_arrival_mean': mean('iat_mean_ms'),
        'inter_arrival_std':  mean('iat_std_ms'),
    }


# ── Sliding window ────────────────────────────────────────────────────────────

class SlidingWindow:
    def __init__(self, window_s: float, slide_s: float):
        self.window_s   = window_s
        self.slide_s    = slide_s
        self._buf: deque[tuple[float, dict]] = deque()
        self._last_emit = time.monotonic()

    def add(self, metrics: dict) -> None:
        self._buf.append((time.monotonic(), metrics))

    def should_emit(self) -> bool:
        return (time.monotonic() - self._last_emit) >= self.slide_s

    def emit(self) -> dict | None:
        now    = time.monotonic()
        cutoff = now - self.window_s
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()
        self._last_emit = now
        if not self._buf:
            return None
        return extract_features([m for _, m in self._buf])


# ── Kafka helpers with reconnect ──────────────────────────────────────────────

def _connect_with_backoff(factory_fn, label: str):
    """Call factory_fn() with exponential backoff until it succeeds."""
    delay = 2
    attempt = 0
    while True:
        attempt += 1
        try:
            obj = factory_fn()
            logger.info(f'[{label}] Connected (attempt {attempt})')
            return obj
        except Exception as e:
            logger.warning(f'[{label}] attempt {attempt} failed: {e} — retry in {delay}s')
            time.sleep(delay)
            delay = min(delay * 2, 60)


def make_consumer(broker: str, group_id: str):
    from kafka import KafkaConsumer
    return KafkaConsumer(
        TOPIC_RAW,
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
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        acks=1,
        linger_ms=50,
        retries=3,
        retry_backoff_ms=300,
        request_timeout_ms=10_000,
    )


# ── Main run loop ─────────────────────────────────────────────────────────────

def run(broker: str, window_s: float, slide_s: float,
        group_id: str, max_emit: int | None):
    logger.info('=' * 60)
    logger.info('  PAD-ONAP Flink Processor  (sliding-window features)')
    logger.info('=' * 60)
    logger.info(f'  Broker  : {broker}')
    logger.info(f'  Window  : {window_s}s / Slide: {slide_s}s')
    logger.info(f'  Input   : {TOPIC_RAW}')
    logger.info(f'  Output  : {TOPIC_FEATURES}')
    logger.info('=' * 60)

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

    sw          = SlidingWindow(window_s=window_s, slide_s=slide_s)
    emit_count  = 0
    last_empty_log = 0.0   # throttle "window empty" log

    logger.info(f'Listening on {TOPIC_RAW}... (Ctrl+C to stop)')

    while _running[0]:

        # ── Consume available messages ─────────────────────────────────────────
        try:
            for msg in consumer:
                metrics = msg.value.get('metrics', {})
                if metrics:
                    sw.add(metrics)
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

        # ── Emit feature vector if slide interval elapsed ──────────────────────
        if not sw.should_emit():
            continue

        features = sw.emit()
        if features is None:
            now = time.monotonic()
            if now - last_empty_log > 30.0:
                logger.debug('Window empty — no features to emit (no raw messages?)')
                last_empty_log = now
            continue

        out = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'window_s':  window_s,
            'slide_s':   slide_s,
            'features':  features,
        }

        try:
            producer.send(TOPIC_FEATURES, value=out)
            producer.flush(timeout=3)   # ensure delivery before next cycle
            emit_count += 1
        except Exception as e:
            logger.error(f'Producer error: {e} — reconnecting...')
            try:
                producer.close(timeout=2)
            except Exception:
                pass
            producer = _connect_with_backoff(
                lambda: make_producer(broker), 'producer')
            continue

        if emit_count <= 5 or emit_count % 20 == 0:
            logger.info(
                f'[W{emit_count:04d}] features emitted: '
                f'pkt_rate={features["pkt_rate"]:.0f}  '
                f'udp={features["proto_dist_udp"]:.3f}  '
                f'syn={features["syn_ratio"]:.4f}  '
                f'entropy_src={features["src_ip_entropy"]:.3f}'
            )

        if max_emit and emit_count >= max_emit:
            logger.info(f'Reached max_emit={max_emit} — stopping.')
            break

    # ── Cleanup ───────────────────────────────────────────────────────────────
    consumer.close()
    producer.flush(timeout=5)
    producer.close()
    logger.info(f'Flink processor stopped. Total emitted: {emit_count}')


def main():
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Flink Processor (sliding-window feature extraction)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--broker',   default='localhost:9092')
    parser.add_argument('--window',   type=float, default=5.0)
    parser.add_argument('--slide',    type=float, default=1.0)
    parser.add_argument('--group-id', default='pad-flink-processor')
    parser.add_argument('--max-emit', type=int,   default=None)
    args = parser.parse_args()

    run(
        broker   = args.broker,
        window_s = args.window,
        slide_s  = args.slide,
        group_id = args.group_id,
        max_emit = args.max_emit,
    )


if __name__ == '__main__':
    main()
