#!/usr/bin/env python3
"""
PAD-ONAP Kafka Producer — Phase 1: Streaming Telemetry
=======================================================
Polls gNMI Simulator every --interval seconds and publishes raw metrics to
Kafka topic `pad.telemetry.raw`.

Stability features:
  - Exponential backoff on Kafka connect (2s → 4s → 8s → ... max 60s)
  - Async fire-and-forget send with error callback (no blocking on future.get)
  - Auto-reconnect: recreates KafkaProducer if connection is lost
  - Error counter with reset logic (logs once per burst, not every message)
  - Graceful SIGINT/SIGTERM shutdown with producer.flush()

Usage:
  python pipeline/s1_telemetry/kafka_producer.py

  python pipeline/s1_telemetry/kafka_producer.py \\
      --gnmi http://localhost:8080 \\
      --broker localhost:9092 \\
      --interval 0.5

Topics:
  pad.telemetry.raw  — raw gNMI metric snapshots (output)
"""

import argparse
import json
import logging
import signal
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('kafka-producer')

TOPIC_RAW = 'pad.telemetry.raw'


# ── gNMI fetch ────────────────────────────────────────────────────────────────

def fetch_gnmi_metrics(gnmi_url: str, timeout: float = 3.0) -> dict | None:
    url = f'{gnmi_url.rstrip("/")}/metrics'
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.debug(f'gNMI fetch failed: {e}')
        return None


# ── Kafka producer factory with exponential backoff ───────────────────────────

def _make_producer(broker: str):
    from kafka import KafkaProducer
    return KafkaProducer(
        bootstrap_servers=[broker],
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8') if k else None,
        acks=1,                 # leader ack (balance durability vs latency)
        retries=5,
        retry_backoff_ms=500,
        linger_ms=200,          # batch small messages for efficiency
        compression_type='gzip',
        request_timeout_ms=10_000,
        max_block_ms=5_000,
    )


def connect_producer(broker: str) -> object:
    """Connect to Kafka with exponential backoff. Blocks until connected."""
    delay = 2
    attempt = 0
    while True:
        attempt += 1
        try:
            p = _make_producer(broker)
            # Probe with a metadata fetch (raises if broker unreachable)
            p.partitions_for(TOPIC_RAW)  # triggers topic auto-create
            logger.info(f'[attempt {attempt}] Connected to Kafka: {broker}')
            return p
        except Exception as e:
            logger.warning(f'[attempt {attempt}] Kafka connect failed: {e} — retry in {delay}s')
            time.sleep(delay)
            delay = min(delay * 2, 60)


# ── Send callback ─────────────────────────────────────────────────────────────

_send_errors = [0]

def _on_error(exc):
    _send_errors[0] += 1
    if _send_errors[0] == 1 or _send_errors[0] % 20 == 0:
        logger.error(f'Kafka send error (#{_send_errors[0]}): {exc}')


# ── Main run loop ─────────────────────────────────────────────────────────────

def run(gnmi_url: str, broker: str, interval: float, max_messages: int | None):
    logger.info('=' * 60)
    logger.info('  PAD-ONAP Kafka Producer  (gNMI → pad.telemetry.raw)')
    logger.info('=' * 60)
    logger.info(f'  gNMI URL : {gnmi_url}')
    logger.info(f'  Broker   : {broker}')
    logger.info(f'  Interval : {interval}s')
    logger.info(f'  Topic    : {TOPIC_RAW}')
    logger.info('=' * 60)

    producer = connect_producer(broker)

    # Graceful shutdown
    _running = [True]
    def _handler(sig, frame):
        logger.info('Shutdown signal — flushing and stopping...')
        _running[0] = False
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    count        = 0
    gnmi_errors  = 0
    MAX_GNMI_ERR = 10
    last_flush   = time.monotonic()
    FLUSH_EVERY  = 5.0   # seconds

    logger.info('Producing messages... (Ctrl+C to stop)')

    while _running[0]:
        t0 = time.perf_counter()

        # ── Fetch from gNMI ───────────────────────────────────────────────────
        metrics = fetch_gnmi_metrics(gnmi_url)
        if metrics is None:
            gnmi_errors += 1
            if gnmi_errors == 1:
                logger.warning(f'gNMI not responding at {gnmi_url} — is simulator running?')
            elif gnmi_errors == MAX_GNMI_ERR:
                logger.error(f'{MAX_GNMI_ERR} consecutive gNMI errors. Check simulator.')
                gnmi_errors = 0  # reset so next burst also logs
            time.sleep(interval)
            continue
        gnmi_errors = 0

        payload = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source':    'gnmi-simulator',
            'metrics':   metrics,
        }

        # ── Async send (fire-and-forget with error callback) ──────────────────
        try:
            producer.send(TOPIC_RAW, key='gnmi', value=payload).add_errback(_on_error)
            count += 1
            _send_errors[0] = 0   # reset error counter on success
        except Exception as e:
            # Producer itself may be broken — reconnect
            logger.error(f'Producer send raised: {e} — reconnecting...')
            try:
                producer.close(timeout=2)
            except Exception:
                pass
            producer = connect_producer(broker)
            continue

        # ── Periodic flush (ensure messages reach broker) ─────────────────────
        now = time.monotonic()
        if now - last_flush >= FLUSH_EVERY:
            producer.flush(timeout=5)
            last_flush = now

        if count % 50 == 0:
            logger.info(f'Published {count} messages to {TOPIC_RAW}')

        if max_messages and count >= max_messages:
            logger.info(f'Reached max_messages={max_messages} — stopping.')
            break

        elapsed = time.perf_counter() - t0
        time.sleep(max(0.0, interval - elapsed))

    # ── Cleanup ───────────────────────────────────────────────────────────────
    logger.info('Flushing remaining messages...')
    producer.flush(timeout=10)
    producer.close()
    logger.info(f'Producer stopped. Total messages sent: {count}')


def main():
    parser = argparse.ArgumentParser(
        description='PAD-ONAP Kafka Producer (gNMI → pad.telemetry.raw)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--gnmi',         default='http://localhost:8080')
    parser.add_argument('--broker',       default='localhost:9092')
    parser.add_argument('--interval',     type=float, default=0.5)
    parser.add_argument('--max-messages', type=int,   default=None)
    args = parser.parse_args()

    run(
        gnmi_url     = args.gnmi,
        broker       = args.broker,
        interval     = args.interval,
        max_messages = args.max_messages,
    )


if __name__ == '__main__':
    main()
