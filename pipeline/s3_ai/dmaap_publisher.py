"""
DMaaP Publisher — Real Kafka + Stub fallback
=============================================
Replaces the file-based emit_to_dmaap_stub() with a real Kafka producer
that publishes AIOutputPayload to ONAP DMaaP (Message Router).

Usage:
  from pipeline.s3_ai.dmaap_publisher import DMaaPPublisher

  pub = DMaaPPublisher()          # auto-detects stub vs real from env
  pub.publish(payload)            # AIOutputPayload → DMaaP topic

Environment variables:
  PAD_ONAP_STUB        true/false        (default: true)
  PAD_DMAAP_HOST       onap-message-router.onap.svc
  PAD_DMAAP_PORT       3904              (HTTP) or 9092 (Kafka direct)
  PAD_DMAAP_TOPIC      PAD_ONAP_AI_SIGNALS
  PAD_DMAAP_USER       (optional, for MR auth)
  PAD_DMAAP_PASS       (optional)
  PAD_DMAAP_USE_KAFKA  false             (true = Kafka direct, false = MR REST)
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config from environment ────────────────────────────────────────────────────
_STUB_MODE      = os.environ.get("PAD_ONAP_STUB",       "true").lower() != "false"
_DMAAP_HOST     = os.environ.get("PAD_DMAAP_HOST",      "onap-message-router.onap.svc")
_DMAAP_PORT_MR  = int(os.environ.get("PAD_DMAAP_PORT",  "3904"))
_DMAAP_PORT_K   = int(os.environ.get("PAD_KAFKA_PORT",  "9092"))
_DMAAP_TOPIC    = os.environ.get("PAD_DMAAP_TOPIC",     "PAD_ONAP_AI_SIGNALS")
_DMAAP_USER     = os.environ.get("PAD_DMAAP_USER",      "")
_DMAAP_PASS     = os.environ.get("PAD_DMAAP_PASS",      "")
_USE_KAFKA      = os.environ.get("PAD_DMAAP_USE_KAFKA", "false").lower() == "true"
_STUB_DIR       = Path(os.environ.get("PAD_DMAAP_STUB_DIR", "/tmp/pad_dmaap"))


def _payload_to_dict(payload) -> dict:
    """Convert AIOutputPayload dataclass to plain dict."""
    try:
        return asdict(payload)
    except Exception:
        # fallback if payload is already a dict
        return payload if isinstance(payload, dict) else vars(payload)


# ══════════════════════════════════════════════════════════════════════════════
#  Stub publisher — writes JSON to local directory
# ══════════════════════════════════════════════════════════════════════════════
class _StubPublisher:
    """File-based DMaaP stub for testbed / evaluation runs."""

    def __init__(self):
        _STUB_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("[DMaaP-STUB] Writing to %s", _STUB_DIR)

    def publish(self, payload) -> bool:
        d = _payload_to_dict(payload)
        event_id = d.get("event_id", f"evt_{int(time.time()*1000)}")
        out = _STUB_DIR / f"{event_id}.json"
        out.write_text(json.dumps(d, indent=2, default=str), encoding="utf-8")
        logger.debug("[DMaaP-STUB] wrote %s", out.name)
        return True

    def close(self):
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  Real publisher — ONAP Message Router REST API
# ══════════════════════════════════════════════════════════════════════════════
class _MRPublisher:
    """
    Publishes to ONAP DMaaP Message Router via HTTP.

    MR REST API:
      POST http://<host>:<port>/events/<topic>
      Content-Type: application/json
      Body: [<json-event>]          ← MR expects a JSON array
    """

    def __init__(self):
        import requests
        self._requests = requests
        self._url = (
            f"http://{_DMAAP_HOST}:{_DMAAP_PORT_MR}/events/{_DMAAP_TOPIC}"
        )
        self._auth = (_DMAAP_USER, _DMAAP_PASS) if _DMAAP_USER else None
        self._session = requests.Session()
        if self._auth:
            self._session.auth = self._auth
        logger.info("[DMaaP-MR] endpoint: %s", self._url)

    def publish(self, payload) -> bool:
        d = _payload_to_dict(payload)
        body = json.dumps([d], default=str)          # MR wants array
        try:
            resp = self._session.post(
                self._url,
                data=body,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if resp.status_code in (200, 207):
                logger.debug("[DMaaP-MR] published event_id=%s", d.get("event_id"))
                return True
            else:
                logger.warning("[DMaaP-MR] HTTP %s: %s", resp.status_code, resp.text[:200])
                return False
        except Exception as exc:
            logger.error("[DMaaP-MR] publish failed: %s", exc)
            return False

    def close(self):
        self._session.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Real publisher — Kafka direct (bypasses MR, faster for testing)
# ══════════════════════════════════════════════════════════════════════════════
class _KafkaPublisher:
    """
    Publishes directly to Kafka broker that backs DMaaP.
    Requires: pip install kafka-python
    """

    def __init__(self):
        from kafka import KafkaProducer
        broker = f"{_DMAAP_HOST}:{_DMAAP_PORT_K}"
        self._producer = KafkaProducer(
            bootstrap_servers=[broker],
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            acks="all",
            retries=3,
            linger_ms=5,
        )
        self._topic = _DMAAP_TOPIC
        logger.info("[DMaaP-Kafka] broker=%s topic=%s", broker, self._topic)

    def publish(self, payload) -> bool:
        d = _payload_to_dict(payload)
        try:
            future = self._producer.send(self._topic, value=d)
            future.get(timeout=5)          # wait for ack
            logger.debug("[DMaaP-Kafka] published event_id=%s", d.get("event_id"))
            return True
        except Exception as exc:
            logger.error("[DMaaP-Kafka] publish failed: %s", exc)
            return False

    def close(self):
        self._producer.flush()
        self._producer.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Public façade — auto-selects backend
# ══════════════════════════════════════════════════════════════════════════════
class DMaaPPublisher:
    """
    Drop-in replacement for emit_to_dmaap_stub().
    Auto-selects backend from environment:
      PAD_ONAP_STUB=true          → _StubPublisher  (default)
      PAD_ONAP_STUB=false + PAD_DMAAP_USE_KAFKA=false → _MRPublisher
      PAD_ONAP_STUB=false + PAD_DMAAP_USE_KAFKA=true  → _KafkaPublisher
    """

    def __init__(self):
        if _STUB_MODE:
            self._backend = _StubPublisher()
            self.mode = "stub"
        elif _USE_KAFKA:
            self._backend = _KafkaPublisher()
            self.mode = "kafka"
        else:
            self._backend = _MRPublisher()
            self.mode = "mr-rest"
        logger.info("[DMaaP] mode=%s topic=%s", self.mode, _DMAAP_TOPIC)

    def publish(self, payload) -> bool:
        """Publish AIOutputPayload to DMaaP. Returns True on success."""
        return self._backend.publish(payload)

    def close(self):
        """Flush and close underlying connection."""
        self._backend.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── Singleton for module-level use ────────────────────────────────────────────
_publisher: Optional[DMaaPPublisher] = None


def get_publisher() -> DMaaPPublisher:
    global _publisher
    if _publisher is None:
        _publisher = DMaaPPublisher()
    return _publisher


def emit(payload) -> bool:
    """Convenience wrapper — module-level publish."""
    return get_publisher().publish(payload)
