"""
M3 — Latency Tracker & Prometheus Exporter (Spec-aligned §5.4)

Instruments E2E latency across pipeline stages:
  t_ai_detection   : AI output emitted (InferenceEngine.infer() returns)
  t_policy_decision: PolicyEngine.evaluate() returns
  t_so_request     : SO instantiation request sent
  t_vnf_active     : VNF container responds to health check
  t_sfc_updated    : OVS SFC rules installed

Derived metrics (all in ms):
  detection_to_policy_ms  = t_policy_decision - t_ai_detection
  policy_to_so_ms         = t_so_request - t_policy_decision
  so_to_vnf_ms            = t_vnf_active - t_so_request
  vnf_to_sfc_ms           = t_sfc_updated - t_vnf_active
  end_to_end_ms           = t_sfc_updated - t_ai_detection

Prometheus metrics exported at :9292/metrics  (configurable via PAD_LATENCY_PORT env).
Falls back to in-memory stats if prometheus_client not installed.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Prometheus port (override with env var to avoid port conflicts)
METRICS_PORT = int(os.environ.get('PAD_LATENCY_PORT', '9292'))


@dataclass
class LatencyRecord:
    """Timestamps for one E2E pipeline execution."""
    event_id:            str
    window_id:           int
    tier:                int

    t_ai_detection:      float = 0.0   # set by InferenceEngine
    t_policy_decision:   float = 0.0   # set by PolicyEngine
    t_so_request:        float = 0.0   # set by ONAPSOClient
    t_vnf_active:        float = 0.0   # set by ONAPSOClient (health poll)
    t_sfc_updated:       float = 0.0   # set by SFCManager

    # Derived (computed by finalize())
    detection_to_policy_ms: float = 0.0
    policy_to_so_ms:        float = 0.0
    so_to_vnf_ms:           float = 0.0
    vnf_to_sfc_ms:          float = 0.0
    end_to_end_ms:          float = 0.0

    def finalize(self):
        """Compute derived latencies. Call after all timestamps are set."""
        def ms(a, b):
            return max(0.0, (b - a) * 1000.0) if a > 0 and b > 0 else 0.0

        self.detection_to_policy_ms = ms(self.t_ai_detection,    self.t_policy_decision)
        self.policy_to_so_ms        = ms(self.t_policy_decision,  self.t_so_request)
        self.so_to_vnf_ms           = ms(self.t_so_request,       self.t_vnf_active)
        self.vnf_to_sfc_ms          = ms(self.t_vnf_active,       self.t_sfc_updated)
        self.end_to_end_ms          = ms(self.t_ai_detection,     self.t_sfc_updated)
        return self

    def to_dict(self) -> dict:
        return {
            'event_id':               self.event_id,
            'window_id':              self.window_id,
            'tier':                   self.tier,
            'detection_to_policy_ms': round(self.detection_to_policy_ms, 3),
            'policy_to_so_ms':        round(self.policy_to_so_ms,        3),
            'so_to_vnf_ms':           round(self.so_to_vnf_ms,           3),
            'vnf_to_sfc_ms':          round(self.vnf_to_sfc_ms,          3),
            'end_to_end_ms':          round(self.end_to_end_ms,          3),
        }


class LatencyTracker:
    """
    Collects LatencyRecords, computes CDF stats, and exports to Prometheus.

    Usage:
        tracker = LatencyTracker()
        tracker.start_server()      # optional — starts /metrics HTTP endpoint

        rec = LatencyRecord(event_id=payload.event_id, window_id=wid, tier=tier)
        rec.t_ai_detection = time.time()
        # ... fill other timestamps ...
        rec.finalize()
        tracker.record(rec)

        print(tracker.summary())
    """

    def __init__(self, max_records: int = 10_000):
        self._records:  List[LatencyRecord] = []
        self._max       = max_records
        self._prom_ok   = False
        self._gauges: Dict = {}

    def start_server(self, port: int = METRICS_PORT) -> bool:
        """Start Prometheus HTTP metrics server. Returns True if successful."""
        try:
            from prometheus_client import start_http_server, Gauge, Histogram, Summary
            self._gauges = {
                'e2e_p50':  Gauge('pad_e2e_latency_p50_ms',   'E2E latency P50 (ms)'),
                'e2e_p95':  Gauge('pad_e2e_latency_p95_ms',   'E2E latency P95 (ms)'),
                'e2e_p99':  Gauge('pad_e2e_latency_p99_ms',   'E2E latency P99 (ms)'),
                'd2p_p95':  Gauge('pad_det_to_policy_p95_ms', 'Detection→Policy P95 (ms)'),
                'p2s_p95':  Gauge('pad_policy_to_so_p95_ms',  'Policy→SO P95 (ms)'),
                's2v_p95':  Gauge('pad_so_to_vnf_p95_ms',     'SO→VNF-active P95 (ms)'),
                'v2s_p95':  Gauge('pad_vnf_to_sfc_p95_ms',    'VNF→SFC P95 (ms)'),
                'n_events': Gauge('pad_latency_events_total',  'Total latency events recorded'),
                # Per-tier histograms
                'e2e_hist': Histogram(
                    'pad_e2e_latency_ms',
                    'E2E latency histogram (ms)',
                    buckets=[50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000],
                    labelnames=['tier'],
                ),
            }
            start_http_server(port)
            self._prom_ok = True
            logger.info(f"LatencyTracker: Prometheus metrics at :{port}/metrics")
            return True
        except ImportError:
            logger.warning("prometheus_client not installed — metrics server disabled")
            return False
        except OSError as e:
            logger.warning(f"LatencyTracker: Could not bind port {port}: {e}")
            return False

    def record(self, rec: LatencyRecord):
        """Add a finalized LatencyRecord and update Prometheus gauges."""
        if len(self._records) >= self._max:
            self._records.pop(0)
        self._records.append(rec)

        if self._prom_ok and rec.end_to_end_ms > 0:
            self._gauges['e2e_hist'].labels(tier=str(rec.tier)).observe(
                rec.end_to_end_ms
            )
            if len(self._records) % 10 == 0:
                self._update_gauges()

    def _update_gauges(self):
        if not self._prom_ok or not self._records:
            return
        e2e = np.array([r.end_to_end_ms for r in self._records if r.end_to_end_ms > 0])
        if len(e2e) == 0:
            return
        self._gauges['e2e_p50'].set(float(np.percentile(e2e, 50)))
        self._gauges['e2e_p95'].set(float(np.percentile(e2e, 95)))
        self._gauges['e2e_p99'].set(float(np.percentile(e2e, 99)))
        self._gauges['n_events'].set(len(self._records))

        for key, attr in [('d2p_p95', 'detection_to_policy_ms'),
                           ('p2s_p95', 'policy_to_so_ms'),
                           ('s2v_p95', 'so_to_vnf_ms'),
                           ('v2s_p95', 'vnf_to_sfc_ms')]:
            arr = np.array([getattr(r, attr) for r in self._records
                            if getattr(r, attr) > 0])
            if len(arr):
                self._gauges[key].set(float(np.percentile(arr, 95)))

    def summary(self, tier: Optional[int] = None) -> dict:
        """Return latency statistics dict (optionally filtered by tier)."""
        recs = self._records
        if tier is not None:
            recs = [r for r in recs if r.tier == tier]
        if not recs:
            return {'n': 0}

        def stats(arr):
            a = np.array(arr)
            if len(a) == 0:
                return {}
            return {
                'p50': round(float(np.percentile(a, 50)), 2),
                'p95': round(float(np.percentile(a, 95)), 2),
                'p99': round(float(np.percentile(a, 99)), 2),
                'max': round(float(np.max(a)), 2),
            }

        return {
            'n':                     len(recs),
            'end_to_end_ms':         stats([r.end_to_end_ms         for r in recs if r.end_to_end_ms > 0]),
            'detection_to_policy_ms': stats([r.detection_to_policy_ms for r in recs if r.detection_to_policy_ms > 0]),
            'policy_to_so_ms':        stats([r.policy_to_so_ms        for r in recs if r.policy_to_so_ms > 0]),
            'so_to_vnf_ms':           stats([r.so_to_vnf_ms           for r in recs if r.so_to_vnf_ms > 0]),
            'vnf_to_sfc_ms':          stats([r.vnf_to_sfc_ms          for r in recs if r.vnf_to_sfc_ms > 0]),
        }

    def per_tier_summary(self) -> dict:
        return {f'tier_{t}': self.summary(tier=t) for t in range(5)}

    @property
    def records(self) -> List[LatencyRecord]:
        return list(self._records)
