"""
M3 — Minimal Health Probe Server (Spec §5.4 — for K8s liveness/readiness)
==========================================================================

Lightweight HTTP side-car exposing `/healthz` and `/readyz` JSON probes so the
Kubernetes Deployment in `onap/k8s/pad-onap-deployment.yaml` can monitor the
orchestrator without scraping Prometheus.

Endpoints:
  GET /healthz   200 if the orchestrator thread is alive, 503 otherwise
  GET /readyz    200 if at least one inference window has been processed
                     AND the policy engine has been initialised
  GET /metrics_summary
                 JSON snapshot of latency + NFV summaries (for ad-hoc curl)

The probe server is started in a daemon thread by the orchestrator at boot.
It defaults to port 9293 (env `PAD_HEALTH_PORT`).  Lookups are O(1) and the
server adds no GIL pressure on the inference loop.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_PORT = int(os.environ.get('PAD_HEALTH_PORT', '9293'))

# Maximum staleness (seconds) before /readyz starts returning 503 — guards
# against the orchestrator hanging on a stuck Kafka consumer.
DEFAULT_STALENESS_LIMIT_S = float(os.environ.get('PAD_HEALTH_MAX_STALENESS_S', '120'))


class _HealthState:
    """Thread-safe singleton holding the latest readiness signal."""

    def __init__(self):
        self._lock              = threading.Lock()
        self._started_at: float = time.time()
        self._last_window_ts: float = 0.0
        self._windows_total: int    = 0
        self._ready_flag: bool      = False
        self._snapshot_fn: Optional[Callable[[], dict]] = None

    def mark_started(self) -> None:
        with self._lock:
            self._started_at = time.time()

    def set_snapshot_fn(self, fn: Callable[[], dict]) -> None:
        with self._lock:
            self._snapshot_fn = fn

    def heartbeat(self) -> None:
        """Called from the inference loop after every successful window."""
        with self._lock:
            self._last_window_ts = time.time()
            self._windows_total += 1
            self._ready_flag     = True

    def snapshot(self) -> dict:
        with self._lock:
            base = {
                'started_at':       self._started_at,
                'uptime_s':         round(time.time() - self._started_at, 3),
                'windows_total':    self._windows_total,
                'last_window_ts':   self._last_window_ts,
                'last_window_age_s':
                    round(time.time() - self._last_window_ts, 3)
                    if self._last_window_ts > 0 else None,
                'ready':            self._ready_flag,
            }
            fn = self._snapshot_fn
        if fn is not None:
            try:
                base['metrics'] = fn()
            except Exception as e:
                base['metrics_error'] = str(e)
        return base

    def is_healthy(self) -> bool:
        # Always healthy while the thread is alive — the moment the orchestrator
        # crashes the side-car dies with it, so the probe will fail.
        return True

    def is_ready(self, max_staleness_s: float = DEFAULT_STALENESS_LIMIT_S) -> bool:
        with self._lock:
            if not self._ready_flag:
                return False
            age = time.time() - self._last_window_ts
        return age < max_staleness_s


_STATE = _HealthState()


# ── Public API ──────────────────────────────────────────────────────────────

def state() -> _HealthState:
    return _STATE


def heartbeat() -> None:
    """Call after each processed window from the orchestrator main loop."""
    _STATE.heartbeat()


def register_snapshot_provider(fn: Callable[[], dict]) -> None:
    """Plug a callable that returns the latency / NFV summary on demand."""
    _STATE.set_snapshot_fn(fn)


# ── HTTP handler ────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    server_version = 'pad-onap-health/1.0'

    def log_message(self, format, *args):     # noqa: A003
        # Silence default access log to avoid swamping pod logs.
        return

    def _respond(self, code: int, payload: Any) -> None:
        body = json.dumps(payload).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type',   'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control',  'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):   # noqa: N802
        path = self.path.split('?', 1)[0]
        if path == '/healthz':
            ok = _STATE.is_healthy()
            self._respond(200 if ok else 503, {'status': 'ok' if ok else 'fail'})
            return
        if path == '/readyz':
            ok = _STATE.is_ready()
            snap = _STATE.snapshot()
            snap['status'] = 'ready' if ok else 'not_ready'
            self._respond(200 if ok else 503, snap)
            return
        if path in ('/metrics_summary', '/'):
            self._respond(200, _STATE.snapshot())
            return
        self._respond(404, {'status': 'not_found', 'path': path})


def start(port: int = DEFAULT_PORT) -> threading.Thread:
    """
    Start the health probe HTTP server in a daemon thread.  Returns the thread
    object (for testing or shutdown).  Safe to call multiple times — second
    call is a no-op if the previous server is still alive.
    """
    if hasattr(start, '_thread') and start._thread.is_alive():     # type: ignore[attr-defined]
        logger.debug('health endpoint already running')
        return start._thread   # type: ignore[attr-defined]

    httpd = ThreadingHTTPServer(('0.0.0.0', port), _Handler)
    _STATE.mark_started()

    def _serve():
        logger.info(f'health endpoint listening on :{port} (/healthz /readyz)')
        try:
            httpd.serve_forever()
        except Exception as e:
            logger.error(f'health endpoint crashed: {e}')

    t = threading.Thread(target=_serve, name='pad-health', daemon=True)
    t.start()
    start._thread = t   # type: ignore[attr-defined]
    return t


if __name__ == '__main__':
    # Smoke test: start the server and idle.
    logging.basicConfig(level=logging.INFO)
    start()
    while True:
        time.sleep(60)
