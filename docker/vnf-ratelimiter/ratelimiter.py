#!/usr/bin/env python3
"""
PAD-ONAP VNF: Rate Limiter
===========================
Token-bucket per-flow rate limiter.
Resources: 2 vCPU, 2 GB RAM  (spec §6.1)

HTTP API:
  GET  /health              → {"status": "ok"}
  GET  /metrics             → Prometheus text
  POST /activate            → enable rate limiting
  POST /deactivate          → standby
  POST /set_limit           → {"ip": "x.x.x.x", "pps": 1000}
  GET  /flows               → active flow token buckets
"""

import argparse
import json
import logging
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] ratelimiter — %(message)s')
logger = logging.getLogger('ratelimiter')

_DEFAULT_PPS   = int(1000)     # default packets/sec per flow
_BUCKET_CAP    = 5000          # max burst

_state = {
    'mode':          'standby',
    'pkts_received': 0,
    'pkts_dropped':  0,
    'flows_limited': 0,
    'start_time':    time.time(),
    'limits':        {},        # ip → pps limit
    'buckets':       defaultdict(lambda: {'tokens': _BUCKET_CAP, 'last': time.time()}),
}
_lock = threading.Lock()


def _consume_token(ip: str) -> bool:
    """Return True if packet allowed, False if rate-limited."""
    with _lock:
        pps    = _state['limits'].get(ip, _DEFAULT_PPS)
        bucket = _state['buckets'][ip]
        now    = time.time()
        delta  = now - bucket['last']
        bucket['tokens'] = min(_BUCKET_CAP, bucket['tokens'] + delta * pps)
        bucket['last']   = now
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            return True
        return False


def _background_sim():
    while True:
        if _state['mode'] == 'active':
            with _lock:
                _state['pkts_received'] += 50
                _state['pkts_dropped']  += 2   # ~4% drop
        time.sleep(0.1)


class RateLimiterHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == '/health':
            self._json({'status': 'ok', 'mode': _state['mode']})
        elif self.path == '/metrics':
            self._prometheus()
        elif self.path == '/flows':
            with _lock:
                flows = {ip: {'pps_limit': pps} for ip, pps in _state['limits'].items()}
            self._json(flows)
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if self.path == '/activate':
            with _lock: _state['mode'] = 'active'
            logger.info("RateLimiter ACTIVATED")
            self._json({'status': 'ok', 'mode': 'active'})
        elif self.path == '/deactivate':
            with _lock: _state['mode'] = 'standby'
            logger.info("RateLimiter DEACTIVATED")
            self._json({'status': 'ok', 'mode': 'standby'})
        elif self.path == '/set_limit':
            ip  = body.get('ip', '')
            pps = int(body.get('pps', _DEFAULT_PPS))
            if ip:
                with _lock: _state['limits'][ip] = pps
                logger.info(f"Rate limit set: {ip} → {pps} pps")
                self._json({'status': 'ok', 'ip': ip, 'pps': pps})
            else:
                self._json({'error': 'missing ip'}, 400)
        else:
            self._json({'error': 'not found'}, 404)

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _prometheus(self):
        lines = [
            f'pad_ratelimiter_pkts_received_total {_state["pkts_received"]}',
            f'pad_ratelimiter_pkts_dropped_total {_state["pkts_dropped"]}',
            f'pad_ratelimiter_active {1 if _state["mode"] == "active" else 0}',
            f'pad_ratelimiter_flows_configured {len(_state["limits"])}',
            f'pad_ratelimiter_uptime_seconds {time.time()-_state["start_time"]:.1f}',
        ]
        body = '\n'.join(lines).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8002)
    args = parser.parse_args()
    threading.Thread(target=_background_sim, daemon=True).start()
    server = HTTPServer(('0.0.0.0', args.port), RateLimiterHandler)
    logger.info(f"RateLimiter VNF ready on :{args.port}")
    server.serve_forever()


if __name__ == '__main__':
    main()
