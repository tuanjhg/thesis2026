#!/usr/bin/env python3
"""
PAD-ONAP VNF: Analyzer
=======================
Packet capture + feature re-extraction → feeds back to M1 telemetry pipeline.
Resources: 2 vCPU, 4 GB RAM  (spec §6.1)

HTTP API:
  GET  /health              → {"status": "ok"}
  GET  /metrics             → Prometheus text
  GET  /features/latest     → latest extracted 17-feature dict (feeds live_pipeline)
  POST /activate            → start capture
  POST /deactivate          → stop
  GET  /capture/stats       → capture statistics
"""

import argparse
import json
import logging
import math
import random
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] analyzer — %(message)s')
logger = logging.getLogger('analyzer')

_state = {
    'mode':          'standby',
    'pkts_captured': 0,
    'flows_tracked': 0,
    'start_time':    time.time(),
    'latest_features': None,
    'feature_ts':    None,
}
_lock = threading.Lock()

# Feature names (must match FEATURE_NAMES in live_pipeline.py)
FEATURE_NAMES = [
    'pkt_rate','byte_rate','src_ip_entropy','dst_ip_entropy',
    'src_port_entropy','dst_port_entropy','proto_dist_tcp',
    'proto_dist_udp','proto_dist_icmp','syn_ratio','fin_ratio',
    'avg_pkt_size','pkt_size_std','new_flows_rate',
    'flow_duration_mean','inter_arrival_mean','inter_arrival_std',
]


def _extract_features_simulated() -> dict:
    """Simulate feature extraction from captured packets."""
    return {
        'pkt_rate':          random.uniform(500, 2000),
        'byte_rate':         random.uniform(50000, 500000),
        'src_ip_entropy':    random.uniform(0.5, 4.0),
        'dst_ip_entropy':    random.uniform(0.1, 2.0),
        'src_port_entropy':  random.uniform(1.0, 5.0),
        'dst_port_entropy':  random.uniform(0.1, 3.0),
        'proto_dist_tcp':    random.uniform(0.3, 0.9),
        'proto_dist_udp':    random.uniform(0.05, 0.6),
        'proto_dist_icmp':   random.uniform(0.0, 0.1),
        'syn_ratio':         random.uniform(0.0, 0.5),
        'fin_ratio':         random.uniform(0.0, 0.2),
        'avg_pkt_size':      random.uniform(64, 1500),
        'pkt_size_std':      random.uniform(10, 400),
        'new_flows_rate':    random.uniform(1, 100),
        'flow_duration_mean': random.uniform(0.1, 10.0),
        'inter_arrival_mean': random.uniform(0.001, 0.1),
        'inter_arrival_std':  random.uniform(0.0005, 0.05),
    }


def _background_capture():
    while True:
        if _state['mode'] == 'active':
            feats = _extract_features_simulated()
            with _lock:
                _state['pkts_captured']    += int(feats['pkt_rate'] * 0.1)
                _state['flows_tracked']    += random.randint(0, 5)
                _state['latest_features']   = feats
                _state['feature_ts']        = time.time()
        time.sleep(0.5)   # extract every 500ms (⅒ of 5s window)


class AnalyzerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == '/health':
            self._json({'status': 'ok', 'mode': _state['mode']})
        elif self.path == '/metrics':
            self._prometheus()
        elif self.path == '/features/latest':
            with _lock:
                feats = _state['latest_features']
                ts    = _state['feature_ts']
            if feats:
                self._json({'timestamp': ts, 'features': feats})
            else:
                self.send_response(204)
                self.end_headers()
        elif self.path == '/capture/stats':
            with _lock:
                s = {k: v for k, v in _state.items()
                     if k not in ('latest_features',)}
            self._json(s)
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self):
        if self.path == '/activate':
            with _lock: _state['mode'] = 'active'
            logger.info("Analyzer ACTIVATED — packet capture ON")
            self._json({'status': 'ok', 'mode': 'active'})
        elif self.path == '/deactivate':
            with _lock: _state['mode'] = 'standby'
            logger.info("Analyzer DEACTIVATED")
            self._json({'status': 'ok', 'mode': 'standby'})
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
            f'pad_analyzer_pkts_captured_total {_state["pkts_captured"]}',
            f'pad_analyzer_flows_tracked {_state["flows_tracked"]}',
            f'pad_analyzer_active {1 if _state["mode"] == "active" else 0}',
            f'pad_analyzer_uptime_seconds {time.time()-_state["start_time"]:.1f}',
        ]
        body = '\n'.join(lines).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8003)
    args = parser.parse_args()
    threading.Thread(target=_background_capture, daemon=True).start()
    server = HTTPServer(('0.0.0.0', args.port), AnalyzerHandler)
    logger.info(f"Analyzer VNF ready on :{args.port}")
    server.serve_forever()


if __name__ == '__main__':
    main()
