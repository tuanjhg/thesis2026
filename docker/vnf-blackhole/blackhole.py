#!/usr/bin/env python3
"""
PAD-ONAP VNF: Blackhole
========================
iptables-based null-routing for critical DDoS isolation (Tier 4).
Resources: 1 vCPU, 1 GB RAM  (spec §6.1)

HTTP API:
  GET  /health              → {"status": "ok"}
  GET  /metrics             → Prometheus text
  POST /blackhole           → {"ip": "x.x.x.x"}  add to null-route
  DELETE /blackhole         → {"ip": "x.x.x.x"}  remove from null-route
  GET  /blackholed          → list of blackholed IPs
  POST /activate            → enable (standby → active)
  POST /deactivate          → standby

In real deployment: calls iptables / ip route add blackhole.
In container/stub: simulates via in-memory set + logs.
"""

import argparse
import json
import logging
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] blackhole — %(message)s')
logger = logging.getLogger('blackhole')

# Detect if running with NET_ADMIN capability (real iptables available)
_REAL_IPTABLES = os.path.exists('/sbin/iptables') and os.geteuid() == 0

_state = {
    'mode':            'standby',
    'blackholed_ips':  set(),
    'pkts_dropped':    0,
    'start_time':      time.time(),
}
_lock = threading.Lock()


def _iptables_add(ip: str) -> bool:
    """Add null-route via iptables DROP rule."""
    if not _REAL_IPTABLES:
        logger.info(f"[stub] iptables -I INPUT -s {ip} -j DROP")
        return True
    try:
        subprocess.run(
            ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except Exception as e:
        logger.error(f"iptables add failed for {ip}: {e}")
        return False


def _iptables_del(ip: str) -> bool:
    """Remove null-route."""
    if not _REAL_IPTABLES:
        logger.info(f"[stub] iptables -D INPUT -s {ip} -j DROP")
        return True
    try:
        subprocess.run(
            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
            check=True, capture_output=True, timeout=5,
        )
        return True
    except Exception as e:
        logger.error(f"iptables del failed for {ip}: {e}")
        return False


class BlackholeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def do_GET(self):
        if self.path == '/health':
            self._json({'status': 'ok', 'mode': _state['mode'],
                        'blackholed': len(_state['blackholed_ips'])})
        elif self.path == '/metrics':
            self._prometheus()
        elif self.path == '/blackholed':
            with _lock:
                ips = sorted(_state['blackholed_ips'])
            self._json({'ips': ips, 'count': len(ips)})
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if self.path == '/activate':
            with _lock: _state['mode'] = 'active'
            logger.info("Blackhole ACTIVATED — null-routing ON")
            self._json({'status': 'ok', 'mode': 'active'})

        elif self.path == '/deactivate':
            # Remove all active rules before going standby
            with _lock:
                ips = list(_state['blackholed_ips'])
                _state['mode'] = 'standby'
            for ip in ips:
                _iptables_del(ip)
            with _lock:
                _state['blackholed_ips'].clear()
            logger.info("Blackhole DEACTIVATED — all null-routes removed")
            self._json({'status': 'ok', 'mode': 'standby', 'removed': len(ips)})

        elif self.path == '/blackhole':
            ip = body.get('ip', '')
            if not ip:
                self._json({'error': 'missing ip'}, 400)
                return
            if _state['mode'] != 'active':
                self._json({'error': 'not active — call /activate first'}, 409)
                return
            ok = _iptables_add(ip)
            if ok:
                with _lock:
                    _state['blackholed_ips'].add(ip)
                logger.info(f"Blackholed: {ip}")
                self._json({'status': 'ok', 'ip': ip, 'action': 'blackholed'})
            else:
                self._json({'status': 'error', 'ip': ip}, 500)

        else:
            self._json({'error': 'not found'}, 404)

    def do_DELETE(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = json.loads(self.rfile.read(length)) if length else {}

        if self.path == '/blackhole':
            ip = body.get('ip', '')
            if not ip:
                self._json({'error': 'missing ip'}, 400)
                return
            ok = _iptables_del(ip)
            with _lock:
                _state['blackholed_ips'].discard(ip)
            logger.info(f"Un-blackholed: {ip}")
            self._json({'status': 'ok', 'ip': ip, 'action': 'removed'})
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
            f'pad_blackhole_blackholed_ips {len(_state["blackholed_ips"])}',
            f'pad_blackhole_pkts_dropped_total {_state["pkts_dropped"]}',
            f'pad_blackhole_active {1 if _state["mode"] == "active" else 0}',
            f'pad_blackhole_uptime_seconds {time.time()-_state["start_time"]:.1f}',
        ]
        body = '\n'.join(lines).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8004)
    args = parser.parse_args()
    server = HTTPServer(('0.0.0.0', args.port), BlackholeHandler)
    logger.info(f"Blackhole VNF ready on :{args.port}  "
                f"iptables={'real' if _REAL_IPTABLES else 'stub'}")
    server.serve_forever()


if __name__ == '__main__':
    main()
