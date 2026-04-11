#!/usr/bin/env python3
"""
PAD-ONAP Prometheus Metrics Exporter
=====================================
Bridges gNMI simulator metrics → Prometheus scrape endpoint.
Runs as a sidecar in Docker testbed, scrapes gNMI every 2s.

Exposed metrics (all prefixed pad_gnmi_):
  pad_gnmi_in_pkts_total{device}         — Inbound packets/s
  pad_gnmi_in_octets_total{device}       — Inbound bytes/s
  pad_gnmi_cpu_pct{device}               — CPU utilization %
  pad_gnmi_memory_pct{device}            — Memory utilization %
  pad_gnmi_queue_depth_pct{device}       — Queue depth %
  pad_gnmi_udp_ratio{device}             — UDP traffic fraction
  pad_gnmi_syn_ratio{device}             — SYN/TCP ratio
  pad_gnmi_src_ip_entropy{device}        — Source IP entropy
  pad_gnmi_new_flows_rate{device}        — New flows per second
  pad_gnmi_attack_mode                   — 1=attack active, 0=normal
"""

import argparse
import json
import time
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from prometheus_client import (
        Gauge, Counter, Info,
        generate_latest, CONTENT_TYPE_LATEST, REGISTRY
    )
    PROM_AVAILABLE = True
except ImportError:
    PROM_AVAILABLE = False
    print('[Exporter] prometheus_client not installed — using plain text format')


# ── Metric definitions ────────────────────────────────────────────────────────
if PROM_AVAILABLE:
    g_in_pkts        = Gauge('pad_gnmi_in_pkts',        'Inbound packets/s',     ['device'])
    g_in_octets      = Gauge('pad_gnmi_in_octets',      'Inbound bytes/s',       ['device'])
    g_cpu_pct        = Gauge('pad_gnmi_cpu_pct',         'CPU utilization %',     ['device'])
    g_memory_pct     = Gauge('pad_gnmi_memory_pct',      'Memory utilization %',  ['device'])
    g_queue_depth    = Gauge('pad_gnmi_queue_depth_pct', 'Queue depth %',         ['device'])
    g_udp_ratio      = Gauge('pad_gnmi_udp_ratio',       'UDP traffic fraction',  ['device'])
    g_syn_ratio      = Gauge('pad_gnmi_syn_ratio',       'SYN/TCP ratio',         ['device'])
    g_src_entropy    = Gauge('pad_gnmi_src_ip_entropy',  'Source IP entropy',     ['device'])
    g_new_flows      = Gauge('pad_gnmi_new_flows_rate',  'New flows per second',  ['device'])
    g_pkt_size       = Gauge('pad_gnmi_avg_pkt_size',    'Avg packet size bytes', ['device'])
    g_attack_mode    = Gauge('pad_gnmi_attack_active',   '1 if attack injected')
    g_scrape_errors  = Counter('pad_gnmi_scrape_errors_total', 'Scrape failures')


# ── Scraper ───────────────────────────────────────────────────────────────────
class GNMIScraper:
    def __init__(self, gnmi_url: str):
        self._url = gnmi_url
        self._last_data = {}
        self._attack_active = 0

    def scrape(self):
        try:
            with urllib.request.urlopen(f'{self._url}/metrics', timeout=3) as r:
                data = json.loads(r.read())
            with urllib.request.urlopen(f'{self._url}/status', timeout=3) as r:
                status = json.loads(r.read())
            self._attack_active = 1 if status.get('attack_mode') else 0
        except Exception as e:
            if PROM_AVAILABLE:
                g_scrape_errors.inc()
            return

        for device, dev_data in data.items():
            m = dev_data.get('metrics', {})
            if PROM_AVAILABLE:
                g_in_pkts.labels(device=device).set(m.get('in_pkts', 0))
                g_in_octets.labels(device=device).set(m.get('in_octets', 0))
                g_cpu_pct.labels(device=device).set(m.get('cpu_pct', 0))
                g_memory_pct.labels(device=device).set(m.get('memory_pct', 0))
                g_queue_depth.labels(device=device).set(m.get('queue_depth_pct', 0))
                g_udp_ratio.labels(device=device).set(m.get('udp_ratio', 0))
                g_syn_ratio.labels(device=device).set(m.get('syn_ratio', 0))
                g_src_entropy.labels(device=device).set(m.get('src_ip_entropy', 0))
                g_new_flows.labels(device=device).set(m.get('new_flows_rate', 0))
                g_pkt_size.labels(device=device).set(m.get('avg_pkt_size', 0))
            self._last_data[device] = m

        if PROM_AVAILABLE:
            g_attack_mode.set(self._attack_active)

    def plain_text_metrics(self) -> str:
        """Fallback plain-text metrics if prometheus_client not installed."""
        lines = []
        for device, m in self._last_data.items():
            for key, val in m.items():
                lines.append(f'pad_gnmi_{key}{{device="{device}"}} {val:.4f}')
        lines.append(f'pad_gnmi_attack_active {self._attack_active}')
        return '\n'.join(lines) + '\n'


# ── HTTP handler ──────────────────────────────────────────────────────────────
_scraper = None


class ExporterHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ('/metrics', '/metrics/'):
            if PROM_AVAILABLE:
                body = generate_latest(REGISTRY)
                ct   = CONTENT_TYPE_LATEST
            else:
                body = _scraper.plain_text_metrics().encode()
                ct   = 'text/plain; version=0.0.4'
            self.send_response(200)
            self.send_header('Content-Type', ct)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/health':
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args): pass


def main():
    global _scraper
    parser = argparse.ArgumentParser(description='PAD-ONAP Prometheus Exporter')
    parser.add_argument('--gnmi',     default='http://localhost:8080')
    parser.add_argument('--port',     type=int, default=9091)
    parser.add_argument('--interval', type=float, default=2.0)
    args = parser.parse_args()

    _scraper = GNMIScraper(args.gnmi)

    def _scrape_loop():
        while True:
            _scraper.scrape()
            time.sleep(args.interval)

    threading.Thread(target=_scrape_loop, daemon=True).start()

    print(f'[Exporter] Prometheus metrics at http://0.0.0.0:{args.port}/metrics')
    print(f'[Exporter] Scraping gNMI at {args.gnmi} every {args.interval}s')
    HTTPServer(('0.0.0.0', args.port), ExporterHandler).serve_forever()


if __name__ == '__main__':
    main()
