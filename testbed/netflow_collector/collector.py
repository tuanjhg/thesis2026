#!/usr/bin/env python3
"""
PAD-ONAP NetFlow Collector
===========================
Receives NetFlow v5/v9 UDP packets from Mininet softflowd / pmacct.
Parses flow records and converts to PAD-ONAP feature format.

For local testing (no real NetFlow), also provides a synthetic mode
that generates feature vectors from the gNMI simulator's metrics.

Usage:
  # Real NetFlow mode (requires softflowd in Mininet):
  python3 collector.py --mode netflow --port 6343

  # Synthetic mode (pulls from gNMI simulator):
  python3 collector.py --mode synthetic --gnmi http://localhost:8080

REST API (for pipeline integration):
  GET /flows          — Latest N flow feature vectors (JSON)
  GET /flows/latest   — Single latest feature vector
  GET /health         — Health check
"""

import argparse
import json
import math
import socket
import struct
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional


# ── NetFlow v5 record format ──────────────────────────────────────────────────
NETFLOW_V5_HEADER_FMT  = '!HHIIIIBBH'
NETFLOW_V5_RECORD_FMT  = '!IIIHHIIIIHH BBBxHHBBxx'
NETFLOW_V5_HEADER_LEN  = struct.calcsize(NETFLOW_V5_HEADER_FMT)
NETFLOW_V5_RECORD_LEN  = struct.calcsize(NETFLOW_V5_RECORD_FMT)


def parse_netflow_v5(data: bytes) -> list:
    """Parse NetFlow v5 UDP packet. Returns list of flow dicts."""
    if len(data) < NETFLOW_V5_HEADER_LEN:
        return []

    header = struct.unpack(NETFLOW_V5_HEADER_FMT,
                           data[:NETFLOW_V5_HEADER_LEN])
    version, count = header[0], header[1]
    if version != 5:
        return []   # Only v5 supported; v9 needs template handling

    flows = []
    offset = NETFLOW_V5_HEADER_LEN
    for _ in range(count):
        if offset + NETFLOW_V5_RECORD_LEN > len(data):
            break
        rec = struct.unpack(NETFLOW_V5_RECORD_FMT,
                            data[offset:offset + NETFLOW_V5_RECORD_LEN])
        offset += NETFLOW_V5_RECORD_LEN
        flows.append({
            'src_ip':    socket.inet_ntoa(struct.pack('!I', rec[0])),
            'dst_ip':    socket.inet_ntoa(struct.pack('!I', rec[1])),
            'nexthop':   socket.inet_ntoa(struct.pack('!I', rec[2])),
            'in_iface':  rec[3],
            'out_iface': rec[4],
            'pkts':      rec[5],
            'bytes':     rec[6],
            'first_ms':  rec[7],
            'last_ms':   rec[8],
            'src_port':  rec[9],
            'dst_port':  rec[10],
            'protocol':  rec[11],
            'tcp_flags': rec[12],
        })
    return flows


# ── Feature extraction from flow records ─────────────────────────────────────
class FlowFeatureExtractor:
    """
    Convert raw flow records into 17 PAD-ONAP features.
    Matches FEATURE_NAMES in the AI pipeline.
    """

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

    def __init__(self, window_sec: float = 5.0):
        self._window_sec = window_sec
        self._flow_buf: deque = deque()   # (timestamp, flow_dict)
        self._lock = threading.Lock()

    def add_flows(self, flows: list):
        now = time.time()
        with self._lock:
            for f in flows:
                self._flow_buf.append((now, f))
            # Evict flows outside window
            cutoff = now - self._window_sec
            while self._flow_buf and self._flow_buf[0][0] < cutoff:
                self._flow_buf.popleft()

    @staticmethod
    def _shannon_entropy(values: list) -> float:
        if not values:
            return 0.0
        from collections import Counter
        counts = Counter(values)
        total = len(values)
        import math
        return -sum((c/total) * math.log2(c/total + 1e-12)
                    for c in counts.values())

    def compute(self) -> Optional[dict]:
        """Compute feature vector from current window. Returns None if empty."""
        with self._lock:
            if not self._flow_buf:
                return None
            flows = [f for _, f in self._flow_buf]

        n = len(flows)
        if n == 0:
            return None

        # Rates
        total_pkts  = sum(f['pkts']  for f in flows)
        total_bytes = sum(f['bytes'] for f in flows)
        pkt_rate    = total_pkts  / self._window_sec
        byte_rate   = total_bytes / self._window_sec

        # Entropy
        src_ips   = [f['src_ip']   for f in flows]
        dst_ips   = [f['dst_ip']   for f in flows]
        src_ports = [f['src_port'] for f in flows]
        dst_ports = [f['dst_port'] for f in flows]
        src_ip_entropy   = self._shannon_entropy(src_ips)
        dst_ip_entropy   = self._shannon_entropy(dst_ips)
        src_port_entropy = self._shannon_entropy(src_ports)
        dst_port_entropy = self._shannon_entropy(dst_ports)

        # Protocol distribution
        protos = [f['protocol'] for f in flows]
        proto_dist_tcp  = protos.count(6)  / n
        proto_dist_udp  = protos.count(17) / n
        proto_dist_icmp = protos.count(1)  / n

        # TCP flag ratios
        tcp_flows  = [f for f in flows if f['protocol'] == 6]
        tcp_pkts   = sum(f['pkts'] for f in tcp_flows) or 1
        syn_flags  = sum(f['pkts'] for f in tcp_flows if f['tcp_flags'] & 0x02)
        fin_flags  = sum(f['pkts'] for f in tcp_flows if f['tcp_flags'] & 0x01)
        syn_ratio  = syn_flags / tcp_pkts
        fin_ratio  = fin_flags / tcp_pkts

        # Packet size
        pkt_sizes    = [f['bytes'] / max(f['pkts'], 1) for f in flows]
        avg_pkt_size = sum(pkt_sizes) / n
        import math
        variance     = sum((p - avg_pkt_size)**2 for p in pkt_sizes) / n
        pkt_size_std = math.sqrt(variance) + 1e-8

        # Flow metrics
        durations    = [(f['last_ms'] - f['first_ms']) / 1000.0 for f in flows]
        mean_dur     = sum(durations) / n
        new_flows_rt = n / self._window_sec

        # Inter-arrival (approx from mean duration)
        inter_arr_mean = mean_dur / max(n, 1)
        inter_arr_std  = pkt_size_std / 100.0  # approximation

        return {
            'timestamp':         time.time(),
            'n_flows':           n,
            'feature_names':     self.FEATURE_NAMES,
            'features': {
                'pkt_rate':           round(pkt_rate, 3),
                'byte_rate':          round(byte_rate, 3),
                'src_ip_entropy':     round(src_ip_entropy, 4),
                'dst_ip_entropy':     round(dst_ip_entropy, 4),
                'src_port_entropy':   round(src_port_entropy, 4),
                'dst_port_entropy':   round(dst_port_entropy, 4),
                'proto_dist_tcp':     round(proto_dist_tcp, 4),
                'proto_dist_udp':     round(proto_dist_udp, 4),
                'proto_dist_icmp':    round(proto_dist_icmp, 4),
                'syn_ratio':          round(syn_ratio, 4),
                'fin_ratio':          round(fin_ratio, 4),
                'avg_pkt_size':       round(avg_pkt_size, 2),
                'pkt_size_std':       round(pkt_size_std, 2),
                'new_flows_rate':     round(new_flows_rt, 3),
                'flow_duration_mean': round(mean_dur, 3),
                'inter_arrival_mean': round(inter_arr_mean, 4),
                'inter_arrival_std':  round(inter_arr_std, 4),
            }
        }


# ── Synthetic mode: generate features from gNMI metrics ──────────────────────
class SyntheticFlowGenerator:
    """
    When no real NetFlow is available, generate feature vectors by reading
    metrics from the gNMI simulator and mapping them to flow features.
    """

    def __init__(self, gnmi_url: str = 'http://localhost:8080'):
        self._gnmi_url = gnmi_url
        self._latest: Optional[dict] = None
        self._lock = threading.Lock()

    def _fetch_gnmi(self) -> Optional[dict]:
        try:
            with urllib.request.urlopen(f'{self._gnmi_url}/metrics/r1', timeout=2) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def update(self):
        data = self._fetch_gnmi()
        if data is None:
            return
        m = data.get('metrics', {})

        # ── Infer attack intensity (0=normal, 1=full attack) from gNMI signals ──
        udp_r    = m.get('udp_ratio', 0.3)
        pkt_r    = m.get('in_pkts',   5000.0)
        syn_r    = m.get('syn_ratio',  0.08)
        cpu      = m.get('cpu_pct',   25.0)

        # Attack signal: combination of UDP ratio and packet rate spikes
        atk_udp  = max(0.0, (udp_r - 0.6) / 0.38)          # 0→0, 0.98→1.0
        atk_pkt  = max(0.0, (pkt_r - 20_000) / 980_000)    # 0→0, 1M→1.0
        atk_syn  = max(0.0, (syn_r - 0.40) / 0.59)         # 0→0, 0.99→1.0
        attack_i = min(1.0, atk_udp * 0.5 + atk_pkt * 0.4 + atk_syn * 0.1)

        avg_pkt  = m.get('avg_pkt_size', 512.0)

        # ── Map gNMI metrics → training-distribution-aligned features ───────────
        #
        # IMPORTANT: feature_extractor.py computes features from CICDDoS2019 flow
        # records, NOT from device counters. The semantic mappings below are
        # calibrated to match the scaler's training distribution:
        #   scaler mean ± std per feature (from pad_onap_v3/models/scaler.pkl):
        #   pkt_rate:         220,891 ± 294,975
        #   byte_rate:        222M    ± 416M
        #   src_ip_entropy:   0.12    ± 0.50   ← packet-SIZE entropy, NOT IP entropy
        #   dst_ip_entropy:   0.18    ± 0.75   ← packet-SIZE entropy, NOT IP entropy
        #   src_port_entropy: 6.17    ± 1.00
        #   dst_port_entropy: 6.42    ± 0.83
        #   proto_dist_tcp:   0.15    ± 0.35
        #   proto_dist_udp:   0.84    ± 0.35
        #   syn_ratio:        0.00    ± 0.01   ← very low even for SYN floods
        #   avg_pkt_size:     870     ± 782
        #   pkt_size_std:     133     ± 154
        #   new_flows_rate:   51,586  ± 48,547
        #   flow_duration_ms: 1,695   ± 5,665
        #   inter_arrival_ms: 164     ± 529
        #   inter_arrival_std:264     ± 791

        # src/dst_ip_entropy: actually = entropy of forward/backward *packet sizes*
        #   attack → uniform packet sizes (all same size) → entropy ≈ 0
        #   normal → varied sizes → entropy 0.3–0.8
        src_ip_entropy = max(0.0, 0.55 * (1.0 - attack_i))
        dst_ip_entropy = max(0.0, 0.70 * (1.0 - attack_i))

        # src_port_entropy: mean=6.17; attack (reflection) = few src ports → lower
        src_port_entropy = 6.2 - attack_i * 3.5      # 6.2 normal → 2.7 full attack

        # dst_port_entropy: mean=6.42; attack = one target port → very low
        dst_port_entropy = 6.5 - attack_i * 5.5      # 6.5 normal → 1.0 full attack

        # Protocol distribution (udp_ratio and icmp_ratio from gNMI are correct)
        icmp_r   = m.get('icmp_ratio', 0.02)
        tcp_r    = max(0.0, 1.0 - udp_r - icmp_r)

        # syn_ratio: training mean=0.00, std=0.01 → scale gNMI syn_ratio down 10x
        # gNMI normal = 0.08 → feature = 0.008; SYN flood gNMI = 0.99 → feature = 0.018
        syn_ratio_feat = min(0.02, syn_r * 0.10)
        fin_ratio_feat = min(0.02, syn_ratio_feat * 0.3)

        # avg_pkt_size: training mean=870, std=782; gNMI gives 64–1500 (correct range)
        # Attack: large reflection packets (1400–1500 bytes) or tiny flood (64 bytes)
        # Map based on attack type signal
        avg_pkt_size = avg_pkt  # gNMI already in bytes, direct use

        # pkt_size_std: training mean=133, std=154
        # Attack: uniform sizes → std 5–30; Normal: varied → std 80–300
        pkt_size_std = max(5.0, 180.0 * (1.0 - attack_i * 0.95))

        # new_flows_rate: training mean=51,586, std=48,547
        # gNMI new_flows_rate baseline=80/s → scale ×600 → 48,000/s (≈ training mean)
        # During attack: gNMI goes up to 50,000 → ×600 = 30M → cap at 200,000
        gnmi_nfr = m.get('new_flows_rate', 80.0)
        new_flows_rate = min(200_000.0, gnmi_nfr * 600.0)

        # flow_duration_mean: training mean=1,695ms, std=5,665ms
        # gNMI flow_duration_ms baseline=150ms → ×11 → 1,650ms (≈ training mean)
        # Attack: very short flows → ×2 only
        gnmi_dur = m.get('flow_duration_ms', 150.0)
        if attack_i > 0.5:
            flow_duration_mean = gnmi_dur * 2.0          # short attack flows
        else:
            flow_duration_mean = gnmi_dur * 11.0         # normal traffic

        # inter_arrival_mean: training mean=164ms, std=529ms
        # gNMI iat_mean_ms baseline=2.5ms → ×60 → 150ms (≈ training mean)
        # Attack: tiny IAT (0.01ms gNMI) → ×60 = 0.6ms, scaled up to at least 1ms
        inter_arrival_mean = max(0.5, m.get('iat_mean_ms', 2.5) * 60.0)

        # inter_arrival_std: training mean=264ms, std=791ms
        inter_arrival_std  = max(0.5, m.get('iat_std_ms', 1.2) * 80.0)

        feature_vec = {
            'timestamp':     time.time(),
            'n_flows':       100,
            'source':        'synthetic_gnmi',
            'feature_names': FlowFeatureExtractor.FEATURE_NAMES,
            'features': {
                'pkt_rate':           round(pkt_r,          3),
                'byte_rate':          round(m.get('in_octets', 800_000), 3),
                'src_ip_entropy':     round(src_ip_entropy,  4),
                'dst_ip_entropy':     round(dst_ip_entropy,  4),
                'src_port_entropy':   round(src_port_entropy, 4),
                'dst_port_entropy':   round(dst_port_entropy, 4),
                'proto_dist_tcp':     round(tcp_r,           4),
                'proto_dist_udp':     round(udp_r,           4),
                'proto_dist_icmp':    round(icmp_r,          4),
                'syn_ratio':          round(syn_ratio_feat,  5),
                'fin_ratio':          round(fin_ratio_feat,  5),
                'avg_pkt_size':       round(avg_pkt_size,    2),
                'pkt_size_std':       round(pkt_size_std,    2),
                'new_flows_rate':     round(new_flows_rate,  2),
                'flow_duration_mean': round(flow_duration_mean, 2),
                'inter_arrival_mean': round(inter_arrival_mean, 4),
                'inter_arrival_std':  round(inter_arrival_std,  4),
            }
        }
        with self._lock:
            self._latest = feature_vec

    def get_latest(self) -> Optional[dict]:
        with self._lock:
            return self._latest


# ── Collector REST API ────────────────────────────────────────────────────────
_feature_history: deque = deque(maxlen=1000)
_history_lock = threading.Lock()


class CollectorHandler(BaseHTTPRequestHandler):
    def _json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.rstrip('/')
        if path == '/health':
            with _history_lock:
                n = len(_feature_history)
            self._json(200, {'status': 'ok', 'buffered_features': n})

        elif path == '/flows':
            with _history_lock:
                data = list(_feature_history)[-50:]
            self._json(200, {'count': len(data), 'flows': data})

        elif path == '/flows/latest':
            with _history_lock:
                latest = _feature_history[-1] if _feature_history else None
            if latest:
                self._json(200, latest)
            else:
                self._json(204, {'error': 'No data yet'})
        else:
            self._json(404, {'error': 'Not found'})

    def log_message(self, *args): pass


def _append_feature(vec: dict):
    with _history_lock:
        _feature_history.append(vec)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='PAD-ONAP NetFlow Collector')
    parser.add_argument('--mode',   default='synthetic',
                        choices=['netflow', 'synthetic'],
                        help='Collection mode')
    parser.add_argument('--port',   type=int, default=6343,
                        help='NetFlow UDP port (mode=netflow)')
    parser.add_argument('--api-port', type=int, default=7070,
                        help='REST API port')
    parser.add_argument('--gnmi',   default='http://localhost:8080',
                        help='gNMI simulator URL (mode=synthetic)')
    parser.add_argument('--interval', type=float, default=1.0,
                        help='Feature computation interval (seconds)')
    args = parser.parse_args()

    # Start REST API
    api = HTTPServer(('0.0.0.0', args.api_port), CollectorHandler)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    print(f'[Collector] REST API: http://localhost:{args.api_port}/flows/latest')

    if args.mode == 'synthetic':
        print(f'[Collector] Mode: synthetic (gNMI={args.gnmi})')
        gen = SyntheticFlowGenerator(args.gnmi)
        while True:
            gen.update()
            vec = gen.get_latest()
            if vec:
                _append_feature(vec)
                print(f'[Collector] Feature: pkt_rate={vec["features"]["pkt_rate"]:.0f} '
                      f'udp_ratio={vec["features"]["proto_dist_udp"]:.3f} '
                      f'src_ip_entropy={vec["features"]["src_ip_entropy"]:.3f}')
            time.sleep(args.interval)

    else:
        print(f'[Collector] Mode: NetFlow v5 UDP :{args.port}')
        extractor = FlowFeatureExtractor(window_sec=5.0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', args.port))
        sock.settimeout(1.0)

        last_compute = time.time()
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                flows = parse_netflow_v5(data)
                if flows:
                    extractor.add_flows(flows)
                    print(f'[Collector] Received {len(flows)} flows from {addr[0]}')
            except socket.timeout:
                pass

            if time.time() - last_compute >= args.interval:
                vec = extractor.compute()
                if vec:
                    _append_feature(vec)
                last_compute = time.time()


if __name__ == '__main__':
    main()
