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

    # ── Normal-state baseline fingerprint (aligned with CICDDoS2019 BENIGN class)
    # These constants represent the BENIGN class centroid from training data.
    # XGBoost was trained on scaled features; these raw values map to the Normal
    # region of feature space, ensuring T0 classification at baseline.
    NORMAL_PKT_RATE        = 5_000.0    # pkt/s — low background traffic
    NORMAL_BYTE_RATE       = 800_000.0  # bytes/s
    NORMAL_UDP_RATIO       = 0.15       # mostly TCP in normal web traffic
    NORMAL_TCP_RATIO       = 0.72
    NORMAL_ICMP_RATIO      = 0.03
    NORMAL_SRC_PORT_ENT    = 6.1        # high entropy — many different src ports
    NORMAL_DST_PORT_ENT    = 5.8        # lower — mostly http/https destination
    NORMAL_SRC_IP_ENT      = 0.50       # moderate packet-size entropy
    NORMAL_DST_IP_ENT      = 0.65
    NORMAL_SYN_RATIO       = 0.008      # very low scaled syn ratio
    NORMAL_AVG_PKT_SIZE    = 900.0      # bytes, mixed packets
    NORMAL_PKT_SIZE_STD    = 180.0      # high variability
    NORMAL_NEW_FLOWS_RATE  = 50_000.0   # ≈ training mean 51,586
    NORMAL_FLOW_DUR_MEAN   = 1_800.0    # ms, ≈ training mean 1,695
    NORMAL_IAT_MEAN        = 160.0      # ms inter-arrival mean
    NORMAL_IAT_STD         = 270.0      # ms

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

        # ── Attack intensity signal (0 = normal, 1 = full attack) ─────────────
        # Derived from gNMI metrics. Thresholds tuned so that idle gNMI
        # (udp_ratio≈0.27, pkt_rate≈5000) yields attack_i ≈ 0 (Normal class).
        atk_udp  = max(0.0, (udp_r - 0.55) / 0.43)       # 0→0, 0.98→1.0
        atk_pkt  = max(0.0, (pkt_r - 15_000) / 985_000)  # 0→0, 1M→1.0
        atk_syn  = max(0.0, (syn_r - 0.40) / 0.59)       # 0→0, 0.99→1.0
        attack_i = min(1.0, atk_udp * 0.5 + atk_pkt * 0.4 + atk_syn * 0.1)

        avg_pkt = m.get('avg_pkt_size', 512.0)

        # ── Feature mapping: interpolate between NORMAL baseline and ATTACK peak ──
        # At attack_i=0 → values match BENIGN class centroid → XGBoost → Normal
        # At attack_i=1 → values match Amplification/UDP_Flood cluster

        # packet rates — NORMAL_PKT_RATE at baseline, scale up linearly during attack
        pkt_rate_feat  = self.NORMAL_PKT_RATE  + attack_i * (1_000_000 - self.NORMAL_PKT_RATE)
        byte_rate_feat = self.NORMAL_BYTE_RATE + attack_i * (500_000_000 - self.NORMAL_BYTE_RATE)
        # override with actual gNMI reading for attack state (it's more realistic)
        if attack_i > 0.1:
            pkt_rate_feat  = pkt_r
            byte_rate_feat = m.get('in_octets', byte_rate_feat)

        # src/dst_ip_entropy: packet-SIZE entropy
        #   Normal: varied sizes → 0.50–0.65
        #   Attack: uniform sizes → near 0
        src_ip_entropy = self.NORMAL_SRC_IP_ENT * (1.0 - attack_i)
        dst_ip_entropy = self.NORMAL_DST_IP_ENT * (1.0 - attack_i)

        # src_port_entropy
        #   Normal: many different src ports → ≈6.1
        #   Attack (reflection): few amplifier src ports → ≈2.5
        src_port_entropy = self.NORMAL_SRC_PORT_ENT - attack_i * 3.6

        # dst_port_entropy
        #   Normal: mixed services (http, dns, smtp…) → ≈5.8
        #   Attack: single target port → ≈0.8
        dst_port_entropy = self.NORMAL_DST_PORT_ENT - attack_i * 5.0

        # Protocol distribution
        #   Normal: mostly TCP, low UDP
        #   Attack (UDP flood): >95% UDP
        icmp_r = m.get('icmp_ratio', 0.02)
        if attack_i < 0.1:
            # Normal state: override gNMI udp_ratio with Normal baseline
            eff_udp  = self.NORMAL_UDP_RATIO
            eff_tcp  = self.NORMAL_TCP_RATIO
            eff_icmp = self.NORMAL_ICMP_RATIO
        else:
            # Attack state: use actual gNMI values
            eff_udp  = udp_r
            eff_icmp = icmp_r
            eff_tcp  = max(0.0, 1.0 - eff_udp - eff_icmp)

        # syn_ratio: training mean≈0.00, std≈0.01
        syn_ratio_feat = min(0.02, syn_r * 0.10)
        fin_ratio_feat = min(0.02, syn_ratio_feat * 0.3)

        # avg_pkt_size
        #   Normal: mixed frames ≈ 900 bytes
        #   Attack: large reflection (1400B) or tiny flood (64B)
        avg_pkt_size = (
            self.NORMAL_AVG_PKT_SIZE * (1.0 - attack_i)
            + avg_pkt * attack_i
        )

        # pkt_size_std
        #   Normal: high variability ≈ 180
        #   Attack: uniform → near 0
        pkt_size_std = max(5.0, self.NORMAL_PKT_SIZE_STD * (1.0 - attack_i * 0.97))

        # new_flows_rate: training mean=51,586
        gnmi_nfr = m.get('new_flows_rate', 80.0)
        if attack_i < 0.1:
            new_flows_rate = self.NORMAL_NEW_FLOWS_RATE
        else:
            new_flows_rate = min(200_000.0, gnmi_nfr * 600.0)

        # flow_duration_mean: training mean=1,695ms
        gnmi_dur = m.get('flow_duration_ms', 150.0)
        if attack_i < 0.1:
            flow_duration_mean = self.NORMAL_FLOW_DUR_MEAN
        elif attack_i > 0.5:
            flow_duration_mean = gnmi_dur * 2.0
        else:
            flow_duration_mean = gnmi_dur * 11.0

        # inter_arrival: training mean≈164ms / std≈264ms
        if attack_i < 0.1:
            inter_arrival_mean = self.NORMAL_IAT_MEAN
            inter_arrival_std  = self.NORMAL_IAT_STD
        else:
            inter_arrival_mean = max(0.5, m.get('iat_mean_ms', 2.5) * 60.0)
            inter_arrival_std  = max(0.5, m.get('iat_std_ms', 1.2) * 80.0)

        feature_vec = {
            'timestamp':     time.time(),
            'n_flows':       100,
            'source':        'synthetic_gnmi',
            'attack_intensity': round(attack_i, 4),   # debug field
            'feature_names': FlowFeatureExtractor.FEATURE_NAMES,
            'features': {
                'pkt_rate':           round(pkt_rate_feat,       3),
                'byte_rate':          round(byte_rate_feat,      3),
                'src_ip_entropy':     round(src_ip_entropy,      4),
                'dst_ip_entropy':     round(dst_ip_entropy,      4),
                'src_port_entropy':   round(src_port_entropy,    4),
                'dst_port_entropy':   round(dst_port_entropy,    4),
                'proto_dist_tcp':     round(eff_tcp,             4),
                'proto_dist_udp':     round(eff_udp,             4),
                'proto_dist_icmp':    round(eff_icmp,            4),
                'syn_ratio':          round(syn_ratio_feat,      5),
                'fin_ratio':          round(fin_ratio_feat,      5),
                'avg_pkt_size':       round(avg_pkt_size,        2),
                'pkt_size_std':       round(pkt_size_std,        2),
                'new_flows_rate':     round(new_flows_rate,      2),
                'flow_duration_mean': round(flow_duration_mean,  2),
                'inter_arrival_mean': round(inter_arrival_mean,  4),
                'inter_arrival_std':  round(inter_arrival_std,   4),
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
