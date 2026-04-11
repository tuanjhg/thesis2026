#!/usr/bin/env python3
"""
PAD-ONAP gNMI Simulator
========================
Mock gNMI/REST server that streams network metrics from virtual routers.
Replaces real gRPC gNMI for local testing without physical hardware.

Endpoints:
  GET  /metrics           — Current metrics for all devices (JSON)
  GET  /metrics/{device}  — Metrics for one device (r1/r2/r3)
  POST /attack/start      — Inject DDoS attack on r1 (UDP flood pattern)
  POST /attack/stop       — Stop attack injection
  POST /attack/ramp       — Gradual bandwidth ramp (BW exhaustion scenario)
  GET  /health            — Health check

Device metrics (updated every 500ms):
  in_pkts        — inbound packets/sec
  in_octets      — inbound bytes/sec
  out_pkts       — outbound packets/sec
  out_octets     — outbound bytes/sec
  cpu_pct        — CPU utilization %
  memory_pct     — Memory utilization %
  queue_depth_pct— TX queue depth %
  new_flows_rate — new flows/sec
  syn_ratio      — SYN / total TCP ratio
  udp_ratio      — UDP / total packets ratio
  avg_pkt_size   — average packet size (bytes)
"""

import json
import math
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


# ── Device configuration ─────────────────────────────────────────────────────
DEVICES = ['r1', 'r2', 'r3']
TICK_INTERVAL = 0.5   # seconds between metric updates
ATTACK_RAMP_STEPS = 10


# ── Metric state ──────────────────────────────────────────────────────────────
class DeviceMetrics:
    """Holds and evolves metrics for one network device."""

    NORMAL_BASELINE = {
        'in_pkts':          5_000,
        'in_octets':        800_000,
        'out_pkts':         4_800,
        'out_octets':       780_000,
        'cpu_pct':          25.0,
        'memory_pct':       45.0,
        'queue_depth_pct':  15.0,
        'new_flows_rate':   80.0,
        'syn_ratio':        0.08,
        'udp_ratio':        0.30,
        'icmp_ratio':       0.02,
        'avg_pkt_size':     512.0,
        'flow_duration_ms': 150.0,
        'iat_mean_ms':      2.5,
        'iat_std_ms':       1.2,
        'src_ip_entropy':   4.2,
        'dst_ip_entropy':   2.1,
        'src_port_entropy': 5.8,
        'dst_port_entropy': 2.4,
    }

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.values = {k: v for k, v in self.NORMAL_BASELINE.items()}
        self._rng = random.Random(hash(device_id))

    def random_walk(self, key: str, delta_pct: float = 0.05,
                    lo: float = None, hi: float = None):
        """Apply random walk bounded by [lo, hi]."""
        base = self.NORMAL_BASELINE[key]
        current = self.values[key]
        delta = current * self._rng.uniform(-delta_pct, delta_pct)
        new_val = current + delta
        if lo is not None: new_val = max(lo, new_val)
        if hi is not None: new_val = min(hi, new_val)
        # Mean-revert toward baseline (elasticity)
        new_val += (base - new_val) * 0.03
        self.values[key] = new_val

    def tick_normal(self):
        """Update all metrics with normal traffic pattern."""
        self.random_walk('in_pkts',          0.08, lo=500,    hi=50_000)
        self.random_walk('in_octets',        0.08, lo=10_000, hi=5_000_000)
        self.random_walk('out_pkts',         0.08, lo=400,    hi=48_000)
        self.random_walk('out_octets',       0.08, lo=8_000,  hi=4_800_000)
        self.random_walk('cpu_pct',          0.05, lo=5.0,    hi=60.0)
        self.random_walk('memory_pct',       0.03, lo=20.0,   hi=80.0)
        self.random_walk('queue_depth_pct',  0.10, lo=0.0,    hi=50.0)
        self.random_walk('new_flows_rate',   0.10, lo=10.0,   hi=500.0)
        self.random_walk('syn_ratio',        0.05, lo=0.01,   hi=0.20)
        self.random_walk('udp_ratio',        0.05, lo=0.10,   hi=0.60)
        self.random_walk('icmp_ratio',       0.10, lo=0.00,   hi=0.05)
        self.random_walk('avg_pkt_size',     0.04, lo=64.0,   hi=1500.0)
        self.random_walk('flow_duration_ms', 0.05, lo=10.0,   hi=500.0)
        self.random_walk('iat_mean_ms',      0.08, lo=0.1,    hi=20.0)
        self.random_walk('iat_std_ms',       0.10, lo=0.0,    hi=10.0)
        self.random_walk('src_ip_entropy',   0.03, lo=1.0,    hi=6.0)
        self.random_walk('dst_ip_entropy',   0.03, lo=0.5,    hi=4.0)
        self.random_walk('src_port_entropy', 0.03, lo=2.0,    hi=7.0)
        self.random_walk('dst_port_entropy', 0.03, lo=1.0,    hi=5.0)

    def tick_udp_flood(self, intensity: float = 1.0):
        """
        Simulate UDP flood DDoS:
        - in_pkts and in_octets spike massively
        - udp_ratio → ~1.0
        - src_ip_entropy → high (spoofed IPs)
        - avg_pkt_size → small (64 bytes typical for flood)
        - syn_ratio → near 0 (UDP, not TCP)
        - cpu and queue → saturate
        """
        scale = intensity
        self.values['in_pkts']          = min(1_000_000, self.values['in_pkts']   * (1 + 0.8 * scale))
        self.values['in_octets']        = min(12_500_000,self.values['in_octets'] * (1 + 0.7 * scale))
        self.values['udp_ratio']        = min(0.98, self.values['udp_ratio']       + 0.15 * scale)
        self.values['icmp_ratio']       = max(0.00, self.values['icmp_ratio']      - 0.01)
        self.values['syn_ratio']        = max(0.00, self.values['syn_ratio']       - 0.02)
        self.values['avg_pkt_size']     = max(64.0, self.values['avg_pkt_size']   - 20 * scale)
        self.values['src_ip_entropy']   = min(7.0, self.values['src_ip_entropy']  + 0.3 * scale)
        self.values['dst_ip_entropy']   = max(0.1, self.values['dst_ip_entropy']  - 0.1)
        self.values['new_flows_rate']   = min(50_000, self.values['new_flows_rate'] * (1 + 0.5*scale))
        self.values['cpu_pct']          = min(99.0, self.values['cpu_pct']         + 3 * scale)
        self.values['queue_depth_pct']  = min(100.0,self.values['queue_depth_pct'] + 5 * scale)
        self.values['flow_duration_ms'] = max(1.0, self.values['flow_duration_ms'] * 0.9)
        self.values['iat_mean_ms']      = max(0.01, self.values['iat_mean_ms']     * 0.8)
        self.values['iat_std_ms']       = max(0.01, self.values['iat_std_ms']      * 0.7)

    def tick_syn_flood(self, intensity: float = 1.0):
        """Simulate SYN flood DDoS."""
        scale = intensity
        self.values['in_pkts']          = min(500_000, self.values['in_pkts']   * (1 + 0.5*scale))
        self.values['syn_ratio']        = min(0.99, self.values['syn_ratio']    + 0.20*scale)
        self.values['new_flows_rate']   = min(100_000,self.values['new_flows_rate']*(1+0.8*scale))
        self.values['avg_pkt_size']     = max(40.0, self.values['avg_pkt_size'] - 10*scale)
        self.values['src_ip_entropy']   = min(7.0,  self.values['src_ip_entropy']+ 0.4*scale)
        self.values['flow_duration_ms'] = max(0.5,  self.values['flow_duration_ms']* 0.5)
        self.values['cpu_pct']          = min(95.0, self.values['cpu_pct']      + 5*scale)
        self.values['queue_depth_pct']  = min(100.0,self.values['queue_depth_pct']+8*scale)

    def tick_bw_ramp(self, ramp_pct: float):
        """Gradual bandwidth ramp — simulates slow BW exhaustion."""
        factor = 1 + ramp_pct
        self.values['in_pkts']         = min(500_000, self.NORMAL_BASELINE['in_pkts']  * factor)
        self.values['in_octets']       = min(10_000_000,self.NORMAL_BASELINE['in_octets']* factor)
        self.values['cpu_pct']         = min(90.0, 25 + 60 * (ramp_pct / 1.0))
        self.values['queue_depth_pct'] = min(100.0, 15 + 80 * (ramp_pct / 1.0))

    def recover_toward_normal(self):
        """Gradually return to normal after attack stops."""
        for key, base in self.NORMAL_BASELINE.items():
            current = self.values[key]
            self.values[key] = current + (base - current) * 0.15

    def snapshot(self) -> dict:
        return {
            'device': self.device_id,
            'timestamp': time.time(),
            'metrics': {k: round(v, 4) for k, v in self.values.items()},
        }


# ── Global simulation state ───────────────────────────────────────────────────
class SimulationState:
    def __init__(self):
        self.devices = {d: DeviceMetrics(d) for d in DEVICES}
        self.lock = threading.Lock()

        self.attack_mode   = None     # None | 'udp_flood' | 'syn_flood' | 'bw_ramp'
        self.attack_target = 'r1'     # device being attacked
        self.ramp_step     = 0
        self.recovery      = False

    def tick(self):
        with self.lock:
            for dev_id, dev in self.devices.items():
                is_target = (dev_id == self.attack_target)

                if self.attack_mode == 'udp_flood' and is_target:
                    dev.tick_udp_flood(intensity=1.0)
                elif self.attack_mode == 'syn_flood' and is_target:
                    dev.tick_syn_flood(intensity=1.0)
                elif self.attack_mode == 'bw_ramp' and is_target:
                    ramp_pct = (self.ramp_step / ATTACK_RAMP_STEPS)
                    dev.tick_bw_ramp(ramp_pct)
                    if self.ramp_step < ATTACK_RAMP_STEPS:
                        self.ramp_step += 1
                elif self.recovery:
                    dev.recover_toward_normal()
                else:
                    dev.tick_normal()

    def start_attack(self, attack_type: str = 'udp_flood', target: str = 'r1'):
        with self.lock:
            self.attack_mode   = attack_type
            self.attack_target = target
            self.ramp_step     = 0
            self.recovery      = False
        print(f'[gNMI-SIM] Attack started: type={attack_type} target={target}')

    def stop_attack(self):
        with self.lock:
            self.attack_mode = None
            self.recovery    = True
        print('[gNMI-SIM] Attack stopped — recovery mode')
        # After 5 seconds of recovery, disable it
        def _end_recovery():
            time.sleep(5)
            with self.lock:
                self.recovery = False
        threading.Thread(target=_end_recovery, daemon=True).start()

    def get_all(self) -> dict:
        with self.lock:
            return {d: dev.snapshot() for d, dev in self.devices.items()}

    def get_device(self, device_id: str) -> dict:
        with self.lock:
            if device_id not in self.devices:
                return None
            return self.devices[device_id].snapshot()

    def status(self) -> dict:
        with self.lock:
            return {
                'attack_mode':   self.attack_mode,
                'attack_target': self.attack_target,
                'recovery':      self.recovery,
                'ramp_step':     self.ramp_step,
                'devices':       DEVICES,
            }


# ── HTTP handler ──────────────────────────────────────────────────────────────
_state = SimulationState()


class GNMIHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, text: str):
        body = text.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_body(self) -> dict:
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip('/')

        if path == '/health':
            self._send_json(200, {'status': 'ok', 'uptime': time.time()})

        elif path == '/metrics':
            self._send_json(200, _state.get_all())

        elif path.startswith('/metrics/'):
            dev_id = path.split('/')[-1]
            data   = _state.get_device(dev_id)
            if data is None:
                self._send_json(404, {'error': f'Unknown device: {dev_id}',
                                      'available': DEVICES})
            else:
                self._send_json(200, data)

        elif path == '/status':
            self._send_json(200, _state.status())

        else:
            self._send_json(404, {'error': 'Not found', 'path': path})

    def do_POST(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip('/')
        body   = self._parse_body()

        if path == '/attack/start':
            attack_type = body.get('type', 'udp_flood')
            target      = body.get('target', 'r1')
            if attack_type not in ('udp_flood', 'syn_flood', 'bw_ramp'):
                self._send_json(400, {'error': f'Unknown attack type: {attack_type}',
                                      'valid': ['udp_flood', 'syn_flood', 'bw_ramp']})
                return
            if target not in DEVICES:
                self._send_json(400, {'error': f'Unknown device: {target}',
                                      'valid': DEVICES})
                return
            _state.start_attack(attack_type, target)
            self._send_json(200, {'status': 'started', 'type': attack_type, 'target': target})

        elif path == '/attack/stop':
            _state.stop_attack()
            self._send_json(200, {'status': 'stopped'})

        else:
            self._send_json(404, {'error': 'Not found', 'path': path})

    # Silence default request logs (we print our own)
    def log_message(self, fmt, *args):
        pass


# ── Background tick thread ────────────────────────────────────────────────────
def _background_tick():
    while True:
        _state.tick()
        time.sleep(TICK_INTERVAL)


# ── Entry point ───────────────────────────────────────────────────────────────
def main(host: str = '0.0.0.0', port: int = 8080):
    threading.Thread(target=_background_tick, daemon=True).start()

    server = HTTPServer((host, port), GNMIHandler)
    print(f'[gNMI-SIM] PAD-ONAP gNMI Simulator running on {host}:{port}')
    print(f'[gNMI-SIM] Tick interval: {TICK_INTERVAL}s | Devices: {DEVICES}')
    print(f'[gNMI-SIM] Endpoints:')
    print(f'  GET  http://localhost:{port}/health')
    print(f'  GET  http://localhost:{port}/metrics')
    print(f'  GET  http://localhost:{port}/metrics/r1')
    print(f'  POST http://localhost:{port}/attack/start  body: {{"type":"udp_flood","target":"r1"}}')
    print(f'  POST http://localhost:{port}/attack/stop')
    print(f'  GET  http://localhost:{port}/status')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[gNMI-SIM] Shutting down.')


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    main(port=port)
