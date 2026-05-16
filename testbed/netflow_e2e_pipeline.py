#!/usr/bin/env python3
"""
PAD-ONAP: Real NetFlow E2E Evaluation Pipeline (Kafka + Flink)
==============================================================
Chạy 1 nhánh điều phối (AI hoặc Baseline-Threshold) trong 1 lần invoke.
So sánh AI vs Baseline = chạy script 2 lần với --mode khác nhau.

Luồng dữ liệu:
  Mininet hosts (softflowd) ──UDP NetFlow──▶ netflow_collector
       collector tính 5s feature window ──▶ Kafka topic pad.telemetry.raw
                                                 │ (kafka_producer-style messages)
                                                 ▼
                            pipeline.s2_features.flink_processor
                              (sliding-window 5s/1s)
                                                 │
                                                 ▼
                                  Kafka topic pad.telemetry.features
                                                 │
                                                 ▼
                       Orchestrator(AI)  /  BaselineOrchestrator   ← chỉ 1 nhánh
                                                 │
                                                 ▼
                              ONAP SO Client (PAD_ONAP_STUB=true) ← STUB

Yêu cầu môi trường (WSL2/Linux):
  - Docker + docker compose
  - Apache Kafka chạy qua testbed/docker-compose.yml (kafka service)
  - softflowd, iperf, hping3, curl
  - Python venv với requirements-pipeline.txt + kafka-python
  - sudo (Mininet)
"""
import os, re, sys, time, json, signal, threading, logging, argparse, subprocess
from pathlib import Path
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from pipeline.s3_ai.live_pipeline import KafkaFeatureConsumer, features_dict_to_array

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('E2E_Eval')


# ── Infra helpers ─────────────────────────────────────────────────────────────

def _run(cmd: str, check=False, timeout=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          check=check, timeout=timeout)


def ensure_kafka(broker: str, compose_dir: Path, wait_s: int = 60, skip_setup: bool = False) -> None:
    """Bring up the kafka service via docker compose if not already running.
    Block until broker accepts connections (probed via kafka-python)."""
    host, port = broker.split(':')
    logger.info(f"*** Đảm bảo Kafka chạy tại {broker} (compose dir: {compose_dir})")

    if not skip_setup:
        # Check if kafka container running
        try:
            chk = _run("docker ps --format '{{.Names}}' | grep -w pad-kafka")
            if chk.returncode != 0:
                logger.info("    pad-kafka chưa chạy — docker compose up -d kafka...")
                up = _run(f"cd '{compose_dir}' && docker compose up -d kafka")
                if up.returncode != 0:
                    logger.warning(f"    ⚠ docker compose up failed:\n{up.stderr}")
                    logger.warning("      Có thể docker không có trong PATH của sudo. Sẽ thử kết nối trực tiếp...")
            else:
                logger.info("    ✓ Container pad-kafka đang chạy.")
        except Exception as e:
            logger.warning(f"    ⚠ Không thể kiểm tra Docker: {e}")
            logger.warning("      Sẽ bỏ qua bước check container và thử kết nối Kafka trực tiếp...")
    else:
        logger.info("    [--skip-kafka-setup] Bỏ qua bước kiểm tra container Docker.")

    # Wait for broker reachable
    from kafka import KafkaProducer
    deadline = time.time() + wait_s
    while time.time() < deadline:
        try:
            p = KafkaProducer(bootstrap_servers=[broker], request_timeout_ms=3000,
                              max_block_ms=3000)
            p.partitions_for('pad.telemetry.raw')
            p.close(timeout=2)
            logger.info(f"    ✓ Kafka broker {broker} sẵn sàng")
            return
        except Exception:
            time.sleep(2)
    logger.error(f"❌ Kafka broker {broker} không phản hồi sau {wait_s}s")
    sys.exit(1)


def spawn_flink_processor(broker: str, log_path: Path) -> subprocess.Popen:
    """Start pipeline/s2_features/flink_processor.py as a subprocess."""
    script = _ROOT / 'pipeline' / 's2_features' / 'flink_processor.py'
    cmd = [
        sys.executable, '-u', str(script),
        '--broker', broker,
        '--flow-window', '5.0',
        '--flow-slide',  '1.0',
    ]
    logger.info(f"*** Khởi động Flink processor: {' '.join(cmd)}")
    log_f = open(log_path, 'a')
    proc = subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid)
    return proc


def stop_subprocess(proc: subprocess.Popen, name: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
        logger.info(f"    ✓ {name} stopped (pid {proc.pid})")
    except Exception as e:
        logger.warning(f"    ⚠ {name} cleanup: {e}")
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


# ── Orchestrator factory ──────────────────────────────────────────────────────

def make_orchestrator(mode: str, args):
    """Return the chosen orchestrator instance. AI uses real s3_ai inference.

    Returns None when args.remote_pipeline is set — the remote pad-onap-pipeline
    Pod owns inference + tier decision; this driver only generates traffic and
    polls remote metrics post-run.
    """
    if getattr(args, 'remote_pipeline', False):
        logger.info("*** remote-pipeline mode: skip local Orchestrator/Baseline construction")
        return None
    if mode == 'ai':
        from pipeline.s4_orchestration.orchestrator import Orchestrator
        return Orchestrator(
            model_dir    = args.model_dir,
            data_dir     = args.data_dir,
            eval_mode    = True,
            shap_enabled = args.shap,
            latency_port = 9298,
        )
    elif mode == 'baseline':
        from evaluation.baseline_threshold import BaselineOrchestrator
        return BaselineOrchestrator(
            eval_mode    = True,
            latency_port = 9299,
        )
    else:
        raise ValueError(f"Unknown mode: {mode}")


# ── Remote tier poller ────────────────────────────────────────────────────────
# When --remote-pipeline is set, this driver does NOT run the orchestrator
# locally. Instead, it polls the remote pad-onap-pipeline Pod's Prometheus
# endpoint (exposed via NodePort 30292 in onap/k8s/pad-onap-metrics-nodeport.yaml)
# to recover the tier time series after the run completes. Schema:
#   pad_current_tier{device="pad-onap-prod"}       gauge
#   pad_proactive_action_total{tier="2|3|4"}       counter
# If those metrics are missing on the remote Pod, the poller falls back to
# scraping `pad_tier_decisions_total{tier="..."}` deltas to reconstruct the
# tier history (1-Hz resolution).

class RemoteTierPoller:
    """Sample the remote pipeline Pod's Prometheus endpoint at 1 Hz."""

    def __init__(self, metrics_url: str, interval: float = 1.0):
        self.metrics_url = metrics_url.rstrip('/')
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread = None
        self.samples: list = []  # list of (epoch, tier_int)
        self._lock = threading.Lock()
        # Cache previous counter values for delta-based fallback
        self._prev_counters: dict = {}

    def _parse_metric(self, body: str, name: str) -> dict:
        """Parse Prometheus exposition format for a single metric.
        Returns {label_dict_str: float_value}."""
        out = {}
        for line in body.splitlines():
            if not line or line.startswith('#'):
                continue
            if not line.startswith(name):
                continue
            # name{labels} value   OR   name value
            try:
                head, _, val = line.rpartition(' ')
                v = float(val)
                if '{' in head:
                    lbl = head.split('{', 1)[1].rstrip('}')
                else:
                    lbl = ''
                out[lbl] = v
            except Exception:
                continue
        return out

    def _sample_once(self) -> None:
        import urllib.request
        try:
            with urllib.request.urlopen(self.metrics_url, timeout=2) as r:
                body = r.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"[RemoteTierPoller] fetch error: {e}")
            return

        # Try gauge first
        gauge = self._parse_metric(body, 'pad_current_tier')
        if gauge:
            tier_val = int(round(next(iter(gauge.values()))))
            with self._lock:
                self.samples.append((time.time(), tier_val))
            return

        # Fallback: derive from counter deltas — assume highest tier with
        # an incremented counter this tick is the "current" tier.
        counters = self._parse_metric(body, 'pad_tier_decisions_total')
        if not counters:
            return
        tier_active = 0
        for lbl, v in counters.items():
            prev = self._prev_counters.get(lbl, v)
            if v > prev:
                # Extract tier from label string like 'tier="3"'
                if 'tier="' in lbl:
                    try:
                        t = int(lbl.split('tier="', 1)[1].split('"', 1)[0])
                        tier_active = max(tier_active, t)
                    except Exception:
                        pass
            self._prev_counters[lbl] = v
        with self._lock:
            self.samples.append((time.time(), tier_active))

    def _run(self) -> None:
        while not self._stop.is_set():
            self._sample_once()
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name='RemoteTierPoller')
        self._thread.start()
        logger.info(f"*** RemoteTierPoller started: {self.metrics_url} @ {self.interval}s")

    def stop(self) -> list:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        with self._lock:
            return list(self.samples)


# ── Evaluator ─────────────────────────────────────────────────────────────────

class E2EEvaluator:
    def __init__(self, args):
        self.args = args
        self.mode = args.mode  # 'ai' or 'baseline'
        self.results_tier   = []
        self.results_proact = []
        self.timestamps     = []
        self.window_sec     = 5.0
        self.collector_host = None
        self._last_vec_ts   = None
        self.phase_t = {'baseline': 0.0, 'attack': 0.0, 'recovery': 0.0, 'end': 0.0}
        self.log_legit  = '/tmp/iperf_legit.log'
        self.log_victim = '/tmp/iperf_victim.log'
        self.log_bg     = '/tmp/iperf_bg_cli.log'

        # Kafka feature consumer (replaces direct HTTP polling of collector)
        self.kafka_consumer: KafkaFeatureConsumer = None
        self.flink_proc: subprocess.Popen = None

        # Remote-pipeline mode: pipeline + ONAP run on a remote K8s server.
        # Local driver only generates traffic and polls remote metrics.
        self.remote_pipeline: bool = bool(getattr(args, 'remote_pipeline', False))
        self.remote_tier_poller: RemoteTierPoller = None

        # The chosen orchestrator (AI or threshold baseline) — only one this run.
        # Returns None when remote_pipeline is set.
        self.orch = make_orchestrator(self.mode, args)

    # ── Step: pull next feature vector from Kafka and feed orchestrator ────────
    def _step_from_kafka(self) -> None:
        # In remote mode the remote Pod owns inference; this local loop
        # is a no-op (the RemoteTierPoller collects tiers in background).
        if self.remote_pipeline:
            return
        if self.kafka_consumer is None:
            return
        raw = self.kafka_consumer.poll_latest()
        if raw is None:
            return
        ts = raw.get('timestamp')
        if ts is None or ts == self._last_vec_ts:
            return
        self._last_vec_ts = ts

        feats = raw.get('features', {})
        if not feats:
            return
        x = features_dict_to_array(feats)

        rec = self.orch._step(x)
        tier = rec['tier'] if isinstance(rec, dict) else int(getattr(rec, 'tier', 0))
        proact = bool(rec.get('proactive', False)) if isinstance(rec, dict) else False
        self.results_tier.append(tier)
        self.results_proact.append(proact)
        self.timestamps.append(time.time())

        marker = ' [PROACTIVE]' if proact else ''
        print(f"Window {len(self.results_tier):03d} | {self.mode.upper():<8s} | T{tier}{marker}")

    # ── Mininet test driver ────────────────────────────────────────────────────
    def run_mininet_test(self):
        from mininet.net import Mininet
        from testbed.mininet.fat_tree_topology import build_fat_tree, attacker_victim

        broker      = self.args.broker
        compose_dir = _ROOT / 'testbed'

        if self.remote_pipeline:
            # ── Remote mode ──────────────────────────────────────────────────
            # 0. Probe Kafka broker (must be NodePort 30992 on remote K8s node)
            logger.info(f"*** [remote-pipeline] Probe Kafka broker {broker}")
            from kafka import KafkaProducer
            try:
                p = KafkaProducer(bootstrap_servers=[broker],
                                  request_timeout_ms=5000, max_block_ms=5000)
                p.partitions_for('pad.telemetry.raw')
                p.close(timeout=2)
                logger.info(f"    ✓ Remote Kafka {broker} reachable")
            except Exception as e:
                logger.error(f"❌ Remote Kafka {broker} không reach được: {e}")
                logger.error("   Kiểm tra: kubectl -n pad-onap get svc kafka-external")
                logger.error("              kubectl -n pad-onap get pod -l app=kafka")
                logger.error("              firewall trên server cho phép port 30992")
                sys.exit(1)

            # 1. Start the remote tier poller (1 Hz)
            self.remote_tier_poller = RemoteTierPoller(
                metrics_url=self.args.remote_metrics_url,
                interval=1.0,
            )
            self.remote_tier_poller.start()
            # Skip local flink_processor + Kafka feature consumer entirely
            self.flink_proc = None
            self.kafka_consumer = None
        else:
            # ── Local mode (original behaviour) ──────────────────────────────
            # 0. Ensure Kafka is up
            ensure_kafka(broker, compose_dir, skip_setup=self.args.skip_kafka_setup)

            # 1. Start flink_processor (consumes pad.telemetry.raw → publishes pad.telemetry.features)
            flink_log = _ROOT / 'evaluation' / 'results' / f'flink_{self.mode}.log'
            flink_log.parent.mkdir(parents=True, exist_ok=True)
            self.flink_proc = spawn_flink_processor(broker, flink_log)
            time.sleep(3)  # let flink connect

            if self.flink_proc.poll() is not None:
                logger.error(f"❌ Flink processor exited immediately. Xem: {flink_log}")
                sys.exit(1)

            # 2. Subscribe to feature topic BEFORE producers start so we don't
            #    miss baseline-phase windows (auto_offset_reset='latest').
            logger.info(f"*** Kết nối Kafka consumer ({broker} → pad.telemetry.features)")
            self.kafka_consumer = KafkaFeatureConsumer(
                broker=broker,
                group_id=f'pad-e2e-{self.mode}-{int(time.time())}',
            )

        # 3. Start Mininet
        logger.info(f"*** Khởi tạo Mininet Fat-Tree k={self.args.k}")
        os.system("sudo mn -c > /dev/null 2>&1")
        os.system("pkill -9 -f iperf > /dev/null 2>&1")
        os.system("pkill -9 -f iperf3 > /dev/null 2>&1")
        os.system("pkill -9 -f softflowd > /dev/null 2>&1")
        os.system("pkill -9 -f hping3 > /dev/null 2>&1")
        os.system("pkill -9 -f netflow_collector/collector.py > /dev/null 2>&1")

        net = build_fat_tree(k=self.args.k)
        net.start()
        time.sleep(3)

        # Pre-check tools
        h1 = net.get('h1')
        missing = []
        for tool in ['softflowd', 'iperf', 'hping3', 'curl']:
            if not h1.cmd(f'which {tool}').strip() or 'not found' in h1.cmd(f'which {tool}'):
                missing.append(tool)
        if missing:
            logger.error(f"❌ Thiếu công cụ: {', '.join(missing)}")
            logger.error("   Cài: sudo apt-get install -y softflowd iperf hping3 curl")
            net.stop()
            sys.exit(1)
        logger.info("✓ Tools check OK")

        # 4. Start NetFlow collector on h0 with --kafka-broker
        collector = net.get('h0')
        collector_ip = collector.IP()
        self.collector_host = collector

        collector_script = _ROOT / 'testbed' / 'netflow_collector' / 'collector.py'
        collector.cmd("fuser -k 7070/tcp 6343/udp 2>/dev/null")
        time.sleep(1)

        # NOTE: Mininet hosts share the root netns FS, so they can resolve
        # localhost:9092 via host network — but Mininet's host namespace has
        # its OWN isolated network. We need the collector to reach the Kafka
        # broker. Easiest: collector publishes via the docker bridge IP.
        # On WSL2 with default docker network, host.docker.internal or the
        # docker0 IP works; we accept --kafka-broker passthrough.
        kafka_for_collector = self.args.collector_kafka or broker

        cmd = (
            f'python3 -u "{collector_script}" '
            f'--mode netflow --port 6343 --api-port 7070 '
            f'--interval {self.window_sec} '
            f'--kafka-broker {kafka_for_collector} '
            f'> /tmp/collector.log 2>&1 &'
        )
        logger.info(f"*** Khởi động NetFlow Collector trên {collector.name} ({collector_ip})")
        logger.info(f"    Kafka broker for collector: {kafka_for_collector}")
        collector.cmd(cmd)
        time.sleep(5)

        # Health check
        health = collector.cmd("curl -s --max-time 2 http://127.0.0.1:7070/health")
        if "ok" in health:
            logger.info(f"    ✓ Collector health: {health.strip()}")
        else:
            logger.warning(f"    ⚠ Collector health check failed: {health.strip()[:200]}")
            logger.warning(f"      Xem log: cat /tmp/collector.log")

        # 5. Start softflowd on every Mininet host
        attacker, victim = attacker_victim(net)
        logger.info(f"*** Attacker: {attacker.name} → Victim: {victim.name}")

        for host in net.hosts:
            if host.name == collector.name:
                continue
            host.cmd(
                f'softflowd -i {host.intf().name} -n {collector_ip}:6343 '
                f'-v 5 -t maxlife=10 -t expint=5 &'
            )

        # 6. Background traffic + legit user + victim server
        bg_src = net.get('h1') if len(net.hosts) > 1 else attacker
        bg_dst = net.get('h14') if 'h14' in net.nameToNode else victim
        bg_dst.cmd('iperf -s -u -i 1 > /tmp/iperf_bg.log 2>&1 &')
        time.sleep(0.5)
        bg_src.cmd(f'iperf -c {bg_dst.IP()} -u -b 10M -t 9999 -i 1 > {self.log_bg} 2>&1 &')

        legit_src = net.get('h2') if 'h2' in net.nameToNode else bg_src
        victim.cmd("fuser -k 5001/udp 2>/dev/null"); time.sleep(0.5)
        victim.cmd(f'iperf -s -u -i 1 > {self.log_victim} 2>&1 &')
        legit_src.cmd(
            f'iperf -c {victim.IP()} -u -b 5M -t 9999 -i 1 > {self.log_legit} 2>&1 &'
        )
        self._iperf_t0 = time.time()

        # 7. Phase 1
        logger.info(">>> Phase 1: Baseline (Normal traffic) - 30 giây")
        self.phase_t['baseline'] = time.time()
        while time.time() - self.phase_t['baseline'] < 30:
            self._step_from_kafka()
            time.sleep(1.0)

        # 8. Phase 2 — Attack dispatched by --attack-class
        ac = self.args.attack_class
        ATTACK_CMDS = {
            # UDP flood (default, legacy behaviour) — high pps generic UDP
            'udpflood': f'hping3 --udp --flood -p 80 {victim.IP()} &',
            # S2-Syn — TCP SYN flood at 500k pps (Pipeline.md §7.2)
            'syn':      f'hping3 -S --flood -p 80 {victim.IP()} &',
            # S2-UDP-lag — UDP small-payload 64B at ~200k pps (Pipeline.md §7.2)
            'udplag':   f'hping3 --udp -i u5 -d 64 -p 80 {victim.IP()} &',
        }
        attack_cmd = ATTACK_CMDS[ac]
        logger.info(f">>> Phase 2: {ac.upper()} Attack - {self.args.duration}s — {attack_cmd}")
        attacker.cmd(attack_cmd)
        self.phase_t['attack'] = time.time()
        while time.time() - self.phase_t['attack'] < self.args.duration:
            self._step_from_kafka()
            time.sleep(1.0)

        # 9. Phase 3
        logger.info(">>> Phase 3: Recovery - 20 giây")
        attacker.cmd('pkill hping3')
        self.phase_t['recovery'] = time.time()
        while time.time() - self.phase_t['recovery'] < 20:
            self._step_from_kafka()
            time.sleep(1.0)
        self.phase_t['end'] = time.time()

        # 10. Cleanup
        logger.info("*** Cleanup")
        try:
            for h in [bg_src, bg_dst, legit_src, victim]:
                h.cmd('pkill -f iperf')
            for h in net.hosts:
                h.cmd('pkill -f softflowd')
            collector.cmd('pkill -f netflow_collector/collector.py')
        except Exception as e:
            logger.warning(f"Cleanup warning: {e}")
        time.sleep(1.0)
        net.stop()

        # 11. Stop Kafka consumer + Flink subprocess (local mode only)
        if self.kafka_consumer:
            self.kafka_consumer.close()
        if self.flink_proc:
            stop_subprocess(self.flink_proc, 'flink_processor')

        # 12. Remote mode: drain RemoteTierPoller into results_tier/timestamps
        if self.remote_pipeline and self.remote_tier_poller:
            samples = self.remote_tier_poller.stop()
            logger.info(f"*** RemoteTierPoller: {len(samples)} samples collected")
            self.timestamps = [s[0] for s in samples]
            self.results_tier = [s[1] for s in samples]
            self.results_proact = [t >= 2 for t in self.results_tier]
            if not samples:
                logger.warning(
                    "⚠ Không lấy được sample tier nào từ remote metrics. "
                    "Kiểm tra:\n"
                    f"   curl {self.args.remote_metrics_url}\n"
                    "   phải trả về một block bắt đầu bằng 'pad_'."
                )

        self.generate_report()

    # ── iperf log parsing (unchanged) ──────────────────────────────────────────
    _IPERF_LINE = re.compile(
        r'\[\s*\d+\]\s+([\d.]+)-\s*([\d.]+)\s*sec\s+'
        r'[\d.]+\s+\w+\s+([\d.]+)\s+([KMG])bits/sec'
        r'(?:\s+[\d.]+\s+ms\s+\d+/\s*\d+\s+\(([\d.]+)%\))?'
    )

    def _parse_iperf_log(self, path: str) -> list:
        out = []
        if not os.path.exists(path):
            return out
        try:
            with open(path) as f:
                for line in f:
                    m = self._IPERF_LINE.search(line)
                    if not m:
                        continue
                    t_start, t_end, rate_val, rate_unit, lost = m.groups()
                    t_s, t_e = float(t_start), float(t_end)
                    if (t_e - t_s) > 1.5:
                        continue
                    rate = float(rate_val)
                    if rate_unit == 'K':   rate /= 1000.0
                    elif rate_unit == 'G': rate *= 1000.0
                    out.append({
                        't_offset': t_e,
                        'mbps':     rate,
                        'lost_pct': float(lost) if lost else None,
                        'epoch':    self._iperf_t0 + t_e,
                    })
        except Exception as e:
            logger.warning(f"iperf parse failed for {path}: {e}")
        return out

    def _phase_of(self, epoch: float) -> str:
        if epoch < self.phase_t['attack']:   return 'baseline'
        if epoch < self.phase_t['recovery']: return 'attack'
        return 'recovery'

    def _mean_by_phase(self, series: list) -> dict:
        buckets = {'baseline': [], 'attack': [], 'recovery': []}
        for p in series:
            buckets[self._phase_of(p['epoch'])].append(p['mbps'])
        return {k: (sum(v)/len(v) if v else 0.0) for k, v in buckets.items()}

    def _compute_metrics(self, legit_series: list, victim_series: list) -> dict:
        tiers = self.results_tier
        wt    = self.timestamps
        n     = len(tiers)

        def _first(seq, pred):
            for i, v in enumerate(seq):
                if pred(v): return i
            return None

        # AI uses tier>=2 (proactive) as positive; baseline uses tier>=3 (mitigate)
        pos_th = 2 if self.mode == 'ai' else 3
        first_pos = _first(tiers, lambda t: t >= pos_th)
        first_t3  = _first(tiers, lambda t: t >= 3)

        e_pos = wt[first_pos] if (first_pos is not None and first_pos < len(wt)) else None
        e_t3  = wt[first_t3]  if (first_t3  is not None and first_t3  < len(wt)) else None

        labels = [1 if self.phase_t['attack'] <= t < self.phase_t['recovery'] else 0
                  for t in wt]
        preds = [1 if t >= pos_th else 0 for t in tiers]

        tp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 1)
        fp = sum(1 for p, y in zip(preds, labels) if p == 1 and y == 0)
        fn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 1)
        tn = sum(1 for p, y in zip(preds, labels) if p == 0 and y == 0)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        f1  = (2 * prec * tpr / (prec + tpr)) if (prec + tpr) else 0.0

        # detect time vs attack-start
        detect_lag = (e_pos - self.phase_t['attack']) if e_pos else None

        return {
            'mode':                 self.mode,
            'n_windows':            n,
            'first_window_pos':     first_pos,
            'first_window_tier3':   first_t3,
            'detect_lag_s':         round(detect_lag, 2) if detect_lag is not None else None,
            'classification': {
                'positive_threshold_tier': pos_th,
                'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                'tpr': round(tpr, 4), 'fpr': round(fpr, 4),
                'precision': round(prec, 4), 'f1': round(f1, 4),
            },
            'goodput_legit_mbps_by_phase':  self._mean_by_phase(legit_series),
            'goodput_victim_mbps_by_phase': self._mean_by_phase(victim_series),
        }

    def generate_report(self):
        out_dir = _ROOT / 'evaluation' / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        legit_series  = self._parse_iperf_log(self.log_legit)
        victim_series = self._parse_iperf_log(self.log_victim)
        bg_series     = self._parse_iperf_log(self.log_bg)
        logger.info(f"[iperf] legit={len(legit_series)}  victim={len(victim_series)}  bg={len(bg_series)}")

        metrics = self._compute_metrics(legit_series, victim_series)
        if metrics['n_windows'] == 0:
            logger.error("❌ Không thu được cửa sổ nào (n_windows=0)!")
            logger.error("   Kiểm tra: cat /tmp/collector.log; cat evaluation/results/flink_*.log")
            return

        if self.timestamps:
            t_attack = self.phase_t['attack'] or self.timestamps[0]
            x_axis = np.array([t - t_attack for t in self.timestamps])
        else:
            x_axis = np.arange(len(self.results_tier)) * self.window_sec - 30.0

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 9), sharex=True)
        color = '#1f77b4' if self.mode == 'ai' else '#d62728'
        label = 'AI-Augmented (Proactive)' if self.mode == 'ai' else 'Threshold-based (Reactive)'
        ax1.step(x_axis, self.results_tier, label=label, color=color,
                 linewidth=2, where='post')
        ax1.set_ylabel('Response Tier')
        ax1.set_yticks([0, 1, 2, 3, 4])
        ax1.set_yticklabels(['T0:Normal', 'T1:Alert', 'T2:Preempt', 'T3:Mitigate', 'T4:Block'])
        ax1.legend(loc='upper left'); ax1.grid(True, linestyle=':', alpha=0.6)
        ax1.axvline(x=0, color='gray', linestyle='-.', alpha=0.5)
        ax1.axvline(x=self.args.duration, color='gray', linestyle=':', alpha=0.5)
        ax1.set_title(f'DDoS Response — {self.mode.upper()} (Mininet + Kafka + Flink)')

        if legit_series:
            t_a = self.phase_t['attack'] or self._iperf_t0
            ax2.plot([p['epoch'] - t_a for p in legit_series],
                     [p['mbps'] for p in legit_series],
                     label='Legit user h2 → victim (5 Mbps offered)',
                     color='#2ca02c', linewidth=1.8)
        if victim_series:
            t_a = self.phase_t['attack'] or self._iperf_t0
            ax2.plot([p['epoch'] - t_a for p in victim_series],
                     [p['mbps'] for p in victim_series],
                     label='Victim received', color='#9467bd',
                     linewidth=1.5, linestyle='--')
        ax2.set_xlabel('Time relative to attack start (s)')
        ax2.set_ylabel('Throughput (Mbps)')
        ax2.axvline(x=0, color='gray', linestyle='-.', alpha=0.5)
        ax2.axvline(x=self.args.duration, color='gray', linestyle=':', alpha=0.5)
        ax2.legend(loc='lower left'); ax2.grid(True, linestyle=':', alpha=0.6)
        plt.tight_layout()

        # Include attack class in filename so 4 S2 sub-scenarios don't overwrite each other
        ac_suffix = f'_{self.args.attack_class}' if getattr(self.args, 'attack_class', 'udpflood') != 'udpflood' else ''
        img_path = out_dir / f'real_e2e_{self.mode}{ac_suffix}_{ts}.png'
        plt.savefig(img_path, dpi=300); plt.close(fig)
        logger.info(f"[✓] Biểu đồ: {img_path}")

        report = {
            'timestamp': ts,
            'mode':      self.mode,
            'config':    {'k': self.args.k, 'duration': self.args.duration,
                          'window_sec': self.window_sec, 'broker': self.args.broker},
            'phases':    {k: round(v, 3) for k, v in self.phase_t.items()},
            'series': {
                'tiers':              self.results_tier,
                'proactive':          self.results_proact,
                'window_timestamps':  [round(t, 3) for t in self.timestamps],
                'time_axis_rel_s':    x_axis.tolist(),
            },
            'iperf': {
                'legit_h2_to_victim': legit_series,
                'victim_received':    victim_series,
                'background_traffic': bg_series,
            },
            'metrics': metrics,
        }
        json_path = out_dir / f'real_e2e_{self.mode}{ac_suffix}_{ts}.json'
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"[✓] JSON: {json_path}")

        m = metrics
        print("\n" + "─" * 60)
        print(f"  Real Mininet + Kafka + Flink — mode={self.mode}, k={self.args.k}, attack={self.args.duration}s")
        print("─" * 60)
        print(f"  Windows collected           : {m['n_windows']}")
        lag = m['detect_lag_s']
        print(f"  Detect lag (vs attack start): {lag:.1f}s" if lag is not None else "  Detect lag                  : n/a")
        c = m['classification']
        print(f"  TPR/FPR/F1                  : {c['tpr']:.2f} / {c['fpr']:.2f} / {c['f1']:.2f}")
        gp = m['goodput_victim_mbps_by_phase']
        print(f"  Victim goodput (Mbps)       : baseline={gp['baseline']:.2f} | "
              f"attack={gp['attack']:.2f} | recovery={gp['recovery']:.2f}")
        print("─" * 60)


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PAD-ONAP: Real NetFlow E2E (Kafka+Flink)')
    parser.add_argument('--mode', required=True, choices=['ai', 'baseline'],
                        help='Chọn nhánh điều phối duy nhất cho lần chạy này')
    parser.add_argument('--k', type=int, default=4, help='Fat-tree k-factor')
    parser.add_argument('--duration', type=int, default=60, help='Attack duration (s)')
    parser.add_argument('--broker', default='localhost:9092',
                        help='Kafka bootstrap server (host-side)')
    parser.add_argument('--collector-kafka', default=None,
                        help='Kafka broker address as seen from Mininet host netns. '
                             'Default = same as --broker (works when broker bound to 0.0.0.0).')
    parser.add_argument('--model-dir', default=str(_ROOT/'pad_onap_v3'/'models'))
    parser.add_argument('--data-dir',  default=str(_ROOT/'pad_onap_v3'/'processed'))
    parser.add_argument('--shap', action='store_true',
                        help='Bật SHAP (chỉ áp dụng cho --mode ai)')
    parser.add_argument('--skip-kafka-setup', action='store_true',
                        help='Bỏ qua bước kiểm tra/khởi động Kafka qua Docker Compose')
    parser.add_argument('--remote-pipeline', action='store_true',
                        help='Pipeline (Flink + s3_ai + Orchestrator + ONAP) chạy trên '
                             'K8s server từ xa. Local chỉ chạy Mininet + softflowd + '
                             'collector, đẩy telemetry lên --broker (NodePort 30992 trên '
                             'remote). Tier decision đọc lại qua --remote-metrics-url.')
    parser.add_argument('--remote-metrics-url',
                        default='http://localhost:30292/metrics',
                        help='URL Prometheus endpoint của pad-onap-pipeline Pod '
                             '(default: http://localhost:30292/metrics — sửa thành '
                             'http://<NODE_IP>:30292/metrics).')
    parser.add_argument('--attack-class',
                        choices=['udpflood', 'syn', 'udplag'],
                        default='udpflood',
                        help='Loại tấn công ở Phase 2: '
                             'udpflood (mặc định, generic), '
                             'syn (Pipeline §7.2 S2 — TCP SYN flood ~500 kpps), '
                             'udplag (S2 — UDP-lag 64B payload ~200 kpps).')
    args = parser.parse_args()

    if os.name != 'nt' and os.geteuid() != 0:
        print("\n[!] Script này phải chạy bằng 'sudo' để khởi tạo Mininet.\n")
        sys.exit(1)

    # Default ONAP stub mode if user hasn't set it
    os.environ.setdefault('PAD_ONAP_STUB', 'true')

    evaluator = E2EEvaluator(args)
    try:
        evaluator.run_mininet_test()
    except KeyboardInterrupt:
        logger.info("Dừng bởi người dùng.")
        os.system('sudo mn -c')
        if evaluator.flink_proc:
            stop_subprocess(evaluator.flink_proc, 'flink_processor')
        if evaluator.kafka_consumer:
            evaluator.kafka_consumer.close()
        if getattr(evaluator, 'remote_tier_poller', None):
            evaluator.remote_tier_poller.stop()
