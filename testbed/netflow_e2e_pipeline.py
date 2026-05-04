#!/usr/bin/env python3
"""
PAD-ONAP: Real NetFlow E2E Evaluation Pipeline
==============================================
So sánh hiệu năng AI (Proactive) vs Threshold (Reactive) trên Mininet.
Dữ liệu được trích xuất từ packet thật (softflowd) và chạy qua 2 bộ điều phối.
"""
import os, re, sys, time, json, threading, logging, argparse
from pathlib import Path
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt

# Thêm đường dẫn gốc vào python path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from pipeline.s4_orchestration.orchestrator import Orchestrator
from evaluation.baseline_threshold import BaselineOrchestrator
from pipeline.s3_ai.live_pipeline import features_dict_to_array

# Thiết lập log
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger('E2E_Eval')

class E2EEvaluator:
    def __init__(self, args):
        self.args = args
        self.results_ai = []
        self.results_base = []
        self.timestamps = []
        self.stop_event = threading.Event()
        self.window_sec = 5.0
        self.collector_url = None
        self.collector_host = None
        self._last_vec_ts = None
        # Phase boundaries (epoch seconds), filled by run_mininet_test
        self.phase_t = {'baseline': 0.0, 'attack': 0.0, 'recovery': 0.0, 'end': 0.0}
        # Paths to iperf logs (in /tmp inside Mininet host netns, but Mininet
        # hosts share the root filesystem so we can read them from root)
        self.log_legit  = '/tmp/iperf_legit.log'   # legit user h2 → victim h15
        self.log_victim = '/tmp/iperf_victim.log'  # iperf -s on victim
        self.log_bg     = '/tmp/iperf_bg_cli.log'  # h1 → h14 background
        
        # 1. Khởi tạo 2 bộ não xử lý (AI và Ngưỡng tĩnh)
        # Tắt shap_enabled để đảm bảo xử lý real-time mượt mà trên Mininet
        self.ai_orch = Orchestrator(
            model_dir=args.model_dir, 
            data_dir=args.data_dir, 
            eval_mode=True,
            shap_enabled=args.shap, # Bật/tắt dựa trên tham số dòng lệnh
            latency_port=9298
        )
        self.base_orch = BaselineOrchestrator(
            eval_mode=True,
            latency_port=9299
        )

    def _run_orchestration(self, x_raw):
        """Chạy song song 2 orchestrator trên cùng 1 vector đặc trưng"""
        res_ai = self.ai_orch._step(x_raw)
        res_base = self.base_orch._step(x_raw)
        
        self.results_ai.append(res_ai['tier'])
        self.results_base.append(res_base['tier'])
        self.timestamps.append(time.time())
        
        print(f"Window {len(self.results_ai):03d} | AI: T{res_ai['tier']} ({'Proactive' if res_ai['proactive'] else 'Normal'}) | Base: T{res_base['tier']}")

    def run_mininet_test(self):
        # Import Mininet bên trong để tránh lỗi trên Windows nếu chỉ check code
        from mininet.net import Mininet
        from testbed.mininet.fat_tree_topology import build_fat_tree, attacker_victim

        logger.info(f"*** Khởi tạo Mininet Fat-Tree k={self.args.k}")
        # Dọn dẹp môi trường cũ trước khi bắt đầu
        os.system("sudo mn -c > /dev/null 2>&1")
        # Use pkill -f to ensure we match the full command line (e.g. "python3 collector.py")
        os.system("pkill -9 -f iperf > /dev/null 2>&1")
        os.system("pkill -9 -f iperf3 > /dev/null 2>&1")
        os.system("pkill -9 -f softflowd > /dev/null 2>&1")
        os.system("pkill -9 -f hping3 > /dev/null 2>&1")
        os.system("pkill -9 -f collector.py > /dev/null 2>&1")
        
        net = build_fat_tree(k=self.args.k)
        net.start()
        time.sleep(3) # Đợi mạng ổn định
        
        # Pre-check: tool availability
        h1 = net.get('h1')
        tools = ['softflowd', 'iperf', 'hping3', 'curl']
        missing = []
        for tool in tools:
            check = h1.cmd(f'which {tool} 2>&1')
            if not check.strip() or 'not found' in check:
                missing.append(tool)
        
        if missing:
            logger.error(f"❌ FATAL: Các công cụ sau chưa được cài đặt: {', '.join(missing)}")
            logger.error("   Cài đặt: sudo apt-get update && sudo apt-get install -y softflowd iperf hping3 curl")
            net.stop()
            sys.exit(1)
        logger.info("✓ Tools check: OK (softflowd, iperf, hping3, curl)")

        # h0 is the collector host. Pipeline runs in root namespace and polls
        # the collector via h0.cmd("curl ...") because hosts share an isolated
        # netns whose 127.0.0.1 is not reachable from root.
        collector = net.get('h0')
        collector_ip = collector.IP()
        self.collector_host = collector
        self.collector_url  = "http://127.0.0.1:7070"

        logger.info(f"*** Khởi động NetFlow Collector trên {collector.name} ({collector_ip}:7070)")
        collector_script = _ROOT / 'testbed' / 'netflow_collector' / 'collector.py'
        
        # Debug: Kiểm tra sự tồn tại của file và in lệnh
        logger.info(f"DEBUG: Collector script path: {collector_script}")
        if not collector_script.exists():
            logger.error(f"❌ LỖI: Không tìm thấy file collector tại {collector_script}")
        
        # Giải phóng port triệt để
        collector.cmd("fuser -k 7070/tcp 6343/udp 2>/dev/null")
        time.sleep(1)

        cmd = (f'python3 -u "{collector_script}" --mode netflow --port 6343 '
               f'--api-port 7070 --interval {self.window_sec} > /tmp/collector.log 2>&1 &')
        logger.info(f"DEBUG: Running cmd: {cmd}")
        
        collector.cmd(cmd)
        logger.info(f"    [Collector logs ghi tại /tmp/collector.log]")
        time.sleep(5) # Tăng thêm thời gian để collector tạo window đầu tiên
        
        # Health check: collector should be responsive
        health = collector.cmd("curl -s --max-time 2 http://127.0.0.1:7070/health")
        if "ok" in health:
            logger.info(f"    ✓ Collector health check passed: {health.strip()}")
        else:
            logger.warning(f"    ⚠  Collector health check failed (Result: '{health.strip()}').")
            logger.warning(f"       Kiểm tra log: cat /tmp/collector.log")
            # Extra diagnostic: check if process is even running
            ps_check = collector.cmd("ps aux | grep collector.py | grep -v grep")
            if not ps_check.strip():
                logger.error("       ERROR: Collector process is NOT running.")
            else:
                logger.info(f"       INFO: Collector process seems to be running: {ps_check.strip()[:100]}...")
        time.sleep(2)

        attacker, victim = attacker_victim(net)
        logger.info(f"*** Attacker: {attacker.name} -> Victim: {victim.name}")

        # softflowd: -t maxlife=10 forces flow export every ≤10s so the 5s
        # collector window has data; expint=5 flushes the cache too.
        logger.info(f"*** Khởi động softflowd trên các hosts (gửi về {collector_ip}:6343)")
        
        # Check if softflowd is available
        check_cmd = net.get('h1').cmd('which softflowd')
        if not check_cmd.strip():
            logger.warning("⚠  softflowd không được cài đặt! Các dòng flow sẽ không được capture.")
            logger.warning("   Cài: apt-get install -y softflowd")
        
        for host in net.hosts:
            if host.name == collector.name:  # Skip collector host
                continue
            try:
                cmd = (
                    f'softflowd -i {host.intf().name} -n {collector_ip}:6343 '
                    f'-v 5 -t maxlife=10 -t expint=5 &'
                )
                host.cmd(cmd)
                logger.info(f"   {host.name}: softflowd started")
            except Exception as e:
                logger.error(f"   {host.name}: Failed to start softflowd: {e}")

        # Baseline background traffic (h1 → h14, 10 Mbps UDP) so softflowd has
        # flows to export during Phase 1; gives the AI a Normal-class signal.
        bg_src = net.get('h1')
        bg_dst = net.get('h14')
        bg_dst.cmd('iperf -s -u -i 1 > /tmp/iperf_bg.log 2>&1 &')
        time.sleep(0.5)
        bg_src.cmd(
            f'iperf -c {bg_dst.IP()} -u -b 10M -t 9999 -i 1 '
            f'> {self.log_bg} 2>&1 &'
        )
        self._bg_pair = (bg_src, bg_dst)

        # Legitimate user h2 → victim h15: stays on throughout. We measure how
        # much of this user's goodput survives during the attack. iperf server
        # on h15 binds UDP 5001; hping3 flood targets port 80, so the two
        # streams are isolated at L4.
        legit_src = net.get('h2')
        # Ensure ports are free on hosts
        victim.cmd("fuser -k 5001/udp 2>/dev/null")
        time.sleep(0.5)
        victim.cmd(f'iperf -s -u -i 1 > {self.log_victim} 2>&1 &')

        legit_src.cmd(
            f'iperf -c {victim.IP()} -u -b 5M -t 9999 -i 1 '
            f'> {self.log_legit} 2>&1 &'
        )
        self._legit_pair = (legit_src, victim)
        # Truncate log mtimes so iperf parser can locate "test start = 0s".
        # All four iperf processes started within ~1 s of each other.
        self._iperf_t0 = time.time()

        logger.info(">>> Phase 1: Baseline (Normal traffic) - 30 giây")
        self.phase_t['baseline'] = time.time()
        while time.time() - self.phase_t['baseline'] < 30:
            self._collect_and_step()
            time.sleep(1.0)

        logger.info(f">>> Phase 2: UDP Flood Attack - {self.args.duration} giây")
        # Sử dụng hping3 flood thật sự
        attacker.cmd(f'hping3 --udp --flood -p 80 {victim.IP()} &')
        self.phase_t['attack'] = time.time()
        while time.time() - self.phase_t['attack'] < self.args.duration:
            self._collect_and_step()
            time.sleep(1.0)

        logger.info(">>> Phase 3: Recovery (Ngừng tấn công) - 20 giây")
        attacker.cmd('pkill hping3')
        self.phase_t['recovery'] = time.time()
        while time.time() - self.phase_t['recovery'] < 20:
            self._collect_and_step()
            time.sleep(1.0)
        self.phase_t['end'] = time.time()

        logger.info("*** Kết thúc kiểm thử. Dừng Mininet.")
        # Cleanup background processes before tearing down
        try:
            bg_src.cmd('pkill -f iperf')
            bg_dst.cmd('pkill -f iperf')
            legit_src.cmd('pkill -f iperf')
            victim.cmd('pkill -f iperf')
            for host in net.hosts:
                host.cmd('pkill -f softflowd')
            collector.cmd('pkill -f netflow_collector/collector.py')
        except Exception as e:
            logger.warning(f"Cleanup warning: {e}")
        # Give iperf a moment to flush its final buffer to the log file.
        time.sleep(1.0)
        net.stop()
        self.generate_report()

    def _collect_and_step(self):
        """
        Fetch latest feature vector from the collector running inside h0's
        netns. Pipeline lives in the root namespace, so we shell into h0
        via Mininet's `host.cmd()` rather than direct HTTP.
        """
        host = getattr(self, 'collector_host', None)
        if host is None:
            return
        raw = host.cmd(
            "curl -s --max-time 1 http://127.0.0.1:7070/flows/latest"
        ).strip()
        
        if not raw:
            logger.debug("[collect] Empty response from collector")
            return
        if not raw.startswith("{"):
            logger.debug(f"[collect] Invalid response (no JSON): {raw[:100]}")
            return
        
        try:
            vec = json.loads(raw)
        except Exception as e:
            logger.debug(f"[collect] JSON parse error: {e}")
            return
        ts = vec.get('timestamp')
        if ts is None or ts == self._last_vec_ts:
            return
        self._last_vec_ts = ts

        features = vec.get('features', {})
        if not features:
            return
        x = features_dict_to_array(features)
        self._run_orchestration(x)

    # ── iperf log parsing ────────────────────────────────────────────────────
    _IPERF_LINE = re.compile(
        r'\[\s*\d+\]\s+([\d.]+)-\s*([\d.]+)\s*sec\s+'
        r'[\d.]+\s+\w+\s+([\d.]+)\s+([KMG])bits/sec'
        r'(?:\s+[\d.]+\s+ms\s+\d+/\s*\d+\s+\(([\d.]+)%\))?'
    )

    def _parse_iperf_log(self, path: str) -> list:
        """
        Parse iperf -i 1 stdout. Returns list of dicts:
            {'t_offset': sec, 'mbps': float, 'lost_pct': float|None, 'epoch': float}
        Converts Kbits/Mbits/Gbits to Mbps. Skips aggregate line (which spans 0 → total seconds).
        """
        out = []
        if not os.path.exists(path):
            return out
        max_window = 1.5  # per-second lines have end-start ≈ 1.0
        try:
            with open(path) as f:
                for line in f:
                    m = self._IPERF_LINE.search(line)
                    if not m:
                        continue
                    t_start, t_end, rate_val, rate_unit, lost = m.groups()
                    t_s, t_e = float(t_start), float(t_end)
                    if (t_e - t_s) > max_window:
                        continue   # skip total/aggregate line
                    
                    # Convert rate to Mbps
                    rate = float(rate_val)
                    if rate_unit == 'K':
                        rate = rate / 1000.0  # Kbits → Mbps
                    elif rate_unit == 'G':
                        rate = rate * 1000.0  # Gbits → Mbps
                    # else: 'M' → already in Mbps
                    
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
        """Classify an epoch into phase name."""
        if epoch < self.phase_t['attack']:
            return 'baseline'
        if epoch < self.phase_t['recovery']:
            return 'attack'
        return 'recovery'

    def _mean_by_phase(self, series: list) -> dict:
        """Mean Mbps per phase from an iperf series."""
        buckets = {'baseline': [], 'attack': [], 'recovery': []}
        for p in series:
            buckets[self._phase_of(p['epoch'])].append(p['mbps'])
        return {k: (sum(v) / len(v) if v else 0.0) for k, v in buckets.items()}

    # ── Metric computation ──────────────────────────────────────────────────
    def _compute_metrics(self, legit_series: list, victim_series: list) -> dict:
        """
        Lead time, TPR/FPR per window, goodput-per-phase.
        Window = 1 entry in self.results_ai / self.results_base.
        Ground truth: window epoch in [attack, recovery) → label=1, else 0.
        AI positive: tier >= 2 (proactive escalation already counts).
        Baseline positive: tier >= 3 (reactive Mitigate).
        """
        ai = self.results_ai
        bs = self.results_base
        wt = self.timestamps
        n  = len(ai)

        def _first(seq, pred):
            for i, v in enumerate(seq):
                if pred(v):
                    return i
            return None

        ai_first_t2   = _first(ai, lambda t: t >= 2)
        ai_first_t3   = _first(ai, lambda t: t >= 3)
        base_first_t3 = _first(bs, lambda t: t >= 3)

        def _epoch(idx):
            return wt[idx] if (idx is not None and idx < len(wt)) else None

        e_ai_t2 = _epoch(ai_first_t2)
        e_ai_t3 = _epoch(ai_first_t3)
        e_bs_t3 = _epoch(base_first_t3)

        lead_vs_baseline = (e_bs_t3 - e_ai_t2) if (e_ai_t2 and e_bs_t3) else None
        lead_proactive   = (e_ai_t3 - e_ai_t2) if (e_ai_t2 and e_ai_t3) else None

        # TPR/FPR per window
        labels = []
        for t in wt:
            labels.append(1 if (self.phase_t['attack'] <= t < self.phase_t['recovery']) else 0)
        ai_pred = [1 if t >= 2 else 0 for t in ai]
        bs_pred = [1 if t >= 3 else 0 for t in bs]

        def _stats(pred):
            tp = sum(1 for p, y in zip(pred, labels) if p == 1 and y == 1)
            fp = sum(1 for p, y in zip(pred, labels) if p == 1 and y == 0)
            fn = sum(1 for p, y in zip(pred, labels) if p == 0 and y == 1)
            tn = sum(1 for p, y in zip(pred, labels) if p == 0 and y == 0)
            tpr = tp / (tp + fn) if (tp + fn) else 0.0
            fpr = fp / (fp + tn) if (fp + tn) else 0.0
            prec = tp / (tp + fp) if (tp + fp) else 0.0
            f1 = (2 * prec * tpr / (prec + tpr)) if (prec + tpr) else 0.0
            return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                    'tpr': round(tpr, 4), 'fpr': round(fpr, 4),
                    'precision': round(prec, 4), 'f1': round(f1, 4)}

        return {
            'n_windows': n,
            'lead_time_vs_baseline_s': round(lead_vs_baseline, 2) if lead_vs_baseline else None,
            'lead_time_proactive_internal_s': round(lead_proactive, 2) if lead_proactive else None,
            'first_window': {
                'ai_tier2':   ai_first_t2,
                'ai_tier3':   ai_first_t3,
                'base_tier3': base_first_t3,
            },
            'classification_ai':       _stats(ai_pred),
            'classification_baseline': _stats(bs_pred),
            'goodput_legit_mbps_by_phase':  self._mean_by_phase(legit_series),
            'goodput_victim_mbps_by_phase': self._mean_by_phase(victim_series),
        }

    # ── Reporting ────────────────────────────────────────────────────────────
    def generate_report(self):
        out_dir = _ROOT / 'evaluation' / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Parse iperf logs
        legit_series  = self._parse_iperf_log(self.log_legit)
        victim_series = self._parse_iperf_log(self.log_victim)
        bg_series     = self._parse_iperf_log(self.log_bg)
        logger.info(f"[iperf] legit={len(legit_series)}  victim={len(victim_series)}  bg={len(bg_series)} samples")

        metrics = self._compute_metrics(legit_series, victim_series)

        if metrics['n_windows'] == 0:
            logger.error("❌ LỖI: Không thu thập được cửa sổ dữ liệu nào (n_windows=0)!")
            logger.error("   Vui lòng kiểm tra log collector: cat /tmp/collector.log")
            logger.error("   Và đảm bảo traffic đang chảy (check iperf logs trong /tmp)")
            return

        # Time axis: prefer real epochs (relative to attack start = 0); fall
        # back to fixed-window approximation if timestamps missing.
        if self.timestamps:
            t_attack = self.phase_t['attack'] or self.timestamps[0]
            x_axis = np.array([t - t_attack for t in self.timestamps])
        else:
            x_axis = np.arange(len(self.results_ai)) * self.window_sec - 30.0

        # Two-panel chart: tier curves + goodput overlay
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 9), sharex=True)

        ax1.step(x_axis, self.results_ai,  label='AI-Augmented (Proactive)',
                 color='#1f77b4', linewidth=2, where='post')
        ax1.step(x_axis, self.results_base, label='Threshold-based (Reactive)',
                 color='#d62728', linestyle='--', linewidth=2, where='post')
        ax1.set_ylabel('Response Tier', fontsize=12)
        ax1.set_yticks([0, 1, 2, 3, 4])
        ax1.set_yticklabels(['T0:Normal', 'T1:Alert', 'T2:Preempt', 'T3:Mitigate', 'T4:Block'])
        ax1.legend(loc='upper left')
        ax1.grid(True, linestyle=':', alpha=0.6)
        ax1.axvline(x=0, color='gray', linestyle='-.', alpha=0.5, label='Attack start')
        ax1.axvline(x=self.args.duration, color='gray', linestyle=':', alpha=0.5)
        ax1.set_title('DDoS Response Comparison — Real Mininet Traffic', fontsize=14)

        # Panel 2: goodput
        if legit_series:
            t_attack = self.phase_t['attack'] or self._iperf_t0
            t_rel = [p['epoch'] - t_attack for p in legit_series]
            ax2.plot(t_rel, [p['mbps'] for p in legit_series],
                     label='Legit user h2 → victim (5 Mbps offered)',
                     color='#2ca02c', linewidth=1.8)
        if victim_series:
            t_attack = self.phase_t['attack'] or self._iperf_t0
            t_rel = [p['epoch'] - t_attack for p in victim_series]
            ax2.plot(t_rel, [p['mbps'] for p in victim_series],
                     label='Victim received (legit only)',
                     color='#9467bd', linewidth=1.5, linestyle='--')
        ax2.set_xlabel('Time relative to attack start (s)', fontsize=12)
        ax2.set_ylabel('Throughput (Mbps)', fontsize=12)
        ax2.axvline(x=0, color='gray', linestyle='-.', alpha=0.5)
        ax2.axvline(x=self.args.duration, color='gray', linestyle=':', alpha=0.5)
        ax2.legend(loc='lower left')
        ax2.grid(True, linestyle=':', alpha=0.6)

        plt.tight_layout()
        img_path = out_dir / f'real_e2e_comparison_{ts}.png'
        plt.savefig(img_path, dpi=300)
        plt.close(fig)
        logger.info(f"[✓] Biểu đồ so sánh đã lưu: {img_path}")

        # Extended JSON
        report_data = {
            'timestamp': ts,
            'config':    {'k': self.args.k, 'duration': self.args.duration,
                          'window_sec': self.window_sec},
            'phases': {k: round(v, 3) for k, v in self.phase_t.items()},
            'series': {
                'ai_tiers':           self.results_ai,
                'base_tiers':         self.results_base,
                'window_timestamps':  [round(t, 3) for t in self.timestamps],
                'time_axis_rel_s':    x_axis.tolist(),
            },
            'iperf': {
                'legit_h2_to_victim': legit_series,
                'victim_received':    victim_series,
                'background_h1_h14':  bg_series,
            },
            'metrics': metrics,
        }
        json_path = out_dir / f'real_e2e_data_{ts}.json'
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        logger.info(f"[✓] Dữ liệu JSON đã lưu: {json_path}")

        # Console summary
        m = metrics
        print("\n" + "─" * 60)
        print(f"  Real Mininet Testbed Summary — k={self.args.k}, attack={self.args.duration}s")
        print("─" * 60)
        print(f"  Windows collected           : {m['n_windows']}")
        lt = m['lead_time_vs_baseline_s']
        print(f"  Lead time AI vs Baseline    : "
              f"{lt:.1f} s" if lt is not None else "  Lead time AI vs Baseline    : n/a")
        print(f"  AI    TPR/FPR/F1            : "
              f"{m['classification_ai']['tpr']:.2f} / "
              f"{m['classification_ai']['fpr']:.2f} / "
              f"{m['classification_ai']['f1']:.2f}")
        print(f"  Base  TPR/FPR/F1            : "
              f"{m['classification_baseline']['tpr']:.2f} / "
              f"{m['classification_baseline']['fpr']:.2f} / "
              f"{m['classification_baseline']['f1']:.2f}")
        gp = m['goodput_victim_mbps_by_phase']
        print(f"  Victim goodput (Mbps)       : "
              f"baseline={gp['baseline']:.2f} | "
              f"attack={gp['attack']:.2f} | "
              f"recovery={gp['recovery']:.2f}")
        print("─" * 60)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PAD-ONAP: Real NetFlow E2E Evaluation')
    parser.add_argument('--k', type=int, default=4, help='Fat-tree k-factor')
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')
    parser.add_argument('--model-dir', default=str(_ROOT/'pad_onap_v3'/'models'))
    parser.add_argument('--data-dir', default=str(_ROOT/'pad_onap_v3'/'processed'))
    parser.add_argument('--shap', action='store_true', help='Enable SHAP explainability (slows down processing)')
    args = parser.parse_args()

    # Check root
    if os.name != 'nt' and os.geteuid() != 0:
        print("\n[!] ERROR: Script này phải chạy bằng 'sudo' để khởi tạo Mininet.\n")
        sys.exit(1)

    evaluator = E2EEvaluator(args)
    try:
        evaluator.run_mininet_test()
    except KeyboardInterrupt:
        logger.info("Dừng script bởi người dùng.")
        os.system('sudo mn -c')
